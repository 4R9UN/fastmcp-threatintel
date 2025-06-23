import logging
from collections.abc import Callable
from datetime import datetime, timedelta
from hashlib import md5
from typing import Any

import anyio
import httpx
from fastmcp import Context
from pydantic import BaseModel, Field

from .settings import settings

# Configure logger
logger = logging.getLogger("threatintel.api")

# Cache for API responses
cache: dict[str, tuple[Any, datetime]] = {}


class IOC(BaseModel):
    """Indicator of Compromise data model."""

    value: str
    type: str  # e.g., "ip", "hash", "domain", "url", "md5", "sha1", "sha256"
    reputation: str | None = None
    score: float | None = None
    engines: list[str] = Field(default_factory=list)
    reports: list[str] = Field(default_factory=list)
    otx_pulses: list[str] = Field(default_factory=list)
    abuseipdb_confidence: int | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    tags: list[str] = Field(default_factory=list)
    city: str | None = None
    region: str | None = None
    country: str | None = None
    asn: str | None = None
    location: str | None = None


class APTAttribution(BaseModel):
    """Advanced Persistent Threat attribution data model."""

    actor: str | None = None
    group: str | None = None
    target_region: str | None = None
    target_sectors: list[str] = Field(default_factory=list)
    motive: str | None = None
    summary: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    confidence: int | None = None


async def check_api_keys(ctx: Context) -> bool:
    """Check if API keys are configured and report missing ones."""
    missing_keys = []

    if not settings.virustotal_api_key:
        missing_keys.append("VirusTotal")

    if not settings.otx_api_key:
        missing_keys.append("OTX")

    if not settings.abuseipdb_api_key:
        missing_keys.append("AbuseIPDB")

    if missing_keys:
        await ctx.warning(f"Missing API keys for: {', '.join(missing_keys)}")
        return len(missing_keys) < 3  # Return True if at least one API is available

    return True


def get_cache_key(func_name: str, *args) -> str:
    """Generate a unique cache key for the function call."""
    key_parts = [func_name, *[str(arg) for arg in args]]
    return md5(":".join(key_parts).encode()).hexdigest()


def cached_api_call(ttl_seconds: int | None = None):
    """Decorator for caching API call results."""

    def decorator(func: Callable) -> Callable:
        async def wrapper(*args, **kwargs) -> Any:
            # Extract context from kwargs
            ctx = kwargs.get("ctx")

            # Use provided TTL or default from settings
            ttl = ttl_seconds or settings.cache_ttl

            # Generate cache key (exclude ctx from cache key)
            cache_args = list(args)
            cache_key = get_cache_key(func.__name__, *cache_args)

            # Check if result in cache and not expired
            if cache_key in cache:
                result, expiry = cache[cache_key]
                if datetime.now() < expiry:
                    if ctx:
                        await ctx.debug(f"Cache hit for {func.__name__}({args})")
                    return result

            # Call the original function with the exact signature it expects
            result = await func(*args, **kwargs)

            # Cache the result
            cache[cache_key] = (result, datetime.now() + timedelta(seconds=ttl))

            return result

        return wrapper

    return decorator


async def retry_api_call(
    func: Callable, *args, max_retries: int | None = None, delay_base: float = 1.0, **kwargs
) -> Any:
    """Retry API calls with exponential backoff."""
    retries = max_retries or settings.max_retries
    ctx = kwargs.pop("ctx", None)  # Remove ctx from kwargs before passing to func
    last_exception = None

    for attempt in range(retries + 1):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            last_exception = e
            # On final attempt, raise the original error
            if attempt == retries:
                raise e from None

            # Calculate backoff delay
            delay = delay_base * (2**attempt)
            if ctx:
                await ctx.warning(f"API call failed: {str(e)}. Retrying in {delay:.2f}s...")
            await anyio.sleep(delay)

    # Should never reach here, but if we do, raise the last exception
    if last_exception:
        raise last_exception from None
    raise RuntimeError("Unexpected: retry loop completed without return or raise")


@cached_api_call()
async def query_virustotal(ioc: str, ioc_type: str, ctx: Context) -> IOC:
    """Query VirusTotal for information about an IOC."""
    if not settings.virustotal_api_key:
        await ctx.warning("VirusTotal API key not configured")
        return IOC(
            value=ioc,
            type=ioc_type,
            reputation="Unknown",
            reports=["VirusTotal: API key not configured"],
            score=None,
            abuseipdb_confidence=None,
            first_seen=None,
            last_seen=None,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        )

    # Map IOC types to VirusTotal endpoints
    base_url = "https://www.virustotal.com/api/v3"
    ioc_type_map = {
        "ip": "ip_addresses",
        "domain": "domains",
        "url": "urls",
        "md5": "files",
        "sha1": "files",
        "sha256": "files",
    }

    # For hash types, map them to the generic "hash" type for further processing
    normalized_type = ioc_type.lower()
    if normalized_type in ["md5", "sha1", "sha256"]:
        endpoint_type = "files"
    else:
        endpoint_type = ioc_type_map.get(normalized_type)

    if not endpoint_type:
        await ctx.error(f"Unsupported IOC type for VirusTotal: {ioc_type}")
        return IOC(
            value=ioc,
            type=ioc_type,
            reputation="Unknown",
            reports=[f"VirusTotal: Unsupported IOC type '{ioc_type}'"],
            score=None,
            abuseipdb_confidence=None,
            first_seen=None,
            last_seen=None,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        )

    # Special handling for URLs - need to hash them first
    url = f"{base_url}/{endpoint_type}/{ioc}"
    if normalized_type == "url":
        import base64

        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        url = f"{base_url}/{endpoint_type}/{url_id}"

    headers = {"x-apikey": settings.virustotal_api_key, "User-Agent": settings.user_agent}

    async def _make_request() -> IOC:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=settings.request_timeout)
            response.raise_for_status()
            return response.json()

    try:
        # Perform the API call with retries
        data = await retry_api_call(_make_request)

        # Process the response
        attributes = data.get("data", {}).get("attributes", {})

        # Extract common fields
        stats = attributes.get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        total_engines = sum(stats.values()) or 1  # Avoid division by zero

        # Calculate normalized score (0-100)
        score = ((malicious_count + (suspicious_count * 0.5)) / total_engines) * 100

        # Determine reputation
        if malicious_count > 0:
            reputation = "Malicious"
        elif suspicious_count > 0:
            reputation = "Suspicious"
        else:
            reputation = "Clean"

        # Get detection engines
        engines = [
            engine
            for engine, result in attributes.get("last_analysis_results", {}).items()
            if result.get("category") in ["malicious", "suspicious"]
        ]

        # Extract first/last seen dates if available
        first_seen = attributes.get("first_submission_date")
        last_seen = attributes.get("last_analysis_date")

        # Convert timestamps to ISO format strings if they exist
        if first_seen:
            first_seen = datetime.fromtimestamp(first_seen).isoformat()
        if last_seen:
            last_seen = datetime.fromtimestamp(last_seen).isoformat()

        # Extract tags if available
        tags = attributes.get("tags", [])

        # Create detailed report message
        report_msg = (
            f"VirusTotal: {malicious_count} malicious, {suspicious_count} suspicious "
            f"out of {total_engines} engines"
        )
        # Create and return the IOC object
        return IOC(
            value=ioc,
            type=ioc_type,
            reputation=reputation,
            score=round(score, 1),
            engines=engines,
            reports=[report_msg],
            first_seen=first_seen,
            last_seen=last_seen,
            tags=tags,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
            abuseipdb_confidence=None,
        )

    except httpx.HTTPStatusError as e:
        error_message = f"VirusTotal API error ({e.response.status_code}): {e.response.text}"
        await ctx.error(error_message)
        return IOC(
            value=ioc,
            type=ioc_type,
            reputation="Unknown",
            reports=[error_message],
            score=None,
            abuseipdb_confidence=None,
            first_seen=None,
            last_seen=None,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        )
    except httpx.TimeoutException as e:
        error_message = f"VirusTotal API timeout: {str(e)}"
        await ctx.error(error_message)
        return IOC(
            value=ioc,
            type=ioc_type,
            reputation="Unknown",
            reports=[error_message],
            score=None,
            abuseipdb_confidence=None,
            first_seen=None,
            last_seen=None,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        )
    except Exception as e:
        error_message = f"VirusTotal API error: {str(e)}"
        await ctx.error(error_message)
        return IOC(
            value=ioc,
            type=ioc_type,
            reputation="Unknown",
            reports=[error_message],
            score=None,
            abuseipdb_confidence=None,
            first_seen=None,
            last_seen=None,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        )


@cached_api_call()
async def query_otx(ioc: str, ioc_type: str, ctx: Context) -> IOC:
    """Query AlienVault OTX for information about an IOC."""
    if not settings.otx_api_key:
        await ctx.warning("OTX API key not configured")
        return IOC(
            value=ioc,
            type=ioc_type,
            reputation="Unknown",
            reports=["OTX: API key not configured"],
            score=None,
            abuseipdb_confidence=None,
            first_seen=None,
            last_seen=None,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        )

    # Map IOC types to OTX endpoint sections
    ioc_type_map = {
        "ip": "IPv4",
        "domain": "domain",
        "url": "url",
        "md5": "file",
        "sha1": "file",
        "sha256": "file",
    }

    normalized_type = ioc_type.lower()
    endpoint_type = ioc_type_map.get(normalized_type)

    if not endpoint_type:
        await ctx.error(f"Unsupported IOC type for OTX: {ioc_type}")
        return IOC(
            value=ioc,
            type=ioc_type,
            reputation="Unknown",
            reports=[f"OTX: Unsupported IOC type '{ioc_type}'"],
            score=None,
            abuseipdb_confidence=None,
            first_seen=None,
            last_seen=None,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        )

    # Set up API call
    base_url = "https://otx.alienvault.com/api/v1/indicators"
    url = f"{base_url}/{endpoint_type}/{ioc}/general"

    headers = {"X-OTX-API-KEY": settings.otx_api_key, "User-Agent": settings.user_agent}

    async def _make_request() -> Any:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=settings.request_timeout)
            response.raise_for_status()
            return response.json()

    try:
        # Perform the API call with retries
        data = await retry_api_call(_make_request)

        # Extract pulse info
        pulse_info = data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        pulses = [pulse.get("name", "") for pulse in pulse_info.get("pulses", [])]

        # Determine reputation based on pulse count
        if pulse_count > 5:
            reputation = "Malicious"
            score = min(80 + (pulse_count // 2), 100)
        elif pulse_count > 0:
            reputation = "Suspicious"
            score = 40 + (pulse_count * 8)
        else:
            reputation = "Clean"
            score = 0

        # Extract first and last seen dates if available
        first_seen = None
        last_seen = None

        if pulses and "created" in pulse_info.get("pulses", [{}])[0]:
            dates = [p.get("created") for p in pulse_info.get("pulses", []) if p.get("created")]
            if dates:
                first_seen = min(dates)
                last_seen = max(dates)
        # Extract tags from pulses
        all_tags = set()
        for pulse in pulse_info.get("pulses", []):
            tags = pulse.get("tags", [])
            all_tags.update(tags)

        # Create detailed report message
        report_msg = f"OTX: Found in {pulse_count} pulses"

        return IOC(
            value=ioc,
            type=ioc_type,
            reputation=reputation,
            score=round(score, 1) if score is not None else None,
            otx_pulses=pulses,
            reports=[report_msg],
            first_seen=first_seen,
            last_seen=last_seen,
            tags=list(all_tags),
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
            abuseipdb_confidence=None,
        )

    except httpx.HTTPStatusError as e:
        error_message = f"OTX API error: {e.response.status_code} - {e.response.text}"
        await ctx.error(error_message)
        return IOC(
            value=ioc,
            type=ioc_type,
            reputation="Unknown",
            reports=[error_message],
            score=None,
            abuseipdb_confidence=None,
            first_seen=None,
            last_seen=None,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        )
    except Exception as e:
        error_message = f"OTX API error: {str(e)}"
        await ctx.error(error_message)
        return IOC(
            value=ioc,
            type=ioc_type,
            reputation="Unknown",
            reports=[error_message],
            score=None,
            abuseipdb_confidence=None,
            first_seen=None,
            last_seen=None,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        )


@cached_api_call()
async def query_abuseipdb(ioc: str, ioc_type: str, ctx: Context) -> IOC:
    """Query AbuseIPDB for IP reputation information."""
    if not settings.abuseipdb_api_key:
        await ctx.warning("AbuseIPDB API key not configured")
        return IOC(
            value=ioc,
            type=ioc_type,
            reputation="Unknown",
            reports=["AbuseIPDB: API key not configured"],
            score=None,
            abuseipdb_confidence=None,
            first_seen=None,
            last_seen=None,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        )

    # AbuseIPDB only supports IP addresses
    normalized_type = ioc_type.lower()
    if normalized_type != "ip":
        await ctx.debug(f"AbuseIPDB only supports IP addresses, not {ioc_type}")
        return IOC(
            value=ioc,
            type=ioc_type,
            reputation="Unknown",
            reports=["AbuseIPDB: Only supports IP addresses"],
            score=None,
            abuseipdb_confidence=None,
            first_seen=None,
            last_seen=None,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        )

    # Set up API call
    base_url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ioc, "maxAgeInDays": 90, "verbose": True}

    headers = {
        "Key": settings.abuseipdb_api_key,
        "Accept": "application/json",
        "User-Agent": settings.user_agent,
    }

    async def _make_request() -> Any:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                base_url, params=params, headers=headers, timeout=settings.request_timeout
            )
            response.raise_for_status()
            return response.json()

    try:
        # Perform the API call with retries
        result = await retry_api_call(_make_request)

        # Extract data from response
        data = result.get("data", {})
        confidence = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)

        # Determine reputation based on confidence score
        if confidence >= 80:
            reputation = "Malicious"
            score = confidence
        elif confidence >= 20:
            reputation = "Suspicious"
            score = confidence
        else:
            reputation = "Clean"
            score = confidence

        # Extract last reported date if available
        last_seen = None
        if data.get("lastReportedAt"):
            last_seen = data.get("lastReportedAt")

        # Get any report comments as additional context
        reports = [f"AbuseIPDB: {confidence}% confidence score, {total_reports} report(s)"]
        # Extract tags from usage type
        tags = []
        if data.get("usageType"):
            tags.append(data.get("usageType"))
        if data.get("domain"):
            tags.append(data.get("domain"))
        if data.get("isTor"):
            tags.append("TOR")

        return IOC(
            value=ioc,
            type=ioc_type,
            reputation=reputation,
            score=float(score) if score is not None else None,
            abuseipdb_confidence=confidence,
            reports=reports,
            first_seen=None,
            last_seen=last_seen,
            tags=tags,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        )

    except httpx.HTTPStatusError as e:
        error_message = f"AbuseIPDB API error: {e.response.status_code} - {e.response.text}"
        await ctx.error(error_message)
        return IOC(
            value=ioc,
            type=ioc_type,
            reputation="Unknown",
            reports=[error_message],
            score=None,
            abuseipdb_confidence=None,
            first_seen=None,
            last_seen=None,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        )
    except Exception as e:
        error_message = f"AbuseIPDB API error: {str(e)}"
        await ctx.error(error_message)
        return IOC(
            value=ioc,
            type=ioc_type,
            reputation="Unknown",
            reports=[error_message],
            score=None,
            abuseipdb_confidence=None,
            first_seen=None,
            last_seen=None,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        )


@cached_api_call()
async def query_ipinfo(ioc: str, ioc_type: str, ctx: Context) -> IOC:
    """Query IPinfo for geolocation and ASN information."""
    if not settings.ipinfo_api_key:
        await ctx.warning("IPinfo API key not configured")
        return IOC(
            value=ioc,
            type=ioc_type,
            reputation="Unknown",
            reports=["IPinfo: API key not configured"],
            score=None,
            abuseipdb_confidence=None,
            first_seen=None,
            last_seen=None,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        )

    # IPinfo only supports IP addresses
    normalized_type = ioc_type.lower()
    if normalized_type != "ip":
        await ctx.debug(f"IPinfo only supports IP addresses, not {ioc_type}")
        return IOC(
            value=ioc,
            type=ioc_type,
            reputation="Unknown",
            reports=["IPinfo: Only supports IP addresses"],
            score=None,
            abuseipdb_confidence=None,
            first_seen=None,
            last_seen=None,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        )

    # Set up API call
    base_url = f"https://ipinfo.io/{ioc}"
    params = {"token": settings.ipinfo_api_key}

    headers = {"Accept": "application/json", "User-Agent": settings.user_agent}

    async def _make_request() -> Any:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                base_url, params=params, headers=headers, timeout=settings.request_timeout
            )
            response.raise_for_status()
            return response.json()

    try:
        # Perform the API call with retries
        data = await retry_api_call(_make_request)

        # Extract data from response
        city = data.get("city")
        region = data.get("region")
        country = data.get("country")
        asn = data.get("org")
        location = data.get("loc")

        report_msg = f"IPinfo: Geolocation - {city}, {region}, {country}; ASN - {asn}"

        tags = []
        if city:
            tags.append(city)
        if region:
            tags.append(region)
        if country:
            tags.append(country)
        if asn:
            tags.append(asn)

        return IOC(
            value=ioc,
            type=ioc_type,
            reputation="Informational",  # IPinfo is informational, not malicious
            score=0,
            reports=[report_msg],
            first_seen=None,
            last_seen=None,
            tags=tags,
            city=city,
            region=region,
            country=country,
            asn=asn,
            location=location,
            abuseipdb_confidence=None,
        )

    except httpx.HTTPStatusError as e:
        error_message = f"IPinfo API error: {e.response.status_code} - {e.response.text}"
        await ctx.error(error_message)
        return IOC(
            value=ioc,
            type=ioc_type,
            reputation="Unknown",
            reports=[error_message],
            score=None,
            abuseipdb_confidence=None,
            first_seen=None,
            last_seen=None,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        )
    except Exception as e:
        error_message = f"IPinfo API error: {str(e)}"
        await ctx.error(error_message)
        return IOC(
            value=ioc,
            type=ioc_type,
            reputation="Unknown",
            reports=[error_message],
            score=None,
            abuseipdb_confidence=None,
            first_seen=None,
            last_seen=None,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        )
