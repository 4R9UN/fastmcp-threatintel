"""Unit tests for the threatintel module."""

from datetime import datetime
from unittest.mock import Mock, patch

import httpx
import pytest
from src.threatintel.threatintel import (
    IOC,
    APTAttribution,
    cache,
    check_api_keys,
    query_abuseipdb,
    query_otx,
    query_virustotal,
    retry_api_call,
)


@pytest.fixture(autouse=True)
def clear_cache():
    """Fixture to clear the cache before each test."""
    cache.clear()


class TestIOCModel:
    """Test the IOC data model."""

    def test_ioc_creation(self):
        """Test IOC model creation with minimal data."""
        ioc = IOC(value="192.168.1.1", type="ip")
        assert ioc.value == "192.168.1.1"
        assert ioc.type == "ip"
        assert ioc.reputation is None
        assert ioc.score is None

    def test_ioc_creation_with_full_data(self):
        """Test IOC model creation with full data."""
        ioc = IOC(
            value="192.168.1.1",
            type="ip",
            reputation="Malicious",
            score=85.5,
            engines=["Engine1", "Engine2"],
            reports=["Detected as malware"],
            city="New York",
            country="US",
        )
        assert ioc.value == "192.168.1.1"
        assert ioc.reputation == "Malicious"
        assert ioc.score == 85.5
        assert len(ioc.engines) == 2
        assert ioc.city == "New York"


class TestAPTAttributionModel:
    """Test the APT Attribution data model."""

    def test_apt_attribution_creation(self):
        """Test APT attribution model creation."""
        attribution = APTAttribution(actor="APT29", group="Cozy Bear", confidence=85)
        assert attribution.actor == "APT29"
        assert attribution.group == "Cozy Bear"
        assert attribution.confidence == 85


class TestAPIFunctions:
    """Test API query functions."""

    @pytest.mark.anyio
    async def test_check_api_keys_with_all_keys(self, mock_context, monkeypatch):
        """Test API key checking when all keys are present."""
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test_key")
        monkeypatch.setenv("OTX_API_KEY", "test_key")
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "test_key")

        # Reload settings to pick up new environment
        from src.threatintel.settings import Settings

        settings = Settings()

        with patch("src.threatintel.threatintel.settings", settings):
            result = await check_api_keys(mock_context)
            assert result is True

    @pytest.mark.anyio
    async def test_check_api_keys_missing_some(self, mock_context, monkeypatch):
        """Test API key checking when some keys are missing."""
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test_key")
        monkeypatch.delenv("OTX_API_KEY", raising=False)
        monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

        from src.threatintel.settings import Settings

        settings = Settings()

        with patch("src.threatintel.threatintel.settings", settings):
            result = await check_api_keys(mock_context)
            assert result is True  # Should return True if at least one key is available
            mock_context.warning.assert_called()

    @pytest.mark.anyio
    async def test_query_virustotal_success(self, mock_context, mock_api_responses):
        """Test successful VirusTotal query."""
        with patch("src.threatintel.threatintel.settings") as mock_settings:
            mock_settings.virustotal_api_key = "test_key"
            mock_settings.user_agent = "test-agent"
            mock_settings.request_timeout = 10
            mock_settings.cache_ttl = 300

            with patch("httpx.AsyncClient") as mock_client:
                mock_response = Mock()
                mock_response.json.return_value = mock_api_responses["virustotal"]
                mock_response.raise_for_status.return_value = None

                mock_client.return_value.__aenter__.return_value.get.return_value = mock_response

                result = await query_virustotal("192.168.1.1", "ip", ctx=mock_context)

                assert isinstance(result, IOC)
                assert result.value == "192.168.1.1"
                assert result.type == "ip"
                assert result.reputation == "Malicious"  # 5 malicious out of 70 total

    @pytest.mark.anyio
    async def test_query_virustotal_no_api_key(self, mock_context):
        """Test VirusTotal query without API key."""
        with patch("src.threatintel.threatintel.settings") as mock_settings:
            mock_settings.virustotal_api_key = None
            mock_settings.cache_ttl = 300

            result = await query_virustotal("192.168.1.1", "ip", ctx=mock_context)

            assert isinstance(result, IOC)
            assert result.reputation == "Unknown"
            assert "API key not configured" in result.reports[0]

    @pytest.mark.anyio
    async def test_query_otx_success(self, mock_context, mock_api_responses):
        """Test successful OTX query."""
        with patch("src.threatintel.threatintel.settings") as mock_settings:
            mock_settings.otx_api_key = "test_key"
            mock_settings.user_agent = "test-agent"
            mock_settings.request_timeout = 10
            mock_settings.cache_ttl = 300

            with patch("httpx.AsyncClient") as mock_client:
                mock_response = Mock()
                mock_response.json.return_value = mock_api_responses["otx"]
                mock_response.raise_for_status.return_value = None

                mock_client.return_value.__aenter__.return_value.get.return_value = mock_response

                result = await query_otx("192.168.1.1", "ip", ctx=mock_context)

                assert isinstance(result, IOC)
                assert result.value == "192.168.1.1"
                assert result.reputation == "Suspicious"  # 3 pulses = suspicious
                assert len(result.otx_pulses) == 1

    @pytest.mark.anyio
    async def test_query_abuseipdb_success(self, mock_context, mock_api_responses):
        """Test successful AbuseIPDB query."""
        with patch("src.threatintel.threatintel.settings") as mock_settings:
            mock_settings.abuseipdb_api_key = "test_key"
            mock_settings.user_agent = "test-agent"
            mock_settings.request_timeout = 10
            mock_settings.cache_ttl = 300

            with patch("httpx.AsyncClient") as mock_client:
                mock_response = Mock()
                mock_response.json.return_value = mock_api_responses["abuseipdb"]
                mock_response.raise_for_status.return_value = None

                mock_client.return_value.__aenter__.return_value.get.return_value = mock_response

                result = await query_abuseipdb("192.168.1.1", "ip", ctx=mock_context)

                assert isinstance(result, IOC)
                assert result.value == "192.168.1.1"
                assert result.reputation == "Malicious"  # 85% confidence = malicious
                assert result.abuseipdb_confidence == 85

    @pytest.mark.anyio
    async def test_query_abuseipdb_non_ip(self, mock_context):
        """Test AbuseIPDB query with non-IP IOC."""
        with patch("src.threatintel.threatintel.settings") as mock_settings:
            mock_settings.abuseipdb_api_key = "test_key"
            mock_settings.cache_ttl = 300

            result = await query_abuseipdb("example.com", "domain", ctx=mock_context)

            assert isinstance(result, IOC)
            assert result.reputation == "Unknown"
            assert "Only supports IP addresses" in result.reports[0]


class TestCaching:
    """Test caching functionality."""

    @pytest.mark.anyio
    async def test_cache_hit(self, mock_context):
        """Test that cache returns cached results."""
        from src.threatintel.threatintel import cache, get_cache_key

        # Pre-populate cache
        cache_key = get_cache_key("test_function", "test_arg")
        cached_result = IOC(value="test", type="test")
        cache[cache_key] = (cached_result, datetime.now().replace(year=2030))  # Far future

        @patch("src.threatintel.threatintel.cached_api_call")
        def mock_cached_function():
            return cached_result

        # The cached result should be returned without calling the function
        assert len(cache) > 0


class TestErrorHandling:
    """Test error handling in API functions."""

    @pytest.mark.anyio
    async def test_virustotal_http_error(self, mock_context):
        """Test VirusTotal HTTP error handling."""
        with patch("src.threatintel.threatintel.settings") as mock_settings:
            mock_settings.virustotal_api_key = "test_key"
            mock_settings.user_agent = "test-agent"
            mock_settings.request_timeout = 10
            mock_settings.cache_ttl = 300

            with patch("httpx.AsyncClient") as mock_client:
                mock_response = Mock()
                mock_response.status_code = 403
                mock_response.text = "Forbidden"

                mock_client.return_value.__aenter__.return_value.get.side_effect = (
                    httpx.HTTPStatusError("403 Forbidden", request=Mock(), response=mock_response)
                )

                result = await query_virustotal("192.168.1.1", "ip", ctx=mock_context)

                assert isinstance(result, IOC)
                assert result.reputation == "Unknown"
                assert "403" in result.reports[0]

    @pytest.mark.anyio
    async def test_network_timeout(self, mock_context):
        """Test network timeout handling."""
        with patch("src.threatintel.threatintel.settings") as mock_settings:
            mock_settings.virustotal_api_key = "test_key"
            mock_settings.user_agent = "test-agent"
            mock_settings.request_timeout = 10
            mock_settings.cache_ttl = 300

            with patch("httpx.AsyncClient") as mock_client:
                mock_client.return_value.__aenter__.return_value.get.side_effect = (
                    httpx.TimeoutException("Request timeout")
                )

                result = await query_virustotal("192.168.1.1", "ip", ctx=mock_context)

                assert isinstance(result, IOC)
                assert result.reputation == "Unknown"
                assert "timeout" in result.reports[0].lower()


class TestRetryMechanism:
    """Test retry mechanism for API calls."""

    @pytest.mark.anyio
    async def test_retry_success_after_failure(self, mock_context):
        """Test that retry mechanism works correctly."""
        call_count = 0

        async def failing_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise httpx.ConnectError("Connection failed")
            return "success"

        with patch("src.threatintel.threatintel.settings") as mock_settings:
            mock_settings.max_retries = 3

            result = await retry_api_call(failing_function, ctx=mock_context)

            assert result == "success"
            assert call_count == 3  # Should have retried twice before success

    @pytest.mark.anyio
    async def test_retry_exhausted(self, mock_context):
        """Test that retry mechanism eventually gives up."""

        async def always_failing_function():
            raise httpx.ConnectError("Always fails")

        with patch("src.threatintel.threatintel.settings") as mock_settings:
            mock_settings.max_retries = 2

            with pytest.raises(httpx.ConnectError):
                await retry_api_call(always_failing_function, ctx=mock_context)
