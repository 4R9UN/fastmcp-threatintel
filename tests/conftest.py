"""Pytest configuration and fixtures for test suite."""

import asyncio
import os
from collections.abc import Generator
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

# Set test environment variables
os.environ["FASTMCP_TEST_MODE"] = "1"
os.environ["FASTMCP_LOG_LEVEL"] = "DEBUG"


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_context():
    """Create a mock MCP context for testing."""
    context = Mock()
    context.info = AsyncMock()
    context.warning = AsyncMock()
    context.error = AsyncMock()
    context.debug = AsyncMock()
    return context


@pytest.fixture
def sample_ioc_data() -> dict[str, Any]:
    """Sample IOC data for testing."""
    return {
        "ip": "192.168.1.1",
        "domain": "example.com",
        "url": "https://example.com/malware",
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }


@pytest.fixture
def mock_api_responses():
    """Mock API responses for testing."""
    return {
        "virustotal": {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 2,
                        "clean": 60,
                        "undetected": 3,
                    },
                    "last_analysis_results": {
                        "Engine1": {"category": "malicious", "result": "Trojan.Test"},
                        "Engine2": {"category": "clean", "result": "Clean"},
                    },
                    "first_submission_date": 1640995200,
                    "last_analysis_date": 1640995200,
                    "tags": ["malware", "trojan"],
                }
            }
        },
        "otx": {
            "pulse_info": {
                "count": 3,
                "pulses": [
                    {
                        "name": "Test Malware Campaign",
                        "created": "2023-01-01T00:00:00.000Z",
                        "tags": ["malware", "apt"],
                    }
                ],
            }
        },
        "abuseipdb": {
            "data": {
                "abuseConfidenceScore": 85,
                "totalReports": 10,
                "lastReportedAt": "2023-01-01T00:00:00+00:00",
                "usageType": "datacenter",
                "isTor": False,
            }
        },
    }


@pytest.fixture
def test_config():
    """Test configuration settings."""
    return {
        "VIRUSTOTAL_API_KEY": "test_vt_key",
        "OTX_API_KEY": "test_otx_key",
        "ABUSEIPDB_API_KEY": "test_abuse_key",
        "IPINFO_API_KEY": "test_ipinfo_key",
        "CACHE_TTL": "60",
        "MAX_RETRIES": "2",
        "REQUEST_TIMEOUT": "5",
    }


@pytest.fixture(autouse=True)
def setup_test_env(test_config, monkeypatch):
    """Set up test environment variables."""
    for key, value in test_config.items():
        monkeypatch.setenv(key, value)


@pytest.fixture
def temp_ioc_file(tmp_path):
    """Create a temporary file with test IOCs."""
    ioc_file = tmp_path / "test_iocs.txt"
    ioc_file.write_text("""192.168.1.1
example.com
https://malware.example.com
d41d8cd98f00b204e9800998ecf8427e
""")
    return str(ioc_file)
