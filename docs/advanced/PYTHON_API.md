# 🐍 Python API Guide

## Overview

The FastMCP ThreatIntel package provides a comprehensive Python API for integrating threat intelligence capabilities into your applications.

## Basic Usage

```python
import asyncio
from threatintel import analyze_iocs, IOC

async def analyze_threats():
    iocs = [
        {"value": "192.168.1.1", "type": "ip"},
        {"value": "malware.exe", "type": "md5"}
    ]
    
    report = await analyze_iocs(
        iocs=iocs,
        output_format="json",
        include_graph=True
    )
    
    print(report)

asyncio.run(analyze_threats())
```

## Advanced Usage

### Single IOC Analysis

```python
from threatintel.tools import process_single_ioc, get_ioc_type
from threatintel.settings import settings

async def analyze_single_ioc(ioc_value: str):
    # Auto-detect IOC type
    ioc_type = await get_ioc_type(ioc_value)
    
    if ioc_type != "unknown":
        result = await process_single_ioc(ioc_value, ioc_type)
        return result
    else:
        raise ValueError(f"Could not determine IOC type for: {ioc_value}")
```

### Batch Processing

```python
from threatintel.tools import _analyze_iocs_impl

async def batch_analysis(ioc_list: list):
    # Format IOCs
    formatted_iocs = [{"value": ioc} for ioc in ioc_list]
    
    # Analyze with custom settings
    report = await _analyze_iocs_impl(
        iocs=formatted_iocs,
        output_format="html",
        include_stix=True,
        include_graph=True
    )
    
    return report
```

## Configuration

### Environment Variables

```python
from threatintel.settings import settings

# Check current configuration
print(f"VirusTotal API Key: {'✓' if settings.virustotal_api_key else '✗'}")
print(f"OTX API Key: {'✓' if settings.otx_api_key else '✗'}")
print(f"Cache TTL: {settings.cache_ttl} seconds")
```

### Custom Settings

```python
import os
from threatintel.settings import Settings

# Override default settings
os.environ['CACHE_TTL'] = '7200'
os.environ['MAX_RETRIES'] = '5'

# Reload settings
custom_settings = Settings()
```

## Error Handling

```python
from threatintel.tools import process_single_ioc
from httpx import RequestError, TimeoutException

async def safe_analysis(ioc_value: str, ioc_type: str):
    try:
        result = await process_single_ioc(ioc_value, ioc_type)
        return result
    except RequestError as e:
        print(f"Network error: {e}")
        return None
    except TimeoutException as e:
        print(f"Request timeout: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None
```

## Data Models

### IOC Result Structure

```python
from threatintel.tools import IOCResult

# IOCResult attributes:
# - value: str
# - type: str
# - reputation: str | None
# - score: float | None
# - engines: list[str]
# - reports: list[str]
# - country: str | None
# - city: str | None
# - asn: str | None
# - organization: str | None
```

## Integration Examples

### Flask Web Application

```python
from flask import Flask, jsonify, request
from threatintel.tools import process_single_ioc, get_ioc_type
import asyncio

app = Flask(__name__)

@app.route('/analyze', methods=['POST'])
def analyze_endpoint():
    data = request.get_json()
    ioc_value = data.get('ioc')
    
    async def analyze():
        ioc_type = await get_ioc_type(ioc_value)
        if ioc_type != "unknown":
            result = await process_single_ioc(ioc_value, ioc_type)
            return result.dict()
        return {"error": "Unknown IOC type"}
    
    result = asyncio.run(analyze())
    return jsonify(result)
```

### FastAPI Integration

```python
from fastapi import FastAPI, HTTPException
from threatintel.tools import process_single_ioc, get_ioc_type
from pydantic import BaseModel

app = FastAPI()

class IOCRequest(BaseModel):
    ioc: str

@app.post("/analyze")
async def analyze_ioc(request: IOCRequest):
    ioc_type = await get_ioc_type(request.ioc)
    
    if ioc_type == "unknown":
        raise HTTPException(status_code=400, detail="Unknown IOC type")
    
    result = await process_single_ioc(request.ioc, ioc_type)
    return result.dict()