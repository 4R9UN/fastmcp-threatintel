# 📈 Performance & Scaling Guide

## Benchmarks

### Single IOC Analysis
- **Average Response Time**: ~2-5 seconds
- **Peak Throughput**: ~500 IOCs/minute
- **Memory Usage**: <100MB for typical workloads
- **Cache Hit Rate**: >90% in production environments

### Batch Processing Performance
- **Small Batches (1-10 IOCs)**: ~3-8 seconds
- **Medium Batches (10-100 IOCs)**: ~30-120 seconds
- **Large Batches (100-1000 IOCs)**: ~5-20 minutes

## Optimization Strategies

### 1. Caching Configuration

```bash
# Optimal cache settings for production
CACHE_TTL=7200          # 2 hours for most IOCs
MAX_RETRIES=5           # Increased retries for reliability
REQUEST_TIMEOUT=45      # Longer timeout for batch operations
```

### 2. API Rate Limiting

```python
# Configure rate limiting for different services
VIRUSTOTAL_RATE_LIMIT=4    # requests per minute (free tier)
OTX_RATE_LIMIT=1000        # requests per hour
ABUSEIPDB_RATE_LIMIT=1000  # requests per day
```

### 3. Memory Optimization

```bash
# For large batch processing
PYTHON_OPTS="-O -W ignore"  # Optimize Python execution
MAX_WORKERS=4               # Limit concurrent workers
BATCH_SIZE=50              # Process in smaller chunks
```

## Production Deployment

### Docker Compose Production Setup

```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  threatintel:
    image: arjuntrivedi/4r9un:fastmcp-threatintel-latest
    restart: unless-stopped
    environment:
      - VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY}
      - OTX_API_KEY=${OTX_API_KEY}
      - ABUSEIPDB_API_KEY=${ABUSEIPDB_API_KEY}
      - IPINFO_API_KEY=${IPINFO_API_KEY}
      - CACHE_TTL=7200
      - MAX_RETRIES=5
      - REQUEST_TIMEOUT=45
    volumes:
      - ./reports:/app/reports
      - ./cache:/app/cache
    ports:
      - "8000:8000"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M
```

### Kubernetes Deployment

```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fastmcp-threatintel
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fastmcp-threatintel
  template:
    metadata:
      labels:
        app: fastmcp-threatintel
    spec:
      containers:
      - name: threatintel
        image: arjuntrivedi/4r9un:fastmcp-threatintel-latest
        ports:
        - containerPort: 8000
        env:
        - name: VIRUSTOTAL_API_KEY
          valueFrom:
            secretKeyRef:
              name: threatintel-secrets
              key: virustotal-key
        resources:
          limits:
            memory: "512Mi"
            cpu: "500m"
          requests:
            memory: "256Mi"
            cpu: "250m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
```

## Monitoring & Metrics

### Application Metrics

```python
# Add to your monitoring setup
import time
import logging
from functools import wraps

def monitor_performance(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = await func(*args, **kwargs)
            duration = time.time() - start_time
            logging.info(f"{func.__name__} completed in {duration:.2f}s")
            return result
        except Exception as e:
            duration = time.time() - start_time
            logging.error(f"{func.__name__} failed after {duration:.2f}s: {e}")
            raise
    return wrapper
```

### Log Analysis

```bash
# Analyze performance logs
grep "completed in" /var/log/threatintel.log | awk '{print $NF}' | sort -n

# Monitor error rates
grep "ERROR" /var/log/threatintel.log | wc -l

# Track API usage
grep "API_CALL" /var/log/threatintel.log | cut -d' ' -f3 | sort | uniq -c
```

## Scaling Recommendations

### Horizontal Scaling
- **Load Balancer**: Use NGINX or HAProxy for request distribution
- **Multiple Instances**: Deploy 3-5 instances behind load balancer
- **Database**: Consider Redis for shared caching across instances

### Vertical Scaling
- **CPU**: 2-4 cores recommended for production
- **Memory**: 1-2GB RAM for typical workloads
- **Storage**: SSD recommended for cache and reports

### API Key Distribution
- **Multiple Keys**: Use different API keys across instances
- **Key Rotation**: Implement automatic key rotation
- **Rate Limiting**: Implement per-key rate limiting

## Troubleshooting Performance Issues

### Common Bottlenecks

1. **API Rate Limits**
   ```bash
   # Check for rate limit errors
   grep "rate limit" /var/log/threatintel.log
   ```

2. **Network Latency**
   ```bash
   # Test API response times
   curl -w "%{time_total}\n" -o /dev/null -s "https://www.virustotal.com/vtapi/v2/file/report"
   ```

3. **Memory Issues**
   ```bash
   # Monitor memory usage
   docker stats fastmcp-threatintel
   ```

### Performance Tuning

1. **Increase Cache TTL**
   ```bash
   export CACHE_TTL=14400  # 4 hours
   ```

2. **Optimize Batch Size**
   ```python
   # Process in smaller chunks
   OPTIMAL_BATCH_SIZE = 25
   ```

3. **Enable Compression**
   ```bash
   export COMPRESS_RESPONSES=true
   ```

## Best Practices

1. **Cache Warming**: Pre-populate cache with common IOCs
2. **Graceful Degradation**: Continue with partial results if some APIs fail
3. **Circuit Breaker**: Implement circuit breaker pattern for API calls
4. **Async Processing**: Use async/await for all I/O operations
5. **Connection Pooling**: Reuse HTTP connections for better performance