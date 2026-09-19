# Deployment Guide

## Prerequisites
- Docker and Docker Compose
- Python 3.10+
- Git

## Quick Start

1. **Clone and setup**:
   ```bash
   git clone <repository-url>
   cd cyber-threat-detection
   chmod +x setup.sh
   ./setup.sh
   source .venv/bin/activate
   ```

2. **Start infrastructure**:
   ```bash
   docker compose up -d redis zeek
   ```

3. **Verify installation**:
   ```bash
   pytest tests/ -v
   ```

4. **Run the system**:
   ```bash
   # Terminal 1: Detection Engine
   python -m src.detection.engine
   
   # Terminal 2: API Server
   python -m app.runner
   ```

5. **Access dashboard**:
   Open `http://localhost:8081` and login with `admin` / `admin123`

## Production Deployment

### Environment Variables
- `REDIS_HOST`: Redis server address (default: localhost)
- `REDIS_PORT`: Redis server port (default: 6379)
- `OLLAMA_MODEL`: LLM model for narratives (default: llama3.2:latest)
- `API_PORT`: API server port (default: 8081)

### Systemd Services

Example service files for Linux:

**detection-engine.service**:
```ini
[Unit]
Description=Sentinel AI Detection Engine
After=redis.service

[Service]
Type=simple
User=sentinel
WorkingDirectory=/opt/sentinel
Environment="PATH=/opt/sentinel/.venv/bin"
ExecStart=/opt/sentinel/.venv/bin/python -m src.detection.engine
Restart=always

[Install]
WantedBy=multi-user.target
```

**api-server.service**:
```ini
[Unit]
Description=Sentinel AI API Server
After=redis.service

[Service]
Type=simple
User=sentinel
WorkingDirectory=/opt/sentinel
Environment="PATH=/opt/sentinel/.venv/bin"
ExecStart=/opt/sentinel/.venv/bin/python -m app.runner
Restart=always

[Install]
WantedBy=multi-user.target
```

### Docker Deployment

The system can be containerized. Example Dockerfile:

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "-m", "app.runner"]
```

## Monitoring

- **Redis**: Monitor stream lengths (`events:live`, `alerts:live`)
  ```bash
  docker exec sih26-redis redis-cli XLEN events:live
  docker exec sih26-redis redis-cli XLEN alerts:live
  ```
- **Logs**: Check engine output for alert patterns
- **API**: Monitor `/api/stats` endpoint for metrics
  ```bash
  curl http://localhost:8081/api/stats
  ```
- **Tests**: Run `pytest tests/test_ctu13.py` for end-to-end validation

## Troubleshooting

### Models not loading
- **Symptom**: `FileNotFoundError: Model not found: models/...`
- **Solution**: Verify `models/` directory exists with `.pkl` files
- **Check**: 
  ```bash
  ls -lh models/dga/
  ls -lh models/dns_tunnel/
  ```

### Redis connection errors
- **Symptom**: `redis.exceptions.ConnectionError`
- **Solution**: 
  - Verify Redis is running: `docker compose ps`
  - Check Redis port: `docker exec sih26-redis redis-cli ping`
  - Verify REDIS_HOST environment variable

### No alerts detected
- **Symptom**: Empty `alerts:live` stream
- **Solution**:
  - Verify log tailer is running and reading logs
  - Check Redis streams: `docker exec sih26-redis redis-cli XLEN events:live`
  - Verify detector initialization in engine output
  - Check log file paths in `src/ingestion/log_tailer.py`

### Frontend not loading
- **Symptom**: 404 or blank page
- **Solution**:
  - Verify API server is running on port 8081
  - Check `frontend/` directory exists and is readable
  - Review browser console for JavaScript errors
  - Verify StaticFiles mount in `app/api.py`

### Import errors
- **Symptom**: `ModuleNotFoundError` or `ImportError`
- **Solution**:
  ```bash
  source .venv/bin/activate
  pip install -r requirements.txt
  ```

### Test failures
- **Symptom**: Tests fail with missing log files
- **Solution**: CTU-13 tests require log files generated from PCAP data
  ```bash
  # Generate logs from PCAP
  docker compose exec zeek zeek -C -r /pcaps/ctu13_sample.pcap /zeek_scripts/local.zeek
  ```

## Performance Tuning

### Redis Memory
- Monitor Redis memory usage: `docker exec sih26-redis redis-cli INFO memory`
- Configure max memory in docker-compose.yml:
  ```yaml
  redis:
    command: redis-server --maxmemory 2gb --maxmemory-policy allkeys-lru
  ```

### Detection Engine
- Adjust detector thresholds in `src/detection/detectors/`
- Tune baseline learning window in `src/detection/baseline.py`
- Configure alert cooldown periods per detector

### API Server
- Increase worker count for Uvicorn:
  ```bash
  uvicorn app.api:app --host 0.0.0.0 --port 8081 --workers 4
  ```

## Security Considerations

1. **Change default credentials** in `frontend/script.js`
2. **Enable HTTPS** for production deployments
3. **Restrict Redis access** to localhost or internal network
4. **Review CORS settings** in `app/api.py`
5. **Regular model updates** to detect evolving threats
6. **Log rotation** to prevent disk space issues

## Backup and Recovery

### Critical Data
- Models: `models/` directory
- Configuration: `docker-compose.yml`, `requirements.txt`
- Custom detectors: `src/detection/detectors/`

### Redis Data
- Backup incidents:
  ```bash
  docker exec sih26-redis redis-cli --rdb /data/dump.rdb
  ```
- Restore:
  ```bash
  docker cp dump.rdb sih26-redis:/data/
  docker restart sih26-redis
  ```

## Scaling

### Horizontal Scaling
- Run multiple detection engine instances (load balanced)
- Use Redis Cluster for distributed state
- Deploy API servers behind load balancer

### Vertical Scaling
- Increase machine resources (CPU, RAM)
- Optimize detector algorithms for efficiency
- Profile code with `cProfile` to identify bottlenecks
