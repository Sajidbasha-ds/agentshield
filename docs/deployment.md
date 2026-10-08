# Deployment Guide

## 1. Local Development
```bash
npm install
npm run dev
```
The Express/Vite server on port `3000` automatically starts and supervises the Python Gateway (`backend/main.py`) on `127.0.0.1:8000`.

## 2. Docker Compose Deployment
```bash
docker compose up --build -d
```
- `Dockerfile.backend`: Builds the Python 3.11 gateway container with FastAPI, Uvicorn, Pydantic, NetworkX, and SQLite persistence.
- `Dockerfile.frontend`: Builds the Node 22 / Vite production bundle and serves the web SOC on port 3000.

## 3. Environment Variables (`.env.example`)
- `AGENTSHIELD_ENV`: `development` or `production`
- `DATABASE_URL` / `AGENTSHIELD_DB_PATH`: Path to SQLite database file (`./agentshield.db`)
- `BACKEND_HOST`: `0.0.0.0` or `127.0.0.1`
- `BACKEND_PORT`: `8000`
- `FRONTEND_PORT`: `3000`
- `OLLAMA_BASE_URL`: `http://localhost:11434`
- `OLLAMA_MODEL`: `llama3.2`
- `CORS_ORIGINS`: Allowed origins for browser requests
