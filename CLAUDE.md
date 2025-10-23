# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Ollama Proxy Fortress is a secure, high-performance FastAPI-based proxy and load balancer for Ollama instances. It provides authentication, rate limiting, user management, and usage analytics for Ollama AI models.

**Tech Stack:** Python 3.11+, FastAPI, SQLAlchemy (async), SQLite/aiosqlite, Redis, Jinja2 templates, Tailwind CSS

## Development Commands

### Running the Application

**Quick Start (Recommended):**
- **Windows:** Double-click `run_windows.bat`
- **macOS/Linux:** `chmod +x run.sh && ./run.sh`

The run scripts handle virtual environment setup, dependency installation, and server startup automatically.

**Manual Run:**
```bash
# Create venv and install dependencies
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt

# Run the server
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

**Docker:**
```bash
docker build -t ollama-proxy-server .
docker run -d --name ollama-proxy -p 8080:8080 --env-file ./.env -v ./ollama_proxy.db:/home/app/ollama_proxy.db ollama-proxy-server
```

### Testing

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_specific.py

# Run with verbose output
pytest -v
```

### Code Formatting

```bash
# Format code with black
black .

# Format specific files
black app/main.py
```

### Reset Installation

**WARNING:** This permanently deletes the database, configuration, and Python environment.

- **Windows:** Double-click `reset.bat`
- **macOS/Linux:** `chmod +x reset.sh && ./reset.sh`

## Architecture Overview

### Application Structure

```
app/
├── main.py              # FastAPI app entry point, lifespan management, middleware
├── core/                # Core configuration and utilities
│   ├── config.py        # Bootstrap settings (from .env)
│   ├── security.py      # Password hashing, API key verification
│   └── logging_config.py # Structured JSON logging setup
├── api/v1/
│   ├── dependencies.py  # FastAPI dependencies (auth, rate limiting, IP filtering, CSRF)
│   └── routes/
│       ├── health.py    # Health check endpoint
│       ├── proxy.py     # Ollama API reverse proxy with smart routing
│       └── admin.py     # Admin UI routes (dashboard, users, servers, settings)
├── database/
│   ├── models.py        # SQLAlchemy models (User, APIKey, UsageLog, OllamaServer, AppSettings)
│   ├── session.py       # Async database session management
│   └── base.py          # SQLAlchemy declarative base
├── crud/                # Database CRUD operations
│   ├── user_crud.py     # User management
│   ├── apikey_crud.py   # API key management
│   ├── server_crud.py   # Ollama server management, model refresh
│   ├── log_crud.py      # Usage logging
│   └── settings_crud.py # Application settings management
├── schema/              # Pydantic models for validation
│   ├── user.py
│   ├── apikey.py
│   ├── server.py
│   └── settings.py      # AppSettingsModel for runtime config
├── templates/           # Jinja2 HTML templates for admin UI
└── static/              # Static assets (CSS, JS)
```

### Configuration Management

The application uses a **two-tier configuration system**:

1. **Bootstrap Settings** (`.env` file → `app/core/config.py`):
   - Read once at startup
   - Required: `DATABASE_URL`, `ADMIN_USER`, `ADMIN_PASSWORD`, `PROXY_PORT`, `SECRET_KEY`
   - Used only to initialize the application and create the admin user

2. **Runtime Settings** (Database → `AppSettings` table → `app.state.settings`):
   - Stored in the database as JSON in the `app_settings` table
   - Managed through the admin UI "Settings" page
   - Includes: Redis config, rate limits, IP filtering, model update intervals
   - Loaded at startup and stored in `app.state.settings` as `AppSettingsModel`
   - Can be updated via admin UI without restart

**IMPORTANT:** After initial setup, all operational settings (Ollama servers, Redis, rate limits) are managed from the database, NOT the `.env` file.

### Database Schema

- **User**: Admin users with bcrypt-hashed passwords
- **APIKey**: User API keys with prefix/secret format (`op_prefix_secret`), optional per-key rate limits, enable/disable/revoke states
- **OllamaServer**: Backend Ollama server URLs, model caching, active/inactive states
- **UsageLog**: Request logs with timestamps, endpoints, status codes, models, server mappings
- **AppSettings**: Single-row table storing runtime configuration as JSON

Database initialization uses `Base.metadata.create_all()` (no Alembic migrations).

### Security Features

1. **API Key Authentication** (`app/api/v1/dependencies.py:get_valid_api_key`):
   - Bearer token format: `Bearer op_prefix_secret`
   - Keys stored with bcrypt hashing (only secret portion is hashed)
   - Supports revocation and enable/disable states

2. **Rate Limiting** (`app/api/v1/dependencies.py:rate_limiter`):
   - Redis-backed sliding window rate limiting
   - Global limits (from `AppSettings`) or per-key overrides
   - Gracefully degrades if Redis unavailable

3. **IP Filtering** (`app/api/v1/dependencies.py:ip_filter`):
   - Allow-list and deny-list support
   - Configured in runtime settings

4. **CSRF Protection** (`app/api/v1/dependencies.py:validate_csrf_token`):
   - Session-based CSRF tokens for admin UI forms

5. **Security Headers** (`app/main.py:add_security_headers`):
   - CSP, X-Frame-Options, X-Content-Type-Options

### Smart Routing & Load Balancing

The proxy implements **model-aware intelligent routing** (`app/api/v1/routes/proxy.py:proxy_ollama`):

1. Request arrives with model name in body
2. Query database for servers that have the requested model cached
3. If match found, route only to servers with that model
4. If no match, fall back to round-robin across all active servers
5. Model lists are refreshed periodically via background task

**Model Refresh Task** (`app/main.py:periodic_model_refresh`):
- Background asyncio task that runs every N minutes (configurable in settings)
- Fetches `/api/tags` from all servers and caches results in `OllamaServer.available_models`
- Runs on startup and then periodically

### Admin UI

- Built with Jinja2 templates + Tailwind CSS
- Routes in `app/api/v1/routes/admin.py`
- Session-based authentication (no JWT)
- Pages: Dashboard, User Management, Server Management, Usage Stats (with Chart.js), Settings, Help

### Request Flow

1. **Client Request** → Proxy (with Bearer token)
2. **Middleware** → Security headers
3. **Dependencies Chain**:
   - IP Filter → check allow/deny lists
   - API Key Validation → verify Bearer token, check revoked/disabled
   - Rate Limiter → check Redis counter
4. **Smart Routing** → select server(s) with model
5. **Reverse Proxy** → stream request/response to backend Ollama
6. **Usage Logging** → record request in database

## Important Notes

### Admin Password Security

The application **will not start** if `ADMIN_PASSWORD` is set to the default value `"changeme"` in the `.env` file. You must change it before running in production.

### Redis Dependency

Redis is **optional but recommended**. If Redis is unavailable:
- Rate limiting is disabled (logged as warning)
- Application continues to function
- Login rate limiting also disabled

### Database Migrations

This project does **NOT use Alembic**. Schema changes require manual migration scripts or database recreation. The schema is created via `Base.metadata.create_all()` on first run.

### API Key Format

API keys use the format: `op_{prefix}_{secret}`
- Only the secret portion is hashed and stored
- The prefix is stored in plaintext for lookups
- Keys can be temporarily disabled without revoking them permanently

### Model Catalog Updates

The smart routing feature requires model catalogs to be up-to-date. If you add a new model to a server:
- Wait for the next automatic refresh (default: 10 minutes)
- OR manually refresh from the Server Management page
- OR restart the server to force an immediate refresh
