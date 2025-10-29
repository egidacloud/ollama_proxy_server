import logging
from fastapi import Depends, HTTPException, status, Request, Form
from fastapi.security import APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as redis
import time

from app.schema.settings import AppSettingsModel # <-- NEW
from app.core.config import settings as config
from app.database.session import get_db
from app.crud import apikey_crud
from app.core.security import verify_api_key
from app.core.lemonsqueezy import LemonSqueezyClient
from app.database.models import APIKey
import secrets

logger = logging.getLogger(__name__)
api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

# --- NEW: Dependency to get DB-loaded settings ---
def get_settings(request: Request) -> AppSettingsModel:
    return request.app.state.settings

# --- CSRF Token Generation and Validation ---
async def get_csrf_token(request: Request) -> str:
    """Get CSRF token from session or create a new one."""
    if "csrf_token" not in request.session:
        request.session["csrf_token"] = secrets.token_hex(32)
    return request.session["csrf_token"]

async def validate_csrf_token(request: Request, csrf_token: str = Form(...)):
    """Dependency to validate CSRF token from a form submission."""
    stored_token = await get_csrf_token(request)
    if not stored_token or not secrets.compare_digest(csrf_token, stored_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token mismatch")
    return True

# --- Login Rate Limiting Dependency ---
async def login_rate_limiter(request: Request):
    redis_client: redis.Redis = request.app.state.redis
    if not redis_client:
        return True

    # Extract real client IP from proxy headers (same logic as ip_filter)
    if "cf-connecting-ip" in request.headers:
        client_ip = request.headers["cf-connecting-ip"]
    elif "x-forwarded-for" in request.headers:
        forwarded_ips = request.headers["x-forwarded-for"].split(",")
        client_ip = forwarded_ips[0].strip()
    else:
        client_ip = request.client.host

    key = f"login_fail:{client_ip}"
    
    try:
        current_fails = await redis_client.get(key)
        if current_fails and int(current_fails) >= 5:
            ttl = await redis_client.ttl(key)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed login attempts. Try again in {ttl} seconds."
            )
    except Exception as e:
        logger.error(f"Could not connect to Redis for login rate limiting: {e}")
    return True

# --- IP Filtering Dependency ---
async def ip_filter(request: Request, settings: AppSettingsModel = Depends(get_settings)):
    # Extract real client IP from proxy headers
    # Priority: Cf-Connecting-Ip (Cloudflare) > X-Forwarded-For > request.client.host
    client_ip = None
    ip_source = None

    # Try Cloudflare header first (most reliable for Cloudflare deployments)
    if "cf-connecting-ip" in request.headers:
        client_ip = request.headers["cf-connecting-ip"]
        ip_source = "Cf-Connecting-Ip"
    # Try X-Forwarded-For (standard proxy header)
    elif "x-forwarded-for" in request.headers:
        # X-Forwarded-For can contain multiple IPs (client, proxy1, proxy2...)
        # Take the first (leftmost) IP which is the original client
        forwarded_ips = request.headers["x-forwarded-for"].split(",")
        client_ip = forwarded_ips[0].strip()
        ip_source = "X-Forwarded-For"
    # Fallback to direct connection IP
    else:
        client_ip = request.client.host
        ip_source = "request.client.host"

    logger.debug(f"IP filter checking: {client_ip} (source: {ip_source})")

    allowed_ips = [ip.strip() for ip in settings.allowed_ips.split(',') if ip.strip()]
    denied_ips = [ip.strip() for ip in settings.denied_ips.split(',') if ip.strip()]

    if "*" not in allowed_ips and allowed_ips and client_ip not in allowed_ips:
        logger.warning(f"IP address {client_ip} (source: {ip_source}) denied by allow-list.")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="IP address not allowed")
    if denied_ips and client_ip in denied_ips:
        logger.warning(f"IP address {client_ip} (source: {ip_source}) denied by deny-list.")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="IP address has been blocked")
    return True

# --- API Key Authentication Dependency ---
async def get_valid_api_key(
    request: Request,
    db: AsyncSession = Depends(get_db),
    auth_header: str = Depends(api_key_header),
    settings: AppSettingsModel = Depends(get_settings),
) -> APIKey:
    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header is missing",
        )

    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication scheme. Use 'Bearer <api_key>'.",
        )

    api_key_str = auth_header.split(" ")[1]

    # Try standard API key authentication first
    try:
        prefix, secret = api_key_str.rsplit("_", 1)
        db_api_key = await apikey_crud.get_api_key_by_prefix(db, prefix=prefix)

        if db_api_key:
            if db_api_key.is_revoked:
                logger.warning(f"Attempt to use revoked API key with prefix '{prefix}'.")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="API Key has been revoked"
                )

            if not db_api_key.is_active:
                logger.warning(f"Attempt to use disabled API key with prefix '{prefix}'.")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="API Key is disabled"
                )

            if verify_api_key(secret, db_api_key.hashed_key):
                request.state.api_key = db_api_key
                return db_api_key
            else:
                logger.warning(f"Invalid secret for API key with prefix '{prefix}'.")
    except ValueError:
        # Not in standard API key format, might be a license key
        pass

    # If standard auth failed and LemonSqueezy is enabled, try license verification
    logger.info(f"Standard API key authentication failed. LemonSqueezy enabled: {config.LEMONSQUEEZY_ENABLED}")

    if config.LEMONSQUEEZY_ENABLED and config.LEMONSQUEEZY_API_KEY:
        logger.info(f"Attempting LemonSqueezy license verification for key: {api_key_str[:20]}...")
        license_key = api_key_str
        redis_client: redis.Redis = request.app.state.redis

        # Check Redis cache first
        cache_key = f"lemonsqueezy:license:{license_key}"
        logger.debug(f"Checking Redis cache for key: {cache_key}")

        if redis_client:
            try:
                cached_result = await redis_client.get(cache_key)
                if cached_result:
                    logger.info(f"✓ LemonSqueezy license validated from Redis cache")
                    # Create a virtual APIKey object for this request
                    virtual_api_key = APIKey(
                        id=0,
                        key_name="LemonSqueezy License",
                        key_prefix=f"ls_{license_key[:8]}",
                        hashed_key="",
                        user_id=0,
                        is_active=True,
                        is_revoked=False,
                    )
                    request.state.api_key = virtual_api_key
                    request.state.is_lemonsqueezy = True
                    return virtual_api_key
                else:
                    logger.debug("License not found in Redis cache, will validate via API")
            except Exception as e:
                logger.error(f"Redis cache check failed: {e}")
        else:
            logger.warning("Redis client not available, skipping cache check")

        # Not in cache, validate via API
        try:
            logger.info("Calling LemonSqueezy API to validate license...")
            ls_client = LemonSqueezyClient(config.LEMONSQUEEZY_API_KEY)
            is_valid, license_data = await ls_client.validate_and_activate_if_needed(license_key)

            if is_valid:
                logger.info(f"✓ LemonSqueezy license validated successfully via API")
                logger.debug(f"License data: {license_data}")

                # Cache the result in Redis for 1 hour
                if redis_client:
                    try:
                        await redis_client.setex(cache_key, 3600, "valid")
                        logger.info(f"Cached valid license in Redis (TTL: 3600s)")
                    except Exception as e:
                        logger.error(f"Failed to cache LemonSqueezy license: {e}")

                # Create a virtual APIKey object for this request
                virtual_api_key = APIKey(
                    id=0,
                    key_name="LemonSqueezy License",
                    key_prefix=f"ls_{license_key[:8]}",
                    hashed_key="",
                    user_id=0,
                    is_active=True,
                    is_revoked=False,
                )
                request.state.api_key = virtual_api_key
                request.state.is_lemonsqueezy = True
                return virtual_api_key
            else:
                logger.warning(f"✗ LemonSqueezy license validation failed")
                logger.debug(f"License data: {license_data}")
        except Exception as e:
            logger.error(f"✗ Exception during LemonSqueezy validation: {e}", exc_info=True)
    elif config.LEMONSQUEEZY_ENABLED and not config.LEMONSQUEEZY_API_KEY:
        logger.warning("LemonSqueezy is enabled but API key is not configured in .env")
    else:
        logger.debug("LemonSqueezy authentication is disabled")

    # Both authentication methods failed
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API Key or License"
    )

# --- Rate Limiting Dependency ---
async def rate_limiter(
    request: Request,
    api_key: APIKey = Depends(get_valid_api_key),
    settings: AppSettingsModel = Depends(get_settings),
):
    redis_client: redis.Redis = request.app.state.redis
    if not redis_client:
        return True

    if api_key.rate_limit_requests is not None and api_key.rate_limit_window_minutes is not None:
        limit = api_key.rate_limit_requests
        window_minutes = api_key.rate_limit_window_minutes
    else:
        limit = settings.rate_limit_requests
        window_minutes = settings.rate_limit_window_minutes
    
    window = window_minutes * 60
    key = f"rate_limit:{api_key.key_prefix}"

    try:
        current_requests = await redis_client.incr(key)
        if current_requests == 1:
            await redis_client.expire(key, window)

        if current_requests > limit:
            logger.warning(f"Rate limit exceeded for API key prefix: {api_key.key_prefix}")
            ttl = await redis_client.ttl(key)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Try again in {ttl} seconds.",
                headers={"Retry-After": str(ttl)}
            )
    except Exception as e:
        logger.error(f"Could not connect to Redis for rate limiting: {e}")
    return True