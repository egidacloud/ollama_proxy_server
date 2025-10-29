#!/usr/bin/env python3
"""
Debug script to check rate limit configuration for API keys
"""

import asyncio
import sys
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.core.config import settings
from app.database.models import APIKey
from app.crud import apikey_crud

async def main():
    # Connect to database
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as db:
        # Get all API keys
        result = await db.execute(text("SELECT id, key_name, key_prefix, rate_limit_requests, rate_limit_window_minutes, is_active, is_revoked FROM api_keys"))
        keys = result.fetchall()

        if not keys:
            print("No API keys found in database.")
            return

        print("=" * 80)
        print("API Key Rate Limit Configuration")
        print("=" * 80)
        print()

        for key in keys:
            id, name, prefix, requests, window, active, revoked = key
            print(f"API Key: {name}")
            print(f"  Prefix: {prefix}")
            print(f"  ID: {id}")
            print(f"  Rate Limit Requests: {requests} (type: {type(requests).__name__})")
            print(f"  Rate Limit Window: {window} minutes (type: {type(window).__name__})")
            print(f"  Active: {active}")
            print(f"  Revoked: {revoked}")

            # Calculate what the rate limiter would use
            if requests is not None and window is not None:
                print(f"  ✓ Using PER-KEY limit: {requests} requests per {window} minute(s)")
                print(f"  Redis key will be: rate_limit:{prefix}")
                print(f"  Window in seconds: {window * 60}")
            else:
                print(f"  → Using GLOBAL default rate limits")

            print()

    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(main())