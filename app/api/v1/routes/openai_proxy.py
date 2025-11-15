"""
OpenAI-compatible API proxy for Ollama.

This module provides OpenAI-compatible endpoints that proxy requests to Ollama backends.
Ollama supports OpenAI-compatible API endpoints at /v1/* paths.

Supported endpoints:
- /v1/chat/completions - Chat completions (compatible with OpenAI)
- /v1/completions - Text completions (compatible with OpenAI)
- /v1/embeddings - Text embeddings (compatible with OpenAI)
- /v1/models - List available models (compatible with OpenAI)
"""

import asyncio
import json
import logging
from typing import List, Tuple, Optional
from fastapi import APIRouter, Depends, Request, Response, HTTPException, status
from fastapi.responses import StreamingResponse
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.api.v1.dependencies import get_valid_api_key, rate_limiter, ip_filter
from app.database.models import APIKey, OllamaServer
from app.crud import log_crud, server_crud

logger = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(ip_filter), Depends(rate_limiter)])


async def get_active_servers(db: AsyncSession = Depends(get_db)) -> List[OllamaServer]:
    """Get list of active Ollama servers."""
    servers = await server_crud.get_servers(db)
    active_servers = [s for s in servers if s.is_active]
    if not active_servers:
        logger.error("No active Ollama backend servers are configured in the database.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No active backend servers available."
        )
    return active_servers


async def extract_model_from_openai_request(request: Request) -> Optional[str]:
    """
    Extract model name from OpenAI-format request body.

    OpenAI format uses "model" field in the request body:
    {
        "model": "llama2",
        "messages": [...],
        ...
    }
    """
    try:
        body_bytes = await request.body()
        if not body_bytes:
            return None

        body = json.loads(body_bytes)
        if isinstance(body, dict) and "model" in body:
            return body["model"]
    except (json.JSONDecodeError, UnicodeDecodeError, Exception) as e:
        logger.debug(f"Could not extract model from OpenAI request body: {e}")

    return None


async def _reverse_proxy_openai(
    request: Request,
    path: str,
    servers: List[OllamaServer],
    body_bytes: bytes = b""
) -> Tuple[Response, OllamaServer]:
    """
    Core reverse proxy logic for OpenAI-compatible endpoints.

    Forwards requests to Ollama's /v1/* endpoints which are OpenAI-compatible.

    Args:
        request: The original FastAPI request
        path: The path to proxy to (e.g., "chat/completions")
        servers: List of servers to choose from
        body_bytes: Pre-read request body (if already read for model extraction)

    Returns:
        Tuple of (response, chosen_server)
    """
    http_client: AsyncClient = request.app.state.http_client

    # Round-robin server selection
    if not hasattr(request.app.state, 'openai_backend_server_index'):
        request.app.state.openai_backend_server_index = 0

    index = request.app.state.openai_backend_server_index
    chosen_server = servers[index]
    request.app.state.openai_backend_server_index = (index + 1) % len(servers)

    # Build backend URL for OpenAI-compatible endpoint
    normalized_url = chosen_server.url.rstrip('/')
    backend_url = f"{normalized_url}/v1/{path}"

    # Filter headers: remove host and browser-specific headers
    headers_to_exclude = {
        'host', 'origin', 'referer', 'sec-fetch-site', 'sec-fetch-mode',
        'sec-fetch-dest', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
        'sec-gpc', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto',
        'x-real-ip', 'x-original-host', 'cf-connecting-ip', 'cf-ray',
        'cf-visitor', 'cf-ipcountry', 'cdn-loop', 'via', 'priority',
        'x-railway-request-id', 'x-railway-edge', 'x-request-start'
    }
    headers = {k: v for k, v in request.headers.items() if k.lower() not in headers_to_exclude}

    # Build backend request
    if body_bytes:
        backend_request = http_client.build_request(
            method=request.method,
            url=backend_url,
            headers=headers,
            params=request.query_params,
            content=body_bytes
        )
    else:
        backend_request = http_client.build_request(
            method=request.method,
            url=backend_url,
            headers=headers,
            params=request.query_params,
            content=request.stream()
        )

    try:
        backend_response = await http_client.send(backend_request, stream=True)
    except Exception as e:
        logger.error(f"Error connecting to backend server {chosen_server.url}: {e}")
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Could not connect to backend server."
        )

    response = StreamingResponse(
        backend_response.aiter_raw(),
        status_code=backend_response.status_code,
        headers=backend_response.headers,
    )
    return response, chosen_server


@router.get("/models")
async def list_models_openai(
    request: Request,
    api_key: APIKey = Depends(get_valid_api_key),
    db: AsyncSession = Depends(get_db),
    servers: List[OllamaServer] = Depends(get_active_servers),
):
    """
    List available models in OpenAI format.

    GET /v1/models

    Returns models from all active Ollama backends in OpenAI-compatible format.
    """
    http_client: AsyncClient = request.app.state.http_client

    async def fetch_models(server: OllamaServer):
        try:
            normalized_url = server.url.rstrip('/')
            # Try OpenAI-compatible endpoint first
            try:
                response = await http_client.get(f"{normalized_url}/v1/models")
                response.raise_for_status()
                return response.json()
            except Exception:
                # Fallback to Ollama native endpoint and convert format
                response = await http_client.get(f"{normalized_url}/api/tags")
                response.raise_for_status()
                ollama_data = response.json()

                # Convert Ollama format to OpenAI format
                models = []
                for model in ollama_data.get("models", []):
                    models.append({
                        "id": model["name"],
                        "object": "model",
                        "created": 0,  # Ollama doesn't provide timestamps
                        "owned_by": "ollama"
                    })
                return {"object": "list", "data": models}
        except Exception as e:
            logger.error(f"Failed to fetch models from {server.url}: {e}")
            return {"object": "list", "data": []}

    tasks = [fetch_models(server) for server in servers]
    results = await asyncio.gather(*tasks)

    # Aggregate unique models
    all_models = {}
    for result in results:
        for model in result.get("data", []):
            model_id = model.get("id")
            if model_id and model_id not in all_models:
                all_models[model_id] = model

    await log_crud.create_usage_log(
        db=db,
        api_key_id=api_key.id,
        endpoint="/v1/models",
        status_code=200,
        server_id=None
    )

    return {
        "object": "list",
        "data": list(all_models.values())
    }


@router.post("/chat/completions")
async def chat_completions_openai(
    request: Request,
    api_key: APIKey = Depends(get_valid_api_key),
    db: AsyncSession = Depends(get_db),
    servers: List[OllamaServer] = Depends(get_active_servers),
):
    """
    Create a chat completion (OpenAI-compatible).

    POST /v1/chat/completions

    Request body (OpenAI format):
    {
        "model": "llama2",
        "messages": [
            {"role": "user", "content": "Hello!"}
        ],
        "stream": false,
        "temperature": 0.7,
        ...
    }
    """
    # Extract model name for smart routing
    body_bytes = await request.body()
    model_name = None

    if body_bytes:
        try:
            body = json.loads(body_bytes)
            if isinstance(body, dict) and "model" in body:
                model_name = body["model"]
        except (json.JSONDecodeError, Exception):
            pass

    # Smart routing: filter servers by model availability
    candidate_servers = servers
    if model_name:
        servers_with_model = await server_crud.get_servers_with_model(db, model_name)

        if servers_with_model:
            candidate_servers = servers_with_model
            logger.info(
                f"Smart routing (OpenAI): Found {len(servers_with_model)} server(s) with model '{model_name}'"
            )
        else:
            logger.warning(
                f"Model '{model_name}' not found in any server's catalog. "
                f"Falling back to round-robin across all {len(servers)} active server(s)."
            )

    # Proxy to backend
    response, chosen_server = await _reverse_proxy_openai(
        request, "chat/completions", candidate_servers, body_bytes
    )

    await log_crud.create_usage_log(
        db=db,
        api_key_id=api_key.id,
        endpoint="/v1/chat/completions",
        status_code=response.status_code,
        server_id=chosen_server.id,
        model=model_name
    )

    return response


@router.post("/completions")
async def completions_openai(
    request: Request,
    api_key: APIKey = Depends(get_valid_api_key),
    db: AsyncSession = Depends(get_db),
    servers: List[OllamaServer] = Depends(get_active_servers),
):
    """
    Create a text completion (OpenAI-compatible, legacy endpoint).

    POST /v1/completions

    Request body (OpenAI format):
    {
        "model": "llama2",
        "prompt": "Once upon a time",
        "stream": false,
        ...
    }
    """
    # Extract model name for smart routing
    body_bytes = await request.body()
    model_name = None

    if body_bytes:
        try:
            body = json.loads(body_bytes)
            if isinstance(body, dict) and "model" in body:
                model_name = body["model"]
        except (json.JSONDecodeError, Exception):
            pass

    # Smart routing
    candidate_servers = servers
    if model_name:
        servers_with_model = await server_crud.get_servers_with_model(db, model_name)

        if servers_with_model:
            candidate_servers = servers_with_model
            logger.info(
                f"Smart routing (OpenAI): Found {len(servers_with_model)} server(s) with model '{model_name}'"
            )
        else:
            logger.warning(
                f"Model '{model_name}' not found in any server's catalog. "
                f"Falling back to round-robin across all {len(servers)} active server(s)."
            )

    # Proxy to backend
    response, chosen_server = await _reverse_proxy_openai(
        request, "completions", candidate_servers, body_bytes
    )

    await log_crud.create_usage_log(
        db=db,
        api_key_id=api_key.id,
        endpoint="/v1/completions",
        status_code=response.status_code,
        server_id=chosen_server.id,
        model=model_name
    )

    return response


@router.post("/embeddings")
async def embeddings_openai(
    request: Request,
    api_key: APIKey = Depends(get_valid_api_key),
    db: AsyncSession = Depends(get_db),
    servers: List[OllamaServer] = Depends(get_active_servers),
):
    """
    Create embeddings (OpenAI-compatible).

    POST /v1/embeddings

    Request body (OpenAI format):
    {
        "model": "llama2",
        "input": "The quick brown fox",
        ...
    }
    """
    # Extract model name for smart routing
    body_bytes = await request.body()
    model_name = None

    if body_bytes:
        try:
            body = json.loads(body_bytes)
            if isinstance(body, dict) and "model" in body:
                model_name = body["model"]
        except (json.JSONDecodeError, Exception):
            pass

    # Smart routing
    candidate_servers = servers
    if model_name:
        servers_with_model = await server_crud.get_servers_with_model(db, model_name)

        if servers_with_model:
            candidate_servers = servers_with_model
            logger.info(
                f"Smart routing (OpenAI): Found {len(servers_with_model)} server(s) with model '{model_name}'"
            )
        else:
            logger.warning(
                f"Model '{model_name}' not found in any server's catalog. "
                f"Falling back to round-robin across all {len(servers)} active server(s)."
            )

    # Proxy to backend
    response, chosen_server = await _reverse_proxy_openai(
        request, "embeddings", candidate_servers, body_bytes
    )

    await log_crud.create_usage_log(
        db=db,
        api_key_id=api_key.id,
        endpoint="/v1/embeddings",
        status_code=response.status_code,
        server_id=chosen_server.id,
        model=model_name
    )

    return response


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy_openai_catchall(
    request: Request,
    path: str,
    api_key: APIKey = Depends(get_valid_api_key),
    db: AsyncSession = Depends(get_db),
    servers: List[OllamaServer] = Depends(get_active_servers),
):
    """
    Catch-all route for other OpenAI-compatible endpoints.

    This handles any /v1/* endpoints not explicitly defined above.
    """
    # Try to extract model for smart routing
    body_bytes = await request.body()
    model_name = None

    if body_bytes:
        try:
            body = json.loads(body_bytes)
            if isinstance(body, dict) and "model" in body:
                model_name = body["model"]
        except (json.JSONDecodeError, Exception):
            pass

    # Smart routing if model is specified
    candidate_servers = servers
    if model_name:
        servers_with_model = await server_crud.get_servers_with_model(db, model_name)
        if servers_with_model:
            candidate_servers = servers_with_model
            logger.info(
                f"Smart routing (OpenAI): Found {len(servers_with_model)} server(s) with model '{model_name}'"
            )

    # Proxy to backend
    response, chosen_server = await _reverse_proxy_openai(
        request, path, candidate_servers, body_bytes
    )

    await log_crud.create_usage_log(
        db=db,
        api_key_id=api_key.id,
        endpoint=f"/v1/{path}",
        status_code=response.status_code,
        server_id=chosen_server.id,
        model=model_name
    )

    return response
