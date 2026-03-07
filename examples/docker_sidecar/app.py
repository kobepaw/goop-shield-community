"""Example application that uses Shield as a sidecar service.

This FastAPI app demonstrates how to integrate Shield into your
existing application by calling the Shield API before processing
LLM requests.

Run with: docker compose up
"""

import os

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="My App with Shield Sidecar")

SHIELD_URL = os.environ.get("SHIELD_URL", "http://localhost:8787")


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    reply: str
    shield_allowed: bool


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """Process a chat message with Shield protection."""

    # Step 1: Defend the prompt via Shield sidecar
    async with httpx.AsyncClient() as client:
        shield_resp = await client.post(
            f"{SHIELD_URL}/api/v1/defend",
            json={"prompt": request.message},
            timeout=5.0,
        )

    shield_data = shield_resp.json()

    if not shield_data.get("allow", True):
        raise HTTPException(
            status_code=400,
            detail="Message blocked by security policy",
        )

    # Step 2: Use the filtered prompt for LLM processing
    filtered = shield_data.get("filtered_prompt", request.message)

    # (Replace this with your actual LLM call)
    llm_response = f"Echo: {filtered}"

    # Step 3: Scan the response via Shield sidecar
    async with httpx.AsyncClient() as client:
        scan_resp = await client.post(
            f"{SHIELD_URL}/api/v1/scan-response",
            json={
                "response_text": llm_response,
                "original_prompt": request.message,
            },
            timeout=5.0,
        )

    scan_data = scan_resp.json()
    final_response = scan_data.get("filtered_response", llm_response)

    return ChatResponse(
        reply=final_response,
        shield_allowed=True,
    )


@app.get("/health")
async def health():
    """Health check including Shield sidecar status."""
    shield_healthy = False
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{SHIELD_URL}/api/v1/health",
                timeout=2.0,
            )
            shield_healthy = resp.json().get("status") == "healthy"
    except Exception:
        pass

    return {
        "app": "healthy",
        "shield": "healthy" if shield_healthy else "unhealthy",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
