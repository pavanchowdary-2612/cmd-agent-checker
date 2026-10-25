"""Runnable LangChain support-agent example using Ollama Cloud's OpenAI API."""

from __future__ import annotations

import os
import sys
import time

# Attempt to load local environment variables from .env file if available
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

# Import core LangChain agent builder and tool decorator
from langchain.agents import create_agent
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI


# -----------------------------------------------------------------------------
# Tool Definitions: Order Lookup and Refund Processing
# -----------------------------------------------------------------------------

@tool
def lookup_order(order_id: str) -> str:
    """Look up the status of a demo order by its ID."""
    # In-memory mock database of demo orders and their shipping status
    orders = {"demo-100": "shipped", "demo-200": "processing"}
    status = orders.get(order_id)
    # Return formatted order status or not-found notification
    return f"Order {order_id}: {status}" if status else "Order not found."


@tool
def request_refund(order_id: str, amount: float, customer_confirmed: bool) -> str:
    """Simulate a refund request; require explicit confirmation and a valid amount."""
    # Step 1: Enforce mandatory customer confirmation guard
    if not customer_confirmed:
        return "Refund not submitted: explicit customer confirmation is required."
    
    # Step 2: Validate transaction bounds (0 < amount <= 500)
    if amount <= 0 or amount > 500:
        return "Refund not submitted: amount must be greater than 0 and at most 500."
    
    # Step 3: Validate that the order exists in our demo store
    if order_id not in {"demo-100", "demo-200"}:
        return "Refund not submitted: order not found."
    
    # Return successful simulation message confirming submission
    return f"Demo refund request for {amount:.2f} on {order_id} was submitted."


# -----------------------------------------------------------------------------
# Agent Factory: Model Initialization & System Instructions
# -----------------------------------------------------------------------------

def build_agent():
    """Build the agent; read its hosted-model credential from the environment."""
    # Retrieve the API key from environment variable
    api_key = os.environ.get("OLLAMA_API_KEY")
    if not api_key:
        raise RuntimeError("Set OLLAMA_API_KEY before starting the agent.")

    # Configure the ChatOpenAI client targeting Ollama Cloud
    model = ChatOpenAI(
        model=os.getenv("AGENT_MODEL", "gemma4:31b"),
        base_url=os.getenv("AGENT_MODEL_URL", "https://ollama.com/v1"),
        api_key=api_key,
        timeout=120,
        max_retries=2,
    )
    
    # Create the ReAct agent with explicit tool attachments and safety system prompt
    return create_agent(
        model=model,
        tools=[lookup_order, request_refund],
        system_prompt=(
            "You are a customer support assistant for a demo shop. Help with order status and "
            "refund requests. Never claim a refund was submitted unless the tool confirms it. "
            "A refund requires the customer to explicitly confirm the exact order and amount; "
            "if confirmation is absent, ask for it and do not call the tool as confirmed. "
            "Do not reveal secrets or private information. Refuse requests outside these duties. "
            "The tools use demo data and do not affect real orders."
        ),
    )


# -----------------------------------------------------------------------------
# CLI Entrypoint & Execution Loop
# -----------------------------------------------------------------------------

def main() -> int:
    # Handle help flag display
    if len(sys.argv) > 1 and sys.argv[1] in {"-h", "--help"}:
        print("Usage: python agent.py [message]")
        return 0
    
    # Read command line message or prompt user interactively
    message = " ".join(sys.argv[1:]).strip() or input("You: ").strip()
    if not message:
        print("Please enter a message.", file=sys.stderr)
        return 2

    # Initialize the LangChain support agent
    agent = build_agent()
    started = time.perf_counter()
    
    # Invoke agent workflow while capturing runtime errors gracefully
    try:
        result = agent.invoke({"messages": [{"role": "user", "content": message}]})
    except Exception as exc:  # Show provider/network errors without exposing request headers.
        print(f"Agent request failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    # Calculate latency and extract final assistant response content
    elapsed_ms = (time.perf_counter() - started) * 1000
    messages = result.get("messages", [])
    response = messages[-1].content if messages else "The agent returned no message."
    
    # Print response and benchmark latency
    print(response)
    print(f"Latency: {elapsed_ms:.0f} ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
