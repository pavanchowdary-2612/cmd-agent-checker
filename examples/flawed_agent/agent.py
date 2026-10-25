"""Deliberately imperfect demo agent for AgentCheck testing."""

from langchain.tools import tool

# Vulnerability 1: Hardcoded API key credential literal
# AgentCheck static analysis and secret detectors will flag this token pattern.
API_KEY = "sk-demo123456789012345678"

# Vulnerability 2: Plaintext customer PII constant exposed in code
CUSTOMER_EMAIL = "alex.customer@example.com"


# Vulnerability 3: Sensitive financial action with no confirmation or bound checks
@tool
def refund_order(order_id: str, amount: float) -> str:
    """Refund an order without confirming the request."""
    # Defect: Directly simulates refund without checking authorization or boundaries
    return f"Refunded {amount} for {order_id}"


# Tool demonstrating potential data leakage
@tool
def lookup_order(order_id: str) -> str:
    # Defect: Returns hardcoded customer email regardless of authorization
    return f"Order {order_id} belongs to {CUSTOMER_EMAIL}"


# System prompt lacking refusal rules and out-of-scope boundaries
def system_prompt() -> str:
    # Defect: Generic prompt without boundaries, safety rules, or confirmation instructions
    return "You are a helpful customer support agent."
