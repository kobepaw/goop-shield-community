"""CrewAI integration: Shield as a tool wrapper.

Requires:
    pip install goop-shield crewai

Start Shield server first:
    goop-shield serve --port 8787
"""

from goop_shield.adapters.crewai import CrewAIShieldAdapter


def example_tool_wrapping():
    """Wrap a CrewAI tool with Shield interception."""
    adapter = CrewAIShieldAdapter(
        shield_url="http://localhost:8787",
    )

    # Simulate a search tool
    def search_tool(query: str) -> str:
        return f"Search results for: {query}"

    # Shield checks the tool call before execution,
    # then scans the output after execution
    result = adapter.wrap_tool_execution(
        "web_search",
        search_tool,
        query="latest Python security updates",
    )
    print(f"Tool result: {result}")

    # A dangerous tool call will be blocked
    try:
        result = adapter.wrap_tool_execution(
            "execute_shell",
            lambda cmd: f"Executed: {cmd}",
            cmd="rm -rf /",
        )
    except PermissionError as e:
        print(f"Tool blocked: {e}")


def example_prompt_interception():
    """Intercept prompts and scan responses."""
    adapter = CrewAIShieldAdapter(
        shield_url="http://localhost:8787",
    )

    # Before sending a prompt to the LLM
    result = adapter.intercept_prompt(
        "Research the latest vulnerabilities in OpenSSL",
        context={"agent_role": "researcher"},
    )
    if result.allowed:
        print(f"Prompt allowed, sending to LLM: {result.filtered_prompt}")
    else:
        print(f"Prompt blocked by: {result.blocked_by}")

    # After receiving a response
    scan = adapter.scan_response(
        response="Here are the CVE details...",
        original_prompt="Research the latest vulnerabilities",
    )
    if scan.safe:
        print("Response is safe to display")
    else:
        print(f"Response flagged by: {scan.flagged_by}")
        print(f"Filtered: {scan.filtered_response}")


if __name__ == "__main__":
    print("=== Tool Wrapping ===")
    example_tool_wrapping()
    print()
    print("=== Prompt Interception ===")
    example_prompt_interception()
