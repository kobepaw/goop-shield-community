# Framework Adapters

goop-shield provides drop-in adapters for popular AI agent frameworks. All adapters implement the same `BaseShieldAdapter` interface and communicate with Shield over HTTP.

## Available Adapters

| Adapter | Module | Framework |
|---------|--------|-----------|
| `GenericHTTPAdapter` | `goop_shield.adapters.generic` | Any HTTP client |
| `LangChainShieldAdapter` | `goop_shield.adapters.langchain` | LangChain |
| `CrewAIShieldAdapter` | `goop_shield.adapters.crewai` | CrewAI |
| `OpenClawAdapter` | `goop_shield.adapters.openclaw` | OpenClaw |

## BaseShieldAdapter Interface

All adapters implement three methods:

```python
class BaseShieldAdapter(ABC):
    def intercept_prompt(self, prompt: str, context: dict | None = None) -> ShieldResult:
        """Intercept and defend a prompt before sending to LLM."""

    def intercept_tool_call(self, tool: str, args: dict | None = None) -> ShieldResult:
        """Intercept a tool call before execution."""

    def scan_response(self, response: str, original_prompt: str = "") -> ScanResult:
        """Scan an LLM response for policy violations."""
```

### ShieldResult

```python
@dataclass
class ShieldResult:
    allowed: bool = True
    filtered_prompt: str = ""
    blocked_by: str | None = None
    confidence: float = 0.0
    defenses_applied: list[str] = field(default_factory=list)
```

### ScanResult

```python
@dataclass
class ScanResult:
    safe: bool = True
    filtered_response: str = ""
    flagged_by: str | None = None
    confidence: float = 0.0
    scanners_applied: list[str] = field(default_factory=list)
```

## Generic HTTP Adapter

Works with any framework. Uses synchronous HTTP calls to Shield.

```python
from goop_shield.adapters.generic import GenericHTTPAdapter

adapter = GenericHTTPAdapter(
    shield_url="http://localhost:8787",
    api_key="sk-...",  # optional
)

# Defend a prompt
result = adapter.intercept_prompt("user input here")
if not result.allowed:
    print(f"Blocked by: {result.blocked_by}")

# Scan a response
scan = adapter.scan_response("LLM output here", original_prompt="user input")
if not scan.safe:
    print(f"Flagged by: {scan.flagged_by}")
    print(f"Filtered: {scan.filtered_response}")
```

## LangChain

### Adapter

```python
from goop_shield.adapters.langchain import LangChainShieldAdapter

adapter = LangChainShieldAdapter(shield_url="http://localhost:8787")

result = adapter.intercept_prompt("What is 2+2?")
print(result.allowed)  # True
```

### Callback Handler

For automatic interception in LangChain chains:

```python
from goop_shield.adapters.langchain import LangChainShieldCallback

callback = LangChainShieldCallback(
    shield_url="http://localhost:8787",
    api_key="sk-...",
)

# Attach to any LangChain chain
from langchain.chains import LLMChain
chain = LLMChain(llm=llm, prompt=prompt, callbacks=[callback])

# Prompts are automatically defended before reaching the LLM
# Tool calls are intercepted before execution
# Responses are scanned after generation
result = chain.run("Tell me about Python")
```

The callback handler hooks into:
- `on_llm_start` -- defends prompts before LLM call
- `on_tool_start` -- intercepts tool calls before execution
- `on_llm_end` -- scans responses after generation

## CrewAI

### Adapter

```python
from goop_shield.adapters.crewai import CrewAIShieldAdapter

adapter = CrewAIShieldAdapter(shield_url="http://localhost:8787")

# Intercept a tool call
result = adapter.intercept_tool_call("web_search", {"query": "test"})
```

### Tool Wrapping

Wrap tool execution with automatic Shield interception:

```python
from goop_shield.adapters.crewai import CrewAIShieldAdapter

adapter = CrewAIShieldAdapter(shield_url="http://localhost:8787")

def search_tool(query: str) -> str:
    return f"Results for: {query}"

# Shield checks the tool call before execution
# and scans the output after execution
result = adapter.wrap_tool_execution("search", search_tool, query="latest news")
```

If Shield blocks the tool call, `wrap_tool_execution` raises `PermissionError`. If the output scan flags the response, it returns the filtered (sanitized) response instead.

## OpenClaw

### Adapter

```python
from goop_shield.adapters.openclaw import OpenClawAdapter

adapter = OpenClawAdapter(shield_url="http://localhost:8787")
```

### Hook Events

Process OpenClaw `before_tool_call` events:

```python
event = {"tool": "execute_code", "args": {"code": "import os; os.system('rm -rf /')"}}
result = adapter.from_hook_event(event)
if not result.allowed:
    print(f"Blocked: {result.blocked_by}")
```

### JSON-RPC Messages

Process OpenClaw WebSocket messages:

```python
# Incoming request
message = {"type": "req", "params": {"content": "Run this shell command"}}
result = adapter.from_jsonrpc_message(message)

# Outgoing response
message = {"type": "res", "result": {"content": "Here is the API key: sk-abc123"}}
result = adapter.from_jsonrpc_message(message)
if isinstance(result, ScanResult) and not result.safe:
    print("Response contains leaked secrets!")
```

## Creating a Custom Adapter

Subclass `BaseShieldAdapter` and implement the three methods:

```python
from goop_shield.adapters.base import BaseShieldAdapter, ScanResult, ShieldResult
from goop_shield.adapters.generic import GenericHTTPAdapter


class MyFrameworkAdapter(BaseShieldAdapter):
    def __init__(self, shield_url: str = "http://localhost:8787"):
        self._http = GenericHTTPAdapter(shield_url=shield_url)

    def intercept_prompt(self, prompt: str, context: dict | None = None) -> ShieldResult:
        ctx = dict(context or {})
        ctx["framework"] = "my_framework"
        return self._http.intercept_prompt(prompt, context=ctx)

    def intercept_tool_call(self, tool: str, args: dict | None = None) -> ShieldResult:
        prompt = f"[MyFramework Tool] {tool}: {args or {}}"
        return self._http.intercept_prompt(prompt, context={"tool_call": True})

    def scan_response(self, response: str, original_prompt: str = "") -> ScanResult:
        return self._http.scan_response(response, original_prompt)
```

All adapters delegate to `GenericHTTPAdapter` for HTTP communication. Customize the context and prompt formatting for your framework.

## Error Handling

All adapters fail open by default. If Shield is unreachable:

- `intercept_prompt` returns `ShieldResult(allowed=True)`
- `scan_response` returns `ScanResult(safe=True)`

This prevents Shield outages from blocking your application. If you need fail-closed behavior, check the result and handle `ShieldClientError` explicitly.
