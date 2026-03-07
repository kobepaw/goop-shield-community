# goop-shield-community v0.3.0 Release Notes

## Summary

v0.3.0 adds 12 new inline defenses and an adaptive Bayesian ranking backend,
bringing total defense capacity to 36 inline defenses (24 enabled by default)
and 3 output scanners.

## Highlights

- **MCPGuard** — MCP tool schema validation before execution
- **CircuitBreaker** — per-session tool-call loop detection
- **ToolCallFirewall** — dangerous tool-call argument blocking
- **ApprovalFlowMonitor** — escalation/approval manipulation detection
- **ChannelImpersonationGuard** — channel spoofing detection
- **ConfigMutationGuard** — runtime config tampering detection
- **CredentialPathGuard** — credential path traversal detection
- **AlignmentInlineDefense** — alignment/persona override detection
- **PluginSupplyChainGuard** — plugin integrity verification
- **PluginHookGuard** — lifecycle hook injection detection
- **ContextWindowGuard** — long-context injection detection
- **BayesianRankingBackend** — Thompson-sampling adaptive defense ranking

## Red Team Enhancements

- MultiTurnProbe framework + 4 multi-turn attack probes
- 5 advanced encoding/obfuscation probes
- CompositionEngine with 3 example rules

## Breaking Changes

None. New defenses are config-gated and backwards-compatible.

## Migration from v0.1.0

Direct upgrade. No mandatory config changes required.

To enable additional v0.3.0 defenses explicitly:

```python
from goop_shield.config import ShieldConfig

shield_config = ShieldConfig(
    mcp_guard_enabled=True,
    circuit_breaker_enabled=True,
    plugin_supply_chain_guard_enabled=True,
)
```
