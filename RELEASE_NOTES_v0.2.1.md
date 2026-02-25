# goop-shield-community v0.2.1

## Security Advisory: ClawHavoc Supply-Chain Attack

On Feb 17, 2026, researchers at Antiy and Koi identified 1,184 malicious packages
on the ClawHub marketplace ("ClawHavoc"). These packages targeted:
- SSH key exfiltration (.ssh/id_rsa, .ssh/authorized_keys)
- Reverse shell deployment (bash -i >& /dev/tcp/, nc -e, socat exec)
- macOS credential theft via AMOS stealer (osascript, Keychain, cookies)

Five C2 IP addresses and two malicious file hashes have been added as IOC signatures.

## What's New

### ClawHavoc IOC Signatures
- **IOCMatcherDefense**: Now detects ClawHavoc C2 IP addresses in prompts
  (91.92.242.30, 95.92.242.30, 96.92.242.30, 202.161.50.59, 54.91.154.110)
- **DomainReputationDefense**: Now blocks IP-based URLs pointing to known C2 servers
- **IOC feed wiring**: `register_defaults()` now loads IOC feeds when `ioc_file` is
  configured in ShieldConfig, feeding both IOCMatcher and DomainReputation defenses

### Audit Scanner
- New standalone scanner: `scripts/audit_clawhavoc.py`
- Scans a directory tree for ClawHavoc indicators (C2 IPs, malicious hashes,
  suspicious patterns like reverse shells, SSH key access, encoded payloads)
- Zero dependencies (stdlib only) — safe to run anywhere
- Usage: `python3 scripts/audit_clawhavoc.py /path/to/skills/ [--json]`

### IOC Feed File
- New: `data/clawhavoc_iocs.yaml` containing all known ClawHavoc IOCs
- Configure via `ShieldConfig(ioc_file="data/clawhavoc_iocs.yaml")`

## Recommended Actions

1. Run `audit_clawhavoc.py` on any ClawHub skill directories
2. Disable the `clawhub` skill until the marketplace is verified clean
3. Configure `ioc_file` in your ShieldConfig to load ClawHavoc IOCs at startup

## Full Changelog
- IOCMatcherDefense: added C2 IP matching + `c2_ips` key in `load_iocs()`
- DomainReputationDefense: added IP-URL blocking + `c2_ips` key in `load_ioc_feed()`
- register_defaults(): wired ioc_file config → defense initialization
- New: data/clawhavoc_iocs.yaml
- New: scripts/audit_clawhavoc.py
- Version bump: 0.2.0 → 0.2.1
