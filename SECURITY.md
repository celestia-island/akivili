# Security

Plugins execute third-party TypeScript inside the Boa engine sandbox. Report
vulnerabilities privately via the celestia-island security process; do not open
public issues for security bugs.

## Known hardening notes

- The SWC transpile pipeline runs the AST security validator (`akivili_iepl`)
  before any code is evaluated; forbidden globals, dynamic code execution and
  unsafe timer usage are rejected.
- Egress HTTP from plugins is gated by `NetworkGuard` (URL allow-list policy).
- `verify_signature` / `trusted_sources` on Layer-3 agent subscriptions are
  currently parsed but not yet enforced (tracked in PLAN §11.3 阶段 5); treat
  subscriptions from untrusted sources accordingly until enforced.
