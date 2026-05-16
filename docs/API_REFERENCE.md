# API Reference

This document is the API entry point for Azazel-Edge.

Detailed endpoint behavior is intentionally split by operational context to avoid stale duplication.

## Primary API Surfaces

- State and dashboard APIs
- Control and mode APIs
- SoT and trust update APIs
- Triage APIs
- Runbook proposal/review/act APIs
- Demo replay APIs
- AI ask/capability APIs

## Authoritative Sources

- Web/API implementation: `azazel_edge_web/app.py`
- Deterministic runtime architecture: [P0 Runtime Architecture](P0_RUNTIME_ARCHITECTURE.md)
- Demo API and replay semantics: [Demo Guide](DEMO_GUIDE.md)
- AI-assist API behavior: [AI Operation Guide](AI_OPERATION_GUIDE.md)
- Post-demo route boundaries: [Post-demo Main Integration Boundary (#104)](POST_DEMO_MAIN_INTEGRATION_104.md)

## Authentication and Authorization

- Protected API routes are fail-closed by default.
- Role/token and optional mTLS controls are documented in:
  - [Configuration Reference](CONFIGURATION.md)
  - [Post-demo Socket Permission Model (#105)](POST_DEMO_SOCKET_PERMISSION_MODEL_105.md)

## Compatibility Note

API contract details evolve with implementation.
For release-specific behavior, consult:
- [Changelog](CHANGELOG.md)
- [Release Verification Guide](RELEASE_VERIFICATION_GUIDE.md)
