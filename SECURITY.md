# Security Policy

Vigil is a defensive security tool, and we take the security of the project itself seriously.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities. Instead, report privately
by emailing the maintainers at: `security@vigil-soc.dev` (placeholder — replace with your address
before publishing).

Include, if possible:

- Affected version / commit
- Steps to reproduce (minimal, sanitized)
- Impact assessment
- Suggested fix (optional)

You should receive an acknowledgement within **5 business days**, and a detailed response
(including a fix timeline) within **14 business days**.

## Scope

- The `vigil` codebase (core pipeline, ingest, CLI)
- Prompt-injection hardening of the LLM pipeline (see `docs/security-model.md`)

## Out of scope

- Vulnerabilities in third-party dependencies (report upstream)
- Misuse of the tool for unauthorized analysis (this is a usage issue, not a code vulnerability)

## Disclosure

We will credit reporters (unless anonymity is requested) once a fix is released. We follow a
90-day coordinated disclosure window.
