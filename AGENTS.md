# Repository AGENTS Rules - PowerShell-PKI-Tools

Canonical instructions and operating constraints for AI coding agents operating within `PowerShell-PKI-Tools`.

---

## Directives & Precedence

1. **Directive Severity Hierarchy:** `critical` > `must` / `must not` > `should` / `should not`. Higher severity wins.
2. **Ambiguity Gate:** Unresolved scope contradictions or cryptographic parameter ambiguities MUST be surfaced to the human architect rather than guessed.

---

## Critical Rules

### Zero-Leak Sanitization (Non-Negotiable)
- All scripts, configurations, documentation, and test fixtures MUST remain completely sanitized.
- **MUST NOT** include proprietary corporate names, internal domains, real corporate emails, or actual IANA enterprise OIDs.
- Always use documentation OIDs (`1.3.6.1.4.1.99999.*`) and generic enterprise naming (`corp.example.com`, `Koality Assured`).

### Zero Private Keys
- **MUST NOT** commit private keys (`.pfx`, `.p12`, `.key`, `BEGIN RSA PRIVATE KEY`, etc.).
- CSR files in `tests/fixtures/` are public signing requests only and must never contain private key components.

### Empirical Validation & Proof-of-Work
- Before completing any task, agents MUST run:
  ```bash
  python adversarial_review.py
  ```
  The audit must report **0 violations** and all test stages must pass.

### Syntax Integrity
- All PowerShell scripts (`.ps1`, `.psm1`) MUST parse cleanly with zero syntax errors under `[System.Management.Automation.Language.Parser]`.
- Avoid syntax constructs that trigger parser bugs (e.g. unescaped drive colons in string variables like `$var:`).

---

## Scripting & Module Conventions

- **PowerShell Verb-Noun:** Adhere to standard PowerShell approved verbs (`Test-`, `Initialize-`, `New-`, `Set-`).
- **Idempotence & Safety:** Declarative DSC configurations must be idempotent. Active Directory delegation scripts must support `-WhatIf` / `-Confirm` (`SupportsShouldProcess`).
- **DSC Standalone Credential Fix:** In workgroup/standalone environments (such as an Offline Root CA), do not require domain credentials. Ensure `xActiveDirectoryCSDsc` resources accommodate workgroup deployment.
