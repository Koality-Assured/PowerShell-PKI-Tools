# Contributing to PowerShell PKI Tools

Thank you for contributing to the enterprise PKI as Code framework. Please follow these guidelines to ensure code quality, cryptographic rigor, and adherence to security standards.

---

## Code of Conduct

All contributors and maintainers are expected to maintain a professional, collaborative, and security-conscious environment.

---

## Development & Verification Workflow

1. **Fork and Branch:**
   - Create a feature or fix branch from `main` (or `master`) following conventional naming:
     - `feat/feature-name`
     - `fix/bug-description`
     - `docs/topic-update`

2. **Coding Standards:**
   - **PowerShell:** Use approved verbs (`Test-`, `Initialize-`, `New-`, `Set-`).
   - Use advanced parameter blocks with explicit types and validation attributes (`[ValidateNotNullOrEmpty()]`, `[ValidateRange()]`, `[ValidateSet()]`).
   - Support pipeline input and `SupportsShouldProcess` (`-WhatIf` / `-Confirm`) on mutating cmdlets.
   - Scripts must parse with **zero AST syntax errors** via `[System.Management.Automation.Language.Parser]`.
   - Never use hardcoded credentials or plain-text passwords; leverage `PSCredential` or Windows Integrated Auth.

3. **Sanitization & Clean Room Policy:**
   - Never commit internal domain names, proprietary organizational names, real corporate emails, or actual corporate OIDs.
   - Use standard IANA documentation OIDs (`1.3.6.1.4.1.99999.*`) and generic placeholders (`corp.example.com`, `ROOTCA01`).
   - Never commit private keys (`.pfx`, `.p12`, `.key`, PEM headers).

4. **Testing Requirements:**
   - Every new feature or validation check must include corresponding tests:
     - PowerShell Pester tests in `tests/*.Tests.ps1`.
     - Python verification tests in `tests/test_pki_framework.py` if adding cross-platform logic.
   - Execute the antagonistic security review before opening a Pull Request:
     ```bash
     python adversarial_review.py
     ```
     All 5 stages must output `[PASS]` with 0 violations.

5. **Commit Discipline:**
   - Follow Conventional Commits:
     - `feat: add ECC curve enforcement to Test-CsrRequest`
     - `fix: correct allowDoubleEscaping IIS location path in CSWebDistBuild`
     - `docs: update Trust-Distribution-Guide for Alpine Linux`
     - `test: add Pester assertions for MSCEP registry settings`

---

## Pull Request Checklist

Before submitting a PR, verify:
- [ ] `python adversarial_review.py` runs with 0 violations.
- [ ] `Invoke-Pester -Path tests` reports 100% passing tests.
- [ ] No proprietary references or real corporate OIDs are introduced.
- [ ] Documentation is updated for any new parameters or modules.
