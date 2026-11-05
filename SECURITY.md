# Security Policy

## Supported Versions

The following versions of `PowerShell-PKI-Tools` are actively supported with security updates and cryptographic policy maintenance:

| Version | Supported          | Cryptographic Standard                               |
|---------|--------------------|------------------------------------------------------|
| 2.x     | :white_check_mark: | RSA >= 2048-bit (4096 recommended), ECC P-384, SHA-2 |
| < 2.0   | :x:                | Deprecated                                           |

---

## Cryptographic Policy & Assurance Standards

All PKI deployment configurations and validation scripts adhere to modern cryptographic recommendations from NIST SP 800-57, BSI TR-02102, and CA/Browser Forum baseline requirements:

1. **Root Certification Authority (Offline):**
   - Minimum Key Size: RSA 4096-bit or ECC P-384 (SECP384R1).
   - Signature Hash: SHA-256 or SHA-384.
   - Operating Environment: Offline, air-gapped, isolated workgroup host. Zero domain join, zero direct internet connectivity.
   - Default Templates: Disabled (`LoadDefaultTemplates = 0`).

2. **Subordinate Certification Authorities (Tier-0 / Tier-1):**
   - Minimum Key Size: RSA 2048-bit (4096-bit enforced for Tier-0 Smartcard/KDC Issuing CAs).
   - Signature Hash: SHA-256 or SHA-384 (MD5 and SHA-1 strictly banned).
   - Revocation: High-availability HTTP CDP endpoints with automated SMB publishing.

3. **Network Device Enrollment Service (NDES / SCEP):**
   - Authentication Identity: Group Managed Service Account (gMSA).
   - Dynamic Passwords: One-time challenge passwords with bounded validity windows and minimum length >= 16 characters.

4. **Zero Private Key Storage in Source Control:**
   - No private keys (`.pfx`, `.p12`, `.key`, PEM private keys) may ever be committed to this repository.
   - Test fixtures contain only public Certificate Signing Requests (`.req`).

---

## Reporting a Vulnerability

Koality Assured takes the security of public key infrastructure tools seriously. If you discover a security vulnerability or cryptographic flaw:

1. **Do not create a public GitHub issue.**
2. Send a detailed report to the security team at `security@example.com`.
3. Include:
   - Component affected (DSC script, Active Directory delegation, validation script).
   - Detailed attack vector or reproduction steps.
   - Cryptographic impact assessment.
4. The security team will acknowledge receipt within 24 business hours and coordinate a coordinated disclosure timeline.
