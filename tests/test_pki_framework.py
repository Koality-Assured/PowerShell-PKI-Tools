#!/usr/bin/env python3
"""
Python PKI Framework Test Suite.
Validates PowerShell PKI Tools repository for syntax, cryptographic correctness,
security compliance, and zero-leak sanitization.
"""

import os
import re
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN_PATTERNS = [
    re.compile(r"blizzard", re.IGNORECASE),
    re.compile(r"activision", re.IGNORECASE),
    re.compile(r"rlab\.local", re.IGNORECASE),
    re.compile(r"chromie\.net", re.IGNORECASE),
    re.compile(r"battle\.net", re.IGNORECASE),
    re.compile(r"1\.3\.6\.1\.4\.1\.27296"),
    re.compile(r"ABK-ROOTCA", re.IGNORECASE),
    re.compile(r"CORE-HICA01", re.IGNORECASE),
    re.compile(r"CORE-MICA01", re.IGNORECASE),
    re.compile(r"RLAB-CWC01", re.IGNORECASE),
    re.compile(r"RANDES01", re.IGNORECASE),
    re.compile(r"COREROOT01", re.IGNORECASE),
    re.compile(r"COREBICA01", re.IGNORECASE),
]

PRIVATE_KEY_PATTERNS = [
    re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-----"),
]


class TestPkiFramework(unittest.TestCase):

    def test_repository_structure(self):
        """Verifies that all required architecture directories and files exist."""
        required_paths = [
            "DSC/CSRootBuild.ps1",
            "DSC/CSHighIssuingBuild.ps1",
            "DSC/CSMedIssuingBuild.ps1",
            "DSC/CSWebDistBuild.ps1",
            "DSC/CSNDESBuild.ps1",
            "ActiveDirectory/Initialize-PkiAdDelegation.ps1",
            "Validation/Test-CsrRequest.ps1",
            "Validation/Test-TlsCipherSupport.ps1",
            "Documentation/Trust-Distribution-Guide.md",
            "tests/Validation.Tests.ps1",
            "tests/DscConfigurations.Tests.ps1",
            "tests/PkiTools.Tests.ps1",
            "tests/fixtures/valid_rsa2048.req",
            "tests/fixtures/valid_rsa4096.req",
            "tests/fixtures/valid_ecc384.req",
            "tests/fixtures/weak_rsa1024.req",
            "tests/fixtures/no_san.req",
            "tests/fixtures/wildcard_san.req",
            "tests/fixtures/corrupted_signature.req",
        ]
        for rel_path in required_paths:
            full_path = REPO_ROOT / rel_path
            self.assertTrue(full_path.exists(), f"Missing required file: {rel_path}")

    def test_sanitization_zero_leak(self):
        """Ensures zero occurrences of proprietary corporate references or real corporate OIDs."""
        scanned_count = 0
        violations = []

        for root, dirs, files in os.walk(REPO_ROOT):
            # Skip .git and __pycache__ directories
            for skip_dir in [".git", "__pycache__", ".pytest_cache"]:
                if skip_dir in dirs:
                    dirs.remove(skip_dir)
            for f in files:
                file_path = Path(root) / f
                # Skip binary fixtures and bytecode
                if file_path.suffix in [".ico", ".png", ".jpg", ".pyc"]:
                    continue

                scanned_count += 1
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                except Exception as e:
                    violations.append(f"Cannot read {file_path}: {e}")
                    continue

                for pat in FORBIDDEN_PATTERNS:
                    matches = pat.findall(content)
                    if matches:
                        # Allow reference inside adversarial_review or test itself when defining the forbidden list
                        if file_path.name in ["test_pki_framework.py", "adversarial_review.py"]:
                            continue
                        violations.append(
                            f"Leak detected in {file_path.relative_to(REPO_ROOT)}: match '{matches[0]}'"
                        )

        self.assertGreater(scanned_count, 10, "Should scan more than 10 files")
        self.assertEqual(len(violations), 0, "\n".join(violations))

    def test_zero_private_keys(self):
        """Ensures zero private keys (.pfx, .p12, .key, PEM private keys) exist in repository."""
        scanned_count = 0
        violations = []

        for root, dirs, files in os.walk(REPO_ROOT):
            for skip_dir in [".git", "__pycache__", ".pytest_cache"]:
                if skip_dir in dirs:
                    dirs.remove(skip_dir)
            for f in files:
                file_path = Path(root) / f
                if file_path.suffix in [".ico", ".png", ".jpg", ".pyc"]:
                    continue
                if file_path.suffix.lower() in [".pfx", ".p12", ".key"]:
                    violations.append(f"Private key file extension found: {file_path.relative_to(REPO_ROOT)}")

                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                for pat in PRIVATE_KEY_PATTERNS:
                    if pat.search(content):
                        # Allow regex definition inside security scripts
                        if file_path.name in ["test_pki_framework.py", "adversarial_review.py"]:
                            continue
                        violations.append(f"Private key header found in {file_path.relative_to(REPO_ROOT)}")

        self.assertEqual(len(violations), 0, "\n".join(violations))

    def test_powershell_file_syntax(self):
        """Parses all .ps1 and .psm1 files using PowerShell parser to verify zero syntax errors."""
        ps_files = list(REPO_ROOT.glob("**/*.ps1")) + list(REPO_ROOT.glob("**/*.psm1"))
        self.assertGreater(len(ps_files), 5, "Should find at least 5 PowerShell files")

        for ps_file in ps_files:
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                f"""
                $errors = $null
                $ast = [System.Management.Automation.Language.Parser]::ParseFile('{str(ps_file)}', [ref]$null, [ref]$errors)
                $realErrors = $errors | Where-Object {{ $_.ErrorId -ne 'ModuleNotFoundDuringParse' }}
                if ($realErrors) {{
                    $realErrors | ForEach-Object {{ Write-Output $_.Message }}
                    exit 1
                }} else {{
                    exit 0
                }}
                """,
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(
                proc.returncode,
                0,
                f"Syntax errors in {ps_file.relative_to(REPO_ROOT)}:\n{proc.stdout}\n{proc.stderr}",
            )

    def test_csr_fixture_cryptography(self):
        """Validates fixture CSRs using the Python cryptography library."""
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        import ipaddress

        fixtures_dir = REPO_ROOT / "tests" / "fixtures"

        # 1. Valid RSA 2048
        with open(fixtures_dir / "valid_rsa2048.req", "rb") as f:
            csr = x509.load_pem_x509_csr(f.read())
            self.assertTrue(csr.is_signature_valid)
            self.assertEqual(csr.public_key().key_size, 2048)
            san_ext = csr.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            dns_names = san_ext.value.get_values_for_type(x509.DNSName)
            self.assertIn("web01.corp.example.com", dns_names)
            ip_addrs = san_ext.value.get_values_for_type(x509.IPAddress)
            self.assertIn(ipaddress.IPv4Address("10.0.1.50"), ip_addrs)

        # 2. Valid RSA 4096
        with open(fixtures_dir / "valid_rsa4096.req", "rb") as f:
            csr = x509.load_pem_x509_csr(f.read())
            self.assertTrue(csr.is_signature_valid)
            self.assertEqual(csr.public_key().key_size, 4096)

        # 3. Valid ECC P-384
        with open(fixtures_dir / "valid_ecc384.req", "rb") as f:
            csr = x509.load_pem_x509_csr(f.read())
            self.assertTrue(csr.is_signature_valid)
            self.assertEqual(csr.public_key().key_size, 384)

        # 4. Weak RSA 1024
        with open(fixtures_dir / "weak_rsa1024.req", "rb") as f:
            csr = x509.load_pem_x509_csr(f.read())
            self.assertEqual(csr.public_key().key_size, 1024)

        # 5. Missing SAN
        with open(fixtures_dir / "no_san.req", "rb") as f:
            csr = x509.load_pem_x509_csr(f.read())
            with self.assertRaises(x509.ExtensionNotFound):
                csr.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)

        # 6. Wildcard SAN
        with open(fixtures_dir / "wildcard_san.req", "rb") as f:
            csr = x509.load_pem_x509_csr(f.read())
            san_ext = csr.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            dns_names = san_ext.value.get_values_for_type(x509.DNSName)
            self.assertIn("*.corp.example.com", dns_names)


if __name__ == "__main__":
    unittest.main()
