#!/usr/bin/env python3
"""
Adversarial Security Review and Verification Suite.
Koality Assured PKI Security Standards.

Executes comprehensive hostile/antagonistic security audits across the codebase:
1. Zero-Leak Sanitization Check (Proprietary OIDs, Hostnames, Corporate Names, Internal Domains).
2. Secret & Private Key Audit (PFX/P12, PEM Private Keys, Plaintext Passwords).
3. Cryptographic Hash Integrity Inventory (SHA-256 for all repository assets).
4. PowerShell Abstract Syntax Tree (AST) & Lexical Validation.
5. Automated Test Suite Execution (Python unittest & Pester integration).
"""

import hashlib
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

# Sanitization Audit Patterns
FORBIDDEN_LEAK_PATTERNS = {
    "Proprietary Corporate Name (Blizzard)": re.compile(r"blizzard", re.IGNORECASE),
    "Proprietary Corporate Name (Activision)": re.compile(r"activision", re.IGNORECASE),
    "Internal Domain (rlab.local)": re.compile(r"rlab\.local", re.IGNORECASE),
    "Internal Domain (chromie.net)": re.compile(r"chromie\.net", re.IGNORECASE),
    "Internal Domain (battle.net)": re.compile(r"battle\.net", re.IGNORECASE),
    "Real IANA Enterprise OID (27296)": re.compile(r"1\.3\.6\.1\.4\.1\.27296"),
    "Proprietary Server (ABK-ROOTCA)": re.compile(r"ABK-ROOTCA", re.IGNORECASE),
    "Proprietary Server (CORE-HICA01)": re.compile(r"CORE-HICA01", re.IGNORECASE),
    "Proprietary Server (CORE-MICA01)": re.compile(r"CORE-MICA01", re.IGNORECASE),
    "Proprietary Server (RLAB-CWC01)": re.compile(r"RLAB-CWC01", re.IGNORECASE),
    "Proprietary Server (RANDES01)": re.compile(r"RANDES01", re.IGNORECASE),
    "Proprietary Server (COREROOT01)": re.compile(r"COREROOT01", re.IGNORECASE),
    "Proprietary Server (COREBICA01)": re.compile(r"COREBICA01", re.IGNORECASE),
    "Proprietary Template (BIIS_NetDevice)": re.compile(r"BIIS_NetDevice", re.IGNORECASE),
}

# Secret / Private Key Patterns
SECRET_LEAK_PATTERNS = {
    "RSA Private Key Header": re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
    "EC Private Key Header": re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
    "Generic Private Key Header": re.compile(r"-----BEGIN PRIVATE KEY-----"),
    "Encrypted Private Key Header": re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-----"),
    "OpenSSH Private Key Header": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
}

BANNED_EXTENSIONS = [".pfx", ".p12", ".key", ".pkcs12"]
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".vscode"}
AUDIT_SELF_FILES = {"adversarial_review.py", "test_pki_framework.py"}


def banner(text: str):
    print(f"\n{'=' * 78}\n[KOALITY ASSURED AUDIT] {text}\n{'=' * 78}")


def run_stage_1_sanitization():
    """Stage 1: Zero-Leak Sanitization Audit."""
    banner("STAGE 1: Zero-Leak Sanitization Audit")
    violations = []
    scanned_files = 0

    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            file_path = Path(root) / f
            if file_path.suffix in [".ico", ".png", ".jpg", ".pyc"]:
                continue
            if file_path.name in AUDIT_SELF_FILES:
                continue

            scanned_files += 1
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                violations.append(f"Unable to read {file_path.relative_to(REPO_ROOT)}: {e}")
                continue

            for label, pattern in FORBIDDEN_LEAK_PATTERNS.items():
                matches = pattern.findall(content)
                if matches:
                    violations.append(
                        f"VIOLATION: [{label}] match '{matches[0]}' in {file_path.relative_to(REPO_ROOT)}"
                    )

    print(f"Scanned {scanned_files} repository files for forbidden corporate leaks.")
    if violations:
        for v in violations:
            print(f"  [!] {v}", file=sys.stderr)
        return False, len(violations)

    print("  [PASS] Zero corporate leaks or proprietary OID references detected.")
    return True, 0


def run_stage_2_secret_audit():
    """Stage 2: Secret and Private Key Leak Audit."""
    banner("STAGE 2: Secret & Private Key Leak Audit")
    violations = []
    scanned_files = 0

    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            file_path = Path(root) / f
            if file_path.suffix in [".ico", ".png", ".jpg", ".pyc"]:
                continue
            if file_path.name in AUDIT_SELF_FILES:
                continue

            # Check banned extensions
            if file_path.suffix.lower() in BANNED_EXTENSIONS:
                violations.append(
                    f"VIOLATION: Prohibited private key extension {file_path.suffix} on {file_path.relative_to(REPO_ROOT)}"
                )

            scanned_files += 1
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            for label, pattern in SECRET_LEAK_PATTERNS.items():
                if pattern.search(content):
                    violations.append(
                        f"VIOLATION: [{label}] found in {file_path.relative_to(REPO_ROOT)}"
                    )

    print(f"Audited {scanned_files} files for private keys and credentials.")
    if violations:
        for v in violations:
            print(f"  [!] {v}", file=sys.stderr)
        return False, len(violations)

    print("  [PASS] Zero private keys or raw credentials present in working tree.")
    return True, 0


def run_stage_3_cryptographic_inventory():
    """Stage 3: SHA-256 Hash Integrity Inventory."""
    banner("STAGE 3: Cryptographic SHA-256 Hash Inventory")
    inventory = []

    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in sorted(files):
            file_path = Path(root) / f
            if file_path.suffix in [".pyc"]:
                continue
            sha = hashlib.sha256()
            try:
                sha.update(file_path.read_bytes())
                digest = sha.hexdigest()
                rel_path = file_path.relative_to(REPO_ROOT).as_posix()
                inventory.append((rel_path, digest))
            except Exception:
                continue

    for rel_path, digest in inventory[:15]:
        print(f"  SHA256: {digest[:16]}... {rel_path}")
    if len(inventory) > 15:
        print(f"  ... and {len(inventory) - 15} additional tracked files hashed.")

    print(f"  [PASS] Generated SHA-256 fingerprints for {len(inventory)} repository assets.")
    return True, 0


def run_stage_4_powershell_syntax():
    """Stage 4: PowerShell AST Syntax and Lexical Parsing."""
    banner("STAGE 4: PowerShell AST Syntax Validation")
    ps_files = list(REPO_ROOT.glob("**/*.ps1")) + list(REPO_ROOT.glob("**/*.psm1"))
    ps_files = [p for p in ps_files if not any(part in SKIP_DIRS for part in p.parts)]

    print(f"Validating PowerShell syntax for {len(ps_files)} scripts...")
    syntax_errors = []

    for ps in ps_files:
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            f"""
            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile('{str(ps)}', [ref]$null, [ref]$errors)
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
        if proc.returncode != 0:
            syntax_errors.append(f"{ps.relative_to(REPO_ROOT)}: {proc.stdout.strip() or proc.stderr.strip()}")

    if syntax_errors:
        for err in syntax_errors:
            print(f"  [!] {err}", file=sys.stderr)
        return False, len(syntax_errors)

    print(f"  [PASS] All {len(ps_files)} PowerShell scripts parsed cleanly with 0 syntax errors.")
    return True, 0


def run_stage_5_test_execution():
    """Stage 5: Test Suite Execution (Python unittest & Pester)."""
    banner("STAGE 5: Automated Test Suite Execution")
    
    # 5A: Python Test Suite
    print("[*] Running Python PKI Test Suite (tests/test_pki_framework.py)...")
    py_cmd = [sys.executable, "-m", "unittest", "tests/test_pki_framework.py"]
    py_proc = subprocess.run(py_cmd, cwd=REPO_ROOT, capture_output=True, text=True)

    if py_proc.returncode != 0:
        print("  [FAIL] Python unit tests failed:", file=sys.stderr)
        print(py_proc.stdout, file=sys.stderr)
        print(py_proc.stderr, file=sys.stderr)
        return False, 1

    print("  [PASS] Python unit tests passed cleanly (100% success).")

    # 5B: PowerShell Pester Suite
    print("[*] Running PowerShell Pester Test Suite (tests/*.Tests.ps1)...")
    ps_cmd = [
        "powershell.exe",
        "-NoProfile",
        "-Command",
        """
        $pester = Invoke-Pester -Path 'tests' -PassThru
        if ($pester.FailedCount -gt 0) {
            Write-Error "Pester tests failed: $($pester.FailedCount)"
            exit 1
        } else {
            Write-Output "All $($pester.PassedCount) Pester tests passed!"
            exit 0
        }
        """,
    ]
    ps_proc = subprocess.run(ps_cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if ps_proc.returncode != 0:
        print("  [FAIL] Pester tests failed:", file=sys.stderr)
        print(ps_proc.stdout, file=sys.stderr)
        print(ps_proc.stderr, file=sys.stderr)
        return False, 1

    print(f"  [PASS] {ps_proc.stdout.strip()}")
    return True, 0


def main():
    start_time = time.time()
    banner("KOALITY ASSURED ANTAGONISTIC SECURITY AUDIT")
    print(f"Target Repository: {REPO_ROOT}")
    print(f"Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")

    stages = [
        ("Sanitization Check", run_stage_1_sanitization),
        ("Secret & Key Audit", run_stage_2_secret_audit),
        ("Hash Inventory", run_stage_3_cryptographic_inventory),
        ("PowerShell AST Syntax", run_stage_4_powershell_syntax),
        ("Test Suite Execution", run_stage_5_test_execution),
    ]

    summary = []
    total_violations = 0
    all_passed = True

    for name, func in stages:
        passed, count = func()
        total_violations += count
        if not passed:
            all_passed = False
        summary.append((name, "PASSED" if passed else "FAILED", count))

    elapsed = time.time() - start_time
    banner("AUDIT SUMMARY REPORT")
    print(f"{'Stage Name':<28} | {'Status':<10} | {'Violations':<10}")
    print(f"{'-' * 28}-+-{'-' * 10}-+-{'-' * 10}")
    for name, status, count in summary:
        print(f"{name:<28} | {status:<10} | {count:<10}")

    print(f"\nAudit completed in {elapsed:.2f} seconds.")

    if all_passed and total_violations == 0:
        print("\n[VERDICT: APPROVED] 0 violations detected. Repository meets Koality Assured Security Standard.")
        return 0
    else:
        print(f"\n[VERDICT: REJECTED] {total_violations} violations detected. Remediation required.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
