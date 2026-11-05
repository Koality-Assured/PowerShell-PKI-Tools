# Pester Tests for PKI Validation Utilities
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $here
$validationDir = Join-Path $repoRoot "Validation"
$fixturesDir = Join-Path $here "fixtures"

Describe "PKI Validation Module Tests" {

    Context "Test-CsrRequest.ps1" {
        $csrScript = Join-Path $validationDir "Test-CsrRequest.ps1"

        It "Script file exists" {
            Test-Path $csrScript | Should Be $true
        }

        It "Validates a compliant 2048-bit RSA CSR with SANs" {
            $fixture = Join-Path $fixturesDir "valid_rsa2048.req"
            $result = & $csrScript -Path $fixture
            $result.IsValid | Should Be $true
            $result.SignatureValid | Should Be $true
            $result.KeySizeBits | Should Be 2048
            $result.KeyAlgorithm | Should Match "RSA"
            $result.SubjectAlternativeNames.Count | Should BeGreaterThan 0
            $result.Violations.Count | Should Be 0
        }

        It "Validates a compliant 4096-bit RSA CSR" {
            $fixture = Join-Path $fixturesDir "valid_rsa4096.req"
            $result = & $csrScript -Path $fixture
            $result.IsValid | Should Be $true
            $result.SignatureValid | Should Be $true
            $result.KeySizeBits | Should Be 4096
            $result.KeyAlgorithm | Should Match "RSA"
            $result.Violations.Count | Should Be 0
        }

        It "Validates a compliant ECC P-384 CSR" {
            $fixture = Join-Path $fixturesDir "valid_ecc384.req"
            $result = & $csrScript -Path $fixture
            $result.IsValid | Should Be $true
            $result.SignatureValid | Should Be $true
            $result.KeySizeBits | Should Be 384
            $result.KeyAlgorithm | Should Match "ECC|ECDSA"
            $result.Violations.Count | Should Be 0
        }

        It "Rejects a weak 1024-bit RSA key" {
            $fixture = Join-Path $fixturesDir "weak_rsa1024.req"
            $result = & $csrScript -Path $fixture -MinRsaKeySize 2048
            $result.IsValid | Should Be $false
            ($result.Violations -join ' ') | Should Match "Insufficient RSA Key Length"
        }

        It "Rejects a CSR missing required Subject Alternative Names" {
            $fixture = Join-Path $fixturesDir "no_san.req"
            $result = & $csrScript -Path $fixture -RequireSan
            $result.IsValid | Should Be $false
            ($result.Violations -join ' ') | Should Match "Missing Subject Alternative Name"
        }

        It "Rejects a wildcard SAN when wildcard policy is enforced" {
            $fixture = Join-Path $fixturesDir "wildcard_san.req"
            $result = & $csrScript -Path $fixture -DisallowWildcardSan
            $result.IsValid | Should Be $false
            ($result.Violations -join ' ') | Should Match "Disallowed Wildcard SAN"
        }

        It "Rejects a corrupted signature CSR" {
            $fixture = Join-Path $fixturesDir "corrupted_signature.req"
            $result = & $csrScript -Path $fixture
            $result.IsValid | Should Be $false
            $result.SignatureValid | Should Be $false
        }

        It "Supports JSON output flag" {
            $fixture = Join-Path $fixturesDir "valid_rsa2048.req"
            $json = & $csrScript -Path $fixture -AsJson
            $json | Should Match '"IsValid":\s*true'
        }
    }

    Context "Test-TlsCipherSupport.ps1" {
        $tlsScript = Join-Path $validationDir "Test-TlsCipherSupport.ps1"

        It "Script file exists" {
            Test-Path $tlsScript | Should Be $true
        }

        It "Validates parameter block schema" {
            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($tlsScript, [ref]$null, [ref]$errors)
            $errors.Count | Should Be 0
            $ast.ParamBlock | Should Not Be $null
        }
    }
}
