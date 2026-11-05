# Pester Tests for Active Directory PKI Delegation and Project Structure
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $here

Describe "PKI Infrastructure and Active Directory Suite" {

    Context "Active Directory Delegation Script" {
        $adScript = Join-Path $repoRoot "ActiveDirectory\Initialize-PkiAdDelegation.ps1"

        It "Initialize-PkiAdDelegation.ps1 exists" {
            Test-Path $adScript | Should Be $true
        }

        It "Parses cleanly without syntax errors" {
            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($adScript, [ref]$null, [ref]$errors)
            $errors.Count | Should Be 0
        }

        It "Supports ShouldProcess (-WhatIf / -Confirm)" {
            $content = Get-Content $adScript -Raw
            $content | Should Match 'SupportsShouldProcess\s*=\s*\$true'
        }

        It "Defines PKI-Admins, PKI-Auditors, and PKI-Cert-Managers parameters" {
            $content = Get-Content $adScript -Raw
            $content | Should Match 'PKI-Admins'
            $content | Should Match 'PKI-Auditors'
            $content | Should Match 'PKI-Cert-Managers'
        }
    }

    Context "Documentation Integrity" {
        $docPath = Join-Path $repoRoot "Documentation\Trust-Distribution-Guide.md"

        It "Trust-Distribution-Guide.md exists" {
            Test-Path $docPath | Should Be $true
        }

        It "Contains guidance for Debian/Ubuntu, RHEL/Rocky, macOS, and Windows" {
            $content = Get-Content $docPath -Raw
            $content | Should Match 'Debian / Ubuntu'
            $content | Should Match 'RHEL / Rocky'
            $content | Should Match 'macOS'
            $content | Should Match 'Windows'
        }
    }
}
