# Pester Tests for Declarative DSC Configurations
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $here
$dscDir = Join-Path $repoRoot "DSC"

Describe "DSC Configurations Test Suite" {

    $dscScripts = @(
        "CSRootBuild.ps1",
        "CSHighIssuingBuild.ps1",
        "CSMedIssuingBuild.ps1",
        "CSWebDistBuild.ps1",
        "CSNDESBuild.ps1"
    )

    foreach ($scriptName in $dscScripts) {
        Context "$scriptName" {
            $scriptPath = Join-Path $dscDir $scriptName

            It "File exists at $scriptName" {
                Test-Path $scriptPath | Should Be $true
            }

            It "Parses cleanly with zero PowerShell syntax errors" {
                $errors = $null
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors)
                # Ignore missing DSC resource module on test machine if present
                $actualErrors = $errors | Where-Object { $_.ErrorId -ne 'ModuleNotFoundDuringParse' }
                $actualErrors.Count | Should Be 0
            }

            It "Defines an advanced Param block" {
                $errors = $null
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors)
                $ast.ParamBlock | Should Not Be $null
                $ast.ParamBlock.Parameters.Count | Should BeGreaterThan 0
            }
        }
    }

    Context "CSRootBuild.ps1 Hardening Assertions" {
        $rootScript = Join-Path $dscDir "CSRootBuild.ps1"
        $content = Get-Content $rootScript -Raw

        It "Enforces 20-year default validity" {
            $content | Should Match 'ValidityPeriodUnits\s*=\s*20'
        }

        It "Enforces 1-year default CRL period" {
            $content | Should Match 'CRLPeriodUnits\s*=\s*1'
        }

        It "Contains Empty=True for CDP and AIA in CAPolicy.inf" {
            $content | Should Match '\[CRLDistributionPoint\]'
            $content | Should Match 'Empty=True'
            $content | Should Match '\[AuthorityInformationAccess\]'
        }

        It "Suppresses default templates (LoadDefaultTemplates = 0)" {
            $content | Should Match 'LoadDefaultTemplates'
            $content | Should Match 'ValueData\s*=\s*0'
        }

        It "Sets CRLFlags = 10 for offline root health checks" {
            $content | Should Match 'CRLFlags'
            $content | Should Match 'ValueData\s*=\s*10'
        }
    }

    Context "CSHighIssuingBuild.ps1 Hardening Assertions" {
        $highScript = Join-Path $dscDir "CSHighIssuingBuild.ps1"
        $content = Get-Content $highScript -Raw

        It "Contains EnterpriseSubordinateCA type" {
            $content | Should Match "CAType\s*=\s*'EnterpriseSubordinateCA'"
        }

        It "Outputs subordinate certificate request file" {
            $content | Should Match 'OutputCertRequestFile'
        }

        It "Configures EventFilter = 511 for full SMTP auditing" {
            $content | Should Match 'EventFilter'
            $content | Should Match 'ValueData\s*=\s*511'
        }
    }

    Context "CSWebDistBuild.ps1 IIS Hardening Assertions" {
        $webScript = Join-Path $dscDir "CSWebDistBuild.ps1"
        $content = Get-Content $webScript -Raw

        It "Enables allowDoubleEscaping for Delta CRLs with plus characters" {
            $content | Should Match 'allowDoubleEscaping'
        }

        It "Registers application/pkix-crl and application/x-x509-ca-cert MIME types" {
            $content | Should Match 'application/pkix-crl'
            $content | Should Match 'application/x-x509-ca-cert'
        }
    }
}
