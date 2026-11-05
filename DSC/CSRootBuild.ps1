<#
.SYNOPSIS
    Declarative DSC build configuration for an Offline Standalone Root Certification Authority (CA).

.DESCRIPTION
    Deploys and configures an enterprise-grade Offline Standalone Root CA using PowerShell Desired State
    Configuration (DSC). Features include:
    - Dynamic CAPolicy.inf generation supporting 4096-bit RSA or ECC P-384 keys with SHA-256.
    - 20-year CA certificate validity and 1-year base CRL publication periods.
    - Strict PKI hardening: disables default certificate templates (LoadDefaultTemplates=0), suppresses
      discrete signature algorithms where appropriate, and configures CRLFlags to bypass online revocation
      checks for the offline root authority.
    - Comprehensive security audit filter activation across all critical AD CS subsystem events.
    - Standalone Non-Domain Credential Fix: Accommodates workgroup / non-domain environments by omitting
      mandatory domain credentials required by upstream MSFT_AdcsCertificationAuthority DSC resources.

.PARAMETER CACommonName
    Common Name (CN) for the Root Certification Authority. Default: 'Koality Assured Root CA'.

.PARAMETER CADistinguishedNameSuffix
    Distinguished Name suffix for the Root CA. Default: 'DC=corp,DC=example,DC=com'.

.PARAMETER CAHostname
    Machine NetBIOS / hostname for the offline server. Default: 'ROOTCA01'.

.PARAMETER KeyAlgorithm
    Cryptographic key algorithm to use ('RSA' or 'ECDSA_P384'). Default: 'RSA'.

.PARAMETER KeyLength
    Cryptographic key length in bits (4096 for RSA; 384 for ECC). Default: 4096.

.PARAMETER HashAlgorithm
    Cryptographic hash algorithm for digital signatures. Default: 'SHA256'.

.PARAMETER ValidityPeriodUnits
    Validity period of the Root CA certificate in units. Default: 20.

.PARAMETER ValidityPeriod
    Unit of validity period ('Years'). Default: 'Years'.

.PARAMETER CRLPeriodUnits
    Validity period of the base Certificate Revocation List (CRL) in units. Default: 1.

.PARAMETER CRLPeriod
    Unit of base CRL publication validity ('Years'). Default: 'Years'.

.PARAMETER PolicyOID
    Certificate Policy Object Identifier (OID). Default: '1.3.6.1.4.1.99999.1.1.1.1' (Documentation OID).

.PARAMETER CpsUrl
    Uniform Resource Identifier pointing to the Certification Practice Statement (CPS). Default: 'http://pki.corp.example.com/pki/cps.txt'.

.PARAMETER PkiPublicationUrls
    Array of HTTP publication endpoints hosting the Root CA certificate and CRL distribution points.

.EXAMPLE
    .\CSRootBuild.ps1 -CACommonName 'Enterprise Root CA' -KeyAlgorithm 'RSA' -KeyLength 4096
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CACommonName = 'Koality Assured Root CA',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CADistinguishedNameSuffix = 'DC=corp,DC=example,DC=com',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CAHostname = 'ROOTCA01',

    [Parameter()]
    [ValidateSet('RSA', 'ECDSA_P384')]
    [string]$KeyAlgorithm = 'RSA',

    [Parameter()]
    [ValidateRange(2048, 8192)]
    [int]$KeyLength = 4096,

    [Parameter()]
    [ValidateSet('SHA256', 'SHA384', 'SHA512')]
    [string]$HashAlgorithm = 'SHA256',

    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$ValidityPeriodUnits = 20,

    [Parameter()]
    [ValidateSet('Years', 'Months')]
    [string]$ValidityPeriod = 'Years',

    [Parameter()]
    [ValidateRange(1, 10)]
    [int]$CRLPeriodUnits = 1,

    [Parameter()]
    [ValidateSet('Years', 'Months', 'Weeks')]
    [string]$CRLPeriod = 'Years',

    [Parameter()]
    [ValidatePattern('^[0-9]+(\.[0-9]+)+$')]
    [string]$PolicyOID = '1.3.6.1.4.1.99999.1.1.1.1',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CpsUrl = 'http://pki.corp.example.com/pki/cps.txt',

    [Parameter()]
    [string[]]$PkiPublicationUrls = @(
        'http://pki.corp.example.com/pki',
        'http://pki2.corp.example.com/pki'
    ),

    [Parameter()]
    [string]$AdminPath = 'C:\Admin',

    [Parameter()]
    [string]$CertLogDbPath = 'C:\CertLog\DB',

    [Parameter()]
    [string]$CertLogPath = 'C:\CertLog',

    [Parameter()]
    [string]$OutputPath = 'C:\DSC\CSRootBuild'
)

# Determine Cryptographic Provider based on chosen algorithm
$CryptoProviderName = if ($KeyAlgorithm -eq 'RSA') {
    'RSA#Microsoft Software Key Storage Provider'
} else {
    'ECDSA_P384#Microsoft Software Key Storage Provider'
}

# Generate CAPolicy.inf contents dynamically
# Note: Root CA certificates do not inherit CDP/AIA from a parent; therefore Empty=True is mandatory.
$capolicyBuilder = New-Object -TypeName System.Text.StringBuilder
[void]$capolicyBuilder.AppendLine("[Version]")
[void]$capolicyBuilder.AppendLine('Signature="$Windows NT$"')
[void]$capolicyBuilder.AppendLine("[PolicyStatementExtension]")
[void]$capolicyBuilder.AppendLine("Policies=InternalPolicy")
[void]$capolicyBuilder.AppendLine("[InternalPolicy]")
[void]$capolicyBuilder.AppendLine("OID=$PolicyOID")
[void]$capolicyBuilder.AppendLine("URL=$CpsUrl")
[void]$capolicyBuilder.AppendLine("[Certsrv_Server]")
[void]$capolicyBuilder.AppendLine("RenewalKeyLength=$KeyLength")
[void]$capolicyBuilder.AppendLine("RenewalValidityPeriod=$ValidityPeriod")
[void]$capolicyBuilder.AppendLine("RenewalValidityPeriodUnits=$ValidityPeriodUnits")
[void]$capolicyBuilder.AppendLine("CRLPeriod=$CRLPeriod")
[void]$capolicyBuilder.AppendLine("CRLPeriodUnits=$CRLPeriodUnits")
[void]$capolicyBuilder.AppendLine("CRLDeltaPeriod=Days")
[void]$capolicyBuilder.AppendLine("CRLDeltaPeriodUnits=0")
[void]$capolicyBuilder.AppendLine("LoadDefaultTemplates=0")
[void]$capolicyBuilder.AppendLine("AlternateSignatureAlgorithm=0")
[void]$capolicyBuilder.AppendLine("[CRLDistributionPoint]")
[void]$capolicyBuilder.AppendLine("Empty=True")
[void]$capolicyBuilder.AppendLine("[AuthorityInformationAccess]")
[void]$capolicyBuilder.AppendLine("Empty=True")

$CA_Policy_Inf = $capolicyBuilder.ToString()
$CA_REG_ROOT   = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CACommonName"

# Build Publication URL Arrays
$CACertPublicationURLs = @()
$CRLPublicationURLs = @()

foreach ($url in $PkiPublicationUrls) {
    $cleanUrl = $url.TrimEnd('/')
    $CACertPublicationURLs += "2:$cleanUrl/$CACommonName.crt"
    $CRLPublicationURLs    += "130:$cleanUrl/$CACommonName.crl"
}
$CACertPublicationURLs += "1:file://C:\Windows\System32\CertSrv\CertEnroll\$CACommonName.crt"
$CRLPublicationURLs    += "1:file://C:\Windows\System32\CertSrv\CertEnroll\$CACommonName.crl"

Configuration CSRootCABuild {
    param(
        [string]$NodeName = 'localhost',
        [string]$AdminPath,
        [string]$CAHostname,
        [string]$CACommonName,
        [string]$CADistinguishedNameSuffix,
        [string]$CryptoProviderName,
        [string]$HashAlgorithm,
        [string]$CertLogDbPath,
        [string]$CertLogPath,
        [string]$ValidityPeriod,
        [int]$ValidityPeriodUnits,
        [string]$CRLPeriod,
        [int]$CRLPeriodUnits,
        [int]$KeyLength,
        [string]$CA_Policy_Inf,
        [string]$CA_REG_ROOT,
        [string[]]$CACertPublicationURLs,
        [string[]]$CRLPublicationURLs
    )

    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xActiveDirectoryCSDsc'

    Node $NodeName {
        # Base Operating System Directory Structure
        File AdminFolder {
            Ensure          = 'Present'
            Type            = 'Directory'
            DestinationPath = $AdminPath
        }

        File CertLogDbFolder {
            Ensure          = 'Present'
            Type            = 'Directory'
            DestinationPath = $CertLogDbPath
        }

        # System Timezone and Execution Policy Hardening
        PowerShellExecutionPolicy ExecutionPolicySet {
            ExecutionPolicyScope = 'LocalMachine'
            ExecutionPolicy      = 'RemoteSigned'
        }

        # Pre-installation CAPolicy.inf deployment to Windows Directory
        File CreateCAPolicy {
            Ensure          = 'Present'
            Type            = 'File'
            Contents        = $CA_Policy_Inf
            Force           = $true
            DestinationPath = "$env:windir\capolicy.inf"
        }

        # Active Directory Certificate Services Feature Installation
        WindowsFeatureSet InstallADCSFeatures {
            Name                 = @('ADCS-Cert-Authority', 'RSAT-ADCS', 'RSAT-ADCS-Mgmt')
            Ensure               = 'Present'
            IncludeAllSubFeature = $true
            DependsOn            = '[File]CreateCAPolicy'
        }

        # Standalone Non-Domain Credential Fix:
        # In upstream MSFT_AdcsCertificationAuthority, 'Credential' was required. For an offline,
        # non-domain standalone root CA, passing domain credentials is fundamentally impossible.
        # This DSC resource declaration omits 'Credential' and executes under the local SYSTEM/Admin context.
        AdcsCertificationAuthority CertificateAuthority {
            IsSingleInstance          = 'Yes'
            Ensure                    = 'Present'
            CADistinguishedNameSuffix = $CADistinguishedNameSuffix
            CAType                    = 'StandaloneRootCA'
            CACommonName              = $CACommonName
            CryptoProviderName        = $CryptoProviderName
            HashAlgorithmName         = $HashAlgorithm
            DatabaseDirectory         = $CertLogDbPath
            LogDirectory              = $CertLogPath
            ValidityPeriod            = $ValidityPeriod
            ValidityPeriodUnits       = $ValidityPeriodUnits
            KeyLength                 = $KeyLength
            DependsOn                 = '[WindowsFeatureSet]InstallADCSFeatures'
        }

        # Authority Settings and Extension Endpoints
        AdcsCertificationAuthoritySettings CertificateAuthoritySettings {
            IsSingleInstance      = 'Yes'
            CRLOverlapUnits       = 0
            CRLOverlapPeriod      = 'Days'
            CRLPeriodUnits        = $CRLPeriodUnits
            CRLPeriod             = $CRLPeriod
            ValidityPeriodUnits   = $ValidityPeriodUnits
            ValidityPeriod        = $ValidityPeriod
            DSConfigDN            = "CN=Configuration,$CADistinguishedNameSuffix"
            DSDomainDN            = $CADistinguishedNameSuffix
            CACertPublicationURLs = $CACertPublicationURLs
            CRLPublicationURLs    = $CRLPublicationURLs
            AuditFilter           = @(
                'StartAndStopADCS'
                'BackupAndRestoreCADatabase'
                'IssueAndManageCertificateRequests'
                'RevokeCertificatesAndPublishCRLs'
                'ChangeCASecuritySettings'
                'StoreAndRetrieveArchivedKeys'
                'ChangeCAConfiguration'
            )
            DependsOn             = '[AdcsCertificationAuthority]CertificateAuthority'
        }

        # Registry Hardening: Suppress Default Templates (Root CAs must not issue end-entity certs)
        Registry LoadDefaultTemplates {
            Key         = $CA_REG_ROOT
            ValueName   = 'LoadDefaultTemplates'
            ValueData   = 0
            ValueType   = 'Dword'
            Force       = $true
            DependsOn   = '[AdcsCertificationAuthority]CertificateAuthority'
        }

        # Registry Hardening: RSASSA-PSS Algorithm Control (0 = standard PKCS#1 v1.5)
        Registry DiscreteSignatureAlgorithm {
            Key         = "$CA_REG_ROOT\csp"
            ValueName   = 'DiscreteSignatureAlgorithm'
            ValueData   = 0
            ValueType   = 'Dword'
            Force       = $true
            DependsOn   = '[AdcsCertificationAuthority]CertificateAuthority'
        }

        # Registry Hardening: CRLFlags 10 (CRLF_DELETE_EXPIRED_CRLS | CRLF_CRLNUMBER_CRITICAL)
        # Bypasses online revocation checks for the offline root authority during health checks.
        Registry CRLFlags {
            Key         = $CA_REG_ROOT
            ValueName   = 'CRLFlags'
            ValueData   = 10
            ValueType   = 'Dword'
            Force       = $true
            DependsOn   = '[AdcsCertificationAuthority]CertificateAuthority'
        }
    }
}

# Compile MOF artifact if invoked directly
$configData = @{
    AllNodes = @(
        @{
            NodeName                    = 'localhost'
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser        = $true
        }
    )
}

if (-not (Test-Path -Path $OutputPath)) {
    $null = New-Item -ItemType Directory -Path $OutputPath -Force
}

CSRootCABuild -OutputPath $OutputPath `
    -AdminPath $AdminPath `
    -CAHostname $CAHostname `
    -CACommonName $CACommonName `
    -CADistinguishedNameSuffix $CADistinguishedNameSuffix `
    -CryptoProviderName $CryptoProviderName `
    -HashAlgorithm $HashAlgorithm `
    -CertLogDbPath $CertLogDbPath `
    -CertLogPath $CertLogPath `
    -ValidityPeriod $ValidityPeriod `
    -ValidityPeriodUnits $ValidityPeriodUnits `
    -CRLPeriod $CRLPeriod `
    -CRLPeriodUnits $CRLPeriodUnits `
    -KeyLength $KeyLength `
    -CA_Policy_Inf $CA_Policy_Inf `
    -CA_REG_ROOT $CA_REG_ROOT `
    -CACertPublicationURLs $CACertPublicationURLs `
    -CRLPublicationURLs $CRLPublicationURLs `
    -ConfigurationData $configData
