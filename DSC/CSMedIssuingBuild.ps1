<#
.SYNOPSIS
    Declarative DSC build configuration for a Tier-1 Enterprise Subordinate Issuing Certification Authority (CA).

.DESCRIPTION
    Deploys and configures an Active Directory-integrated Enterprise Subordinate CA dedicated to Tier-1
    workloads and infrastructure:
    - Web Server TLS/SSL Certificates (Internal HTTPS)
    - User Authentication and S/MIME Email Encryption
    - Virtual Private Network (VPN) and Remote Access Gateways
    - Client Authentication and Workstation Device Certificates
    
    Hardening features:
    - Domain join with Tier-1 administrative role delegation.
    - Automated CAPolicy.inf generation enforcing 2048/4096-bit RSA or ECC keys and SHA-256.
    - 10-year CA validity window with 28-day CRL publication cycle.
    - Generates PKCS#10 subordinate certificate request (.req) for offline signing by the Root CA.
    - Configures high-availability HTTP and SMB publication endpoints.
    - Enables full AD CS security audit filtering and SMTP Exit Module email alerting.

.PARAMETER CACommonName
    Common Name for the Issuing CA. Default: 'Koality Assured Medium Assurance Issuing CA'.

.PARAMETER CAHostname
    Server NetBIOS hostname. Default: 'MICA01'.

.PARAMETER DomainName
    Fully Qualified Domain Name (FQDN) for Active Directory. Default: 'corp.example.com'.

.PARAMETER DomainNetBios
    NetBIOS domain name. Default: 'CORP'.

.PARAMETER AdminRole
    Tier-1 AD security group granted local administrative authority. Default: 'CORP\Admin-Tier1-PKI'.

.PARAMETER KeyLength
    Cryptographic key length in bits. Default: 2048.

.PARAMETER ValidityPeriodUnits
    Validity period of the Subordinate CA certificate in units. Default: 10.

.PARAMETER ValidityPeriod
    Unit of validity period ('Years'). Default: 'Years'.

.PARAMETER CRLPeriodUnits
    CRL publication period in units. Default: 28.

.PARAMETER CRLPeriod
    Unit of CRL publication period ('Days'). Default: 'Days'.

.PARAMETER CRLDeltaPeriodUnits
    Delta CRL publication period in units. Default: 1.

.PARAMETER CRLDeltaPeriod
    Unit of Delta CRL publication period ('Days'). Default: 'Days'.

.PARAMETER PolicyOID
    Certificate Policy OID. Default: '1.3.6.1.4.1.99999.1.3.1.1' (Tier-1 Policy OID).

.PARAMETER CpsUrl
    URI to the Certification Practice Statement. Default: 'http://pki.corp.example.com/pki/cps.txt'.

.PARAMETER PkiPublicationUrls
    Primary and secondary HTTP publication endpoints.

.PARAMETER PkiWebPubShare
    SMB UNC share path for automated certificate and CRL publishing. Default: 'WEBDIST01\pki'.

.PARAMETER SmtpServer
    SMTP mail relay for CA alerts. Default: 'smtp.corp.example.com'.

.PARAMETER AlertEmailTo
    Recipient email for operational alerts. Default: 'pki-ops@example.com'.

.PARAMETER AlertEmailFrom
    Sender email for CA notifications. Default: 'pki-mica@example.com'.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CACommonName = 'Koality Assured Medium Assurance Issuing CA',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CAHostname = 'MICA01',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DomainName = 'corp.example.com',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DomainNetBios = 'CORP',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AdminRole = 'CORP\Admin-Tier1-PKI',

    [Parameter()]
    [ValidateRange(2048, 8192)]
    [int]$KeyLength = 2048,

    [Parameter()]
    [ValidateSet('SHA256', 'SHA384', 'SHA512')]
    [string]$HashAlgorithm = 'SHA256',

    [Parameter()]
    [ValidateRange(1, 20)]
    [int]$ValidityPeriodUnits = 10,

    [Parameter()]
    [ValidateSet('Years', 'Months')]
    [string]$ValidityPeriod = 'Years',

    [Parameter()]
    [ValidateRange(1, 50)]
    [int]$ParentCaValidityYears = 20,

    [Parameter()]
    [ValidateRange(1, 90)]
    [int]$CRLPeriodUnits = 28,

    [Parameter()]
    [ValidateSet('Days', 'Weeks')]
    [string]$CRLPeriod = 'Days',

    [Parameter()]
    [ValidateRange(0, 14)]
    [int]$CRLDeltaPeriodUnits = 1,

    [Parameter()]
    [ValidateSet('Days', 'Hours')]
    [string]$CRLDeltaPeriod = 'Days',

    [Parameter()]
    [ValidatePattern('^[0-9]+(\.[0-9]+)+$')]
    [string]$PolicyOID = '1.3.6.1.4.1.99999.1.3.1.1',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CpsUrl = 'http://pki.corp.example.com/pki/cps.txt',

    [Parameter()]
    [string[]]$PkiPublicationUrls = @(
        'http://pki.corp.example.com/pki',
        'http://pki2.corp.example.com/pki'
    ),

    [Parameter()]
    [string]$PkiWebPubShare = 'WEBDIST01\pki',

    [Parameter()]
    [string]$AdminPath = 'C:\Admin',

    [Parameter()]
    [string]$CertLogDbPath = 'C:\CertLog\DB',

    [Parameter()]
    [string]$CertLogPath = 'C:\CertLog',

    [Parameter()]
    [string]$SmtpServer = 'smtp.corp.example.com',

    [Parameter()]
    [string]$AlertEmailTo = 'pki-ops@example.com',

    [Parameter()]
    [string]$AlertEmailFrom = 'pki-mica@example.com',

    [Parameter()]
    [pscredential]$DomainCredential,

    [Parameter()]
    [string]$OutputPath = 'C:\DSC\CSMedIssuingBuild'
)

# Convert domain name to Distinguished Name (e.g., corp.example.com -> DC=corp,DC=example,DC=com)
$domainParts = $DomainName.Split('.')
$DomainDN = ($domainParts | ForEach-Object { "DC=$_" }) -join ','

# Hierarchy Validity Pre-flight Check:
# Subordinate CA validity must be strictly less than Parent Root CA validity (NIST SP 800-57 Part 1 Rev 5).
$requestedValidityYears = if ($ValidityPeriod -eq 'Years') { $ValidityPeriodUnits } else { [math]::Ceiling($ValidityPeriodUnits / 12) }
if ($requestedValidityYears -ge $ParentCaValidityYears) {
    throw "Conflicting CA Validity Periods: Subordinate Issuing CA validity ($requestedValidityYears years) must be strictly less than Parent Root CA validity ($ParentCaValidityYears years). Best practice recommends Root CA validity >= 2x Subordinate CA validity."
}

# CAPolicy.inf generation for Subordinate CA
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
[void]$capolicyBuilder.AppendLine("CRLDeltaPeriod=$CRLDeltaPeriod")
[void]$capolicyBuilder.AppendLine("CRLDeltaPeriodUnits=$CRLDeltaPeriodUnits")
[void]$capolicyBuilder.AppendLine("LoadDefaultTemplates=0")
[void]$capolicyBuilder.AppendLine("AlternateSignatureAlgorithm=0")
[void]$capolicyBuilder.AppendLine("[CRLDistributionPoint]")
[void]$capolicyBuilder.AppendLine("Empty=True")
[void]$capolicyBuilder.AppendLine("[AuthorityInformationAccess]")
[void]$capolicyBuilder.AppendLine("Empty=True")

$CA_Policy_Inf = $capolicyBuilder.ToString()
$CA_REG_ROOT   = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CACommonName"

# Build CDP / AIA Publication URL lists
$CACertPublicationURLs = @()
$CRLPublicationURLs = @()

foreach ($url in $PkiPublicationUrls) {
    $cleanUrl = $url.TrimEnd('/')
    $CACertPublicationURLs += "2:$cleanUrl/$CACommonName.crt"
    $CRLPublicationURLs    += "130:$cleanUrl/$CACommonName.crl"
}
$CACertPublicationURLs += "1:file://\\$PkiWebPubShare\$CACommonName.crt"
$CACertPublicationURLs += "1:file://C:\Windows\System32\CertSrv\CertEnroll\$CACommonName.crt"

$CRLPublicationURLs    += "130:file://\\$PkiWebPubShare\$CACommonName.crl"
$CRLPublicationURLs    += "1:file://C:\Windows\System32\CertSrv\CertEnroll\$CACommonName.crl"

Configuration CSMediumIssuingBuild {
    param(
        [string]$NodeName = 'localhost',
        [string]$AdminPath,
        [string]$CAHostname,
        [string]$CACommonName,
        [string]$DomainName,
        [string]$DomainDN,
        [string]$AdminRole,
        [string]$HashAlgorithm,
        [string]$CertLogDbPath,
        [string]$CertLogPath,
        [string]$CA_Policy_Inf,
        [string]$CA_REG_ROOT,
        [string[]]$CACertPublicationURLs,
        [string[]]$CRLPublicationURLs,
        [string]$SmtpServer,
        [string]$AlertEmailTo,
        [string]$AlertEmailFrom,
        [pscredential]$DomainCredential
    )

    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xActiveDirectoryCSDsc'

    Node $NodeName {
        # Base Administration Folders
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

        # Execution Policy Hardening
        PowerShellExecutionPolicy ExecutionPolicySet {
            ExecutionPolicyScope = 'LocalMachine'
            ExecutionPolicy      = 'RemoteSigned'
        }

        # Domain Join Configuration
        if ($DomainCredential) {
            Computer JoinDomain {
                Name       = $CAHostname
                DomainName = $DomainName
                Credential = $DomainCredential
            }

            # Restrict local Administrator access to Tier-1 PKI Admins and Builtin Admin
            Group AdjustLocalAdmin {
                GroupName  = 'Administrators'
                Ensure     = 'Present'
                Members    = @($AdminRole, 'Built-In\Administrator')
                DependsOn  = '[Computer]JoinDomain'
            }
        }

        # Deploy CAPolicy.inf prior to feature initialization
        File CreateCAPolicy {
            Ensure          = 'Present'
            Type            = 'File'
            Contents        = $CA_Policy_Inf
            Force           = $true
            DestinationPath = "$env:windir\capolicy.inf"
        }

        # Install AD CS Role Services and Management Tools
        WindowsFeatureSet InstallADCSFeatures {
            Name                 = @('ADCS-Cert-Authority', 'RSAT-ADCS', 'RSAT-ADCS-Mgmt')
            Ensure               = 'Present'
            IncludeAllSubFeature = $true
            DependsOn            = '[File]CreateCAPolicy'
        }

        # Configure Enterprise Subordinate Certification Authority
        # Generates PKCS#10 Certificate Request file for signature by Root CA
        AdcsCertificationAuthority CertificateAuthority {
            IsSingleInstance          = 'Yes'
            CADistinguishedNameSuffix = $DomainDN
            Ensure                    = 'Present'
            CAType                    = 'EnterpriseSubordinateCA'
            CACommonName              = $CACommonName
            CryptoProviderName        = 'RSA#Microsoft Software Key Storage Provider'
            HashAlgorithmName         = $HashAlgorithm
            OutputCertRequestFile     = "$AdminPath\$CACommonName.req"
            DatabaseDirectory         = $CertLogDbPath
            LogDirectory              = $CertLogPath
            DependsOn                 = '[WindowsFeatureSet]InstallADCSFeatures'
        }

        # Authority Settings: CDP/AIA Publishing and Audit Filters
        AdcsCertificationAuthoritySettings CertificateAuthoritySettings {
            IsSingleInstance      = 'Yes'
            CRLOverlapUnits       = 0
            CRLOverlapPeriod      = 'Hours'
            CRLPeriodUnits        = 28
            CRLPeriod             = 'Days'
            ValidityPeriodUnits   = 10
            ValidityPeriod        = 'Years'
            DSConfigDN            = "CN=Configuration,$DomainDN"
            DSDomainDN            = $DomainDN
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

        # Suppress Default Templates (Enterprise templates assigned after approval)
        Registry LoadDefaultTemplates {
            Key         = $CA_REG_ROOT
            ValueName   = 'LoadDefaultTemplates'
            ValueData   = 0
            ValueType   = 'Dword'
            Force       = $true
            DependsOn   = '[AdcsCertificationAuthority]CertificateAuthority'
        }

        Registry DiscreteSignatureAlgorithm {
            Key         = "$CA_REG_ROOT\csp"
            ValueName   = 'DiscreteSignatureAlgorithm'
            ValueData   = 0
            ValueType   = 'Dword'
            Force       = $true
            DependsOn   = '[AdcsCertificationAuthority]CertificateAuthority'
        }

        Registry CRLFlags {
            Key         = $CA_REG_ROOT
            ValueName   = 'CRLFlags'
            ValueData   = 10
            ValueType   = 'Dword'
            Force       = $true
            DependsOn   = '[AdcsCertificationAuthority]CertificateAuthority'
        }

        # SMTP Exit Module Configuration for Operational Alerting
        Registry SMTPServer {
            Key         = "$CA_REG_ROOT\ExitModules\CertificateAuthority_MicrosoftDefault.Exit\SMTP"
            ValueName   = 'SMTPServer'
            ValueData   = $SmtpServer
            ValueType   = 'String'
            Force       = $true
            DependsOn   = '[AdcsCertificationAuthority]CertificateAuthority'
        }

        Registry EventFilter {
            Key         = "$CA_REG_ROOT\ExitModules\CertificateAuthority_MicrosoftDefault.Exit\SMTP"
            ValueName   = 'EventFilter'
            ValueData   = 511
            ValueType   = 'Dword'
            Force       = $true
            DependsOn   = '[AdcsCertificationAuthority]CertificateAuthority'
        }

        Registry CRLIssuedTo {
            Key         = "$CA_REG_ROOT\ExitModules\CertificateAuthority_MicrosoftDefault.Exit\SMTP\CRLissued"
            ValueName   = 'To'
            ValueData   = $AlertEmailTo
            ValueType   = 'String'
            Force       = $true
            DependsOn   = '[AdcsCertificationAuthority]CertificateAuthority'
        }

        Registry CRLIssuedFrom {
            Key         = "$CA_REG_ROOT\ExitModules\CertificateAuthority_MicrosoftDefault.Exit\SMTP\CRLissued"
            ValueName   = 'From'
            ValueData   = $AlertEmailFrom
            ValueType   = 'String'
            Force       = $true
            DependsOn   = '[AdcsCertificationAuthority]CertificateAuthority'
        }

        Registry CAShutdownTo {
            Key         = "$CA_REG_ROOT\ExitModules\CertificateAuthority_MicrosoftDefault.Exit\SMTP\Shutdown"
            ValueName   = 'To'
            ValueData   = $AlertEmailTo
            ValueType   = 'String'
            Force       = $true
            DependsOn   = '[AdcsCertificationAuthority]CertificateAuthority'
        }

        Registry CAShutdownFrom {
            Key         = "$CA_REG_ROOT\ExitModules\CertificateAuthority_MicrosoftDefault.Exit\SMTP\Shutdown"
            ValueName   = 'From'
            ValueData   = $AlertEmailFrom
            ValueType   = 'String'
            Force       = $true
            DependsOn   = '[AdcsCertificationAuthority]CertificateAuthority'
        }

        Registry CAStartupTo {
            Key         = "$CA_REG_ROOT\ExitModules\CertificateAuthority_MicrosoftDefault.Exit\SMTP\Startup"
            ValueName   = 'To'
            ValueData   = $AlertEmailTo
            ValueType   = 'String'
            Force       = $true
            DependsOn   = '[AdcsCertificationAuthority]CertificateAuthority'
        }

        Registry CAStartupFrom {
            Key         = "$CA_REG_ROOT\ExitModules\CertificateAuthority_MicrosoftDefault.Exit\SMTP\Startup"
            ValueName   = 'From'
            ValueData   = $AlertEmailFrom
            ValueType   = 'String'
            Force       = $true
            DependsOn   = '[AdcsCertificationAuthority]CertificateAuthority'
        }

        Registry CertDeniedTo {
            Key         = "$CA_REG_ROOT\ExitModules\CertificateAuthority_MicrosoftDefault.Exit\SMTP\templates\default\Denied"
            ValueName   = 'To'
            ValueData   = $AlertEmailTo
            ValueType   = 'String'
            Force       = $true
            DependsOn   = '[AdcsCertificationAuthority]CertificateAuthority'
        }

        Registry CertDeniedFrom {
            Key         = "$CA_REG_ROOT\ExitModules\CertificateAuthority_MicrosoftDefault.Exit\SMTP\templates\default\Denied"
            ValueName   = 'From'
            ValueData   = $AlertEmailFrom
            ValueType   = 'String'
            Force       = $true
            DependsOn   = '[AdcsCertificationAuthority]CertificateAuthority'
        }

        Registry CertRevokedTo {
            Key         = "$CA_REG_ROOT\ExitModules\CertificateAuthority_MicrosoftDefault.Exit\SMTP\templates\default\Revoked"
            ValueName   = 'To'
            ValueData   = $AlertEmailTo
            ValueType   = 'String'
            Force       = $true
            DependsOn   = '[AdcsCertificationAuthority]CertificateAuthority'
        }

        Registry CertRevokedFrom {
            Key         = "$CA_REG_ROOT\ExitModules\CertificateAuthority_MicrosoftDefault.Exit\SMTP\templates\default\Revoked"
            ValueName   = 'From'
            ValueData   = $AlertEmailFrom
            ValueType   = 'String'
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

CSMediumIssuingBuild -OutputPath $OutputPath `
    -AdminPath $AdminPath `
    -CAHostname $CAHostname `
    -CACommonName $CACommonName `
    -DomainName $DomainName `
    -DomainDN $DomainDN `
    -AdminRole $AdminRole `
    -HashAlgorithm $HashAlgorithm `
    -CertLogDbPath $CertLogDbPath `
    -CertLogPath $CertLogPath `
    -CA_Policy_Inf $CA_Policy_Inf `
    -CA_REG_ROOT $CA_REG_ROOT `
    -CACertPublicationURLs $CACertPublicationURLs `
    -CRLPublicationURLs $CRLPublicationURLs `
    -SmtpServer $SmtpServer `
    -AlertEmailTo $AlertEmailTo `
    -AlertEmailFrom $AlertEmailFrom `
    -DomainCredential $DomainCredential `
    -ConfigurationData $configData
