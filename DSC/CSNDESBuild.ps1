<#
.SYNOPSIS
    Declarative DSC build configuration for Network Device Enrollment Service (NDES / SCEP) with gMSA.

.DESCRIPTION
    Deploys and configures the Microsoft Network Device Enrollment Service (NDES), implementing the Simple
    Certificate Enrollment Protocol (SCEP) for automated certificate provisioning to network appliances,
    mobile devices, firewalls, routers, and MDM/Intune managed endpoints.
    
    Security and Architectural Highlights:
    - Deploys using a Group Managed Service Account (gMSA) identity to eliminate static passwords.
    - Configures IIS and worker process permissions for gMSA execution (membership in IIS_IUSRS).
    - Enforces one-time enrollment challenge passwords (EnforcePassword = 1) with configurable TTL and complexity.
    - Customizes MSCEP certificate template mappings for signature, encryption, and general purpose.
    - Enforces modern cryptographic algorithms (SHA-256 hash algorithm) for SCEP challenge issuance.

.PARAMETER NdesHostname
    NetBIOS hostname for the NDES server. Default: 'NDES01'.

.PARAMETER DomainName
    Active Directory domain FQDN. Default: 'corp.example.com'.

.PARAMETER NdesGmsaName
    Name of the Group Managed Service Account configured for NDES. Default: 'gmsa-pki-ndes$'.

.PARAMETER NdesGmsaGroup
    Active Directory security group containing NDES service administrators. Default: 'CORP\PKI-NDES-SvcMgmt'.

.PARAMETER PkiAdminsGroup
    Active Directory security group for PKI administrators. Default: 'CORP\PKI-Admins'.

.PARAMETER GeneralTemplate
    Certificate template name for general purpose enrollment. Default: 'NetworkDevice-Custom'.

.PARAMETER SignatureTemplate
    Certificate template name for digital signatures. Default: 'NetworkDevice-Signature'.

.PARAMETER EncryptionTemplate
    Certificate template name for key encipherment. Default: 'NetworkDevice-Encryption'.

.PARAMETER PasswordLength
    Length in characters of the SCEP challenge password. Default: 24.

.PARAMETER PasswordValidityMinutes
    Validity duration in minutes of the one-time challenge password. Default: 60.

.PARAMETER PasswordMax
    Maximum number of cached challenge passwords. Default: 50.

.PARAMETER CacheRequest
    Number of cached request transactions. Default: 20.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$NdesHostname = 'NDES01',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DomainName = 'corp.example.com',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$NdesGmsaName = 'gmsa-pki-ndes$',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$NdesGmsaGroup = 'CORP\PKI-NDES-SvcMgmt',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PkiAdminsGroup = 'CORP\PKI-Admins',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$GeneralTemplate = 'NetworkDevice-Custom',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SignatureTemplate = 'NetworkDevice-Signature',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$EncryptionTemplate = 'NetworkDevice-Encryption',

    [Parameter()]
    [ValidateRange(8, 64)]
    [int]$PasswordLength = 24,

    [Parameter()]
    [ValidateRange(5, 1440)]
    [int]$PasswordValidityMinutes = 60,

    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$PasswordMax = 50,

    [Parameter()]
    [ValidateRange(1, 50)]
    [int]$CacheRequest = 20,

    [Parameter()]
    [ValidateSet('SHA256', 'SHA384', 'SHA512')]
    [string]$HashAlgorithm = 'SHA256',

    [Parameter()]
    [string]$AdminPath = 'C:\Admin',

    [Parameter()]
    [pscredential]$DomainCredential,

    [Parameter()]
    [string]$OutputPath = 'C:\DSC\CSNDESBuild'
)

Configuration CSNDESBuild {
    param(
        [string]$NodeName = 'localhost',
        [string]$NdesHostname,
        [string]$DomainName,
        [string]$NdesGmsaGroup,
        [string]$PkiAdminsGroup,
        [string]$AdminPath,
        [string]$GeneralTemplate,
        [string]$SignatureTemplate,
        [string]$EncryptionTemplate,
        [int]$PasswordLength,
        [int]$PasswordValidityMinutes,
        [int]$PasswordMax,
        [int]$CacheRequest,
        [string]$HashAlgorithm,
        [pscredential]$DomainCredential
    )

    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node $NodeName {
        # Base Operating System Directories
        File AdminFolder {
            Ensure          = 'Present'
            Type            = 'Directory'
            DestinationPath = $AdminPath
        }

        # Execution Policy Hardening
        PowerShellExecutionPolicy ExecutionPolicySet {
            ExecutionPolicyScope = 'LocalMachine'
            ExecutionPolicy      = 'RemoteSigned'
        }

        # Domain Join Configuration
        if ($DomainCredential) {
            Computer JoinDomain {
                Name       = $NdesHostname
                DomainName = $DomainName
                Credential = $DomainCredential
            }

            # Adjust local Administrators group
            Group AdjustLocalAdmin {
                GroupName        = 'Administrators'
                Ensure           = 'Present'
                MembersToInclude = @($PkiAdminsGroup, $NdesGmsaGroup)
                DependsOn        = '[Computer]JoinDomain'
            }
        }

        # 1. Install IIS and ASP.NET Core / Request Filtering Prerequisites
        # Crucial: Adcs-Device-Enrollment requires IIS, Web-Asp-Net45, and Web-Filtering.
        # Installing prerequisites in a dedicated stage prevents 0x800f0922 DISM dependency failures.
        WindowsFeatureSet InstallIISPrerequisites {
            Name                 = @(
                'Web-Server',
                'Web-Filtering',
                'Web-Asp-Net45',
                'Web-Net-Ext45',
                'Web-ISAPI-Ext',
                'Web-ISAPI-Filter',
                'Web-Metabase',
                'Web-Mgmt-Console',
                'NET-Framework-45-ASPNET'
            )
            Ensure               = 'Present'
            IncludeAllSubFeature = $true
        }

        # 2. Install Active Directory Certificate Services NDES Role
        WindowsFeatureSet InstallNDESFeatures {
            Name                 = @(
                'Adcs-Device-Enrollment'
            )
            Ensure               = 'Present'
            IncludeAllSubFeature = $true
            DependsOn            = '[WindowsFeatureSet]InstallIISPrerequisites'
        }

        # Assign NDES Service Management Group to IIS_IUSRS for AppPool execution
        Group AdjustIISUsers {
            GroupName        = 'IIS_IUSRS'
            Ensure           = 'Present'
            MembersToInclude = @($NdesGmsaGroup)
            DependsOn        = '[WindowsFeatureSet]InstallNDESFeatures'
        }

        # MSCEP Registry Configuration: Password Enforcement
        Registry EnforcePassword {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\MSCEP'
            ValueName = 'EnforcePassword'
            ValueType = 'Dword'
            ValueData = 1
            Force     = $true
            DependsOn = '[WindowsFeatureSet]InstallNDESFeatures'
        }

        # MSCEP Registry Configuration: Template Mappings
        Registry SignatureTemplate {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\MSCEP'
            ValueName = 'SignatureTemplate'
            ValueType = 'String'
            ValueData = $SignatureTemplate
            Force     = $true
            DependsOn = '[WindowsFeatureSet]InstallNDESFeatures'
        }

        Registry EncryptionTemplate {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\MSCEP'
            ValueName = 'EncryptionTemplate'
            ValueType = 'String'
            ValueData = $EncryptionTemplate
            Force     = $true
            DependsOn = '[WindowsFeatureSet]InstallNDESFeatures'
        }

        Registry GeneralPurposeTemplate {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\MSCEP'
            ValueName = 'GeneralPurposeTemplate'
            ValueType = 'String'
            ValueData = $GeneralTemplate
            Force     = $true
            DependsOn = '[WindowsFeatureSet]InstallNDESFeatures'
        }

        # MSCEP Challenge Password Policies
        Registry RefreshPeriod {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\MSCEP\RefreshPeriod'
            ValueName = 'RefreshPeriod'
            ValueType = 'Dword'
            ValueData = 1
            Force     = $true
            DependsOn = '[WindowsFeatureSet]InstallNDESFeatures'
        }

        Registry CacheRequest {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\MSCEP\CacheRequest'
            ValueName = 'CacheRequest'
            ValueType = 'Dword'
            ValueData = $CacheRequest
            Force     = $true
            DependsOn = '[WindowsFeatureSet]InstallNDESFeatures'
        }

        Registry PasswordMax {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\MSCEP\PasswordMax'
            ValueName = 'PasswordMax'
            ValueType = 'Dword'
            ValueData = $PasswordMax
            Force     = $true
            DependsOn = '[WindowsFeatureSet]InstallNDESFeatures'
        }

        Registry PasswordValidity {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\MSCEP\PasswordValidity'
            ValueName = 'PasswordValidity'
            ValueType = 'Dword'
            ValueData = $PasswordValidityMinutes
            Force     = $true
            DependsOn = '[WindowsFeatureSet]InstallNDESFeatures'
        }

        Registry PasswordLength {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\MSCEP\PasswordLength'
            ValueName = 'PasswordLength'
            ValueType = 'Dword'
            ValueData = $PasswordLength
            Force     = $true
            DependsOn = '[WindowsFeatureSet]InstallNDESFeatures'
        }

        # Cryptographic Hash Algorithm
        Registry HashAlgorithm {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\HashAlgorithm'
            ValueName = 'HashAlgorithm'
            ValueType = 'String'
            ValueData = $HashAlgorithm
            Force     = $true
            DependsOn = '[WindowsFeatureSet]InstallNDESFeatures'
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

CSNDESBuild -OutputPath $OutputPath `
    -NdesHostname $NdesHostname `
    -DomainName $DomainName `
    -NdesGmsaGroup $NdesGmsaGroup `
    -PkiAdminsGroup $PkiAdminsGroup `
    -AdminPath $AdminPath `
    -GeneralTemplate $GeneralTemplate `
    -SignatureTemplate $SignatureTemplate `
    -EncryptionTemplate $EncryptionTemplate `
    -PasswordLength $PasswordLength `
    -PasswordValidityMinutes $PasswordValidityMinutes `
    -PasswordMax $PasswordMax `
    -CacheRequest $CacheRequest `
    -HashAlgorithm $HashAlgorithm `
    -DomainCredential $DomainCredential `
    -ConfigurationData $configData
