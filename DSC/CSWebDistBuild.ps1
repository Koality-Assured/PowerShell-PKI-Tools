<#
.SYNOPSIS
    Declarative DSC build configuration for an HTTP/IIS CRL Distribution Point (CDP) and Authority Information Access (AIA) server.

.DESCRIPTION
    Deploys and configures a high-availability Web Distribution server hosting Certificate Revocation Lists (CRLs)
    and Certification Authority certificates (.crt) for enterprise PKI validation.
    
    Features:
    - Installs IIS Web Server roles and administration tools.
    - Creates dedicated PKI distribution directory structure and SMB network share for automated publishing.
    - Configures IIS site bindings for HTTP port 80 (CDP/AIA standard per RFC 5280).
    - Configures IIS requestFiltering with allowDoubleEscaping=true to properly serve Delta CRLs containing '+' characters.
    - Registers standard MIME types for .crl (application/pkix-crl) and .crt (application/x-x509-ca-cert).
    - Applies least-privilege security controls on SMB distribution shares.

.PARAMETER DistHostname
    NetBIOS hostname for the distribution server. Default: 'WEBDIST01'.

.PARAMETER DomainName
    Active Directory domain FQDN. Default: 'corp.example.com'.

.PARAMETER DomainNetBios
    Active Directory NetBIOS domain name. Default: 'CORP'.

.PARAMETER PkiDistPath
    Local filesystem path hosting published CRLs and CRT files. Default: 'C:\PKI\Distribution'.

.PARAMETER AdminPath
    Administrative tools directory. Default: 'C:\Admin'.

.PARAMETER PublishersGroup
    AD security group granted write authority to push CRLs/CRTs. Default: 'CORP\Cert Publishers'.

.PARAMETER AdminGroup
    AD security group granted full administrative control over the share. Default: 'CORP\Admin-Tier1-PKI'.

.PARAMETER SiteName
    IIS Website name for PKI distribution. Default: 'PKI-Web-Distribution'.

.PARAMETER SitePort
    TCP port for the distribution website. Default: 80.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DistHostname = 'WEBDIST01',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DomainName = 'corp.example.com',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DomainNetBios = 'CORP',

    [Parameter()]
    [string]$PkiDistPath = 'C:\PKI\Distribution',

    [Parameter()]
    [string]$AdminPath = 'C:\Admin',

    [Parameter()]
    [string]$PublishersGroup = 'CORP\Cert Publishers',

    [Parameter()]
    [string]$AdminGroup = 'CORP\Admin-Tier1-PKI',

    [Parameter()]
    [string]$SiteName = 'PKI-Web-Distribution',

    [Parameter()]
    [int]$SitePort = 80,

    [Parameter()]
    [pscredential]$DomainCredential,

    [Parameter()]
    [string]$OutputPath = 'C:\DSC\CSWebDistBuild'
)

$PkiRootPath = Split-Path -Path $PkiDistPath -Parent

Configuration CSWebDistBuild {
    param(
        [string]$NodeName = 'localhost',
        [string]$DistHostname,
        [string]$DomainName,
        [string]$AdminPath,
        [string]$PkiRootPath,
        [string]$PkiDistPath,
        [string]$PublishersGroup,
        [string]$AdminGroup,
        [string]$SiteName,
        [int]$SitePort,
        [pscredential]$DomainCredential
    )

    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xWebAdministration'

    Node $NodeName {
        # Base Operating System Directories
        File AdminFolder {
            Ensure          = 'Present'
            Type            = 'Directory'
            DestinationPath = $AdminPath
        }

        File PKIRootFolder {
            Ensure          = 'Present'
            Type            = 'Directory'
            DestinationPath = $PkiRootPath
        }

        File PKIDistFolder {
            Ensure          = 'Present'
            Type            = 'Directory'
            DestinationPath = $PkiDistPath
            DependsOn       = '[File]PKIRootFolder'
        }

        # Execution Policy Hardening
        PowerShellExecutionPolicy ExecutionPolicySet {
            ExecutionPolicyScope = 'LocalMachine'
            ExecutionPolicy      = 'RemoteSigned'
        }

        # Domain Join Configuration
        if ($DomainCredential) {
            Computer JoinDomain {
                Name       = $DistHostname
                DomainName = $DomainName
                Credential = $DomainCredential
            }
        }

        # Windows Features for IIS HTTP Web Distribution
        WindowsFeatureSet InstallWebFeatures {
            Name                 = @(
                'Web-Server',
                'Web-Common-Http',
                'Web-Static-Content',
                'Web-Default-Doc',
                'Web-Dir-Browsing',
                'Web-Http-Errors',
                'Web-Http-Redirect',
                'Web-Filtering',
                'Web-Mgmt-Console',
                'Web-Scripting-Tools'
            )
            Ensure               = 'Present'
            IncludeAllSubFeature = $true
        }

        # Stop Default IIS Web Site
        xWebsite DefaultSite {
            Ensure       = 'Present'
            Name         = 'Default Web Site'
            State        = 'Stopped'
            PhysicalPath = 'C:\inetpub\wwwroot'
            DependsOn    = '[WindowsFeatureSet]InstallWebFeatures'
        }

        # Create Dedicated PKI Distribution Web Site
        xWebsite PKIDistSite {
            Ensure       = 'Present'
            Name         = $SiteName
            State        = 'Started'
            PhysicalPath = $PkiDistPath
            Port         = $SitePort
            DependsOn    = @('[WindowsFeatureSet]InstallWebFeatures', '[File]PKIDistFolder')
        }

        # Configure SMB Share for automated CRL / Certificate publication by CAs
        SmbShare PKISmbShare {
            Ensure      = 'Present'
            Name        = 'pki'
            Path        = $PkiDistPath
            Description = 'Internal CDP and AIA publication share'
            FullAccess  = @($AdminGroup, $PublishersGroup)
            ReadAccess  = @('Everyone')
            DependsOn   = '[File]PKIDistFolder'
        }

        # Enable Double Escaping for Delta CRLs (RFC and AD CS support)
        # Note: Delta CRL file names contain '+' symbols. IIS blocks requests containing '+' by default unless
        # requestFiltering/allowDoubleEscaping is set to true.
        Script ConfigureIISDoubleEscaping {
            SetScript = {
                Import-Module WebAdministration
                Set-WebConfigurationProperty -Filter 'system.webServer/security/requestFiltering' -PSPath 'IIS:\' -Location $using:SiteName -Name allowDoubleEscaping -Value $true
                
                # Ensure MIME types for PKI artifacts
                $crlMime = Get-WebConfigurationProperty -Filter "system.webServer/staticContent/mimeMap[@fileExtension='.crl']" -PSPath 'IIS:\' -Name mimeType
                if (-not $crlMime) {
                    Add-WebConfigurationProperty -Filter 'system.webServer/staticContent' -PSPath 'IIS:\' -Name '.' -Value @{fileExtension='.crl'; mimeType='application/pkix-crl'}
                }
                $crtMime = Get-WebConfigurationProperty -Filter "system.webServer/staticContent/mimeMap[@fileExtension='.crt']" -PSPath 'IIS:\' -Name mimeType
                if (-not $crtMime) {
                    Add-WebConfigurationProperty -Filter 'system.webServer/staticContent' -PSPath 'IIS:\' -Name '.' -Value @{fileExtension='.crt'; mimeType='application/x-x509-ca-cert'}
                }
            }
            TestScript = {
                Import-Module WebAdministration
                $prop = Get-WebConfigurationProperty -Filter 'system.webServer/security/requestFiltering' -PSPath 'IIS:\' -Location $using:SiteName -Name allowDoubleEscaping
                return ($prop.Value -eq $true)
            }
            GetScript = {
                Import-Module WebAdministration
                $prop = Get-WebConfigurationProperty -Filter 'system.webServer/security/requestFiltering' -PSPath 'IIS:\' -Location $using:SiteName -Name allowDoubleEscaping
                return @{ allowDoubleEscaping = $prop.Value }
            }
            DependsOn = '[xWebsite]PKIDistSite'
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

CSWebDistBuild -OutputPath $OutputPath `
    -DistHostname $DistHostname `
    -DomainName $DomainName `
    -AdminPath $AdminPath `
    -PkiRootPath $PkiRootPath `
    -PkiDistPath $PkiDistPath `
    -PublishersGroup $PublishersGroup `
    -AdminGroup $AdminGroup `
    -SiteName $SiteName `
    -SitePort $SitePort `
    -DomainCredential $DomainCredential `
    -ConfigurationData $configData
