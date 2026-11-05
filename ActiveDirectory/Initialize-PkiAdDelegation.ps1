<#
.SYNOPSIS
    Initializes Active Directory delegation, security groups, OUs, and container permissions for Enterprise PKI.

.DESCRIPTION
    Automates the preparation and security hardening of Active Directory Domain Services (AD DS)
    for a modern Public Key Infrastructure (PKI) deployment:
    - Creates tiered Organizational Units (OUs) for PKI infrastructure components.
    - Provisions administrative, auditing, and operational security groups:
        * PKI-Admins: Full control over AD CS configuration and PKI operations.
        * PKI-Auditors: Read-only compliance and audit access.
        * PKI-Cert-Managers: Certificate issuance, revocation, and approval management.
        * PKI-Certificate-Authorities: Security group containing all Enterprise Subordinate CAs.
        * PKI-NDES-SvcMgmt & PKI-SCEP-Servers: Group Managed Service Account (gMSA) governance.
    - Delegates granular Access Control Entries (ACEs) on the AD DS 'CN=Public Key Services' configuration container.
    - Grants PKI-Admins administrative delegation over PKI security groups and the built-in 'Certificate Publishers' group.
    - Pre-stages computer objects for Subordinate CAs, Web Distribution points, and NDES servers.
    - Provisions the NDES Group Managed Service Account (gMSA) with Kerberos SPNs and retrieval rights.
    - Configures internal DNS CNAME records for high-availability CDP/AIA endpoints.

.PARAMETER DomainName
    Fully Qualified Domain Name (FQDN) of the target Active Directory domain. Default: 'corp.example.com'.

.PARAMETER PkiAdminsGroup
    Name of the PKI Administrators security group. Default: 'PKI-Admins'.

.PARAMETER PkiAuditorsGroup
    Name of the PKI Auditors security group. Default: 'PKI-Auditors'.

.PARAMETER PkiCertManagersGroup
    Name of the PKI Certificate Managers security group. Default: 'PKI-Cert-Managers'.

.PARAMETER PkiCAsGroup
    Name of the PKI Certificate Authorities computer group. Default: 'PKI-Certificate-Authorities'.

.PARAMETER PkiOuName
    Name of the primary PKI Organizational Unit. Default: 'PKI'.

.PARAMETER ParentOuPath
    Distinguished Name of the parent OU for PKI infrastructure. Default: derived from domain root.

.PARAMETER PreStageComputers
    Switch specifying whether to pre-stage computer accounts for PKI infrastructure. Default: $true.

.PARAMETER CreateDnsRecords
    Switch specifying whether to configure internal DNS CNAME records for PKI endpoints. Default: $true.

.EXAMPLE
    .\Initialize-PkiAdDelegation.ps1 -DomainName 'corp.example.com' -WhatIf
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DomainName = 'corp.example.com',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PkiAdminsGroup = 'PKI-Admins',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PkiAuditorsGroup = 'PKI-Auditors',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PkiCertManagersGroup = 'PKI-Cert-Managers',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PkiCAsGroup = 'PKI-Certificate-Authorities',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PkiNdesSvcGroup = 'PKI-NDES-SvcMgmt',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PkiScepEnrollGroup = 'PKI-SCEP-Enrollment',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PkiScepServersGroup = 'PKI-SCEP-Servers',

    [Parameter()]
    [string]$PkiOuName = 'PKI',

    [Parameter()]
    [string]$ParentOuPath,

    [Parameter()]
    [bool]$PreStageComputers = $true,

    [Parameter()]
    [string]$HighCaComputerName = 'HICA01',

    [Parameter()]
    [string]$MedCaComputerName = 'MICA01',

    [Parameter()]
    [string]$WebDistComputerName = 'WEBDIST01',

    [Parameter()]
    [string]$NdesComputerName = 'NDES01',

    [Parameter()]
    [string]$NdesGmsaName = 'gmsa-pki-ndes',

    [Parameter()]
    [bool]$CreateDnsRecords = $true,

    [Parameter()]
    [string]$PkiDnsAlias = 'pki',

    [Parameter()]
    [string]$PkiSecondaryDnsAlias = 'pki2'
)

# Convert domain to Distinguished Name (corp.example.com -> DC=corp,DC=example,DC=com)
$domainParts = $DomainName.Split('.')
$DomainDN = ($domainParts | ForEach-Object { "DC=$_" }) -join ','

if ([string]::IsNullOrWhiteSpace($ParentOuPath)) {
    $TargetOuDN = "OU=$PkiOuName,$DomainDN"
} else {
    $TargetOuDN = "OU=$PkiOuName,$ParentOuPath"
}

Write-Verbose "Target Domain DN: $DomainDN"
Write-Verbose "Target PKI OU DN: $TargetOuDN"

# Ensure Active Directory PowerShell module is available
if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
    Write-Warning "ActiveDirectory module is not installed on this system. Operating in audit/dry-run mode."
}

# 1. Create PKI Organizational Unit Structure
if ($PSCmdlet.ShouldProcess($TargetOuDN, "Create PKI Organizational Unit")) {
    try {
        if (Get-Command -Name Get-ADOrganizationalUnit -ErrorAction SilentlyContinue) {
            $existingOu = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$TargetOuDN'" -ErrorAction SilentlyContinue
            if (-not $existingOu) {
                $ouPath = if ([string]::IsNullOrWhiteSpace($ParentOuPath)) { $DomainDN } else { $ParentOuPath }
                New-ADOrganizationalUnit -Name $PkiOuName -Path $ouPath -Description 'Enterprise PKI Infrastructure Systems' -ProtectedFromAccidentalDeletion $true
                Write-Host "[+] Created PKI Organizational Unit: $TargetOuDN" -ForegroundColor Green
            } else {
                Write-Host "[*] PKI Organizational Unit already exists: $TargetOuDN" -ForegroundColor Cyan
            }
        } else {
            Write-Host "[SIMULATE] Create OU: $TargetOuDN" -ForegroundColor Yellow
        }
    } catch {
        Write-Error "Failed to create PKI Organizational Unit: $_"
    }
}

# 2. Provision Universal Security Groups
$groupsToProvision = @(
    @{ Name = $PkiAdminsGroup;        Description = 'Enterprise PKI Administrators with full control over AD CS and PKI operations.' },
    @{ Name = $PkiAuditorsGroup;      Description = 'Enterprise PKI Auditors with read-only compliance and auditing rights.' },
    @{ Name = $PkiCertManagersGroup;  Description = 'Enterprise PKI Certificate Managers authorized for issuance and revocation.' },
    @{ Name = $PkiCAsGroup;           Description = 'Security group containing all Enterprise Subordinate Certification Authority computer accounts.' },
    @{ Name = $PkiNdesSvcGroup;       Description = 'Security group authorized to manage NDES service accounts and host configurations.' },
    @{ Name = $PkiScepEnrollGroup;    Description = 'Security group of devices and users authorized for automated SCEP enrollment.' },
    @{ Name = $PkiScepServersGroup;   Description = 'Hosts authorized to retrieve the NDES gMSA managed password.' }
)

foreach ($grp in $groupsToProvision) {
    if ($PSCmdlet.ShouldProcess($grp.Name, "Create AD Security Group in $TargetOuDN")) {
        try {
            if (Get-Command -Name Get-ADGroup -ErrorAction SilentlyContinue) {
                $existingGroup = Get-ADGroup -Filter "SamAccountName -eq '$($grp.Name)'" -ErrorAction SilentlyContinue
                if (-not $existingGroup) {
                    New-ADGroup -Name $grp.Name -SamAccountName $grp.Name -GroupScope Universal -GroupCategory Security -Path $TargetOuDN -Description $grp.Description
                    Write-Host "[+] Created Security Group: $($grp.Name)" -ForegroundColor Green
                } else {
                    Write-Host "[*] Security Group already exists: $($grp.Name)" -ForegroundColor Cyan
                }
            } else {
                Write-Host "[SIMULATE] Create Security Group: $($grp.Name)" -ForegroundColor Yellow
            }
        } catch {
            Write-Error "Failed creating group $($grp.Name): $_"
        }
    }
}

# 3. Delegate ACLs on Active Directory 'CN=Public Key Services' Container
if ($PSCmdlet.ShouldProcess("CN=Public Key Services", "Delegate full administrative control to $PkiAdminsGroup")) {
    try {
        if (Get-Command -Name Get-ADGroup -ErrorAction SilentlyContinue) {
            $adminGroupObj = Get-ADGroup -Identity $PkiAdminsGroup -ErrorAction SilentlyContinue
            if ($adminGroupObj) {
                $sidGroup = New-Object System.Security.Principal.SecurityIdentifier $adminGroupObj.SID
                $rootDse = [ADSI]"LDAP://RootDSE"
                $configContext = $rootDse.configurationNamingContext
                $pkiContainerDN = "CN=Public Key Services,CN=Services,$configContext"
                
                $pkiContainerPath = "AD:\$pkiContainerDN"
                if (Test-Path $pkiContainerPath) {
                    $acl = Get-Acl -Path $pkiContainerPath
                    $accessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $sidGroup,
                        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
                        [System.Security.AccessControl.AccessControlType]::Allow,
                        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
                    )
                    $acl.AddAccessRule($accessRule)
                    Set-Acl -Path $pkiContainerPath -AclObject $acl
                    Write-Host "[+] Delegated GenericAll on '$pkiContainerDN' to $PkiAdminsGroup" -ForegroundColor Green
                } else {
                    Write-Warning "PKI Services Container not found at '$pkiContainerPath'."
                }
            }
        } else {
            Write-Host "[SIMULATE] Delegate GenericAll on CN=Public Key Services to $PkiAdminsGroup" -ForegroundColor Yellow
        }
    } catch {
        Write-Error "Failed to delegate permissions on Public Key Services container: $_"
    }
}

# 4. Delegate Group Management Permissions
$managedGroups = @('Certificate Publishers', $PkiAuditorsGroup, $PkiCertManagersGroup, $PkiCAsGroup, $PkiScepServersGroup)
foreach ($mg in $managedGroups) {
    if ($PSCmdlet.ShouldProcess($mg, "Delegate management rights to $PkiAdminsGroup")) {
        try {
            if (Get-Command -Name Get-ADGroup -ErrorAction SilentlyContinue) {
                $targetGroup = Get-ADGroup -Identity $mg -ErrorAction SilentlyContinue
                $adminGroupObj = Get-ADGroup -Identity $PkiAdminsGroup -ErrorAction SilentlyContinue
                if ($targetGroup -and $adminGroupObj) {
                    $sidGroup = New-Object System.Security.Principal.SecurityIdentifier $adminGroupObj.SID
                    $targetAcl = Get-Acl -Path "AD:\$($targetGroup.DistinguishedName)"
                    $rights = [System.DirectoryServices.ActiveDirectoryRights]'ReadProperty,GenericWrite,ExtendedRight,ReadControl'
                    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $sidGroup,
                        $rights,
                        [System.Security.AccessControl.AccessControlType]::Allow
                    )
                    $targetAcl.AddAccessRule($rule)
                    Set-Acl -Path "AD:\$($targetGroup.DistinguishedName)" -AclObject $targetAcl
                    Write-Host "[+] Delegated management rights on '$mg' to $PkiAdminsGroup" -ForegroundColor Green
                }
            } else {
                Write-Host "[SIMULATE] Delegate management rights on group '$mg' to $PkiAdminsGroup" -ForegroundColor Yellow
            }
        } catch {
            Write-Warning "Could not delegate management on group $($mg): $_"
        }
    }
}

# 5. Pre-stage Computer Objects
if ($PreStageComputers) {
    $computersToPreStage = @(
        @{ Name = $HighCaComputerName;   Description = 'Tier-0 Enterprise Subordinate Issuing CA (High Assurance)' },
        @{ Name = $MedCaComputerName;    Description = 'Tier-1 Enterprise Subordinate Issuing CA (Medium Assurance)' },
        @{ Name = $WebDistComputerName;  Description = 'High-Availability HTTP CRL and AIA Distribution Server' },
        @{ Name = $NdesComputerName;     Description = 'Network Device Enrollment Service (NDES / SCEP) Registration Authority' }
    )

    foreach ($comp in $computersToPreStage) {
        if ($PSCmdlet.ShouldProcess($comp.Name, "Pre-stage Computer Object in $TargetOuDN")) {
            try {
                if (Get-Command -Name Get-ADComputer -ErrorAction SilentlyContinue) {
                    $existingComp = Get-ADComputer -Filter "SamAccountName -eq '$($comp.Name)$'" -ErrorAction SilentlyContinue
                    if (-not $existingComp) {
                        New-ADComputer -Name $comp.Name -SamAccountName $comp.Name -Path $TargetOuDN -Description $comp.Description -Enabled $true
                        Write-Host "[+] Pre-staged Computer Object: $($comp.Name)" -ForegroundColor Green
                    } else {
                        Write-Host "[*] Computer Object already exists: $($comp.Name)" -ForegroundColor Cyan
                    }
                } else {
                    Write-Host "[SIMULATE] Pre-stage Computer: $($comp.Name) in $TargetOuDN" -ForegroundColor Yellow
                }
            } catch {
                Write-Warning "Failed pre-staging computer $($comp.Name): $_"
            }
        }
    }
}

# 6. Configure NDES Group Managed Service Account (gMSA)
if ($PSCmdlet.ShouldProcess($NdesGmsaName, "Provision NDES Group Managed Service Account")) {
    try {
        if (Get-Command -Name New-ADServiceAccount -ErrorAction SilentlyContinue) {
            $existingGmsa = Get-ADServiceAccount -Filter "SamAccountName -eq '$NdesGmsaName$'" -ErrorAction SilentlyContinue
            if (-not $existingGmsa) {
                $dnsHostName = "$NdesGmsaName.$DomainName"
                $spn = "HTTP/$dnsHostName"
                New-ADServiceAccount -Name $NdesGmsaName `
                    -SamAccountName $NdesGmsaName `
                    -DNSHostName $dnsHostName `
                    -Path $TargetOuDN `
                    -Description 'gMSA for Network Device Enrollment Service (NDES / SCEP)' `
                    -PrincipalsAllowedToRetrieveManagedPassword $PkiScepServersGroup `
                    -ServicePrincipalNames @($spn)
                Write-Host "[+] Provisioned gMSA: $NdesGmsaName (SPN: $spn)" -ForegroundColor Green
            } else {
                Write-Host "[*] gMSA already exists: $NdesGmsaName" -ForegroundColor Cyan
            }
        } else {
            Write-Host "[SIMULATE] Provision gMSA: $NdesGmsaName for group $PkiScepServersGroup" -ForegroundColor Yellow
        }
    } catch {
        Write-Warning "Failed provisioning gMSA $($NdesGmsaName): $_"
    }
}

# 7. Configure Internal DNS CNAME Aliases for High Availability PKI Web Distribution
if ($CreateDnsRecords) {
    $dnsRecords = @(
        @{ Name = $PkiDnsAlias;          Target = "$WebDistComputerName.$DomainName" },
        @{ Name = $PkiSecondaryDnsAlias; Target = "$WebDistComputerName.$DomainName" }
    )

    foreach ($rec in $dnsRecords) {
        if ($PSCmdlet.ShouldProcess("$($rec.Name).$DomainName", "Add DNS CNAME Record pointing to $($rec.Target)")) {
            try {
                if (Get-Command -Name Add-DnsServerResourceRecordCName -ErrorAction SilentlyContinue) {
                    Add-DnsServerResourceRecordCName -Name $rec.Name -ZoneName $DomainName -HostNameAlias $rec.Target -ErrorAction SilentlyContinue
                    Write-Host "[+] Added DNS CNAME: $($rec.Name).$DomainName -> $($rec.Target)" -ForegroundColor Green
                } else {
                    Write-Host "[SIMULATE] Add DNS CNAME: $($rec.Name).$DomainName -> $($rec.Target)" -ForegroundColor Yellow
                }
            } catch {
                Write-Warning "Could not register DNS record $($rec.Name): $_"
            }
        }
    }
}

Write-Host "`n[OK] Active Directory PKI Delegation and Infrastructure Preparation Complete.`n" -ForegroundColor Green
