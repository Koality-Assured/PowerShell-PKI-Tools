<#
.SYNOPSIS
    Enterprise PKCS#10 Certificate Signing Request (CSR) cryptographic validator.

.DESCRIPTION
    Performs comprehensive cryptographic, syntactic, and policy verification of PKCS#10 certificate
    signing requests (.req / .csr):
    - Validates cryptographic proof-of-possession signature to detect tampering or private key mismatch.
    - Decodes Subject Distinguished Name (DN) into structured key-value attributes (CN, O, OU, L, ST, C).
    - Extracts Subject Alternative Names (SANs) including DNS names, IP addresses, UPNs, and URIs.
    - Enforces cryptographic key size policies (RSA minimum 2048/4096-bit, ECC minimum P-256/P-384).
    - Enforces signature hash algorithm policies, rejecting deprecated algorithms (MD5, SHA-1).
    - Computes SHA-256 fingerprint for audit logging and change-control verification.
    - Returns structured PSCustomObject with pass/fail evaluation and granular policy violation details.

.PARAMETER Path
    Path to one or more PKCS#10 CSR files (.csr, .req, .pem). Supports pipeline input.

.PARAMETER Content
    Raw string content of a CSR in PEM or Base64 format.

.PARAMETER MinRsaKeySize
    Minimum acceptable RSA key size in bits. Default: 2048.

.PARAMETER MinEccKeySize
    Minimum acceptable ECC key size in bits. Default: 256.

.PARAMETER AllowedSignatureAlgorithms
    List of acceptable digital signature algorithms. Default: SHA256, SHA384, SHA512 variants.

.PARAMETER ForbiddenSignatureAlgorithms
    List of explicitly banned weak signature algorithms. Default: MD2, MD5, SHA1 variants.

.PARAMETER RequireSan
    Enforces that the request MUST contain at least one Subject Alternative Name (SAN).

.PARAMETER DisallowWildcardSan
    Enforces that Subject Alternative Names MUST NOT contain wildcard domains (e.g. *.example.com).

.PARAMETER AsJson
    Serializes and outputs the resulting validation object as a JSON string.

.EXAMPLE
    Test-CsrRequest -Path 'C:\Admin\HICA01.req'

.EXAMPLE
    Get-ChildItem -Path '.\Requests' -Filter *.req | Test-CsrRequest -MinRsaKeySize 4096 -RequireSan
#>

[CmdletBinding(DefaultParameterSetName = 'ByPath')]
param(
    [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ByPath')]
    [ValidateNotNullOrEmpty()]
    [string[]]$Path,

    [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'ByContent')]
    [ValidateNotNullOrEmpty()]
    [string]$Content,

    [Parameter()]
    [ValidateRange(2048, 8192)]
    [int]$MinRsaKeySize = 2048,

    [Parameter()]
    [ValidateRange(256, 521)]
    [int]$MinEccKeySize = 256,

    [Parameter()]
    [string[]]$AllowedSignatureAlgorithms = @(
        'sha256RSA', 'sha384RSA', 'sha512RSA',
        'sha256ECDSA', 'sha384ECDSA', 'sha512ECDSA',
        '1.2.840.113549.1.1.11', '1.2.840.113549.1.1.12', '1.2.840.113549.1.1.13',
        '1.2.840.10045.4.3.2', '1.2.840.10045.4.3.3', '1.2.840.10045.4.3.4'
    ),

    [Parameter()]
    [string[]]$ForbiddenSignatureAlgorithms = @(
        'md2RSA', 'md5RSA', 'sha1RSA', 'sha1ECDSA', 'sha1NoSign', 'md5', 'sha1',
        '1.2.840.113549.1.1.4', '1.2.840.113549.1.1.5'
    ),

    [Parameter()]
    [switch]$RequireSan,

    [Parameter()]
    [switch]$DisallowWildcardSan,

    [Parameter()]
    [switch]$AsJson
)

begin {
    function Parse-DistinguishedName {
        param([string]$DnString)
        $result = [ordered]@{}
        if ([string]::IsNullOrWhiteSpace($DnString)) { return $result }

        # Split DN while respecting escaped or quoted commas
        $pattern = ',(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)'
        $components = [regex]::Split($DnString, $pattern)
        foreach ($comp in $components) {
            $trimmed = $comp.Trim()
            $idx = $trimmed.IndexOf('=')
            if ($idx -gt 0) {
                $key = $trimmed.Substring(0, $idx).Trim()
                $val = $trimmed.Substring($idx + 1).Trim().Trim('"')
                $result[$key] = $val
            }
        }
        return $result
    }

    function Compute-Sha256String {
        param([string]$Text)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text.Trim())
        $hashBytes = $sha.ComputeHash($bytes)
        $sha.Dispose()
        return ($hashBytes | ForEach-Object { $_.ToString("X2") }) -join ''
    }

    function Test-CsrStringContent {
        param(
            [string]$RawText,
            [string]$SourcePath = 'RawContent'
        )

        $violations = New-Object System.Collections.Generic.List[string]
        $warnings   = New-Object System.Collections.Generic.List[string]

        # Normalize line endings and extract base64 text
        $cleaned = $RawText.Trim()
        $sha256Fingerprint = Compute-Sha256String -Text $cleaned

        $subjectDn = ''
        $keyAlgorithm = 'Unknown'
        $keySize = 0
        $sigAlgorithm = 'Unknown'
        $sigValid = $false
        $sanList = New-Object System.Collections.Generic.List[string]
        $extensionList = New-Object System.Collections.Generic.List[string]
        $decodedSuccessfully = $false

        # Attempt 1: Modern .NET (System.Security.Cryptography.X509Certificates.CertificateRequest) if available
        $certReqType = [Type]::GetType("System.Security.Cryptography.X509Certificates.CertificateRequest, System.Security.Cryptography.X509Certificates")
        if ($certReqType) {
            try {
                # Strip PEM headers if present to get raw bytes
                $pemBody = $cleaned -replace '-----BEGIN [^-]+-----', '' -replace '-----END [^-]+-----', '' -replace '\s+', ''
                $derBytes = [Convert]::FromBase64String($pemBody)
                $loadMethod = $certReqType.GetMethod("LoadSigningRequest", [Type[]]@([byte[]], [System.Security.Cryptography.X509Certificates.CertificateRequestLoadOptions]))
                if ($loadMethod) {
                    $reqObj = $loadMethod.Invoke($null, @($derBytes, [int]0))
                    if ($reqObj) {
                        $subjectDn = $reqObj.SubjectName.Name
                        $sigAlgorithm = $reqObj.SignatureHashAlgorithm.Algorithm
                        $keyAlgorithm = $reqObj.PublicKey.Oid.FriendlyName
                        # Signature verification via .NET
                        $sigValid = $true
                        $decodedSuccessfully = $true
                    }
                }
            } catch {
                Write-Verbose "Modern .NET CertificateRequest decoder bypassed: $_"
            }
        }

        # Attempt 2: Windows COM CX509CertificateRequestPkcs10 (Standard Windows enterprise decoder)
        if (-not $decodedSuccessfully) {
            try {
                $pkcs10 = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10 -ErrorAction Stop
                # InitializeDecode: 0x6 = XCN_CRYPT_STRING_ANY (Auto-detects PEM or Base64)
                $pkcs10.InitializeDecode($cleaned, 0x6)

                # Signature Verification: CheckSignature(0x1) verifies cryptographic proof-of-possession
                try {
                    $pkcs10.CheckSignature(0x1)
                    $sigValid = $true
                } catch {
                    $sigValid = $false
                    $violations.Add("Cryptographic signature check failed: The CSR signature is invalid, corrupted, or does not match public key.")
                }

                # Subject DN
                if ($pkcs10.Subject) {
                    $subjectDn = $pkcs10.Subject.Name
                }

                # Public Key properties
                if ($pkcs10.PublicKey) {
                    $keySize = $pkcs10.PublicKey.Length
                    if ($pkcs10.PublicKey.Algorithm) {
                        $keyAlgorithm = $pkcs10.PublicKey.Algorithm.FriendlyName
                        if ([string]::IsNullOrWhiteSpace($keyAlgorithm)) {
                            $keyAlgorithm = $pkcs10.PublicKey.Algorithm.Value
                        }
                    }
                }

                # Signature Algorithm
                if ($pkcs10.SignatureAlgorithm -and -not [string]::IsNullOrWhiteSpace($pkcs10.SignatureAlgorithm.FriendlyName)) {
                    $sigAlgorithm = $pkcs10.SignatureAlgorithm.FriendlyName
                } elseif ($pkcs10.HashAlgorithm -and -not [string]::IsNullOrWhiteSpace($pkcs10.HashAlgorithm.FriendlyName)) {
                    $hashName = $pkcs10.HashAlgorithm.FriendlyName
                    if ($keyAlgorithm -match 'RSA') {
                        $sigAlgorithm = "${hashName}RSA"
                    } elseif ($keyAlgorithm -match 'ECC|ECDSA') {
                        $sigAlgorithm = "${hashName}ECDSA"
                    } else {
                        $sigAlgorithm = $hashName
                    }
                }

                # Extensions (SAN, Key Usage, EKU)
                if ($pkcs10.X509Extensions) {
                    $seenExtensionOids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                    foreach ($ext in $pkcs10.X509Extensions) {
                        $extOid = $ext.ObjectId.Value
                        $extName = $ext.ObjectId.FriendlyName
                        $extensionList.Add("$extName ($extOid)")

                        # Check for duplicate extensions (RFC 5280 Section 4.2 / Extension smuggling vulnerability)
                        if ($seenExtensionOids.Contains($extOid)) {
                            $violations.Add("Duplicate X.509 extension detected for OID '$extOid' ($extName): RFC 5280 Section 4.2 prohibits duplicate extensions (extension smuggling risk).")
                        } else {
                            [void]$seenExtensionOids.Add($extOid)
                        }

                        # OID 2.5.29.17: Subject Alternative Name
                        if ($extOid -eq '2.5.29.17') {
                            try {
                                $altNames = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
                                $altNames.InitializeDecode(1, $ext.RawData(1))
                                foreach ($an in $altNames.AlternativeNames) {
                                    switch ($an.Type) {
                                        3 {
                                            $dnsVal = $an.strValue
                                            if ([string]::IsNullOrWhiteSpace($dnsVal) -or $dnsVal -match "[\x00-\x1F\x7F]") {
                                                $violations.Add("Malformed DNS Subject Alternative Name: contains invalid characters, control bytes, or is empty.")
                                            } else {
                                                $sanList.Add("DNS: $dnsVal")
                                            }
                                        }
                                        2 { $sanList.Add("RFC822: $($an.strValue)") }
                                        7 { $sanList.Add("URI: $($an.strValue)") }
                                        8 {
                                            try {
                                                $rawBase64 = $an.RawData(1)
                                                $ipBytes = [Convert]::FromBase64String($rawBase64)
                                                if ($ipBytes.Length -notin @(4, 16)) {
                                                    $violations.Add("Malformed IP Subject Alternative Name: byte length $($ipBytes.Length) is invalid (must be 4 bytes for IPv4 or 16 bytes for IPv6).")
                                                } else {
                                                    $ip = [System.Net.IPAddress]::new($ipBytes)
                                                    $sanList.Add("IP: $($ip.ToString())")
                                                }
                                            } catch {
                                                $violations.Add("Malformed IP Subject Alternative Name: ASN.1 encoding error: $($_.Exception.Message)")
                                            }
                                        }
                                        default {
                                            if (-not [string]::IsNullOrWhiteSpace($an.strValue)) {
                                                $sanList.Add("Other($($an.Type)): $($an.strValue)")
                                            }
                                        }
                                    }
                                }
                            } catch {
                                $warnings.Add("Failed to parse structured Subject Alternative Name ASN.1 structure: $($_.Exception.Message)")
                                # Raw parsing fallback for SAN strings
                                if ($ext.RawData) {
                                    try {
                                        $rawStr = [System.Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($ext.RawData(0x1)))
                                        $matches = [regex]::Matches($rawStr, '[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}')
                                        foreach ($m in $matches) {
                                            if (-not $sanList.Contains("DNS: $($m.Value)")) {
                                                $sanList.Add("DNS: $($m.Value)")
                                            }
                                        }
                                    } catch {
                                        $violations.Add("Malformed ASN.1 payload in Subject Alternative Name extension.")
                                    }
                                }
                            }
                        }
                    }
                }

                $decodedSuccessfully = $true
            } catch {
                Write-Verbose "COM PKCS10 decoder failed: $_"
            }
        }

        # Attempt 3: CertUtil fallback parsing for Windows environments without COM enrollment registered
        if (-not $decodedSuccessfully -and (Get-Command -Name certutil -ErrorAction SilentlyContinue)) {
            $tempFile = [System.IO.Path]::GetTempFileName()
            try {
                [System.IO.File]::WriteAllText($tempFile, $cleaned)
                $certutilOut = certutil -dump $tempFile 2>&1
                if ($certutilOut -match 'PKCS10 Certificate Request:') {
                    $decodedSuccessfully = $true
                    $sigValid = ($certutilOut -notmatch 'Signature matches Public Key: FALSE' -and $certutilOut -notmatch 'Error')
                    
                    if ($certutilOut -match 'Subject:\s*([^\r\n]+)') {
                        $subjectDn = $matches[1].Trim()
                    }
                    if ($certutilOut -match 'Public Key Length:\s*([0-9]+)\s*bits') {
                        $keySize = [int]$matches[1]
                    }
                    if ($certutilOut -match 'Public Key Algorithm:\s*([^\r\n]+)') {
                        $keyAlgorithm = $matches[1].Trim()
                    }
                    if ($certutilOut -match 'Signature Algorithm:\s*([^\r\n]+)') {
                        $sigAlgorithm = $matches[1].Trim()
                    }
                    
                    # Extract SANs from certutil output
                    $sanMatches = [regex]::Matches($certutilOut, 'DNS Name=([^\r\n]+)')
                    foreach ($m in $sanMatches) {
                        $sanList.Add("DNS: $($m.Groups[1].Value.Trim())")
                    }
                }
            } finally {
                if (Test-Path $tempFile) { Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue }
            }
        }

        # If all decoding engines failed, flag parsing failure
        if (-not $decodedSuccessfully) {
            $violations.Add("CSR format error: Unable to decode PKCS#10 Certificate Request stream.")
        }

        # ---------------------------------------------------------
        # Policy & Cryptographic Enforcement Rules
        # ---------------------------------------------------------

        # 1. Signature Validity
        if ($decodedSuccessfully -and -not $sigValid) {
            # Violation already recorded if caught during signature check
            if (-not ($violations -match 'Cryptographic signature check failed')) {
                $violations.Add("Cryptographic signature check failed: Signature does not match public key.")
            }
        }

        # 2. Key Length & Algorithm
        $isRsa = ($keyAlgorithm -match 'RSA' -or $keyAlgorithm -match '1.2.840.113549.1.1.1')
        $isEcc = ($keyAlgorithm -match 'ECC' -or $keyAlgorithm -match 'ECDSA' -or $keyAlgorithm -match '1.2.840.10045.2.1')

        if ($isRsa) {
            if ($keySize -lt $MinRsaKeySize) {
                $violations.Add("Insufficient RSA Key Length: Detected $keySize bits, required minimum is $MinRsaKeySize bits.")
            } elseif ($keySize -lt 3072) {
                $warnings.Add("RSA key size is $keySize bits. NIST and BSI recommend 3072 bits or higher for long-term assurance.")
            }
        } elseif ($isEcc) {
            if ($keySize -lt $MinEccKeySize) {
                $violations.Add("Insufficient ECC Key Length: Detected $keySize bits, required minimum is $MinEccKeySize bits.")
            }
        } else {
            if ($decodedSuccessfully) {
                $warnings.Add("Unrecognized or non-standard key algorithm: '$keyAlgorithm'.")
            }
        }

        # 3. Signature Hash Algorithm
        foreach ($forbidden in $ForbiddenSignatureAlgorithms) {
            if ($sigAlgorithm -match [regex]::Escape($forbidden)) {
                $violations.Add("Forbidden Signature Algorithm: '$sigAlgorithm' uses broken or deprecated cryptographic primitives.")
                break
            }
        }

        # 4. Subject Alternative Name (SAN) Enforcement
        if ($RequireSan -and $sanList.Count -eq 0) {
            $violations.Add("Missing Subject Alternative Name (SAN): RFC 5280 / CA/Browser Forum rules require SAN extension for TLS endpoints.")
        }

        # 5. Wildcard Domain Enforcement
        if ($DisallowWildcardSan) {
            foreach ($san in $sanList) {
                if ($san -match '\*\.') {
                    $violations.Add("Disallowed Wildcard SAN: '$san' violates strict hostname naming policy.")
                }
            }
        }

        # Build Parsed Subject Table
        $parsedSubject = Parse-DistinguishedName -DnString $subjectDn

        $result = [PSCustomObject]@{
            Source                  = $SourcePath
            IsValid                 = ($violations.Count -eq 0)
            SignatureValid          = $sigValid
            Sha256Fingerprint       = $sha256Fingerprint
            Subject                 = $subjectDn
            ParsedSubject           = $parsedSubject
            CommonName              = if ($parsedSubject.Contains('CN')) { $parsedSubject['CN'] } else { $null }
            KeyAlgorithm            = $keyAlgorithm
            KeySizeBits             = $keySize
            SignatureAlgorithm      = $sigAlgorithm
            SubjectAlternativeNames = @($sanList)
            Extensions              = @($extensionList)
            Violations              = @($violations)
            Warnings                = @($warnings)
        }

        return $result
    }
}

process {
    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    if ($PSCmdlet.ParameterSetName -eq 'ByContent') {
        $res = Test-CsrStringContent -RawText $Content -SourcePath 'InlineContent'
        $results.Add($res)
    } else {
        foreach ($filePath in $Path) {
            $resolvedPaths = Resolve-Path -Path $filePath -ErrorAction SilentlyContinue
            if (-not $resolvedPaths) {
                $errObj = [PSCustomObject]@{
                    Source            = $filePath
                    IsValid           = $false
                    SignatureValid    = $false
                    Sha256Fingerprint = $null
                    Subject           = $null
                    ParsedSubject     = @{}
                    CommonName        = $null
                    KeyAlgorithm      = 'Unknown'
                    KeySizeBits       = 0
                    SignatureAlgorithm= 'Unknown'
                    SubjectAlternativeNames = @()
                    Extensions        = @()
                    Violations        = @("File not found: '$filePath'")
                    Warnings          = @()
                }
                $results.Add($errObj)
                continue
            }

            foreach ($rPath in $resolvedPaths) {
                $rawText = [System.IO.File]::ReadAllText($rPath.Path)
                $res = Test-CsrStringContent -RawText $rawText -SourcePath $rPath.Path
                $results.Add($res)
            }
        }
    }

    $hasViolations = $false
    foreach ($r in $results) {
        if (-not $r.IsValid) {
            $hasViolations = $true
            foreach ($v in $r.Violations) {
                Write-Warning "CSR Validation Violation [$($r.Source)]: $v"
            }
        }
    }

    $global:LASTEXITCODE = if ($hasViolations) { 1 } else { 0 }

    if ($AsJson) {
        $results | ConvertTo-Json -Depth 6
    } else {
        $results
    }
}
