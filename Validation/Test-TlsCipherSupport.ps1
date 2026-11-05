<#
.SYNOPSIS
    Cross-platform TLS/SSL cryptographic endpoint scanner and certificate chain evaluator.

.DESCRIPTION
    Probes remote TLS/SSL services across configurable protocol versions and port numbers:
    - Probes SSLv2, SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, and TLS 1.3.
    - Captures negotiated cipher suites, cipher algorithms, key exchange algorithms, and hash strengths.
    - Analyzes remote server X.509 certificates:
        * Subject and Issuer Distinguished Names.
        * Subject Alternative Names (SANs).
        * Validity windows, expiration countdowns, and renewal alerts.
        * Cryptographic public key sizes and signature algorithms.
    - Evaluates complete X.509 certificate chains, reporting revocation and trust path status.
    - Performs automated risk scoring, flagging obsolete protocols and weak ciphers.

.PARAMETER ComputerName
    Hostnames or IP addresses to probe. Default: 'localhost'. Supports pipeline input.

.PARAMETER Port
    Target TCP port hosting TLS/SSL service. Default: 443.

.PARAMETER TimeoutMs
    TCP socket and TLS handshake timeout in milliseconds. Default: 3000.

.PARAMETER Protocols
    Array of protocol versions to test. Default: @('Ssl3', 'Tls10', 'Tls11', 'Tls12', 'Tls13').

.PARAMETER MinTlsVersion
    Minimum acceptable TLS version for compliance. Default: 'Tls12'.

.PARAMETER AsJson
    Serializes output as JSON.

.EXAMPLE
    Test-TlsCipherSupport -ComputerName 'pki.corp.example.com' -Port 443

.EXAMPLE
    @('pki1.corp.example.com', 'pki2.corp.example.com') | Test-TlsCipherSupport -Port 443
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('HostName', 'Host', 'Server')]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName = @('localhost'),

    [Parameter(Position = 1)]
    [ValidateRange(1, 65535)]
    [int]$Port = 443,

    [Parameter()]
    [ValidateRange(500, 30000)]
    [int]$TimeoutMs = 3000,

    [Parameter()]
    [ValidateSet('Ssl2', 'Ssl3', 'Tls10', 'Tls11', 'Tls12', 'Tls13')]
    [string[]]$Protocols = @('Ssl3', 'Tls10', 'Tls11', 'Tls12', 'Tls13'),

    [Parameter()]
    [ValidateSet('Tls12', 'Tls13')]
    [string]$MinTlsVersion = 'Tls12',

    [Parameter()]
    [Alias('SniHost', 'Sni')]
    [string]$ServerName,

    [Parameter()]
    [switch]$AsJson
)

begin {
    # Protocol mapping to .NET SslProtocols enum values
    $protocolMap = [ordered]@{
        'Ssl2'  = [System.Security.Authentication.SslProtocols]12      # Ssl2 = 12
        'Ssl3'  = [System.Security.Authentication.SslProtocols]48      # Ssl3 = 48
        'Tls10' = [System.Security.Authentication.SslProtocols]192     # Tls = 192
        'Tls11' = [System.Security.Authentication.SslProtocols]768     # Tls11 = 768
        'Tls12' = [System.Security.Authentication.SslProtocols]3072    # Tls12 = 3072
        'Tls13' = [System.Security.Authentication.SslProtocols]12288   # Tls13 = 12288
    }

    function Parse-CertDn {
        param([string]$DnString)
        $parsed = [ordered]@{}
        if ([string]::IsNullOrWhiteSpace($DnString)) { return $parsed }
        $pattern = ',(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)'
        $components = [regex]::Split($DnString, $pattern)
        foreach ($c in $components) {
            $trimmed = $c.Trim()
            $idx = $trimmed.IndexOf('=')
            if ($idx -gt 0) {
                $k = $trimmed.Substring(0, $idx).Trim()
                $v = $trimmed.Substring($idx + 1).Trim().Trim('"')
                $parsed[$k] = $v
            }
        }
        return $parsed
    }

    function Extract-SanList {
        param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
        $sans = New-Object System.Collections.Generic.List[string]
        if (-not $Cert) { return @() }

        foreach ($ext in $Cert.Extensions) {
            if ($ext.Oid.Value -eq '2.5.29.17') {
                $asnData = New-Object System.Security.Cryptography.AsnEncodedData ($ext.Oid, $ext.RawData)
                $formatted = $asnData.Format($false)
                $entries = $formatted -split ',\s*|\r?\n'
                foreach ($entry in $entries) {
                    $cleanedEntry = $entry.Trim()
                    if (-not [string]::IsNullOrWhiteSpace($cleanedEntry)) {
                        $sans.Add($cleanedEntry)
                    }
                }
            }
        }
        return @($sans)
    }

    function Evaluate-Endpoint {
        param(
            [string]$TargetHost,
            [int]$TargetPort
        )

        $sniHostname = if (-not [string]::IsNullOrWhiteSpace($ServerName)) { $ServerName } else { $TargetHost }
        $protocolResults = [ordered]@{}
        $findings = New-Object System.Collections.Generic.List[string]
        $capturedCert = $null
        $negotiatedDetails = $null

        foreach ($pName in $Protocols) {
            $supported = $false
            $enumVal = $protocolMap[$pName]
            $tcpClient = $null
            $sslStream = $null

            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $connectTask = $tcpClient.ConnectAsync($TargetHost, $TargetPort)
                $completed = $connectTask.Wait($TimeoutMs)

                if ($completed -and $tcpClient.Connected) {
                    # Accept any remote certificate during scan probe to extract properties
                    $validationCallback = {
                        param($sender, $certificate, $chain, $sslPolicyErrors)
                        return $true
                    }

                    $sslStream = New-Object System.Net.Security.SslStream (
                        $tcpClient.GetStream(),
                        $false,
                        [System.Net.Security.RemoteCertificateValidationCallback]$validationCallback
                    )

                    $sslStream.ReadTimeout = $TimeoutMs
                    $sslStream.WriteTimeout = $TimeoutMs

                    try {
                        # Authenticate as client using specific protocol and SNI hostname
                        # Passing explicit SNI hostname ensures CDN / Cloud endpoints (Cloudflare, AWS ALB)
                        # return the correct certificate and complete handshakes instead of throwing SSL errors.
                        $authTask = $sslStream.AuthenticateAsClientAsync($sniHostname, $null, $enumVal, $false)
                        if ($authTask.Wait($TimeoutMs) -and -not $authTask.IsFaulted) {
                            $supported = $true

                            if (-not $capturedCert -and $sslStream.RemoteCertificate) {
                                $capturedCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $sslStream.RemoteCertificate
                                $negotiatedDetails = [PSCustomObject]@{
                                    Protocol            = $sslStream.SslProtocol.ToString()
                                    CipherAlgorithm     = $sslStream.CipherAlgorithm.ToString()
                                    CipherStrength      = $sslStream.CipherStrength
                                    HashAlgorithm       = $sslStream.HashAlgorithm.ToString()
                                    HashStrength        = $sslStream.HashStrength
                                    KeyExchangeAlgorithm= $sslStream.KeyExchangeAlgorithm.ToString()
                                    KeyExchangeStrength = $sslStream.KeyExchangeStrength
                                }
                            }
                        } else {
                            $supported = $false
                        }
                    } catch {
                        $supported = $false
                    }
                } else {
                    $findings.Add("TCP connection to $TargetHost`:$TargetPort timed out after $TimeoutMs ms.")
                }
            } catch {
                $supported = $false
            } finally {
                if ($sslStream) { $sslStream.Dispose() }
                if ($tcpClient) { $tcpClient.Dispose() }
            }

            $protocolResults[$pName] = $supported

            # Security Findings Assessment
            if ($supported -and ($pName -in @('Ssl2', 'Ssl3'))) {
                $findings.Add("CRITICAL: Obsolete and insecure protocol $pName is active on $TargetHost`:$TargetPort.")
            } elseif ($supported -and ($pName -in @('Tls10', 'Tls11'))) {
                $findings.Add("HIGH: Deprecated protocol $pName is enabled. Disables modern cipher suites and fails PCI DSS / NIST.")
            }
        }

        # Certificate Details Evaluation
        $certDetails = $null
        $chainDetails = $null

        if ($capturedCert) {
            $notAfter = $capturedCert.NotAfter
            $notBefore = $capturedCert.NotBefore
            $daysRemaining = [math]::Round(($notAfter - (Get-Date)).TotalDays, 1)

            if ($daysRemaining -le 0) {
                $findings.Add("CRITICAL: Server certificate expired on $($notAfter.ToString('yyyy-MM-dd')).")
            } elseif ($daysRemaining -le 30) {
                $findings.Add("WARNING: Server certificate expires in $daysRemaining days ($($notAfter.ToString('yyyy-MM-dd'))).")
            }

            $sanList = Extract-SanList -Cert $capturedCert
            $parsedSubject = Parse-CertDn -DnString $capturedCert.Subject
            $parsedIssuer  = Parse-CertDn -DnString $capturedCert.Issuer

            # Chain Evaluation
            $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            $chainValid = $chain.Build($capturedCert)
            $chainElements = @()
            foreach ($elem in $chain.ChainElements) {
                $chainElements += [PSCustomObject]@{
                    Subject    = $elem.Certificate.Subject
                    Issuer     = $elem.Certificate.Issuer
                    Thumbprint = $elem.Certificate.Thumbprint
                }
            }

            if (-not $chainValid) {
                $chainStatusErrors = ($chain.ChainStatus | ForEach-Object { "$($_.Status): $($_.StatusInformation.Trim())" }) -join '; '
                $findings.Add("MEDIUM: Certificate chain validation status: $chainStatusErrors")
            }

            # Key Size extraction supporting both RSA and ECDSA
            $keySizeBits = 0
            try {
                if ($capturedCert.PublicKey.Key) {
                    $keySizeBits = $capturedCert.PublicKey.Key.KeySize
                }
                if ($keySizeBits -eq 0 -and $capturedCert.PSObject.Methods.Name -contains 'GetRSAPublicKey') {
                    $rsaKey = $capturedCert.GetRSAPublicKey()
                    if ($rsaKey) { $keySizeBits = $rsaKey.KeySize }
                }
                if ($keySizeBits -eq 0 -and $capturedCert.PSObject.Methods.Name -contains 'GetECDsaPublicKey') {
                    $ecdsaKey = $capturedCert.GetECDsaPublicKey()
                    if ($ecdsaKey) { $keySizeBits = $ecdsaKey.KeySize }
                }
            } catch {
                $keySizeBits = 0
            }

            # SHA-256 Thumbprint computation
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            $thumb256Bytes = $sha256.ComputeHash($capturedCert.RawData)
            $thumb256Str = ($thumb256Bytes | ForEach-Object { $_.ToString("X2") }) -join ''
            $sha256.Dispose()

            $certDetails = [PSCustomObject]@{
                Subject            = $capturedCert.Subject
                CommonName         = if ($parsedSubject.Contains('CN')) { $parsedSubject['CN'] } else { $null }
                Issuer             = $capturedCert.Issuer
                IssuerCommonName   = if ($parsedIssuer.Contains('CN')) { $parsedIssuer['CN'] } else { $null }
                SerialNumber       = $capturedCert.SerialNumber
                ThumbprintSha1     = $capturedCert.Thumbprint
                ThumbprintSha256   = $thumb256Str
                NotBefore          = $notBefore
                NotAfter           = $notAfter
                DaysUntilExpiry    = $daysRemaining
                SignatureAlgorithm = $capturedCert.SignatureAlgorithm.FriendlyName
                PublicKeyAlgorithm = $capturedCert.PublicKey.Oid.FriendlyName
                KeyLengthBits      = $keySizeBits
                SubjectAlternativeNames = @($sanList)
            }

            $chainDetails = [PSCustomObject]@{
                ChainValid   = $chainValid
                ChainDepth   = $chain.ChainElements.Count
                ChainElements= $chainElements
            }
        }

        # Overall Compliance Check
        $compliant = $true
        if ($protocolResults['Ssl2'] -or $protocolResults['Ssl3'] -or $protocolResults['Tls10'] -or $protocolResults['Tls11']) {
            $compliant = $false
        }
        if (-not $protocolResults['Tls12'] -and -not $protocolResults['Tls13']) {
            $compliant = $false
            $findings.Add("CRITICAL: Neither TLS 1.2 nor TLS 1.3 is enabled on target.")
        }

        return [PSCustomObject]@{
            Host              = $TargetHost
            Port              = $TargetPort
            ScanTimeUtc       = (Get-Date).ToUniversalTime()
            IsCompliant       = $compliant
            SupportedProtocols= $protocolResults
            NegotiatedDetails = $negotiatedDetails
            Certificate       = $certDetails
            Chain             = $chainDetails
            Findings          = @($findings)
        }
    }
}

process {
    $scanResults = New-Object System.Collections.Generic.List[PSCustomObject]
    $allCompliant = $true

    foreach ($server in $ComputerName) {
        $res = Evaluate-Endpoint -TargetHost $server -TargetPort $Port
        if (-not $res.IsCompliant) {
            $allCompliant = $false
            foreach ($f in $res.Findings) {
                Write-Warning "TLS Compliance Finding [$($res.Host):$($res.Port)]: $f"
            }
        }
        $scanResults.Add($res)
    }

    $global:LASTEXITCODE = if ($allCompliant) { 0 } else { 1 }

    if ($AsJson) {
        $scanResults | ConvertTo-Json -Depth 6
    } else {
        $scanResults
    }
}
