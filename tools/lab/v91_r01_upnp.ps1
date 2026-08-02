function Get-R01UpnpOwnershipDescription {
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-fA-F]{32}$')][string]$Nonce,
        [Parameter(Mandatory = $true)]
        [ValidateSet('SERVER', 'PROBE', 'PREFLIGHT')][string]$Role,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)][int]$ExternalPort,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)][int]$InternalPort,
        [Parameter(Mandatory = $true)][string]$InternalClient
    )
    $canonicalRole = $Role.ToUpperInvariant()
    $clientAddress = $null
    if (-not [Net.IPAddress]::TryParse(
            $InternalClient, [ref]$clientAddress) -or
        $clientAddress.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork -or
        $clientAddress.Equals([Net.IPAddress]::Any)) {
        throw 'R01 UPnP ownership requires a canonical IPv4 client.'
    }
    $roleCode = switch ($canonicalRole) {
        'SERVER' { 'S' }
        'PROBE' { 'P' }
        'PREFLIGHT' { 'F' }
        default { throw 'Unsupported R01 UPnP ownership role.' }
    }
    $canonical = 'ese.v91.r01-upnp/v1|{0}|{1}|TCP|{2}|{3}|{4}' -f
        $Nonce.ToLowerInvariant(), $canonicalRole, $ExternalPort,
        $InternalPort, $clientAddress.ToString()
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = (($sha.ComputeHash(
                    [Text.Encoding]::UTF8.GetBytes($canonical)) |
                ForEach-Object { $_.ToString('x2') }) -join '')
    } finally { $sha.Dispose() }
    # 31 characters and 96 bits of nonce-bound ownership evidence. Several
    # consumer IGDs reject descriptions longer than 32 characters.
    return "eR01-$roleCode-$($digest.Substring(0, 24))"
}

function ConvertFrom-R01UpnpXml {
    param([Parameter(Mandatory = $true)][string]$Text)
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = [Xml.XmlReader]::Create(
        [IO.StringReader]::new($Text), $settings)
    try {
        $document = [Xml.XmlDocument]::new()
        $document.XmlResolver = $null
        $document.Load($reader)
        return $document
    } finally { $reader.Dispose() }
}

function Assert-R01UpnpHttpUri {
    param(
        [Parameter(Mandatory = $true)][Uri]$Uri,
        [Parameter(Mandatory = $true)][string]$GatewayAddress
    )
    $gateway = $null
    $hostAddress = $null
    if (-not $Uri.IsAbsoluteUri -or $Uri.Scheme -cne 'http' -or
        -not [Net.IPAddress]::TryParse($GatewayAddress, [ref]$gateway) -or
        $gateway.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork -or
        -not [Net.IPAddress]::TryParse($Uri.Host, [ref]$hostAddress) -or
        -not $gateway.Equals($hostAddress) -or $Uri.Port -lt 1 -or
        $Uri.Port -gt 65535 -or -not [string]::IsNullOrEmpty($Uri.UserInfo) -or
        -not [string]::IsNullOrEmpty($Uri.Fragment)) {
        throw 'UPnP URI is not a safe HTTP endpoint on the selected gateway.'
    }
}

function Invoke-R01UpnpHttpRequest {
    param(
        [Parameter(Mandatory = $true)][Uri]$Uri,
        [Parameter(Mandatory = $true)][string]$LocalAddress,
        [Parameter(Mandatory = $true)][string]$GatewayAddress,
        [ValidateSet('GET', 'POST')][string]$Method = 'GET',
        [Collections.IDictionary]$Headers = @{},
        [string]$Body = '',
        [ValidateRange(500, 10000)][int]$TimeoutMilliseconds = 4000
    )
    Assert-R01UpnpHttpUri -Uri $Uri -GatewayAddress $GatewayAddress
    $localIp = $null
    if (-not [Net.IPAddress]::TryParse($LocalAddress, [ref]$localIp) -or
        $localIp.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork -or
        $localIp.Equals([Net.IPAddress]::Any)) {
        throw 'UPnP HTTP requires an explicit local IPv4 source.'
    }
    $request = [Net.HttpWebRequest]::Create($Uri)
    $request.Method = $Method
    $request.Proxy = $null
    $request.AllowAutoRedirect = $false
    $request.KeepAlive = $false
    $request.Pipelined = $false
    $request.ConnectionGroupName = 'ese-r01-' +
        [Guid]::NewGuid().ToString('N')
    $request.ProtocolVersion = [Version]'1.1'
    $request.ServicePoint.Expect100Continue = $false
    $request.AllowWriteStreamBuffering = $true
    $request.SendChunked = $false
    $request.UserAgent = 'Windows/10.0 UPnP/1.1 eSE-R01/1.0'
    $request.Timeout = $TimeoutMilliseconds
    $request.ReadWriteTimeout = $TimeoutMilliseconds
    # HttpWebRequest rejects zero even when redirects are disabled.
    $request.MaximumAutomaticRedirections = 1
    $request.AutomaticDecompression = [Net.DecompressionMethods]::None
    foreach ($entry in $Headers.GetEnumerator()) {
        $request.Headers.Add([string]$entry.Key, [string]$entry.Value)
    }
    $bindScript = {
        param($servicePoint, $remoteEndPoint, $retryCount)
        return [Net.IPEndPoint]::new($localIp, 0)
    }.GetNewClosure()
    $bindDelegate = [Net.BindIPEndPoint]$bindScript
    $servicePoint = $request.ServicePoint
    $previousBindDelegate = $servicePoint.BindIPEndPointDelegate
    if ($null -ne $previousBindDelegate) {
        throw 'UPnP HTTP endpoint already has an unowned source-binding delegate.'
    }
    $servicePoint.BindIPEndPointDelegate = $bindDelegate
    $absoluteDeadline = [DateTimeOffset]::UtcNow.AddMilliseconds(
        $TimeoutMilliseconds)
    $response = $null
    try {
        if ($Method -ceq 'POST') {
            $bodyBytes = [Text.Encoding]::UTF8.GetBytes($Body)
            if ($bodyBytes.Length -gt 262144) {
                throw 'UPnP request body exceeds the bounded size.'
            }
            $request.ContentType = 'text/xml; charset="utf-8"'
            $request.ContentLength = $bodyBytes.Length
            $requestStream = $request.GetRequestStream()
            try {
                $requestStream.Write($bodyBytes, 0, $bodyBytes.Length)
            } finally { $requestStream.Dispose() }
        }
        try {
            $response = [Net.HttpWebResponse]$request.GetResponse()
        } catch [Net.WebException] {
            if ($null -eq $_.Exception.Response) { throw }
            $response = [Net.HttpWebResponse]$_.Exception.Response
        }
        $stream = $response.GetResponseStream()
        try {
            $reader = [IO.StreamReader]::new(
                $stream, [Text.Encoding]::UTF8, $true, 4096, $true)
            try {
                $builder = [Text.StringBuilder]::new()
                $buffer = New-Object char[] 4096
                while ($true) {
                    $remaining = $absoluteDeadline - [DateTimeOffset]::UtcNow
                    if ($remaining.TotalMilliseconds -le 0) {
                        throw 'UPnP HTTP response exceeded its absolute deadline.'
                    }
                    if ($stream.CanTimeout) {
                        $stream.ReadTimeout = [Math]::Max(1, [Math]::Min(
                                $TimeoutMilliseconds,
                                [int][Math]::Ceiling(
                                    $remaining.TotalMilliseconds)))
                    }
                    $read = $reader.Read($buffer, 0, $buffer.Length)
                    if ($read -le 0) { break }
                    if ([DateTimeOffset]::UtcNow -gt $absoluteDeadline) {
                        throw 'UPnP HTTP response exceeded its absolute deadline.'
                    }
                    $null = $builder.Append($buffer, 0, $read)
                    if ($builder.Length -gt 1048576) {
                        throw 'UPnP response exceeds the bounded size.'
                    }
                }
                $responseBody = $builder.ToString()
            }
            finally { $reader.Dispose() }
        } finally { $stream.Dispose() }
        return [pscustomobject][ordered]@{
            status_code = [int]$response.StatusCode
            body = $responseBody
        }
    } finally {
        if ($null -ne $response) { $response.Dispose() }
        if ([object]::ReferenceEquals(
                $servicePoint.BindIPEndPointDelegate, $bindDelegate)) {
            $servicePoint.BindIPEndPointDelegate = $previousBindDelegate
        }
    }
}

function Get-R01UpnpSoapFaultCode {
    param([Parameter(Mandatory = $true)]$Response)
    if ([int]$Response.status_code -ne 500 -or
        [string]::IsNullOrWhiteSpace([string]$Response.body)) {
        return $null
    }
    try {
        $document = ConvertFrom-R01UpnpXml -Text ([string]$Response.body)
        $namespaces = [Xml.XmlNamespaceManager]::new($document.NameTable)
        $namespaces.AddNamespace(
            's', 'http://schemas.xmlsoap.org/soap/envelope/')
        $namespaces.AddNamespace(
            'u', 'urn:schemas-upnp-org:control-1-0')
        $bodies = @($document.SelectNodes(
                '/s:Envelope/s:Body', $namespaces))
        if ($bodies.Count -ne 1) { return $null }
        $bodyElements = @($bodies[0].ChildNodes | Where-Object {
                $_.NodeType -eq [Xml.XmlNodeType]::Element
            })
        $faults = @($document.SelectNodes(
                '/s:Envelope/s:Body/s:Fault', $namespaces))
        if ($faults.Count -ne 1 -or $bodyElements.Count -ne 1 -or
            -not [object]::ReferenceEquals($faults[0], $bodyElements[0])) {
            return $null
        }
        $faultCodes = @($faults[0].SelectNodes('./faultcode'))
        $faultStrings = @($faults[0].SelectNodes('./faultstring'))
        if ($faultCodes.Count -ne 1 -or $faultStrings.Count -ne 1 -or
            ([string]$faultStrings[0].InnerText) -cne 'UPnPError') {
            return $null
        }
        $faultCodeText = [string]$faultCodes[0].InnerText
        if ($faultCodeText -cnotmatch
            '^([A-Za-z_][A-Za-z0-9_.-]*):Client$' -or
            [string]$faults[0].GetNamespaceOfPrefix($Matches[1]) -cne
                'http://schemas.xmlsoap.org/soap/envelope/') {
            return $null
        }
        $details = @($faults[0].SelectNodes('./detail'))
        if ($details.Count -ne 1) { return $null }
        $upnpErrors = @($details[0].SelectNodes('./u:UPnPError', $namespaces))
        $allUpnpErrors = @($document.SelectNodes('//u:UPnPError', $namespaces))
        if ($upnpErrors.Count -ne 1 -or $allUpnpErrors.Count -ne 1) {
            return $null
        }
        $nodes = @($upnpErrors[0].SelectNodes('./u:errorCode', $namespaces))
        $allCodes = @($document.SelectNodes('//u:errorCode', $namespaces))
        if ($nodes.Count -ne 1 -or $allCodes.Count -ne 1) { return $null }
        $text = [string]$nodes[0].InnerText
        if ($text -cnotmatch '^[0-9]{3}$') { return $null }
        $code = 0
        if ([int]::TryParse($text, [ref]$code) -and
            $code -ge 400 -and $code -le 899) {
            return $code
        }
    } catch {}
    return $null
}

function Get-R01UpnpSoapResponseElement {
    param(
        [Parameter(Mandatory = $true)]$Backend,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9]+$')][string]$Action,
        [Parameter(Mandatory = $true)]$Response
    )
    if ([string]$Backend.kind -cne 'soap' -or
        [string]$Backend.service_type -notmatch
            '^urn:schemas-upnp-org:service:(WANIP|WANPPP)Connection:[0-9]+$' -or
        [int]$Response.status_code -ne 200) {
        throw "UPnP $Action did not return a valid SOAP success response."
    }
    $document = ConvertFrom-R01UpnpXml -Text ([string]$Response.body)
    $namespaces = [Xml.XmlNamespaceManager]::new($document.NameTable)
    $namespaces.AddNamespace(
        's', 'http://schemas.xmlsoap.org/soap/envelope/')
    $namespaces.AddNamespace('u', [string]$Backend.service_type)
    $bodies = @($document.SelectNodes('/s:Envelope/s:Body', $namespaces))
    if ($bodies.Count -ne 1) {
        throw "UPnP $Action response did not contain one SOAP Body."
    }
    $bodyElements = @($bodies[0].ChildNodes | Where-Object {
            $_.NodeType -eq [Xml.XmlNodeType]::Element
        })
    $responses = @($document.SelectNodes(
            "/s:Envelope/s:Body/u:${Action}Response", $namespaces))
    if ($responses.Count -ne 1 -or $bodyElements.Count -ne 1 -or
        -not [object]::ReferenceEquals($responses[0], $bodyElements[0])) {
        throw "UPnP $Action response wrapper is invalid or ambiguous."
    }
    return [pscustomobject][ordered]@{
        element = $responses[0]
        namespaces = $namespaces
    }
}

function Get-R01UpnpSoapChildValue {
    param(
        [Parameter(Mandatory = $true)]$ResponseElement,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^New[A-Za-z0-9]+$')][string]$Name,
        [switch]$AllowEmpty
    )
    $nodes = @($ResponseElement.element.SelectNodes(
            "./*[namespace-uri()='' and local-name()='$Name']"))
    if ($nodes.Count -ne 1) {
        throw "UPnP response did not contain exactly one $Name child."
    }
    $value = [string]$nodes[0].InnerText
    if (-not $AllowEmpty -and [string]::IsNullOrWhiteSpace($value)) {
        throw "UPnP response contained an empty $Name value."
    }
    return $value
}

function Invoke-R01UpnpSoapAction {
    param(
        [Parameter(Mandatory = $true)]$Backend,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9]+$')][string]$Action,
        [Parameter(Mandatory = $true)]
        [Collections.IDictionary]$Arguments
    )
    if ([string]$Backend.kind -cne 'soap') {
        throw 'SOAP action received a non-SOAP UPnP backend.'
    }
    $argumentXml = [Text.StringBuilder]::new()
    foreach ($entry in $Arguments.GetEnumerator()) {
        $name = [string]$entry.Key
        if ($name -notmatch '^New[A-Za-z0-9]+$') {
            throw 'UPnP SOAP argument name is not allowed.'
        }
        $escaped = [Security.SecurityElement]::Escape([string]$entry.Value)
        $null = $argumentXml.Append(
            "<$name>$escaped</$name>")
    }
    $serviceType = [string]$Backend.service_type
    $escapedService = [Security.SecurityElement]::Escape($serviceType)
    $body = "<?xml version=`"1.0`"?>`r`n" +
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ' +
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' +
        '<s:Body>' +
        ('<u:{0} xmlns:u="{1}">' -f $Action, $escapedService) +
        $argumentXml.ToString() +
        ('</u:{0}></s:Body></s:Envelope>' -f $Action) + "`r`n"
    return Invoke-R01UpnpHttpRequest -Uri ([Uri]$Backend.control_uri) `
        -LocalAddress ([string]$Backend.local_address) `
        -GatewayAddress ([string]$Backend.gateway_address) -Method POST `
        -Headers ([ordered]@{
            SOAPAction = '"{0}#{1}"' -f $serviceType, $Action
        }) -Body $body
}

function Find-R01UpnpSoapBackend {
    param(
        [Parameter(Mandatory = $true)][string]$LocalAddress,
        [Parameter(Mandatory = $true)][string]$GatewayAddress
    )
    $localIp = $null
    $gatewayIp = $null
    if (-not [Net.IPAddress]::TryParse($LocalAddress, [ref]$localIp) -or
        $localIp.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork -or
        -not [Net.IPAddress]::TryParse($GatewayAddress, [ref]$gatewayIp) -or
        $gatewayIp.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'R01 SOAP discovery requires explicit IPv4 literals.'
    }
    $locations = [Collections.Generic.List[string]]::new()
    $client = [Net.Sockets.UdpClient]::new(
        [Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $client.Client.Bind([Net.IPEndPoint]::new($localIp, 0))
        $client.Client.ReceiveTimeout = 450
        $destination = [Net.IPEndPoint]::new(
            [Net.IPAddress]::Parse('239.255.255.250'), 1900)
        $requestText = "M-SEARCH * HTTP/1.1`r`n" +
            "HOST: 239.255.255.250:1900`r`n" +
            "MAN: `"ssdp:discover`"`r`n" +
            "MX: 1`r`n" +
            "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1`r`n`r`n"
        $requestBytes = [Text.Encoding]::ASCII.GetBytes($requestText)
        for ($attempt = 0; $attempt -lt 3; $attempt++) {
            $null = $client.Send(
                $requestBytes, $requestBytes.Length, $destination)
            $deadline = [DateTimeOffset]::UtcNow.AddMilliseconds(1200)
            while ([DateTimeOffset]::UtcNow -lt $deadline) {
                $sender = [Net.IPEndPoint]::new(
                    [Net.IPAddress]::Any, 0)
                try { $bytes = $client.Receive([ref]$sender) }
                catch [Net.Sockets.SocketException] { continue }
                if (-not $gatewayIp.Equals($sender.Address)) { continue }
                if ($bytes.Length -gt 8192) { continue }
                $text = [Text.Encoding]::ASCII.GetString($bytes)
                if ($text -notmatch '(?i)^HTTP/1\.[01]\s+200(?:\s|$)') {
                    continue
                }
                $match = [regex]::Match(
                    $text, '(?im)^\s*LOCATION\s*:\s*(\S+)\s*$')
                if ($match.Success) {
                    $locations.Add($match.Groups[1].Value.Trim())
                }
            }
            if ($locations.Count -gt 0) { break }
        }
    } finally { $client.Dispose() }
    $uniqueLocations = @($locations.ToArray() | Select-Object -Unique)
    if ($uniqueLocations.Count -eq 0) {
        throw 'Selected gateway did not answer direct IGD SSDP discovery.'
    }
    $candidates = [Collections.Generic.List[object]]::new()
    foreach ($locationText in $uniqueLocations) {
        $location = $null
        if (-not [Uri]::TryCreate(
                $locationText, [UriKind]::Absolute, [ref]$location)) {
            continue
        }
        try {
            Assert-R01UpnpHttpUri -Uri $location `
                -GatewayAddress $GatewayAddress
            $descriptorResponse = Invoke-R01UpnpHttpRequest -Uri $location `
                -LocalAddress $LocalAddress `
                -GatewayAddress $GatewayAddress
            if ([int]$descriptorResponse.status_code -ne 200) { continue }
            $document = ConvertFrom-R01UpnpXml `
                -Text ([string]$descriptorResponse.body)
            $services = @($document.SelectNodes(
                    "//*[local-name()='service']"))
            foreach ($service in $services) {
                $typeNodes = @($service.SelectNodes(
                        "./*[local-name()='serviceType']"))
                $controlNodes = @($service.SelectNodes(
                        "./*[local-name()='controlURL']"))
                if ($typeNodes.Count -ne 1 -or $controlNodes.Count -ne 1) {
                    continue
                }
                $serviceType = [string]$typeNodes[0].InnerText
                if ($serviceType -notmatch
                    '^urn:schemas-upnp-org:service:(WANIP|WANPPP)Connection:([0-9]+)$') {
                    continue
                }
                $serviceFamily = [string]$Matches[1]
                $serviceVersion = [int]$Matches[2]
                $controlUri = [Uri]::new(
                    $location, [string]$controlNodes[0].InnerText)
                Assert-R01UpnpHttpUri -Uri $controlUri `
                    -GatewayAddress $GatewayAddress
                $candidates.Add([pscustomobject][ordered]@{
                        kind = 'soap'
                        local_address = $LocalAddress
                        gateway_address = $GatewayAddress
                        control_uri = $controlUri.AbsoluteUri
                        service_type = $serviceType
                        service_family = $serviceFamily
                        service_version = $serviceVersion
                    })
            }
        } catch { continue }
    }
    $wanIp = @($candidates.ToArray() | Where-Object {
            [string]$_.service_family -ceq 'WANIP'
        } | Sort-Object service_version -Descending)
    if ($wanIp.Count -gt 0) {
        $eligible = @($wanIp)
    } else {
        $eligible = @($candidates.ToArray() |
            Sort-Object service_version -Descending)
    }
    if ($eligible.Count -eq 0) {
        throw 'IGD descriptor did not expose a safe WAN mapping service.'
    }
    $endpointKeys = @($eligible | ForEach-Object {
            '{0}|{1}' -f [string]$_.control_uri, [string]$_.service_type
        } | Select-Object -Unique)
    if ($endpointKeys.Count -ne 1) {
        throw 'IGD discovery exposed an ambiguous WAN mapping service.'
    }
    return $eligible[0]
}

function New-R01UpnpBackend {
    param(
        [Parameter(Mandatory = $true)][string]$LocalAddress,
        [Parameter(Mandatory = $true)][string]$GatewayAddress
    )
    # The Windows COM facade does not expose enough identity to prove that its
    # collection belongs to the physical route selected above. Formal R01 uses
    # only gateway-scoped SOAP; COM remains a unit-tested lifecycle adapter.
    return Find-R01UpnpSoapBackend -LocalAddress $LocalAddress `
        -GatewayAddress $GatewayAddress
}

function Get-R01UpnpSoapExternalAddress {
    param([Parameter(Mandatory = $true)]$Backend)
    $response = Invoke-R01UpnpSoapAction -Backend $Backend `
        -Action GetExternalIPAddress -Arguments ([ordered]@{})
    $element = Get-R01UpnpSoapResponseElement -Backend $Backend `
        -Action GetExternalIPAddress -Response $response
    $children = @($element.element.ChildNodes | Where-Object {
            $_.NodeType -eq [Xml.XmlNodeType]::Element
        })
    if ($children.Count -ne 1 -or
        [string]$children[0].LocalName -cne 'NewExternalIPAddress' -or
        [string]$children[0].NamespaceURI -cne '') {
        throw 'UPnP GetExternalIPAddress response fields are invalid.'
    }
    return Get-R01UpnpSoapChildValue -ResponseElement $element `
        -Name NewExternalIPAddress -AllowEmpty
}

function Get-R01UpnpMapping {
    param(
        [Parameter(Mandatory = $true)]$Backend,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)][int]$ExternalPort
    )
    if ([string]$Backend.kind -ceq 'com') {
        try { $mapping = $Backend.mappings.Item($ExternalPort, 'TCP') }
        catch {
            throw 'UPnP COM mapping lookup failed; absence is unproven.'
        }
        if ($null -eq $mapping) { return $null }
        return [pscustomobject][ordered]@{
            Description = [string]$mapping.Description
            InternalClient = [string]$mapping.InternalClient
            InternalPort = [int]$mapping.InternalPort
            Enabled = [bool]$mapping.Enabled
            ExternalIPAddress = [string]$mapping.ExternalIPAddress
        }
    }
    if ([string]$Backend.kind -cne 'soap') {
        throw 'Unknown R01 UPnP backend.'
    }
    $response = Invoke-R01UpnpSoapAction -Backend $Backend `
        -Action GetSpecificPortMappingEntry -Arguments ([ordered]@{
            NewRemoteHost = ''
            NewExternalPort = $ExternalPort
            NewProtocol = 'TCP'
        })
    if ([int]$response.status_code -ne 200) {
        if ((Get-R01UpnpSoapFaultCode -Response $response) -eq 714) {
            return $null
        }
        throw 'UPnP GetSpecificPortMappingEntry failed unexpectedly.'
    }
    $element = Get-R01UpnpSoapResponseElement -Backend $Backend `
        -Action GetSpecificPortMappingEntry -Response $response
    $children = @($element.element.ChildNodes | Where-Object {
            $_.NodeType -eq [Xml.XmlNodeType]::Element
        })
    $expectedNames = @(
        'NewEnabled', 'NewInternalClient', 'NewInternalPort',
        'NewLeaseDuration', 'NewPortMappingDescription'
    )
    $actualNames = @($children | ForEach-Object {
            if ([string]$_.NamespaceURI -cne '') {
                throw 'UPnP mapping response field namespace is invalid.'
            }
            [string]$_.LocalName
        } | Sort-Object)
    if ($children.Count -ne $expectedNames.Count -or
        @(Compare-Object -ReferenceObject $expectedNames `
            -DifferenceObject $actualNames).Count -ne 0) {
        throw 'UPnP mapping response fields are invalid or ambiguous.'
    }
    $internalPortText = Get-R01UpnpSoapChildValue `
        -ResponseElement $element -Name NewInternalPort
    $internalPort = 0
    if (-not [int]::TryParse($internalPortText, [ref]$internalPort) -or
        $internalPort -lt 1 -or $internalPort -gt 65535) {
        throw 'UPnP returned an invalid internal port.'
    }
    $enabledText = Get-R01UpnpSoapChildValue `
        -ResponseElement $element -Name NewEnabled
    if ($enabledText -notin @('1', 'true')) {
        throw 'UPnP returned a disabled or invalid mapping.'
    }
    $leaseText = Get-R01UpnpSoapChildValue `
        -ResponseElement $element -Name NewLeaseDuration
    $lease = [uint32]0
    if (-not [uint32]::TryParse($leaseText, [ref]$lease)) {
        throw 'UPnP returned an invalid mapping lease duration.'
    }
    return [pscustomobject][ordered]@{
        Description = Get-R01UpnpSoapChildValue `
            -ResponseElement $element -Name NewPortMappingDescription `
            -AllowEmpty
        InternalClient = Get-R01UpnpSoapChildValue `
            -ResponseElement $element -Name NewInternalClient
        InternalPort = $internalPort
        Enabled = $true
        ExternalIPAddress = ''
    }
}

function Add-R01UpnpMapping {
    param(
        [Parameter(Mandatory = $true)]$Backend,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)][int]$ExternalPort,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)][int]$InternalPort,
        [Parameter(Mandatory = $true)][string]$InternalClient,
        [Parameter(Mandatory = $true)][string]$Description
    )
    if ($Description.Length -gt 32) {
        throw 'R01 refuses UPnP descriptions longer than 32 characters.'
    }
    if ([string]$Backend.kind -ceq 'com') {
        $created = $Backend.mappings.Add(
            $ExternalPort, 'TCP', $InternalPort, $InternalClient, $true,
            $Description)
        if ($null -eq $created) { return $null }
        return [pscustomobject][ordered]@{
            Description = [string]$created.Description
            InternalClient = [string]$created.InternalClient
            InternalPort = [int]$created.InternalPort
            Enabled = [bool]$created.Enabled
            ExternalIPAddress = [string]$created.ExternalIPAddress
        }
    }
    if ([string]$Backend.kind -cne 'soap') {
        throw 'Unknown R01 UPnP backend.'
    }
    $response = Invoke-R01UpnpSoapAction -Backend $Backend `
        -Action AddPortMapping -Arguments ([ordered]@{
            NewRemoteHost = ''
            NewExternalPort = $ExternalPort
            NewProtocol = 'TCP'
            NewInternalPort = $InternalPort
            NewInternalClient = $InternalClient
            NewEnabled = '1'
            NewPortMappingDescription = $Description
            NewLeaseDuration = '0'
        })
    if ([int]$response.status_code -ne 200) {
        $fault = Get-R01UpnpSoapFaultCode -Response $response
        throw "UPnP AddPortMapping failed with fault $fault."
    }
    $created = Get-R01UpnpMapping -Backend $Backend `
        -ExternalPort $ExternalPort
    if ($null -ne $created) {
        $created.ExternalIPAddress = Get-R01UpnpSoapExternalAddress `
            -Backend $Backend
    }
    return $created
}

function Remove-R01UpnpMapping {
    param(
        [Parameter(Mandatory = $true)]$Backend,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)][int]$ExternalPort
    )
    if ([string]$Backend.kind -ceq 'com') {
        $Backend.mappings.Remove($ExternalPort, 'TCP')
        return
    }
    if ([string]$Backend.kind -cne 'soap') {
        throw 'Unknown R01 UPnP backend.'
    }
    $response = Invoke-R01UpnpSoapAction -Backend $Backend `
        -Action DeletePortMapping -Arguments ([ordered]@{
            NewRemoteHost = ''
            NewExternalPort = $ExternalPort
            NewProtocol = 'TCP'
        })
    if ([int]$response.status_code -ne 200) {
        $fault = Get-R01UpnpSoapFaultCode -Response $response
        throw "UPnP DeletePortMapping failed with fault $fault."
    }
}
