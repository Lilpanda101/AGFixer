#Requires -Version 5.1
function ConvertTo-AGRoutePrefix {
    param([string]$Prefix)
    $parts=$Prefix.Split('/')
    $network=$null;$length=0
    if($parts.Count -ne 2 -or -not [Net.IPAddress]::TryParse($parts[0],[ref]$network) -or -not [int]::TryParse($parts[1],[ref]$length)){return $null}
    $bytes=$network.GetAddressBytes()
    if($length -lt 0 -or $length -gt ($bytes.Length*8)){return $null}
    return [pscustomobject]@{Bytes=$bytes;Length=$length;Family=if($bytes.Length -eq 4){'IPv4'}else{'IPv6'}}
}
function Test-AGAddressInPrefix {
    param([byte[]]$AddressBytes,$Prefix)
    if($AddressBytes.Length -ne $Prefix.Bytes.Length){return $false}
    $remaining=$Prefix.Length
    for($position=0;$remaining -gt 0;$position++){
        $bits=[Math]::Min(8,$remaining);$mask=(255 -shl (8-$bits)) -band 255
        if(($AddressBytes[$position] -band $mask) -ne ($Prefix.Bytes[$position] -band $mask)){return $false}
        $remaining-=$bits
    }
    return $true
}
function Resolve-AGDestinationRoute {
    param([Net.IPAddress]$Destination,[object[]]$Routes,[object[]]$Interfaces,[int[]]$VpnIndices,[bool]$RoutesKnown=$true)
    $result=[ordered]@{Destination=[string]$Destination;State='Unknown';InterfaceIndex=$null;PrefixLength=$null;EffectiveMetric=$null;Reason='Route table unavailable';Candidates=@()}
    if(-not $RoutesKnown -or -not $Destination){return [pscustomobject]$result}
    $bytes=$Destination.GetAddressBytes();$family=if($bytes.Length -eq 4){'IPv4'}else{'IPv6'}
    $candidates=New-Object 'Collections.Generic.List[object]'
    foreach($route in @($Routes)){
        if([string]$route.State -in @('Dead','Invalid')){continue}
        $prefix=ConvertTo-AGRoutePrefix ([string]$route.DestinationPrefix)
        if(-not $prefix){$result.Reason='Malformed route prefix';return [pscustomobject]$result}
        if(-not (Test-AGAddressInPrefix $bytes $prefix)){continue}
        $candidates.Add([pscustomobject]@{Route=$route;Length=$prefix.Length})
    }
    if(-not $candidates.Count){$result.State='NoRoute';$result.Reason='No matching route';return [pscustomobject]$result}
    $longest=($candidates|Measure-Object Length -Maximum).Maximum
    $result.PrefixLength=[int]$longest
    $ranked=New-Object 'Collections.Generic.List[object]'
    foreach($candidate in @($candidates|Where-Object Length -eq $longest)){
        $route=$candidate.Route;$index=0;$routeMetric=0L;$interfaceMetric=0L
        $iface=@($Interfaces|Where-Object { $_.InterfaceIndex -eq $route.InterfaceIndex -and [string]$_.AddressFamily -in @($family, $(if($family -eq 'IPv4'){'2'}else{'23'})) })
        if($null -eq $route.InterfaceIndex -or -not [int]::TryParse([string]$route.InterfaceIndex,[ref]$index) -or $index -le 0 -or $iface.Count -ne 1 -or $null -eq $route.RouteMetric -or -not [long]::TryParse([string]$route.RouteMetric,[ref]$routeMetric) -or $routeMetric -lt 0 -or $null -eq $iface[0].InterfaceMetric -or -not [long]::TryParse([string]$iface[0].InterfaceMetric,[ref]$interfaceMetric) -or $interfaceMetric -lt 0 -or $routeMetric -gt ([long]::MaxValue-$interfaceMetric)){
            $result.Reason='Matching competitor has missing/invalid interface or metric';return [pscustomobject]$result
        }
        $ranked.Add([pscustomobject]@{InterfaceIndex=$index;EffectiveMetric=($routeMetric+$interfaceMetric);Prefix=[string]$route.DestinationPrefix;ViaVpn=($index -in $VpnIndices)})
    }
    $best=($ranked|Measure-Object EffectiveMetric -Minimum).Minimum
    $winners=@($ranked|Where-Object EffectiveMetric -eq $best)
    $result.Candidates=$winners;$result.EffectiveMetric=[long]$best
    if(@($winners.InterfaceIndex|Select-Object -Unique).Count -ne 1){$result.State='Ambiguous';$result.Reason='Equal-cost routes across interfaces';return [pscustomobject]$result}
    $result.InterfaceIndex=$winners[0].InterfaceIndex
    $result.State=if($winners[0].ViaVpn){'ViaVpn'}else{'ViaOther'}
    $result.Reason='Longest prefix, then RouteMetric + InterfaceMetric'
    return [pscustomobject]$result
}
function Get-AGVpnRouteConfiguration {
    param([object[]]$Routes,[object[]]$Interfaces,[int[]]$VpnIndices,[ValidateSet('IPv4','IPv6')][string]$AddressFamily,[bool]$RoutesKnown=$true)
    $configurationRoutes=@($Routes|Where-Object { $parsed=ConvertTo-AGRoutePrefix ([string]$_.DestinationPrefix); -not $parsed -or ($parsed.Family -eq $AddressFamily -and $parsed.Length -le 1) })
    $addresses=if($AddressFamily -eq 'IPv4'){@('0.0.0.0','128.0.0.0')}else{@('::','8000::')}
    $halves=@(foreach($address in $addresses){Resolve-AGDestinationRoute -Destination $address -Routes $configurationRoutes -Interfaces $Interfaces -VpnIndices $VpnIndices -RoutesKnown $RoutesKnown})
    $state=if('Unknown' -in @($halves.State)){'Unknown'}elseif('Ambiguous' -in @($halves.State)){'Ambiguous'}elseif(@($halves|Where-Object State -eq ViaVpn).Count -eq 2){'ViaVpn'}elseif('ViaVpn' -in @($halves.State)){'Partial'}elseif(@($halves|Where-Object State -eq NoRoute).Count -eq 2){'NoRoute'}else{'ViaOther'}
    $hasVpnDefault=[bool]($RoutesKnown -and @($configurationRoutes|Where-Object {$_.InterfaceIndex -in $VpnIndices -and [string]$_.State -notin @('Dead','Invalid')}).Count)
    return [pscustomobject]@{AddressFamily=$AddressFamily;State=$state;HasVpnDefaultOrSplit=$hasVpnDefault;Halves=$halves;Scope='Default/split-default configuration only; not every destination or application'}
}
function Test-AGVpnRouteVia {
    param([object[]]$Routes,[object[]]$Interfaces,[int[]]$VpnIndices,[string]$Prefix)
    $parsed=ConvertTo-AGRoutePrefix $Prefix
    if(-not $parsed){return $false}
    if($parsed.Length -eq 0){return ((Get-AGVpnRouteConfiguration -Routes $Routes -Interfaces $Interfaces -VpnIndices $VpnIndices -AddressFamily $parsed.Family).State -eq 'ViaVpn')}
    $eligible=@($Routes|Where-Object { $candidate=ConvertTo-AGRoutePrefix ([string]$_.DestinationPrefix); $candidate -and $candidate.Length -le $parsed.Length })
    return ((Resolve-AGDestinationRoute -Destination $Prefix.Split('/')[0] -Routes $eligible -Interfaces $Interfaces -VpnIndices $VpnIndices).State -eq 'ViaVpn')
}
function Test-AGVpnRoutePrefix {
    param([object[]]$Routes,[object[]]$Interfaces,[int[]]$VpnIndices,[string]$Prefix)
    return (Test-AGVpnRouteVia $Routes $Interfaces $VpnIndices $Prefix)
}
function Test-AGConnectionVpnRouteVia {
    param([object[]]$Routes,[object[]]$Interfaces,[int[]]$VpnIndices,[string]$Prefix)
    return (Test-AGVpnRouteVia $Routes $Interfaces $VpnIndices $Prefix)
}
function Get-AGSuggestedRepairMode {
    param($Vpn,[bool]$ZapretRunning)
    if(-not $Vpn){return ''}
    if($Vpn.State -eq 'NotDetected' -and $ZapretRunning -and $Vpn.RouteKnown){return 'Zapret'}
    $destinations=@($Vpn.DestinationRoutes|Where-Object { $_ -and $_.Destination })
    if(-not $ZapretRunning -and $destinations.Count -and -not @($destinations|Where-Object State -ne ViaVpn).Count){return 'VpnDirect'}
    return ''
}
function Get-AGWindowsDestinationRoute {
    param([Net.IPAddress]$Destination)
    try{
        $routes=@(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop)
        $interfaces=@(Get-NetIPInterface -ErrorAction Stop)
        $indices=@(Get-NetAdapter -ErrorAction Stop|Where-Object { [string]$_.Status -eq 'Up' -and ([string]$_.InterfaceDescription+' '+[string]$_.Name) -match '(?i)wireguard|wintun|\btun\b|vpn|sing-box|mihomo|clash|amnezia|openvpn|outline|warp|tailscale|tap-windows' }|ForEach-Object { [int]$_.InterfaceIndex })
        $result=Resolve-AGDestinationRoute -Destination $Destination -Routes $routes -Interfaces $interfaces -VpnIndices $indices
        $native=@(Find-NetRoute -RemoteIPAddress ([string]$Destination) -ErrorAction Stop|Where-Object { $_.PSObject.Properties['DestinationPrefix'] })
        if($native.Count -ne 1 -or ($result.InterfaceIndex -and $result.InterfaceIndex -ne $native[0].InterfaceIndex) -or ($result.PrefixLength -ne $null -and (ConvertTo-AGRoutePrefix ([string]$native[0].DestinationPrefix)).Length -ne $result.PrefixLength)){$result.State='Unknown';$result.Reason='Windows selection unavailable or snapshot changed'}
        $result|Add-Member NoteProperty WindowsSelectionChecked $true
        return $result
    }catch{return [pscustomobject]@{Destination=[string]$Destination;State='Unknown';Reason='Windows route selection unavailable';WindowsSelectionChecked=$false}}
}
