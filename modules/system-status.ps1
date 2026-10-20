#Requires -Version 5.1
. "$PSScriptRoot/route-selection.ps1"
function ConvertTo-AGCommandTokens {
    param([string]$Command)
    return @([regex]::Matches($Command,'(?:"[^"]*"|[^\s"])+')|ForEach-Object{$_.Value.Replace('"','').Replace('/','\').ToLowerInvariant()})
}
function Get-AGRunningStrategy {
    param([string]$Root,[string[]]$Commands)
    if(-not $Root -or -not $Commands.Count){return 'не определена'}
    $strategyMatches=New-Object 'System.Collections.Generic.List[string]'
    foreach($file in @(Get-ChildItem -LiteralPath $Root -File -Filter '*.bat' -ErrorAction SilentlyContinue|Where-Object{$_.Name -match '^(?i)general(?: |\.)'}|Select-Object -First 100)){
        try{
            $candidate=@(ConvertTo-AGCommandTokens (Get-StrategyCommand $Root $file.Name))
            foreach($command in $Commands){$actual=@(ConvertTo-AGCommandTokens $command)
                if(($candidate -join "`n") -ceq ($actual -join "`n")){$strategyMatches.Add($file.BaseName);break}
            }
        }catch{}
    }
    $names=@($strategyMatches.ToArray()|Select-Object -Unique)
    if($names.Count -eq 1){return $names[0]}
    if($names.Count -gt 1){return ('одинаковые аргументы: '+($names -join ', '))}
    return 'не определена (аргументы не совпали)'
}
function Get-AGVpnStatus {
    param([object[]]$Processes,[object[]]$Adapters,[bool]$AdaptersKnown=$true,[object[]]$Routes=@(),[object[]]$Interfaces=@(),[bool]$RoutesKnown=$false,[object[]]$DestinationRoutes=@())
    $map=@{
        'throne'='Throne';'flclash'='FlClash';'clash-nyanpasu'='Clash Nyanpasu';'clash nyanpasu'='Clash Nyanpasu';'gui.for.singbox'='GUI.for.SingBox';'happ'='Happ';'amnezia'='Amnezia VPN';'amneziawg'='AmneziaWG';'openvpnconnect'='OpenVPN Connect';'ovpnconnector'='OpenVPN Connect';'protonvpn.client'='Proton VPN';'v2rayn'='v2rayN';'v2ray'='v2ray';'xray'='Xray';'nekoray'='NekoRay';'nekobox'='NekoBox';'hiddify'='Hiddify';'sing-box'='sing-box';'mihomo'='Mihomo';'clash'='Clash';'clash-verge'='Clash Verge';'verge-mihomo'='Clash Verge/Mihomo';'wireguard'='WireGuard';'wireguardmanager'='WireGuard';'openvpn'='OpenVPN';'openvpn-gui'='OpenVPN';'amneziavpn'='Amnezia VPN';'amnezia-service'='Amnezia VPN';'outline'='Outline';'protonvpn'='Proton VPN';'protonvpn.service'='Proton VPN';'warp-svc'='Cloudflare WARP';'warp'='Cloudflare WARP';'forticlient'='FortiClient';'tailscale'='Tailscale';'nordvpn'='NordVPN';'vpnui'='Cisco VPN';'nekoray_core'='NekoRay core'
    }
    $clients=@(foreach($p in $Processes){$name=([string]$p.ProcessName) -replace '\.exe$','';$key=$name.ToLowerInvariant();if($map.ContainsKey($key)){[pscustomobject]@{Client=$map[$key];Process=$name+'.exe';PID=$p.Id}}})
    $up=@($Adapters|Where-Object{[string]$_.Status -eq 'Up' -and ([string]$_.InterfaceDescription+' '+[string]$_.Name) -match '(?i)wireguard|wintun|\btun\b|vpn|sing-box|mihomo|clash|amnezia|openvpn|outline|warp|tailscale|tap-windows'})
    $indices=@($up|ForEach-Object{[int]$_.InterfaceIndex})
    $v4=Get-AGVpnRouteConfiguration -Routes $Routes -Interfaces $Interfaces -VpnIndices $indices -AddressFamily IPv4 -RoutesKnown $RoutesKnown
    $v6=Get-AGVpnRouteConfiguration -Routes $Routes -Interfaces $Interfaces -VpnIndices $indices -AddressFamily IPv6 -RoutesKnown $RoutesKnown
    $tunnelConfirmed=[bool]($DestinationRoutes.Count -and -not @($DestinationRoutes|Where-Object State -ne ViaVpn).Count)
    $state=if($tunnelConfirmed){'DestinationViaVpn'}elseif($v4.State -eq 'ViaVpn' -or $v6.State -eq 'ViaVpn'){'RouteConfigured'}elseif($up.Count){'AdapterUp'}elseif($clients.Count){'ClientOnly'}elseif(-not $AdaptersKnown){'Unknown'}else{'NotDetected'}
    $label=switch($state){'DestinationViaVpn'{'маршрут к проверенным адресам через VPN; не все приложения'}'RouteConfigured'{'VPN default/split-default; назначение не проверено'}'AdapterUp'{'активен VPN-адаптер; маршрут назначения не подтверждён'}'ClientOnly'{'клиент запущен, туннель не подтверждён'}'Unknown'{'состояние недоступно'}default{'не обнаружен'}}
    if($clients.Count){$label+=' — '+(@($clients|Select-Object -First 2|ForEach-Object{"$($_.Client) ($($_.Process))"}) -join ', ');if($clients.Count -gt 2){$label+=" +$($clients.Count-2)"}}
    elseif($up.Count){$label+=' — '+(@($up.Name) -join ', ')}
    return [pscustomobject]@{State=$state;Label=$label;Clients=$clients;ClientRunning=[bool]$clients.Count;Adapters=$up;AdapterActive=[bool]$up.Count;TunnelConfirmed=$tunnelConfirmed;DestinationRoutes=@($DestinationRoutes);RouteKnown=[bool]$RoutesKnown;IPv4Route=($v4.State -eq 'ViaVpn');IPv6Route=($v6.State -eq 'ViaVpn');IPv4Configuration=$v4;IPv6Configuration=$v6;Routes=@($Routes);Interfaces=@($Interfaces)}
}
function Get-AGSystemStatus {
    $issues=New-Object 'System.Collections.Generic.List[string]';$processes=@();$adapters=@();$adaptersKnown=$false;$routes=@();$interfaces=@();$routesKnown=$false;$vpnDns=@()
    try{$processes=@(Get-Process -ErrorAction Stop|ForEach-Object{
        $started=$null;$path='';try{$started=$_.StartTime.ToUniversalTime().ToString('o')}catch{};try{$path=$_.Path}catch{}
        [pscustomobject]@{ProcessName=$_.ProcessName;Id=$_.Id;Path=$path;Started=$started}
    })}catch{$issues.Add('Список процессов недоступен.')}
    try{$adapters=@(Get-NetAdapter -ErrorAction Stop|Select-Object Name,Status,InterfaceDescription,InterfaceIndex);$adaptersKnown=$true}catch{$issues.Add('VPN-адаптеры не прочитаны.')}
    try{
        $routes=@(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop|Select-Object InterfaceIndex,AddressFamily,DestinationPrefix,RouteMetric,State)
        $interfaces=@(Get-NetIPInterface -ErrorAction Stop|Select-Object InterfaceIndex,AddressFamily,InterfaceMetric)
        $routesKnown=$true
    }catch{$issues.Add('Маршруты VPN не прочитаны; активный процесс не считается подтверждённым туннелем.')}
    $vpn=Get-AGVpnStatus -Processes $processes -Adapters $adapters -AdaptersKnown $adaptersKnown -Routes $routes -Interfaces $interfaces -RoutesKnown $routesKnown
    try{if(@($vpn.Adapters).Count){$vpnDns=@(Get-DnsClientServerAddress -ErrorAction Stop|Where-Object{$_.InterfaceIndex -in @($vpn.Adapters|ForEach-Object{[int]$_.InterfaceIndex})}|Select-Object InterfaceIndex,InterfaceAlias,AddressFamily,ServerAddresses)}}catch{$issues.Add('DNS VPN-адаптера не прочитан.')}
    $dns=@($processes|Where-Object ProcessName -in @('ag_dns','dns_ai'))
    $ide=@($processes|Where-Object ProcessName -in @('Antigravity','Antigravity IDE','agy'))
    $gui=@($processes|Where-Object ProcessName -in @('AntigravityUnlocker','AGUnlocker','Antigravity Unlocker'))
    $zap=@($processes|Where-Object ProcessName -in @('winws','winws2'))
    $commands=@();$root='';$strategy='не запущен'
    if($zap.Count){
        try{$commands=@(Get-CimInstance Win32_Process -Filter "Name='winws.exe' OR Name='winws2.exe'" -ErrorAction Stop|Where-Object{$_.ProcessId -in @($zap.Id)}|ForEach-Object{[string]$_.CommandLine})}catch{$issues.Add('Аргументы Zapret недоступны.')}
        try{$root=Get-ZapretPath;$strategy=Get-AGRunningStrategy $root $commands}catch{$strategy='папка не найдена'}
    }
    $lastTask=$null
    try{$taskTimes=@(foreach($name in @('AG Unlocker DNS','AG Unlocker Watchdog')){
        $info=Get-ScheduledTaskInfo -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue
        if($info -and $info.LastRunTime -and $info.LastRunTime.Year -ge 2000){$info.LastRunTime.ToUniversalTime().ToString('o')}
    });$lastTask=@($taskTimes|Sort-Object -Descending|Select-Object -First 1)}catch{}
    return [pscustomobject]@{At=[datetime]::UtcNow.ToString('o');Vpn=$vpn;Routes=$routes;RoutesKnown=$routesKnown;VpnDns=$vpnDns;ZapretRunning=($zap.Count -gt 0);ZapretStrategy=$strategy;ZapretRoot=$root;AgDnsRunning=($dns.Count -gt 0);AgDnsStarted=@($dns.Started|Where-Object{$_}|Sort-Object|Select-Object -First 1);UnlockerStarted=@($gui.Started|Where-Object{$_}|Sort-Object|Select-Object -First 1);UnlockerLastTaskRun=$lastTask;AntigravityStarted=@($ide.Started|Where-Object{$_}|Sort-Object|Select-Object -First 1);Processes=$processes;Issues=@($issues.ToArray())}
}
function Format-AGLocalStart {
    param($Value)
    $value=@($Value|Where-Object{$_}|Select-Object -First 1)
    if(-not $value.Count){return 'нет данных'}
    try{return ([datetimeoffset]::Parse([string]$value[0])).ToLocalTime().ToString('dd.MM.yyyy HH:mm:ss')}catch{return [string]$value[0]}
}
function Get-AGStatusHeader {
    param($Status,[int]$Width=80)
    if(-not $Status){return @('Статусы недоступны — обновите главное меню.')}
    $zap=if($Status.ZapretRunning){'запущен — '+$Status.ZapretStrategy}else{'не запущен'}
    $dns=if($Status.AgDnsRunning){'запущен'}else{'не запущен'}
    $vpn='VPN: '+$Status.Vpn.Label
    if($Width -lt 65){
        if($Status.ZapretRunning){$zap=$Status.ZapretStrategy}
        $client=@($Status.Vpn.Clients|Select-Object -First 1)
        $name=if($client.Count){[string]$client[0].Process}else{'клиент не найден'}
        $state=switch($Status.Vpn.State){'RouteConfigured'{'VPN default; путь: ?'}'DestinationViaVpn'{'адреса через VPN'}'AdapterUp'{'адаптер ВКЛ; маршрут: ?'}'ClientOnly'{'туннель: ?'}'NotDetected'{'не обнаружен'}default{'статус: ?'}}
        $vpn='VPN: '+$name+'; '+$state
    }
    return @("Zapret: $zap","ag_dns: $dns",$vpn)
}
