#Requires -Version 5.1
. "$PSScriptRoot/route-selection.ps1"
# Observation and explicit diagnostics only. No process killing, patches or environment writes.
function Get-AGConnectionModeLabel {
    param([string]$Mode)
    switch($Mode){'Zapret'{'Zapret: системный путь'}'VpnTun'{'VPN/TUN: системный путь'}'OwnProxy'{'Свой HTTP/SOCKS5-прокси'}'Relay'{'Отдельный локальный релей'}default{'Не определён'}}
}
function ConvertTo-AGProxyObservation {
    param([AllowNull()][string]$Value)
    if([string]::IsNullOrWhiteSpace($Value)){return [pscustomobject]@{State='Unset';Endpoint='';Host='';Port=0;ProbeSupported=$false}}
    $u=$null
    if($Value.Length -gt 2048 -or $Value -match '[\x00-\x20\x7f]' -or -not [uri]::TryCreate($Value,[UriKind]::Absolute,[ref]$u) -or $u.Scheme -notin @('http','https','socks5') -or -not $u.Host -or $u.Port -lt 1 -or $u.Query -or $u.Fragment -or $u.AbsolutePath -notin @('','/')){
        return [pscustomobject]@{State='Unsupported';Endpoint='Неподдерживаемое значение (содержимое скрыто)';Host='';Port=0;ProbeSupported=$false}
    }
    if($u.UserInfo){return [pscustomobject]@{State='Credentials';Endpoint='Адрес с логином/паролем скрыт';Host='';Port=0;ProbeSupported=$false}}
    return [pscustomobject]@{State='Valid';Endpoint=$u.AbsoluteUri;Host=$u.DnsSafeHost;Port=$u.Port;ProbeSupported=($u.Scheme -in @('http','socks5'))}
}
function Test-AGLoopbackHost {
    param([string]$HostName)
    if($HostName -ieq 'localhost'){return $true}
    $address=$null
    return ([Net.IPAddress]::TryParse($HostName.Trim('[',']'),[ref]$address) -and [Net.IPAddress]::IsLoopback($address))
}
function Get-AGTransportRole {
    param([string]$Name,[AllowNull()][string]$CommandLine)
    switch -Regex ($Name){
        '^(ag_dns|dns_ai)(\.exe)?$' {return 'Unlocker'}
        '^(winws|winws2)(\.exe)?$' {return 'Zapret'}
        '^Antigravity(Unlocker| Manager)(\.exe)?$' {return 'UnlockerGuiCandidate'}
        '^(Antigravity|Antigravity IDE|language_server.*)(\.exe)?$' {return 'IDE'}
        '^gateway(\.exe)?$' {return 'GatewayCandidate'}
        '^python(w)?(\.exe)?$' {if($CommandLine -match '(?i)(?:^|[\s"/\\])relay\.py(?:[\s"]|$)'){return 'RelayCandidate'}}
    }
    return ''
}
function Get-AGConnectionSnapshot {
    if($env:OS -ne 'Windows_NT'){throw 'Снимок запущенных программ доступен только на Windows.'}
    $issues=New-Object 'System.Collections.Generic.List[string]'
    $variables=@(foreach($scope in @('Process','User','Machine')){foreach($name in @('AG_LS_PROXY','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY')){
        try{
            $raw=[Environment]::GetEnvironmentVariable($name,[EnvironmentVariableTarget]::$scope)
            # NO_PROXY can contain private names. Keep presence only, never its value.
            if($name -eq 'NO_PROXY'){$item=[pscustomobject]@{State=if($raw){'Present'}else{'Unset'};Endpoint='Список исключений не выводится';Host='';Port=0;ProbeSupported=$false}}
            else{$item=ConvertTo-AGProxyObservation $raw}
            [pscustomobject]@{Scope=$scope;Name=$name;Value=$item}
        }catch{$issues.Add("Не удалось прочитать $scope / $name.")}
    }})
    $processes=@()
    try{
        $processes=@(Get-CimInstance Win32_Process -ErrorAction Stop|ForEach-Object{
            $role=Get-AGTransportRole -Name $_.Name -CommandLine $_.CommandLine
            if($role){[pscustomobject]@{Name=$_.Name;PID=[int]$_.ProcessId;Role=$role}}
        })
    }catch{$issues.Add('Не удалось прочитать список процессов. Схема подключения может быть неполной.')}
    $listeners=@();$edges=@();$allTcp=@();$adapters=@();$routes=@();$interfaces=@();$vpnDns=@();$networkKnown=$false
    try{
        $allTcp=@(Get-NetTCPConnection -ErrorAction Stop)
        $pids=@($processes.PID)
        $ports=@($variables|Where-Object{$_.Value.State -eq 'Valid' -and (Test-AGLoopbackHost $_.Value.Host)}|ForEach-Object{$_.Value.Port})
        $listeners=@($allTcp|Where-Object{$_.State -eq 'Listen' -and ($_.OwningProcess -in $pids -or $_.LocalPort -in $ports)}|ForEach-Object{
            $ownerPid=$_.OwningProcess
            $owner=@($processes|Where-Object PID -eq $ownerPid|Select-Object -First 1)
            # Capture fields explicitly. Do not retain raw CIM/process command lines.
            [pscustomobject]@{Address=[string]$_.LocalAddress;Port=[int]$_.LocalPort;PID=[int]$_.OwningProcess;Owner=if($owner.Count){$owner[0].Name}else{'Не определён'}}
        })
        $idePids=@($processes|Where-Object Role -eq 'IDE'|ForEach-Object{$_.PID})
        $edges=@(foreach($connection in @($allTcp|Where-Object{$_.State -eq 'Established' -and $_.OwningProcess -in $idePids -and (Test-AGLoopbackHost ([string]$_.RemoteAddress))})){
            foreach($listener in $listeners){
                $familyMatch=if($connection.RemoteAddress -eq '::1'){$listener.Address -in @('::1','::')}else{$listener.Address -in @([string]$connection.RemoteAddress,'0.0.0.0')}
                if($listener.Port -eq $connection.RemotePort -and $familyMatch){[pscustomobject]@{ClientPID=[int]$connection.OwningProcess;ServerPID=$listener.PID;Address=[string]$connection.RemoteAddress;Port=$listener.Port}}
            }
        })
    }catch{$issues.Add('Не удалось прочитать TCP-соединения. Отсутствие строк не означает отсутствие подключения.')}
    try{
        $adapters=@(Get-NetAdapter -ErrorAction Stop|Select-Object InterfaceIndex,Name,Status,InterfaceDescription)
        $routes=@(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop|Select-Object InterfaceIndex,AddressFamily,DestinationPrefix,RouteMetric,State)
        $interfaces=@(Get-NetIPInterface -ErrorAction Stop|Select-Object InterfaceIndex,AddressFamily,InterfaceMetric)
        $networkKnown=$true
    }catch{$issues.Add('Не удалось прочитать адаптеры/маршруты. Активный VPN-клиент не считается поднятым туннелем.')}
    $vpnAdapters=@($adapters|Where-Object{[string]$_.Status -eq 'Up' -and ([string]$_.InterfaceDescription+' '+[string]$_.Name) -match '(?i)wireguard|wintun|\btun\b|vpn|sing-box|mihomo|clash|amnezia|openvpn|outline|warp|tailscale|tap-windows'})
    $vpnIndices=@($vpnAdapters|ForEach-Object{[int]$_.InterfaceIndex})
    try{if($vpnIndices.Count){$vpnDns=@(Get-DnsClientServerAddress -ErrorAction Stop|Where-Object{$_.InterfaceIndex -in $vpnIndices}|Select-Object InterfaceIndex,InterfaceAlias,AddressFamily,ServerAddresses)}}catch{$issues.Add('Не удалось прочитать DNS VPN-адаптера.')}
    $v4=Get-AGVpnRouteConfiguration -Routes $routes -Interfaces $interfaces -VpnIndices $vpnIndices -AddressFamily IPv4 -RoutesKnown $networkKnown
    $v6=Get-AGVpnRouteConfiguration -Routes $routes -Interfaces $interfaces -VpnIndices $vpnIndices -AddressFamily IPv6 -RoutesKnown $networkKnown
    $vpnRouteConfirmed=$false
    $vpnRouteState=if(-not $networkKnown){'Unknown'}elseif($v4.State -eq 'ViaVpn' -or $v6.State -eq 'ViaVpn'){'RouteConfigured'}elseif($vpnAdapters.Count){'AdapterUp'}elseif(@($processes|Where-Object{$_.Role -in @('RelayCandidate','GatewayCandidate')}).Count){'ClientOnly'}else{'NotDetected'}
    $settings=$null
    try{
        $cfg=Read-AGSettings
        $flags=[ordered]@{}
        foreach($name in @('dns','local_proxy','builtin_exits','group_proxy','own_proxy_enabled')){
            $flags[$name]=if($cfg.$name -is [bool]){$cfg.$name}else{$null}
        }
        $settings=[pscustomobject]$flags
    }catch{$issues.Add('Настройки Unlocker недоступны или не читаются. Содержимое ошибки скрыто.')}
    return [pscustomobject]@{CollectedAt=[datetime]::UtcNow.ToString('o');Variables=$variables;Processes=$processes;Listeners=$listeners;ObservedLocalEdges=$edges;Adapters=$adapters;Routes=$routes;Interfaces=$interfaces;VpnDns=$vpnDns;VpnRouteState=$vpnRouteState;VpnRouteConfirmed=$vpnRouteConfirmed;IPv4Configuration=$v4;IPv6Configuration=$v6;Unlocker=$settings;Issues=@($issues.ToArray())}
}
function Get-AGConnectionPathLines {
    param($Snapshot)
    $lines=@('Это снимок, а не автоматическое определение всего маршрута. Настройки не меняются.','Наблюдаемые локальные подключения IDE')
    if(@($Snapshot.ObservedLocalEdges).Count){foreach($edge in $Snapshot.ObservedLocalEdges){$lines+="IDE PID $($edge.ClientPID) → $($edge.Address):$($edge.Port) → PID $($edge.ServerPID)"}}
    else{$lines+='Подключение IDE к локальному слушателю не обнаружено. Запрос мог уже закончиться; это не доказательство сбоя.'}
    $lines+='Что запущено'
    foreach($process in @($Snapshot.Processes)){
        $label=switch($process.Role){'Unlocker'{'сетевая часть Unlocker'}'Zapret'{'процесс Zapret; участие в этом запросе не доказано'}'IDE'{'IDE / языковой сервер'}'UnlockerGuiCandidate'{'возможный интерфейс Unlocker/Manager; не IDE'}'RelayCandidate'{'возможный Python-релей; версия и происхождение не проверены'}default{'возможный gateway; имя не подтверждает происхождение'}}
        $lines+="$($process.Name), PID $($process.PID): $label"
    }
    $lines+='Сетевые адаптеры и маршрут по умолчанию'
    $routeLabels=@{RouteConfigured='VPN default/split-default; конкретное назначение не проверено';AdapterUp='VPN-адаптер включён, маршрут по умолчанию не подтверждён';ClientOnly='клиент/релей запущен, туннель не подтверждён';Unknown='маршруты недоступны';NotDetected='VPN-маршрут не обнаружен'}
    $routeLabel=if($routeLabels.ContainsKey([string]$Snapshot.VpnRouteState)){$routeLabels[[string]$Snapshot.VpnRouteState]}else{'состояние не определено'}
    $lines+='Состояние VPN: '+$routeLabel
    foreach($adapter in @($Snapshot.Adapters)){$lines+="Адаптер $($adapter.InterfaceIndex): $($adapter.Name) [$($adapter.Status)] — $($adapter.InterfaceDescription)"}
    foreach($route in @($Snapshot.Routes)){$lines+="Маршрут $($route.DestinationPrefix), адаптер $($route.InterfaceIndex), метрика $($route.RouteMetric), состояние $($route.State)"}
    foreach($dns in @($Snapshot.VpnDns)){$lines+="DNS $($dns.InterfaceAlias) / $($dns.AddressFamily): $(@($dns.ServerAddresses) -join ', ')"}
    $lines+='Локальные слушатели: это ещё не подтверждённые HTTP/SOCKS-прокси'
    foreach($listener in @($Snapshot.Listeners)){$lines+="$($listener.Address):$($listener.Port) → $($listener.Owner), PID $($listener.PID)"}
    $lines+='Переменные прокси (только AGFixer и сохранённые значения Windows)'
    foreach($variable in @($Snapshot.Variables|Where-Object{$_.Value.State -ne 'Unset'})){$lines+="$($variable.Scope) / $($variable.Name): $($variable.Value.Endpoint)"}
    $lines+='Process — окружение AGFixer, НЕ запущенной IDE. User/Machine — сохранённые значения, а не доказательство их использования IDE.'
    $lines+='Порт не определяет протокол. 10809/53129 не выбираются автоматически. Маршрут подтверждает только выход через локальный VPN-адаптер; страна и путь конкретного запроса не установлены.'
    if($Snapshot.Unlocker){
        $lines+='Сохранённые переключатели Unlocker (не подтверждение текущего маршрута)'
        foreach($p in $Snapshot.Unlocker.PSObject.Properties){$value=if($null -eq $p.Value){'неизвестно'}elseif($p.Value){'включено'}else{'выключено'};$label=@{dns='Обход через DNS';local_proxy='Локальный прокси';builtin_exits='Встроенные выходы';group_proxy='Прокси из группы';own_proxy_enabled='Свой прокси'}[$p.Name];$lines+="${label}: $value"}
    }
    foreach($issue in @($Snapshot.Issues)){$lines+='Не проверено: '+$issue}
    $lines+='Для подтверждения выберите явный адрес/протокол в проверке соединения. Работа модели проверяется отдельным запросом в IDE.'
    return $lines
}
function Assert-AGConnectionProfile {
    param($Profile)
    if($null -eq $Profile -or $Profile -isnot [pscustomobject]){throw 'Нужен объект профиля проверки.'}
    $keys=@('Kind','FormatVersion','Mode','ProxyUrl','FallbackToDirect')
    foreach($key in @($Profile.PSObject.Properties.Name)){if($key -cnotin $keys){throw 'Неизвестное поле профиля проверки.'}}
    foreach($key in $keys){if($key -cnotin @($Profile.PSObject.Properties.Name)){throw 'Неполный профиль проверки.'}}
    if($Profile.Kind -cne 'AGFixer.ConnectionCheck' -or ($Profile.FormatVersion -isnot [int] -and $Profile.FormatVersion -isnot [long]) -or $Profile.FormatVersion -ne 1 -or $Profile.Mode -cnotin @('Zapret','VpnTun','OwnProxy','Relay')){throw 'Неизвестный формат или режим проверки.'}
    if($Profile.FallbackToDirect -isnot [bool] -or $Profile.FallbackToDirect){throw 'Скрытый переход напрямую запрещён. FallbackToDirect должен быть false.'}
    if($Profile.ProxyUrl -isnot [string]){throw 'Адрес должен быть строкой.'}
    if($Profile.Mode -in @('Zapret','VpnTun')){if($Profile.ProxyUrl){throw 'Системный путь не должен содержать адрес прокси.'}}
    else{
        $observation=ConvertTo-AGProxyObservation $Profile.ProxyUrl
        if($observation.State -ne 'Valid' -or -not $observation.ProbeSupported){throw 'Нужен http://host:port или socks5://host:port без пароля. HTTPS-прокси этой проверкой не поддерживается; не заменяйте https на http вслепую.'}
        if($Profile.Mode -eq 'Relay' -and -not (Test-AGLoopbackHost $observation.Host)){throw 'Режим локального релея требует loopback-адрес. Для внешнего адреса выберите свой прокси.'}
    }
}
function New-AGConnectionProfile {
    param([ValidateSet('Zapret','VpnTun','OwnProxy','Relay')][string]$Mode,[string]$ProxyUrl='')
    $profile=[pscustomobject]@{Kind='AGFixer.ConnectionCheck';FormatVersion=1;Mode=$Mode;ProxyUrl=$ProxyUrl;FallbackToDirect=$false}
    Assert-AGConnectionProfile $profile
    return $profile
}
function Read-AGConnectionProfile {
    param([string]$Path)
    $file=Get-Item -LiteralPath $Path -ErrorAction Stop
    if($file.PSIsContainer -or $file.Length -gt 16KB){throw 'Профиль проверки должен быть JSON-файлом до 16 КБ.'}
    $profile=Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
    Assert-AGConnectionProfile $profile
    return $profile
}
function Write-AGConnectionProfile {
    param($Profile,[string]$Path)
    Assert-AGConnectionProfile $Profile
    if(-not $Path.EndsWith('.agcheck.json',[StringComparison]::OrdinalIgnoreCase)){throw 'Для профиля проверки используйте расширение .agcheck.json.'}
    $full=[IO.Path]::GetFullPath($Path)
    # CreateNew never overwrites an existing config or follows an existing file symlink.
    $stream=New-Object IO.FileStream($full,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$bytes=(New-Object Text.UTF8Encoding($false)).GetBytes(($Profile|ConvertTo-Json -Depth 4));$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
    return $full
}
function Get-AGConnectionProfileLines {
    param($Profile)
    Assert-AGConnectionProfile $Profile
    $lines=@('Режим: '+(Get-AGConnectionModeLabel $Profile.Mode))
    $lines+='Путь: '+$(if($Profile.ProxyUrl){$Profile.ProxyUrl}else{'системная маршрутизация; VPN/TUN может оставаться активным'})
    $lines+='При ошибке прокси: остановить проверку. Ухода напрямую нет.'
    $lines+='Это профиль ПРОВЕРКИ AGFixer. Он не включает VPN, не меняет IDE/Unlocker, DNS, Zapret и переменные Windows.'
    return $lines
}
function ConvertTo-AGConnectionFailure {
    param([string]$Message,[bool]$UsesProxy)
    $stage='Runtime'
    foreach($candidate in @('DNS','TCP connect','HTTP CONNECT','SOCKS5 CONNECT','TLS handshake','TLS 1.3 handshake')){if($Message.Contains($candidate+' failed:')){$stage=$candidate;break}}
    $states=[ordered]@{DNS='Не проверено';TCP='Не проверено';Proxy=if($UsesProxy){'Не проверено'}else{'Не используется'};TLS='Не проверено'}
    switch($stage){
        'DNS'{$states.DNS='Ошибка'}
        'TCP connect'{$states.DNS='Пройдено';$states.TCP='Ошибка'}
        {$_ -in @('HTTP CONNECT','SOCKS5 CONNECT')}{$states.DNS='Пройдено';$states.TCP='Пройдено';$states.Proxy='Ошибка'}
        {$_ -in @('TLS handshake','TLS 1.3 handshake')}{$states.DNS='Пройдено';$states.TCP='Пройдено';if($UsesProxy){$states.Proxy='Пройдено'};$states.TLS='Ошибка'}
    }
    # Never forward raw exception text, which may include remote banners or private input.
    return [pscustomobject]@{Success=$false;FailedStage=$stage;Stages=[pscustomobject]$states;Metrics=$null}
}
function ConvertFrom-AGTlsFailure {
    param($ErrorRecord)
    $exception=$ErrorRecord.Exception
    while($exception){if($exception.PSObject.Properties['Result'] -and $exception.Result){return $exception.Result};$exception=$exception.InnerException}
    return $null
}
function Invoke-AGConnectionProbe {
    param($Profile,[ValidateRange(100,60000)][int]$TimeoutMs=5000,[switch]$RequireTls13)
    Assert-AGConnectionProfile $Profile
    try{
        if(-not(Get-Command Test-AGTls13 -CommandType Function -ErrorAction SilentlyContinue)){. "$PSScriptRoot/TLS-Probe.ps1"}
        $proxy=$null;if($Profile.ProxyUrl){$proxy=[uri]$Profile.ProxyUrl}
        $metrics=Test-AGTls13 -TimeoutMs $TimeoutMs -ProxyUri $proxy -AllowTls12:(-not $RequireTls13)
        $destinationRoute=[pscustomobject]@{State='Unknown';Reason='Destination route not inspected'}
        if(-not $proxy -and $metrics.ConnectedAddress){$destinationRoute=Get-AGWindowsDestinationRoute -Destination $metrics.ConnectedAddress}
        elseif($proxy){$destinationRoute=[pscustomobject]@{State='Unknown';Reason='Proxy resolves remote destination; local route is only to proxy'}}
        return [pscustomobject]@{Success=$true;Status='Passed';FailedStage='';Stages=[pscustomobject]@{DNS=if($metrics.DnsStatus){$metrics.DnsStatus}else{'Пройдено'};TCP='Пройдено';Proxy=if($proxy){'Пройдено'}else{'Не используется'};TLS='Пройдено'};Metrics=$metrics;DestinationRoute=$destinationRoute}
    }catch{
        $metrics=ConvertFrom-AGTlsFailure $_
        if($metrics){return [pscustomobject]@{Success=$false;Status=$metrics.Status;FailedStage=$metrics.FailedStage;Stages=[pscustomobject]@{DNS=$metrics.DnsStatus;TCP=$metrics.TcpStatus;Proxy=$metrics.ProxyStatus;TLS=$metrics.TlsStatus};Metrics=$metrics;DestinationRoute=[pscustomobject]@{State='Unknown';Reason='Probe failed'}}}
        return (ConvertTo-AGConnectionFailure -Message $_.Exception.Message -UsesProxy:([bool]$Profile.ProxyUrl))
    }
}
function Get-AGConnectionProbeLines {
    param($Result)
    $lines=@('Назначение: daily-cloudcode-pa.googleapis.com:443; TLS 1.2/1.3 с проверкой сертификата.')
    if($Result.Status -eq 'Unsupported'){$lines+='TLS 1.3 не поддерживается ОС/runtime; это не доказательство блокировки сервера. Используйте совместимый режим.'}
    if($Result.DestinationRoute){$lines+='Маршрут к фактическому адресу: '+$Result.DestinationRoute.State+'; '+$Result.DestinationRoute.Reason}
    foreach($name in @('DNS','TCP','Proxy','TLS')){$label=@{DNS='Поиск адреса (DNS)';TCP='Связь с портом (TCP)';Proxy='Туннель прокси';TLS='Защищённое соединение (TLS)'}[$name];$lines+="$label — $($Result.Stages.$name)"}
    if($Result.Success){
        foreach($name in @('DnsMs','TcpConnectMs','ProxyNegotiationMs','TlsHandshakeMs')){$lines+="$name = $([Math]::Round($Result.Metrics.$name,2)) мс"}
        if($Result.Metrics.Protocol){$lines+='Согласованный протокол: '+$Result.Metrics.Protocol}
        if($Result.Metrics.IsTls13 -eq $false){$lines+='TLS 1.3 не заявлен: согласован TLS 1.2. На Windows 10 это ожидаемо для системного Schannel.'}
        $lines+='TlsHandshakeMs — длительность AuthenticateAsClientAsync, не чистый сетевой RTT; включает локальную обработку и проверку сертификата. Resumption не исключён.'
    }else{
        $lines+='Остановились на этапе: '+$Result.FailedStage
        $lines+=switch($Result.FailedStage){
            'DNS'{'Не найден адрес назначения или прокси. Проверьте DNS и выбранный адрес.'}
            'TCP connect'{'Не удалось открыть TCP-соединение. Проверьте адрес, порт и запущенную программу.'}
            {$_ -in @('HTTP CONNECT','SOCKS5 CONNECT')}{'Порт ответил, но туннель не создан. Проверьте протокол, необходимость авторизации и ответ прокси. Напрямую повторять не будем.'}
            {$_ -in @('TLS handshake','TLS 1.3 handshake')}{'TCP/туннель прошли, но защищённое соединение не подтверждено. Возможны тайм-аут, отказ сертификата или отсутствие подходящего TLS; точная причина здесь не установлена.'}
            default{'Проверка не выполнена встроенным TLS-зондом Windows PowerShell 5.1 / .NET Framework 4.8.'}
        }
    }
    $lines+='Успех TLS не доказывает работу модели, обход ТСПУ именно Zapret, доступ по региону или наличие квоты.'
    return $lines
}
if(-not(Get-Command Protect-AGText -ErrorAction SilentlyContinue)){. "$PSScriptRoot/report-analysis.ps1"}
function Invoke-AGConnectionCheckMenu {
    if(-not(Get-Command Read-AGListChoice -CommandType Function -ErrorAction SilentlyContinue)){. "$PSScriptRoot/ui.ps1"}
    $profile=$null
    while($true){
        $intro=@('Сначала посмотрите цепочку. Затем явно выберите путь проверки. Никакие настройки Windows не меняются.')
        if($profile){$intro+='Выбрано: '+(Get-AGConnectionModeLabel $profile.Mode)}
        $choice=Read-AGListChoice -Title 'Мой путь подключения' -Options @('Посмотреть процессы, порты и наблюдаемую цепочку','Выбрать путь: Zapret / VPN / прокси / релей','Проверить выбранный путь до Google','Открыть профиль проверки .agcheck.json','Сохранить профиль проверки .agcheck.json') -Intro $intro
        if(-not $choice){return}
        try{
            switch($choice){
                1 {$snapshot=Get-AGConnectionSnapshot;Show-AGTextPages -Title 'Что удалось установить о подключении' -Lines @(Get-AGConnectionPathLines $snapshot)}
                2 {
                    $modeChoice=Read-AGListChoice -Title 'Какой путь проверить?' -Options @('Zapret: системный путь (VPN отключайте самостоятельно)','VPN/TUN: системный путь через уже включённый VPN','Свой HTTP/SOCKS5-прокси','Отдельный локальный релей (уже запущен)')
                    if(-not $modeChoice){continue}
                    $mode=@('Zapret','VpnTun','OwnProxy','Relay')[$modeChoice-1];$url=''
                    if($mode -in @('OwnProxy','Relay')){$url=(Read-AGInput 'URL с протоколом и портом, без пароля (Enter — отмена)').Trim();if(-not $url){continue}}
                    $candidate=New-AGConnectionProfile -Mode $mode -ProxyUrl $url
                    Show-AGTextPages -Title 'Проверьте выбранный путь' -Lines @(Get-AGConnectionProfileLines $candidate)
                    if(Confirm-Change 'Выбрать этот путь только для проверки AGFixer?'){$profile=$candidate}
                }
                3 {
                    if(-not $profile){Show-AGTextPages -Title 'Сначала выберите путь' -Lines @('Откройте «Выбрать путь» или загрузите профиль проверки. Программа не угадывает протокол по номеру порта.');continue}
                    Show-AGTextPages -Title 'Куда пойдёт проверка' -Lines @(Get-AGConnectionProfileLines $profile)
                    if(-not(Confirm-Change 'Разрешить сетевую TLS-проверку? Запрос модели не отправляется.')){continue}
                    $result=Invoke-AGConnectionProbe $profile
                    Show-AGTextPages -Title 'Результат проверки по этапам' -Lines @(Get-AGConnectionProbeLines $result)
                }
                4 {
                    $path=(Read-AGInput 'Файл .agcheck.json (Enter — отмена)').Trim().Trim('"');if(-not $path){continue}
                    $candidate=Read-AGConnectionProfile $path
                    Show-AGTextPages -Title 'Профиль проверки из файла' -Lines @(Get-AGConnectionProfileLines $candidate)
                    if(Confirm-Change 'Выбрать этот профиль только для проверки? Windows/Unlocker не меняются.'){$profile=$candidate}
                }
                5 {
                    if(-not $profile){Show-AGTextPages -Title 'Нечего сохранять' -Lines @('Сначала выберите путь проверки.');continue}
                    $path=(Read-AGInput 'Новый файл .agcheck.json (Enter — отмена)').Trim().Trim('"');if(-not $path){continue}
                    if(Confirm-Change 'Сохранить профиль проверки? Адрес будет виден получателю файла.'){$null=Write-AGConnectionProfile $profile $path;Show-AGTextPages -Title 'Профиль сохранён' -Lines @('Файл создан. При загрузке он не изменяет Windows или настройки Unlocker.','Для стратегии Zapret и настроек Unlocker используйте обычный раздел «Конфиги».')}
                }
            }
        }catch{Show-AGTextPages -Title 'Не удалось выполнить действие' -Lines @('Ничего автоматически не применено.',(Protect-AGText $_.Exception.Message))}
    }
}
