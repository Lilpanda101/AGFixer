#Requires -Version 5.1
. "$PSScriptRoot/route-selection.ps1"
if(-not(Get-Command Get-AGRepairSnapshot -CommandType Function -ErrorAction SilentlyContinue)){. "$PSScriptRoot/repair-engine.ps1"}
if(-not(Get-Command Show-AGExpressVerdict -CommandType Function -ErrorAction SilentlyContinue)){. "$PSScriptRoot/express-verdict.ps1"}
# Read current local settings; never read VPN private keys/subscriptions or execute report text.
function Invoke-AGSetupRepair {
    param($Snapshot,$Analysis,[ValidateSet('Keep','VpnDirect','Zapret')][string]$Mode='Keep',[switch]$Deep,[switch]$Inspect,[string]$StrategyFile)
    if($Inspect){Invoke-AGSmartSetup -Analysis $Analysis;return}
    if(-not $Snapshot){$Snapshot=Get-AGRepairSnapshot}
    if(-not(Initialize-AGRepairPaths -Mode $Mode -Snapshot $Snapshot -Analysis $Analysis -Deep:$Deep)){Add-AGUiJournal 'Выбор папки отменён.';return}
    # Folder selection may change the settings source: never plan from the old snapshot.
    $Snapshot=Get-AGRepairSnapshot
    if($Mode -eq 'Zapret' -and -not $StrategyFile){. "$PSScriptRoot/config-wizard.ps1";$StrategyFile=Read-AGStrategyChoice;if(-not $StrategyFile){return}}
    if($Analysis -and $Analysis.ReportText){
        $smartStatus=$null;try{$smartStatus=Get-AGSystemStatus}catch{}
        $smart=Get-AGSmartDiagnosis -Text $Analysis.ReportText -Analysis $Analysis -Snapshot $Snapshot -Status $smartStatus
        $Analysis.Diagnosis.Actions=@($smart.Verdicts|Where-Object{$_.Action -in @('Nrpt','Restart')}|ForEach-Object Action|Select-Object -Unique)
    }
    $plan=New-AGAutoRepairPlan -Snapshot $Snapshot -Analysis $Analysis -Mode $Mode -Deep:$Deep -StrategyFile $StrategyFile
    if(-not @($plan.Steps).Count){
        $configured=[bool]($plan.PSObject.Properties['Configured'] -and $plan.Configured)
        $footer=if($configured){'(Настроено) | Esc/Enter: назад'}else{'Нет изменений | Esc/Enter: назад'}
        $resultLine=if($configured){'Профиль VPN/TUN уже настроен. Подтверждённых конфликтующих правил NRPT нет.'}else{'Для выбранного действия изменений не найдено.'}
        Show-AGTextPages -Title 'Автоматических изменений нет' -Footer $footer -Lines @(
            '=== Результат проверки ===',
            $resultLine,
            'Ничего не изменено.',
            $(foreach($reason in @($plan.Blocked)){if($reason){'Нужна проверка: '+$reason}}),
            '=== Настроить подключение ===',
            'Если Google не отвечает, вернитесь в главное меню:',
            '2 — свой VPN/TUN: настроить Unlocker.',
            '3 — Zapret: списки доменов и выбор стратегии.',
            '=== Дополнительные проверки ===',
            'L — проверить и дополнить списки доменов Zapret.',
            'Гайды сообщества — выберите этот пункт в главном меню.',
            'Таблица маршрутов: T → инструменты → проверка текущих настроек.'
        )
        return
    }
    if(Show-AGExpressVerdict -Analysis $Analysis -Plan $plan){
        $result=Invoke-AGAutoRepair -Plan $plan -Confirmed
        $label=if($result.Status -eq 'Applied'){'план применён'}elseif($result.Status -eq 'Partial'){'выполнен не полностью — смотрите результат'}else{'без изменений'}
        Add-AGUiJournal ('Ремонт: '+$label);Show-AGRepairResult $result
    }else{Add-AGUiJournal 'Применение плана отменено.'}
}
function Get-AGSetupProfileDiff {
    param($Settings,[ValidateSet('VpnDirect','Zapret')][string]$Mode)
    if(-not $Settings){return @()}
    $expected=@{dns=($Mode -eq 'Zapret');local_proxy=($Mode -eq 'Zapret');group_proxy=$false;builtin_exits=$false;own_proxy_enabled=$false}
    $labels=@{dns='Обход через DNS';local_proxy='Локальный прокси';group_proxy='Прокси из группы';builtin_exits='Встроенные выходы';own_proxy_enabled='Свой прокси'}
    foreach($name in @('dns','local_proxy','group_proxy','builtin_exits','own_proxy_enabled')){
        if($Settings.$name -isnot [bool] -or $Settings.$name -ne $expected[$name]){
            $state=if($Settings.$name -isnot [bool]){'неизвестно'}elseif($Settings.$name){'ВКЛ'}else{'ВЫКЛ'}
            $wanted=if($expected[$name]){'ВКЛ'}else{'ВЫКЛ'}
            "$($labels[$name]): $state → $wanted"
        }
    }
}
function Get-AGSetupAssessment {
    $status=Get-AGSystemStatus;$snapshot=Get-AGRepairSnapshot
    $issues=@($status.Issues)+@($snapshot.Issues);$settings=$null;$settingsPath='';$root='';$health=$null;$routes=@();$interfaces=@();$dns=@();$routesKnown=$false
    try{
        $settingsPath=Get-AGPath 'settings.json';$raw=Read-AGSettings;$flags=[ordered]@{}
        foreach($name in @('dns','local_proxy','group_proxy','builtin_exits','own_proxy_enabled')){$flags[$name]=if($raw.$name -is [bool]){$raw.$name}else{$null}}
        $settings=[pscustomobject]$flags;$raw=$null
    }catch{$issues+='Настройки Unlocker не найдены или не читаются. Укажите папку с settings.json.'}
    try{$root=Get-ZapretPath;$health=Get-AGZapretListHealth $root}catch{$issues+='Настройки списков Zapret не прочитаны. Если используете Zapret, укажите его папку.'}
    try{
        $routes=@(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop|Select-Object InterfaceIndex,AddressFamily,DestinationPrefix,RouteMetric,State)
        $interfaces=@(Get-NetIPInterface -ErrorAction Stop|Select-Object InterfaceIndex,AddressFamily,InterfaceMetric);$routesKnown=$true
    }catch{$issues+='Таблица маршрутов VPN не прочитана. Клиент в процессах сам по себе не подтверждает маршрут.'}
    $indices=@($status.Vpn.Adapters|ForEach-Object{[int]$_.InterfaceIndex})
    try{if($indices.Count){$dns=@(Get-DnsClientServerAddress -ErrorAction Stop|Where-Object{$_.InterfaceIndex -in $indices}|Select-Object InterfaceIndex,InterfaceAlias,AddressFamily,ServerAddresses)}}catch{$issues+='DNS VPN-адаптера не прочитан.'}
    $v4Configuration=Get-AGVpnRouteConfiguration -Routes $routes -Interfaces $interfaces -VpnIndices $indices -AddressFamily IPv4 -RoutesKnown $routesKnown
    $v6Configuration=Get-AGVpnRouteConfiguration -Routes $routes -Interfaces $interfaces -VpnIndices $indices -AddressFamily IPv6 -RoutesKnown $routesKnown
    $v4=($v4Configuration.State -eq 'ViaVpn');$v6=($v6Configuration.State -eq 'ViaVpn')
    $vpn=[pscustomobject]@{State=$status.Vpn.State;RouteKnown=$routesKnown;DestinationRoutes=@()}
    $suggested=Get-AGSuggestedRepairMode -Vpn $vpn -ZapretRunning $status.ZapretRunning
    $diff=@();if($suggested){$diff=@(Get-AGSetupProfileDiff -Settings $settings -Mode $suggested)}
    $needsProfile=($suggested -and $settings -and ($diff.Count -gt 0 -or ($suggested -eq 'VpnDirect' -and @($snapshot.Nrpt).Count -gt 0) -or ($suggested -eq 'Zapret' -and $health -and $health.Missing.Count -gt 0)))
    return [pscustomobject]@{Status=$status;Snapshot=$snapshot;Settings=$settings;SettingsPath=$settingsPath;ZapretRoot=$root;ZapretHealth=$health;Routes=$routes;RoutesKnown=$routesKnown;VpnDns=$dns;VpnIPv4=[bool]$v4;VpnIPv6=[bool]$v6;IPv4Configuration=$v4Configuration;IPv6Configuration=$v6Configuration;SuggestedMode=$suggested;ProfileDiff=$diff;NeedsProfile=[bool]$needsProfile;Issues=@($issues|Select-Object -Unique)}
}
function Get-AGSetupSummary {
    param($Assessment)
    $unlocker=if(-not $Assessment.Settings){'Unlocker: настройки не прочитаны'}elseif($Assessment.ProfileDiff.Count){'Unlocker: расхождений настроек — '+$Assessment.ProfileDiff.Count}else{'Unlocker: настройки прочитаны'}
    $zap=if($Assessment.ZapretHealth){'Zapret: '+$Assessment.ZapretHealth.Status+'; '+$Assessment.Status.ZapretStrategy}else{'Zapret: списки не прочитаны'}
    $vpn=if($Assessment.VpnIPv4){$client=@($Assessment.Status.Vpn.Clients|Select-Object -First 1);$name=if($client.Count){$client[0].Client+'; '}else{''};'VPN: '+$name+'default/split-default IPv4 VPN; назначение не проверено'}else{'VPN: '+$Assessment.Status.Vpn.Label}
    return @($unlocker,$zap,$vpn)
}
function Get-AGSetupDetailLines {
    param($Assessment)
    $a=$Assessment;$lines=@('Настройки Unlocker','Файл: '+$a.SettingsPath)
    if($a.Settings){
        $labels=@{dns='Обход через DNS';local_proxy='Локальный прокси';group_proxy='Прокси из группы';builtin_exits='Встроенные выходы';own_proxy_enabled='Свой прокси'}
        foreach($name in @('dns','local_proxy','group_proxy','builtin_exits','own_proxy_enabled')){$value=if($a.Settings.$name -isnot [bool]){'неизвестно'}elseif($a.Settings.$name){'ВКЛ'}else{'ВЫКЛ'};$lines+="$($labels[$name]): $value"}
    }else{$lines+='Не удалось прочитать settings.json.'}
    $lines+=@('','VPN: '+$a.Status.Vpn.Label)
    $lines+='Основной/раздельный маршрут IPv4 через VPN: '+[string]$a.VpnIPv4
    $lines+='Основной/раздельный маршрут IPv6 через VPN: '+[string]$a.VpnIPv6
    foreach($r in $a.Routes){$lines+="Маршрут $($r.DestinationPrefix), адаптер $($r.InterfaceIndex), метрика $($r.RouteMetric)"}
    foreach($d in $a.VpnDns){$lines+="DNS $($d.InterfaceAlias): $(@($d.ServerAddresses) -join ', ')"}
    $lines+='Страна выхода и путь конкретного запроса здесь не проверяются.'
    $lines+=@('','Zapret: '+$a.Status.ZapretStrategy,'Папка: '+$a.ZapretRoot)
    if($a.ZapretHealth){$lines+=@(Get-AGZapretHealthLines $a.ZapretHealth)}
    $lines+=@('','Найденные расхождения профиля')
    if($a.ProfileDiff.Count){$lines+=@($a.ProfileDiff)}elseif($a.SuggestedMode -and $a.Settings){$lines+='Пять настроек подключения совпадают с найденным режимом.'}else{$lines+='Режим не определён однозначно. Сначала выберите свой способ подключения.'}
    foreach($p in @($a.Snapshot.Proxies)){if($p.Server){$kind=if($p.Eligible){'локальный порт не слушается'}else{'автоудаление не предлагается'};$address=if(@(Get-AGRepairProxyPorts $p.Server).Count){$p.Server}else{'адрес скрыт'};$lines+="$($p.Scope) прокси: $address — $kind"}}
    $lines+='Подходящих для точечной очистки NRPT: '+@($a.Snapshot.Nrpt).Count
    if($a.Issues.Count){$lines+=@('','Не удалось проверить');$lines+=@($a.Issues)}
    return $lines
}
function Invoke-AGSmartSetup {
    param($Analysis)
    while($true){
        $a=Get-AGSetupAssessment;$items=@()
        if(-not $a.Settings){$items+=@([pscustomobject]@{Label='Найти настройки Unlocker (settings.json)';Action='Folders'})}
        if($a.NeedsProfile){$label=if($a.SuggestedMode -eq 'VpnDirect'){'Исправить настройки Unlocker под найденный VPN'}else{'Исправить связку Unlocker и Zapret'};$items+=@([pscustomobject]@{Label=$label;Action=$a.SuggestedMode})}
        if(@($a.Snapshot.Proxies|Where-Object{$_.Eligible -and $_.Scope -eq 'HKCU'}).Count -or ($Analysis -and @($Analysis.Diagnosis.Actions).Count)){$items+=@([pscustomobject]@{Label='Показать исправления сетевых хвостов / ошибок отчёта';Action='Keep'})}
        if($a.ZapretRoot){$items+=@([pscustomobject]@{Label='Проверить/исправить списки Zapret';Action='Lists'})}
        $items+=@([pscustomobject]@{Label='Что найдено — настройки, папки, VPN и Zapret';Action='Details'},[pscustomobject]@{Label='Найти или указать папки программ';Action='Folders'},[pscustomobject]@{Label='Настроить Unlocker под свой VPN';Action='VpnDirect'},[pscustomobject]@{Label='Настроить Unlocker под Zapret';Action='Zapret'},[pscustomobject]@{Label='Проверить соединение с Google';Action='Connection'},[pscustomobject]@{Label='Обновить проверку';Action='Refresh'})
        $pick=Read-AGListChoice -Title 'Проверка текущих настроек' -Options @($items.Label) -Status @(Get-AGSetupSummary $a) -Intro @('Проверены текущие настройки. Выберите действие; запись только после просмотра плана.')
        if(-not $pick){return}
        switch($items[$pick-1].Action){
            'Details'{Show-AGTextPages -Title 'Найденные настройки' -Lines @(Get-AGSetupDetailLines $a)}
            'Folders'{Show-AGInstallationFolders}
            'Lists'{Show-AGZapretListHealth}
            'Refresh'{}
            'Connection'{. "$PSScriptRoot/connection-path.ps1";Invoke-AGConnectionCheckMenu}
            default{Invoke-AGSetupRepair -Analysis $Analysis -Mode $items[$pick-1].Action}
        }
    }
}
