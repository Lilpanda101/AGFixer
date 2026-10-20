#Requires -Version 5.1
# Pure functions: text is evidence, never executable repair code.
function Get-AGExpressDiagnosis {
    param([string]$Text,[ValidateRange(1,100)][int]$TailCount=15)
    $records=@(Get-AGReportRecords -Lines @($Text -split '\r?\n'))
    $eligible=@($records|Where-Object{-not $_.Ignored -and $_.Context -ne 'Inactive'})
    $logs=@($eligible|Where-Object{$_.Text -match '^\s*(?:\[?\d{4}-\d{2}-\d{2}[ T])?\[?\d{2}:\d{2}:\d{2}\b'})
    if(-not $logs.Count){$logs=@($eligible|Where-Object{$_.Context -eq 'History'})}
    if(-not $logs.Count){$logs=$eligible}
    $tail=@($logs|Select-Object -Last $TailCount)
    $recent=($tail|ForEach-Object{$_.Text}) -join "`n"
    $issues=New-Object 'System.Collections.Generic.List[object]'
    $vpn='Unknown';$country=''
    $matches=[regex]::Matches($Text,'(?im)^\s*VPN\s*(?:\(по сокетам\))?\s*:\s*(?<v>[^\r\n]+)')
    if($matches.Count){
        $value=$matches[$matches.Count-1].Groups['v'].Value
        if($value -match '(?i)^\s*(None|нет|не обнаружен)\s*$'){$vpn='NotDetected'}
        elseif($value -match '(?i)выход\s*[:=]?\s*(?<c>[A-Z]{2})\b'){$country=$Matches['c'].ToUpperInvariant();$vpn='Detected'}
        elseif($value -match '(?i)включ[её]н|подключ[её]н|active|connected'){$vpn='Detected'}
    }
    $dns='Unknown';$m=[regex]::Matches($Text,'(?im)^\s*Обход через DNS:\s*(вкл|выкл)\b')
    if($m.Count){$dns=$m[$m.Count-1].Groups[1].Value.ToLowerInvariant()}
    $localStatuses=[regex]::Matches($Text,'(?im)^\s*Локальный прокси:\s*([^\r\n]+)')
    $proxyBlocked=$localStatuses.Count -gt 0 -and $localStatuses[$localStatuses.Count-1].Groups[1].Value -match '(?i)^недоступно\s*\(в системе задан свой прокси\)'
    if($proxyBlocked){$issues.Add([pscustomobject]@{Code='SYSTEM_PROXY_CONFIGURED';Priority=1;Title='Системный прокси блокирует переключатель Unlocker';Cause='Проверим его адрес и наличие работающего локального слушателя.';Actions=@('Proxy');Evidence=@('Локальный прокси: недоступно (в системе задан свой прокси)')})}
    $region=@($tail|Where-Object{$_.Text -match '(?i)region-400|User location is not supported|location.*not supported'})
    if($region.Count){
        $code='REGION_REFUSAL';$cause='Сервис отклонил выбранный выход по региону. Выберите свой VPN или подходящий путь Zapret.';$actions=@('Profile')
        if($country -eq 'RU'){$code='VPN_EXIT_RU';$cause='В отчёте указан выход VPN RU. Выберите поддерживаемую сервисом страну, например Германию или Нидерланды.'}
        elseif($vpn -eq 'NotDetected'){$code='VPN_NOT_DETECTED';$cause='VPN не обнаружен по сокетам. Включите свой VPN/TUN или выберите настроенный Zapret.'}
        elseif($vpn -eq 'Detected' -and $country -and $country -ne 'RU' -and $dns -eq 'вкл'){$code='VPN_DNS_CONFLICT';$cause='Одновременно выбраны VPN и DNS-обход Unlocker. Проверим относящиеся к Unlocker NRPT-правила.';$actions+= 'Nrpt'}
        $issues.Add([pscustomobject]@{Code=$code;Priority=2;Title='Региональный отказ при обращении к Google';Cause=$cause;Actions=$actions;Evidence=@($region|Select-Object -Last 2|ForEach-Object{Protect-AGText $_.Text})})
    }
    $nodes=@($tail|Where-Object{
        $_.Text -match '(?i)прокси из группы|встроенн(?:ый|ые) выход' -and $_.Text -match '(?i)не отвечает|не ответил|рв[её]т|разорва|сброс|reset|timed out|os error\s*(?:10054|10060)|отложен'
    })
    if($nodes.Count){$issues.Add([pscustomobject]@{Code='COMMUNITY_ROUTE_FAILURE';Priority=3;Title='Сбои подключения через выходы сообщества';Cause='Отключим групповые/встроенные выходы при переходе на выбранный вами VPN или Zapret.';Actions=@('Profile');Evidence=@($nodes|Select-Object -Last 2|ForEach-Object{Protect-AGText $_.Text})})}
    $cooldown=@($tail|Where-Object{$_.Text -match '(?i)отложен[^\r\n]{0,45}?(?<n>\d+)\s*мин\b' -and [double]$Matches['n'] -ge 10 -and [double]$Matches['n'] -le 80})
    if($cooldown.Count){$issues.Add([pscustomobject]@{Code='ROUTE_COOLDOWN';Priority=4;Title='Маршрут отложен локальным таймером Unlocker';Cause='Перезапустим известные задачи Unlocker и пересоздадим gate.json с резервной копией.';Actions=@('Restart');Evidence=@($cooldown|Select-Object -Last 2|ForEach-Object{Protect-AGText $_.Text})})}
    # A current route snapshot can show high latency even when no timestamped log is present.
    $slow=@($eligible|Where-Object{$_.Context -ne 'History' -and $_.Text -match '(?i)^\s*(?:прокси из группы|встроенный выход)\s*—' -and $_.Text -match '(?i)(?<n>\d+)\s*мс\b' -and [double]$Matches['n'] -ge 1800})
    if($slow.Count -and -not $nodes.Count){$issues.Add([pscustomobject]@{Code='COMMUNITY_ROUTE_SLOW';Priority=3;Title='Высокая задержка выхода сообщества';Cause='Можно перейти на свой VPN или Zapret. Нагрузка сервера по задержке не определяется.';Actions=@('Profile');Evidence=@($slow|Select-Object -Last 2|ForEach-Object{Protect-AGText $_.Text})})}
    $sorted=@($issues.ToArray()|Sort-Object Priority)
    $title=if($sorted.Count){$sorted[0].Title}else{'Автоматически исправляемая причина не найдена'}
    return [pscustomobject]@{Title=$title;VPN=$vpn;VpnCountry=$country;DnsBypass=$dns;TailCount=$tail.Count;Issues=$sorted;Actions=@($sorted|ForEach-Object{$_.Actions}|Sort-Object -Unique);RecentEvidence=@($tail|Select-Object -Last 4|ForEach-Object{Protect-AGText $_.Text})}
}
