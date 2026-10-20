#Requires -Version 5.1
# Observations only. Reports and clipboard data never become executable commands.
function Get-AGLatencyGrade {
    param($Milliseconds)
    if($null -eq $Milliseconds -or $Milliseconds -isnot [ValueType] -or [double]$Milliseconds -lt 0){return 'Не измерено'}
    if($Milliseconds -lt 80){return 'Очень низкая задержка'}
    if($Milliseconds -lt 250){return 'Идеально'}
    if($Milliseconds -le 400){return 'Норма'}
    if($Milliseconds -lt 800){return 'Высокая задержка'}
    return 'Критически высокая задержка'
}
function Get-AGReportClock {
    param([string]$Text)
    $matches=[regex]::Matches($Text,'(?im)^\s*(?:Report time|Created at|Timestamp|Время отч[её]та|Отч[её]т создан)\s*:\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s*$')
    if($matches.Count){$date=[DateTimeOffset]::MinValue;if([DateTimeOffset]::TryParse($matches[$matches.Count-1].Groups[1].Value,[ref]$date)){return $date}}
    return $null
}
function Get-AGTimedReportEvents {
    param([string]$Text,[DateTimeOffset]$ReferenceTime,[AllowNull()]$ReportTime)
    $anchor=$ReferenceTime;if($null -ne $ReportTime){$anchor=[DateTimeOffset]$ReportTime}
    $ordinal=0
    foreach($record in @(Get-AGReportRecords -Lines @($Text -split '\r?\n'))){
        if($record.Ignored -or $record.Context -eq 'Inactive'){continue}
        $line=$record.Text;$age=$null;$time=$null;$basis='Unknown'
        # Relative ages are relative to report capture, never silently to the current clock.
        if($line -match '(?i)(?<age>\d+)\s*(?<unit>с|сек(?:унд[уы]?)?|мин(?:ут[уы]?)?|ч(?:ас(?:а|ов)?)?)\s+назад\b'){
            $rawAge=$Matches.age;$unit=$Matches.unit;$parsedAge=0L
            if([long]::TryParse($rawAge,[ref]$parsedAge)){$age=[double]$parsedAge}else{$age=[double]::PositiveInfinity}
            if($unit -like 'мин*'){$age*=60}elseif($unit -like 'ч*'){$age*=3600}
            $basis='RelativeToReport';if([double]::IsInfinity($age) -or $age -gt 3155760000){$age=$null;$basis='Unknown'}elseif($null -ne $ReportTime){try{$time=$anchor.AddSeconds(-$age)}catch{$age=$null;$basis='Unknown'}}
        }elseif($line -match '^\s*\[?(?<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\]?'){
            $parsed=[DateTimeOffset]::MinValue;if([DateTimeOffset]::TryParse($Matches.iso,[ref]$parsed)){$time=$parsed;$age=($anchor-$parsed).TotalSeconds;$basis='Absolute'}
        }elseif($null -ne $ReportTime -and $line -match '^\s*\[?(?<clock>\d{2}:\d{2}:\d{2})\]?\s+'){
            $span=[TimeSpan]::Zero;if([TimeSpan]::TryParse($Matches.clock,[ref]$span) -and $span.TotalHours -lt 24){$time=[DateTimeOffset]::new($anchor.Year,$anchor.Month,$anchor.Day,$span.Hours,$span.Minutes,$span.Seconds,$anchor.Offset);if($time -gt $anchor){$time=$time.AddDays(-1)};$age=($anchor-$time).TotalSeconds;$basis='ReportClock'}
        }
        $kind='Other'
        if($line -match '(?i)(?:ответ модели|модель ответила|model (?:reply|response)|проверен ответом модели)' -and $line -notmatch '(?i)(?:нет|без|не было|не получен|не н[её]с|отсутств|no\s+model|ответов\s+0)'){$kind='ModelReply'}
        elseif($line -match '(?i)region-400|User location is not supported'){$kind='Region400'}
        elseif($line -match '(?i)(?:HTTP(?:/\d(?:\.\d)?)?\s+|ошибк[аи]?\s*:?\s*|status\s*:?\s*)400\b'){$kind='Http400'}
        elseif($line -match '(?i)(?:os error\s*10060\b|connection timed out|прокси не ответил вовремя)'){$kind='Timeout'}
        elseif($line -match '(?i)(?:HTTP(?:/\d(?:\.\d)?)?\s+|ошибк[аи]?\s*:?\s*)503\b'){$kind='Http503'}
        elseif($line -match '(?i)(?:HTTP(?:/\d(?:\.\d)?)?\s+|ошибк[аи]?\s*:?\s*)429\b'){$kind='Http429'}
        elseif($line -match '(?i)рв[её]т соединение|connection reset|os error\s*10054|обрыв стрима|unexpected end of file'){$kind='Disconnect'}
        $recent=$null -ne $age -and $age -ge 0 -and $age -le 600
        [pscustomobject]@{Order=$ordinal;Kind=$kind;AgeSeconds=$age;At=$time;Recent=$recent;TimeBasis=$basis;Text=(Protect-AGText $line)}
        $ordinal++
    }
}
function Get-AGSmartDiagnosis {
    param([string]$Text,$Analysis,$Snapshot,$Status,[DateTimeOffset]$ReferenceTime=[DateTimeOffset]::UtcNow,$ReportTime)
    if(-not $Analysis -and $Text){$Analysis=Get-AGReportAnalysis $Text}
    if($null -eq $ReportTime){$ReportTime=Get-AGReportClock $Text}
    $events=@(Get-AGTimedReportEvents -Text $Text -ReferenceTime $ReferenceTime -ReportTime $ReportTime)
    $recent=@($events|Where-Object Recent);$success=@($recent|Where-Object Kind -eq 'ModelReply'|Sort-Object AgeSeconds,@{Expression='Order';Descending=$true}|Select-Object -First 1)
    $errors=@($recent|Where-Object Kind -in @('Region400','Http400','Timeout','Disconnect'))
    $active=$errors.Count -gt 0 -and (-not $success.Count -or @($errors|Where-Object{($_.AgeSeconds -lt $success[0].AgeSeconds -or ($_.AgeSeconds -eq $success[0].AgeSeconds -and $_.Order -gt $success[0].Order))}).Count -gt 0)
    $freshModel=$success.Count -gt 0 -and $success[0].AgeSeconds -lt 60 -and -not $active
    $scope=if($null -ne $ReportTime){'На время отчёта '+([DateTimeOffset]$ReportTime).ToString('o')}else{'По тексту отчёта; время захвата не указано'}
    $errorNames=@{Region400='региональный отказ Google (400)';Http400='ошибка HTTP 400';Timeout='нет ответа вовремя';Disconnect='соединение оборвалось'}
    $model=if($freshModel){'Есть ответ модели ('+[int]$success[0].AgeSeconds+' с назад)'}elseif($active){'Есть свежий сбой: '+(@($errors.Kind|Select-Object -Unique|ForEach-Object{$errorNames[$_]}) -join ', ')}else{'Нет подтверждения свежего ответа'}
    $route='Не определён';$latency=$null;$routes=@()
    if($Analysis){$route=$Analysis.FirstRoute;$routes=@($Analysis.Routes|Where-Object{-not $_.Inactive -and $_.Name -eq $Analysis.FirstRoute});if($routes.Count -eq 1){$latency=$routes[0].LatencyMs}}
    $verdicts=New-Object 'Collections.Generic.List[object]'
    function Add-SmartVerdict {param($Code,$Title,$Level='Warning',$Action='',$EvidenceSource='Report') $verdicts.Add([pscustomobject]@{Code=$Code;Title=$Title;Level=$Level;Action=$Action;Source=$EvidenceSource})}
    $vpn='Unknown';$country='';$dns=$null;$local=$null
    if($Analysis){$vpn=$Analysis.Diagnosis.VPN;$country=$Analysis.Diagnosis.VpnCountry;$dns=$Analysis.Toggles.'Обход через DNS';$local=$Analysis.Toggles.'Локальный прокси'}
    $tun=$Status -and $Status.Vpn -and $Status.Vpn.State -eq 'DestinationViaVpn'
    if($route -in @('','неизвестно','Не определён') -and $vpn -eq 'Detected'){$route='VPN указан в отчёте; путь не проверен'}
    if($Snapshot){
        if(@($Snapshot.Proxies|Where-Object Eligible).Count){Add-SmartVerdict 'SYSTEM_PROXY_STUCK' 'Локальный прокси не слушает порт' 'Error' 'Proxy' 'Windows'}
        if(@($Snapshot.Proxies|Where-Object{$_.State.PAC}).Count){Add-SmartVerdict 'PAC_URL_HIJACK' 'Настроен PAC: проверьте, нужен ли он' 'Info' '' 'Windows'}
        if(@($Snapshot.Nrpt).Count -and ($tun -or $vpn -eq 'Detected')){Add-SmartVerdict 'DNS_LEAK_NRPT_CONFLICT' 'VPN и правила DNS Unlocker требуют согласования' 'Warning' 'Nrpt' 'WindowsAndReport'}
    }
    if($Snapshot -and $Snapshot.WinHttpDump -match '(?im)^\s*set\s+(?:proxy|advproxy)\b'){Add-SmartVerdict 'WINHTTP_DIRTY_PROXY' 'WinHTTP использует прокси: проверьте назначение' 'Info' '' 'Windows'}
    if($Status -and $Status.ZapretHealth -and @($Status.ZapretHealth.Missing).Count){
        $missing=@($Status.ZapretHealth.Missing);$required=@($Status.ZapretHealth.Required)
        $label=if($required.Count){'Zapret: есть '+($required.Count-$missing.Count)+' из '+$required.Count+' доменов; добавить '+$missing.Count+' (L: список)'}else{'Zapret: добавить домены — '+($missing -join ', ')}
        Add-SmartVerdict 'ZAPRET_MISSING_GOOGLE_DOMAINS' $label 'Warning' 'ZapretLists' 'Windows'
    }
    if($Status -and $Status.GameFilter -and $Status.GameFilter.Mode -notin @('disabled','unknown','')){Add-SmartVerdict 'ZAPRET_GAMEFILTER_COLLISION' 'Включён Game Filter: совместимость требует проверки' 'Info' '' 'Windows'}
    if(@($recent|Where-Object Kind -eq Region400).Count -and $active){
        if($country -eq 'RU'){Add-SmartVerdict 'VPN_EXIT_RUSSIA' 'В отчёте выход VPN — RU: смените страну' 'Error'}
        elseif($vpn -eq 'NotDetected'){Add-SmartVerdict 'REGION_400_RAW_RUSSIA' 'Google отклонил регион; VPN в отчёте не обнаружен' 'Error'}
    }
    if(($tun -or ($vpn -eq 'Detected' -and $country -and $country -ne 'RU')) -and $local -eq 'вкл'){Add-SmartVerdict 'LOCAL_PROXY_ACTIVE_UNDER_VPN' 'Для прямого VPN/TUN выключите локальный прокси Unlocker' 'Warning' 'ChooseVpn'}
    $community=@($recent|Where-Object{$_.Kind -in @('Timeout','Disconnect') -and $_.Text -match '(?i)прокси из группы|встроенн.*выход'})
    if($community.Count){Add-SmartVerdict 'COMMUNITY_PROXY_COLLAPSE' 'Сбои выхода сообщества: выберите свой VPN или Zapret' 'Error' 'ChooseProfile'}
    if($active -and $Analysis -and @($Analysis.Routes|Where-Object{$_.Delayed -and -not $_.Inactive}).Count){Add-SmartVerdict 'ROUTE_PENALTY_BAN' 'Маршрут отложен таймером Unlocker' 'Warning' 'Restart'}
    if(@($recent|Where-Object Kind -eq Timeout).Count){Add-SmartVerdict 'TSPU_TCP_DROP_10060' 'Соединение не ответило вовремя; проверьте путь' 'Error'}
    if(@($recent|Where-Object Kind -eq Http503).Count){Add-SmartVerdict 'GOOGLE_CAPACITY_503' 'Сервис вернул 503: повторите позже или смените модель' 'Warning'}
    if(@($recent|Where-Object Kind -eq Http429).Count){Add-SmartVerdict 'MODEL_QUOTA_429' 'Сервис ограничил запросы: проверьте квоту и Retry-After' 'Warning'}
    if($Analysis){
        foreach($finding in @($Analysis.Findings)){
            switch($finding.Code){
                'SERVICE_UNREACHABLE'{Add-SmartVerdict 'UNLOCKER_SERVICE_STOPPED' 'Сетевая часть Unlocker не отвечает: проверьте задачи' 'Error' ''}
                'ACCOUNT_SETUP'{Add-SmartVerdict 'OAUTH_LOGIN_PORT_BLOCKED' 'Ошибка входа: проверьте официальный вход и настройки сети' 'Warning'}
            }
        }
    }
    if($Text -match '(?im)^\s*Сокеты службы:\s*Mixed\b'){Add-SmartVerdict 'MIXED_SOCKETS_LEAK' 'Смешанные сокеты: уточните маршруты, это не доказательство утечки' 'Info'}
    if($Text -match '(?im)^\s*(?:Проблема|Симптом):\s*(?:ч[её]рный|белый|пустой)\s*(?:экран|фрейм)'){Add-SmartVerdict 'GPU_CACHE_CORRUPTION' 'Пустое окно IDE: можно пересоздать GPUCache с копией' 'Warning' 'GpuCache'}
    if($null -ne $latency -and $latency -gt 400){Add-SmartVerdict 'LATENCY_OVERLOAD_GEMINI' ('Высокая задержка активного маршрута: '+$latency+' мс') 'Warning'}
    if($freshModel -and -not $verdicts.Count){Add-SmartVerdict 'FULLY_OPERATIONAL' 'Есть свежий ответ модели; сетевой ремонт не нужен' 'Info'}
    $windows=@($verdicts|Where-Object{$_.Source -in @('Windows','WindowsAndReport') -and $_.Level -ne 'Info'}|ForEach-Object Title)
    $counts=[ordered]@{errors_400_last_10m=@($recent|Where-Object Kind -in @('Region400','Http400')).Count;errors_503_last_10m=@($recent|Where-Object Kind -eq Http503).Count;stream_disconnects_last_10m=@($recent|Where-Object Kind -eq Disconnect).Count;last_model_reply_sec_ago=if($success.Count){$success[0].AgeSeconds}else{$null};window_anchor=if($null -ne $ReportTime){([DateTimeOffset]$ReportTime).ToString('o')}else{$null};untimed_events=@($events|Where-Object{$null -eq $_.AgeSeconds -and $_.Kind -ne 'Other'}).Count}
    return [pscustomobject]@{Model=$model;Route=$route;LatencyMs=$latency;LatencyGrade=(Get-AGLatencyGrade $latency);WindowsProblems=$windows;Verdicts=@($verdicts.ToArray());Events=$events;Summary=[pscustomobject]$counts;ActiveFailure=[bool]$active;FreshModel=[bool]$freshModel;Scope=$scope;ReportTime=$ReportTime;Analysis=$Analysis}
}
function Get-AGSmartCardLines {
    param($Diagnosis)
    $issues=if($Diagnosis.WindowsProblems.Count){$Diagnosis.WindowsProblems -join '; '}else{'Нет подтверждённых локальных неисправностей'}
    return @(
        ('Модель: '+$Diagnosis.Model)
        ('Маршрут: '+$Diagnosis.Route)
        ('Задержка: '+$Diagnosis.LatencyGrade+$(if($null -ne $Diagnosis.LatencyMs){' ('+$Diagnosis.LatencyMs+' мс; замер маршрута)'}else{''}))
        ('Проверка: '+$issues)
    )
}
function ConvertTo-AGForensicDump {
    param($Diagnosis,$Snapshot,$Status)
    $toggles=[ordered]@{};$analysis=$Diagnosis.Analysis
    $map=@{login_unlock='Разблокировка входа';autopatch='Автопатч';dns_bypass='Обход через DNS';local_proxy='Локальный прокси';builtin_exits='Встроенные выходы';group_proxy='Прокси из группы';custom_proxy='Свой прокси'}
    foreach($key in @($map.Keys|Sort-Object)){$v=$null;if($analysis){$v=switch($analysis.Toggles.($map[$key])){'вкл'{$true}'выкл'{$false}default{$null}}};$toggles[$key]=$v}
    $stuck=@();$pac=$null;$namespaces=@();$nrptCount=$null
    if($Snapshot){
        $stuck=@($Snapshot.Proxies|Where-Object Eligible|ForEach-Object{[pscustomobject]@{scope=$_.Scope;server=if(@(Get-AGRepairProxyPorts $_.Server).Count){[string]$_.Server}else{$null}}})
        $pac=[bool]@($Snapshot.Proxies|Where-Object{$_.State.PAC}).Count
        if($Snapshot.NrptKnown){$namespaces=@($Snapshot.Nrpt|ForEach-Object{$_.Namespace}|Sort-Object -Unique);$nrptCount=@($Snapshot.Nrpt).Count}
    }
    $penalties=@();if($analysis){$penalties=@($analysis.Routes|ForEach-Object{[pscustomobject]@{route=if($_.Name -in @('напрямую','встроенный выход','прокси из группы','свой прокси','через ваш VPN')){$_.Name}else{'other'};delayed=[bool]$_.Delayed;inactive=[bool]$_.Inactive;latency_ms=$_.LatencyMs;answers=$_.Answers;refusals=$_.Refusals}})}
    $os=$null;try{$os=[Environment]::OSVersion.VersionString}catch{}
    $obj=[ordered]@{schema_version=1;agfixer_version='1.10.8';timestamp=[DateTimeOffset]::UtcNow.ToString('o');report_timestamp=$Diagnosis.ReportTime;system=[ordered]@{os=$os;is_admin=$null;stuck_proxies=$stuck;pac_configured=$pac;winhttp_proxy=if($Snapshot -and $Snapshot.WinHttpDump){if($Snapshot.WinHttpDump -match '(?im)^\s*set\s+(?:proxy|advproxy)\b'){'configured'}elseif($Snapshot.WinHttpDump -match '(?im)^\s*reset\s+proxy\s*$'){'direct'}else{$null}}else{$null};eligible_unlocker_nrpt_count=$nrptCount;nrpt_namespaces=$namespaces};unlocker=[ordered]@{version=if($analysis){$analysis.ReportVersion}else{$null};service_running=if($Status){[bool]$Status.AgDnsRunning}else{$null};toggles=$toggles;toggle_source='Report';current_first_route=if($Diagnosis.Route -in @('напрямую','встроенный выход','прокси из группы','свой прокси','через ваш VPN')){$Diagnosis.Route}else{'unknown'};route_penalties=$penalties};network_reality=[ordered]@{vpn_client_detected=if($Status){[bool]$Status.Vpn.ClientRunning}else{$null};vpn_route_configuration=if($Status){$Status.Vpn.State}else{$null};vpn_exit_country=if($analysis -and $analysis.Diagnosis.VpnCountry){$analysis.Diagnosis.VpnCountry}else{$null};country_source='Report; not independently verified';direct_google_tcp_syn=$null;zapret_running=if($Status){[bool]$Status.ZapretRunning}else{$null}};last_events_summary=$Diagnosis.Summary;verdicts=@($Diagnosis.Verdicts);unknowns=@('WinHTTP endpoint intentionally omitted; configuration status only','External exit country not measured','TCP SYN not captured','All NRPT rules count not collected; only eligible Unlocker rules');evidence_scope=$Diagnosis.Scope}
    try{if($env:OS -eq 'Windows_NT'){$obj.system.is_admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}}catch{}
    return ($obj|ConvertTo-Json -Depth 12 -Compress)
}
