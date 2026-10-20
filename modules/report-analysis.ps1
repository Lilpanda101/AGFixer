#Requires -Version 5.1
# Pure/offline report analysis. No network, services or adapter changes.
. "$PSScriptRoot/express-analysis.ps1"
function Protect-AGText {
    param([AllowEmptyString()][string]$Text)
    if ($null -eq $Text) { return '' }
    # Conservative line removal: don't attempt to parse secret JSON/URI formats exhaustively.
    $secret = '(?i)(?:authorization\s*:|bearer\s+|(?:api[_ -]?key|token|токен|password|пароль|passwd|secret|private[_ -]?key|presharedkey|ключ[^:=\r\n]{0,60}|код\s*ПК|own_proxy|group_code|group_key)\s*["'':=]|\bagk1\b|\bagk1[.:_-])'
    $Text = [regex]::Replace($Text, '(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----', '[PRIVATE KEY REDACTED]')
    $lines = foreach ($line in ($Text -split '\r?\n')) {
        if ($line -match $secret -or $line -match '://[^/\s]*@' -or $line -match '-----BEGIN .*PRIVATE KEY-----') { '[REDACTED sensitive line]'; continue }
        $line
    }
    $result = $lines -join "`n"
    $result = [regex]::Replace($result, '(?i)\b(?:https?|socks5|vless|vmess|trojan|ss)://[^\s<>"'']+', '[URL REDACTED]')
    $result = [regex]::Replace($result, '(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', '[EMAIL]')
    $result = [regex]::Replace($result, '(?i)\b(?:[a-z]:\\Users\\|/Users/|/home/)[^\\/\s"'']+', '[USER_HOME]')
    $result = [regex]::Replace($result, '(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])', '[IPv4]')
    $result = [regex]::Replace($result, '(?i)(?<![\w:])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:]{0,4}(?:%[\w.-]+)?(?![\w:])', [Text.RegularExpressions.MatchEvaluator]{
        param($match)
        $address=$null
        if ([Net.IPAddress]::TryParse($match.Value,[ref]$address) -and $address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { '[IPv6]' } else { $match.Value }
    })
    $result = [regex]::Replace($result, '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', '[UUID]')
    $result = [regex]::Replace($result, '(?i)(?<![a-z0-9])[a-z0-9_+/=-]{32,}(?![a-z0-9])', '[LONG_ID]')
    return $result
}
function ConvertTo-AGReportNumber {
    param([string]$Value)
    $number=0L
    if([long]::TryParse($Value,[ref]$number)){return $number}
    return $null
}
function Get-AGReportRecords {
    param([string[]]$Lines)
    $history=$false
    # Separate clauses so "no 400 errors; HTTP 429" does not hide the real 429.
    $clauses=@(foreach($sourceLine in $Lines){foreach($part in ($sourceLine -split '(?:;|,\s*но\s+|\s+но\s+(?=HTTP))')){$part}})
    foreach($line in $clauses){
        if($line -match '(?i)^\s*(?:[-—=]+\s*)?(?:последние\s+(?:строки|события)|фрагмент\s+лога|журнал событий|лог службы)'){$history=$true}
        if($line -match '(?i)^\s*(?:маршруты\s*\(|настройки\s*:|служба\s*:)'){$history=$false}
        $context=if($line -match '(?i)сейчас не используется'){'Inactive'}elseif($history -or $line -match '^\s*(?:\[?\d{4}-\d{2}-\d{2}[ T])?\[?\d{2}:\d{2}:\d{2}' -or $line -match '(?i)последн(?:яя|ий)\s+(?:ошибка|ответ)|\d+\s*(?:с|сек|мин|ч)\s+назад'){'History'}elseif($line -match '(?i)^\s*(?:служба:|версия службы:|сверять TLS:|Antigravity[^:]*:|\S.*?—\s*(?:отложен|доступен))'){'Snapshot'}else{'Unknown'}
        # Explanations are not observed failures, even inside a timestamped log.
        $explanation=$line -match '(?i)сервисы разблокировки не подменили адрес|напрямую будет ошибка|(?:если|например|пример|допустим)[^\r\n]{0,80}(?:HTTP|ошибк|10060|10054)|(?:не является|не означает|не доказывает)[^\r\n]{0,45}(?:ошибк|блокиров|DNS)|^\s*(?:проверьте|сравните|рекомендация|совет|инструкция)\b'
        $negative=$line -match '(?i)(?:ошиб(?:ок|ки|ка)[^\r\n]{0,45}(?:нет\b|не (?:было|найден|обнаружен))|(?:HTTP\s*\d{3}[^\r\n]{0,15}(?:нет\b|не обнаружен))|no\s+(?:(?:HTTP\s*)?\d{3}\s+)?errors?\b|ошибок\s+\d{3}[^:\r\n]*:\s*0\b)'
        [pscustomobject]@{Text=$line;Context=$context;Ignored=($explanation -or $negative)}
    }
}
function Format-AGReportContext {
    param([string]$Context)
    switch($Context){'Snapshot'{'На момент создания отчёта'} 'History'{'Журнал'} 'Inactive'{'Маршрут сейчас не используется'} 'Mixed'{'Записи разного времени и состояния'} default {'Актуальность не установлена'}}
}
function New-AGReportFinding {
    param([string]$Code,[string]$Summary,[string]$Action,[object[]]$Records)
    $sampleList=New-Object 'System.Collections.Generic.List[object]'
    foreach($kind in @('Snapshot','Unknown','History','Inactive')){
        $representative=@($Records|Where-Object{$_.Context -eq $kind}|Select-Object -Last 1)
        if($representative.Count){$sampleList.Add($representative[0])}
    }
    foreach($record in @($Records|Select-Object -Last 8)){
        if($sampleList.Count -ge 8){break}
        if(-not $sampleList.Contains($record)){$sampleList.Add($record)}
    }
    $sample=@($sampleList.ToArray())
    $details=@(foreach($record in $sample){[pscustomobject]@{Text=(Protect-AGText $record.Text);Context=$record.Context}})
    $contexts=@($Records|ForEach-Object{$_.Context}|Select-Object -Unique)
    $context=if($contexts.Count -eq 1){$contexts[0]}else{'Mixed'}
    $label=switch($context){'Snapshot'{'состояние на момент отчёта'} 'History'{'события журнала'} 'Inactive'{'неиспользуемый маршрут; не общий диагноз'} 'Mixed'{'смешанный контекст; сверить со свежим запросом'} default {'время и актуальность не установлены'}}
    [pscustomobject]@{Code=$Code;Severity=$(if($context -in @('History','Inactive')){'Info'}else{'Warning'});Context=$context;Confidence=$label;Summary=$Summary;Evidence=@($details|ForEach-Object{$_.Text});EvidenceDetails=$details;EvidenceCount=$Records.Count;Action=$Action}
}
function Get-AGReportAnalysis {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][AllowEmptyString()][string]$Text, [int]$StaleAfterSeconds = 300)
    if ([string]::IsNullOrWhiteSpace($Text)) { throw 'Отчёт пуст.' }
    if ($Text.Length -gt 10MB) { throw 'Максимум 10 МБ текста.' }
    $findings = New-Object 'System.Collections.Generic.List[object]'
    $lines = @($Text -split '\r?\n')
    $records=@(Get-AGReportRecords -Lines $lines)
    $toggles = [ordered]@{}
    foreach ($label in @('Разблокировка входа','Автопатч','Обход через DNS','Локальный прокси','Встроенные выходы','Прокси из группы','Свой прокси','Сверять TLS')) {
        $allMatches = [regex]::Matches($Text, ('(?im)^\s*' + [regex]::Escape($label) + ':\s*(вкл|выкл|частично)\b'))
        $m = if($allMatches.Count){$allMatches[$allMatches.Count-1]}else{[regex]::Match('', 'never')}
        $toggles[$label] = if ($m.Success) { $m.Groups[1].Value.ToLowerInvariant() } else { 'неизвестно' }
    }
    $rules = @(
        @{ Code='CONNECTION_REFUSED'; Severity='Warning'; Pattern='(?i)(?:os error\s*|WSA\w*\s*[:=]?\s*|(?:ошибк[аи]|error|код)\s*[:=]?\s*|^\s*)10061\b|connection refused|активно отверг'; Summary='Соединение отклонено, возможны неверный порт или отсутствующий listener.'; Action='Сверьте фактический порт и владельца listener с настройками клиента. Не считайте 10809 или 53129 постоянным портом.' },
        @{ Code='MODEL_UNAVAILABLE'; Severity='Warning'; Pattern='(?i)model is not available|model.*not (?:available|found)|модель недоступна'; Summary='В тексте есть отказ доступности модели.'; Action='Проверьте точный идентификатор/доступ аккаунта/квоту и свежий ответ сервиса. Не удаляйте историю или профиль автоматически.' },
        @{ Code='ACCOUNT_SETUP'; Severity='Warning'; Pattern='(?i)unexpected issue setting up your account|account.*verification.*required|требуется.*верификац'; Summary='Ошибка настройки/проверки аккаунта.'; Action='Используйте проверку, предлагаемую официальным приложением; отдельно проверьте патч и сеть. Не извлекайте cookies/токены.' },
        @{ Code='REQUEST_SIZE'; Severity='Warning'; Pattern='(?i)payload too large|request (?:body )?too large|request[^\r\n]{0,30}exceeds[^\r\n]{0,30}limit'; Summary='Есть явное сообщение о слишком большом запросе.'; Action='Уменьшите контекст и определите, какой компонент вернул отказ. Не обещайте обход лимита сторонним релеем без проверки доверия и фактического ответа.' },
        @{ Code='REGION_REFUSAL'; Severity='Warning'; Pattern='(?i)User location is not supported|region-400|location.*not supported'; Summary='В тексте есть явный отказ по региону.'; Action='Проверьте, какой маршрут нёс отказ, а не только страну VPN. Для смены пути откройте быстрый ремонт.' },
        @{ Code='TIMEOUT'; Severity='Warning'; Pattern='(?i)(?:os error\s*|WSA\w*\s*[:=]?\s*|(?:ошибк[аи]|error|код)\s*[:=]?\s*|^\s*)10060\b|connection timed out|не подключиться:.*(?:тайм|timed out)|прокси не ответил вовремя'; Summary='Таймаут установления соединения/ответа прокси.'; Action='Сравните прямой TLS и TLS через фактический локальный прокси. Проверьте маршрут, фильтрацию и доступность сервера; это не доказательство ТСПУ.' },
        @{ Code='NETWORK_UNREACHABLE'; Severity='Warning'; Pattern='(?i)(?:os error\s*|(?:ошибк[аи]|error|код)\s*[:=]?\s*|^\s*)(?:10051|10065)\b|network is unreachable|no route to host'; Summary='В тексте недоступна сеть или маршрут к узлу.'; Action='Проверьте активный адаптер, маршрут и состояние VPN/kill-switch. Не сбрасывайте все сетевые настройки.' },
        @{ Code='RESET'; Severity='Warning'; Pattern='(?i)(?:os error\s*|WSA\w*\s*[:=]?\s*|(?:ошибк[аи]|error|код)\s*[:=]?\s*|^\s*)10054\b|connection reset|принудительно разорвал'; Summary='Сброс соединения.'; Action='Проверьте повторяемость на том же IP, DNS/маршрут, антивирусную TLS-инспекцию и стратегию Zapret. Не отключайте защиту автоматически.' },
        @{ Code='SOCKET_ACCESS_DENIED'; Severity='Warning'; Pattern='(?i)(?:os error\s*|WSA\w*\s*[:=]?\s*|(?:ошибк[аи]|error|код)\s*[:=]?\s*|^\s*)10013\b|socket.*access.*denied'; Summary='Операция сокета запрещена ОС/политикой.'; Action='Проверьте брандмауэр, VPN kill-switch, исключённые диапазоны портов и права. 10013 не означает автоматически занятый порт.' },
        @{ Code='PORT_IN_USE'; Severity='Warning'; Pattern='(?i)(?:os error\s*|WSA\w*\s*[:=]?\s*|(?:ошибк[аи]|error|код)\s*[:=]?\s*|^\s*)10048\b|address already in use|порт[^\r\n]{0,35}занят'; Summary='В тексте указан конфликт привязки порта.'; Action='Откройте локальный аудит: PID владельца DNS/прокси-порта. Не завершайте неизвестный процесс.' },
        @{ Code='DNS_FAILURE'; Severity='Warning'; Pattern='(?i)имя не разрешается|имя не разрешилось|name resolution failed|no such host'; Summary='Ошибка разрешения имени.'; Action='Проверьте hosts и относящиеся к Google NRPT-правила, DNS адаптера, TUN/fake-IP. Не очищайте все NRPT-правила.' },
        @{ Code='TLS_EOF'; Severity='Warning'; Pattern='(?i)рукопожатие:.*(?:unexpected end of file|EOF)|TLS.*handshake.*(?:fail|EOF)|certificate.*(?:invalid|unknown|expired)'; Summary='Ошибка TLS/преждевременное закрытие handshake.'; Action='Повторите строгий TLS-тест с фиксированным SNI напрямую и через прокси. Проверьте время ОС и доверие сертификату; не отключайте verify_tls.' },
        @{ Code='SERVICE_UNREACHABLE'; Severity='Warning'; Pattern='(?i)^\s*Служба:\s*(?:не запущена|остановлена|нет)|служба не отвечает|запись службы устарела'; Summary='В отчёте служба не работает/не отвечает.'; Action='Проверьте задачи, живой PID/путь ag_dns, владельцев портов и совместимость версий до перезапуска.' },
        @{ Code='PATCH_MISSING'; Severity='Warning'; Pattern='(?i)^\s*Antigravity[^\r\n]*—\s*НЕ\s+пропатчен'; Summary='Отчёт явно сообщает об отсутствии патча в установленном приложении.'; Action='Закройте IDE с сохранением работы; примените патч штатным Unlocker для нужной установки и версии. Эта утилита не подменяет файлы IDE.' },
        @{ Code='SILENT_TUNNEL'; Severity='Warning'; Pattern='(?i)Google не ответил ни байта|tunnels? in a row carried no answer'; Summary='Туннель открылся, но полезного ответа не было.'; Action='TCP-доступность не доказывает работу модели. Сопоставьте маршрут/время со свежим запросом и TLS-тестом.' }
    )
    foreach ($rule in $rules) {
        $hits=@($records|Where-Object{-not $_.Ignored -and [regex]::IsMatch($_.Text,$rule.Pattern)})
        if($hits.Count){$findings.Add((New-AGReportFinding -Code $rule.Code -Summary $rule.Summary -Action $rule.Action -Records $hits))}
    }
    # HTTP codes require status context: never match 429 inside timestamps/latencies/byte counts.
    $statusContext = '(?i)(?:\bHTTP(?:/\d(?:\.\d)?)?\s+|\bstatus(?:\s+code)?\s*[:=]?\s*|\berror\s*[:=]?\s*|ошибк[аи]?\s*[:=]?\s*)'
    foreach ($status in @(400,401,403,413,429,503)) {
        $hits = @($records | Where-Object { -not $_.Ignored -and $_.Text -match ($statusContext + $status + '\b') })
        if ($status -eq 400) {
            $hits += @($records | Where-Object { -not $_.Ignored -and $_.Text -match '(?i)^Ошибок\s+400(?:\s+за\s+\d+\s+ч)?\s*:\s*[1-9]\d*\b' })
        }
        if (-not $hits.Count) { continue }
        $action = switch ($status) {
            400 { 'Смотрите текст ошибки. Сам код не определяет ни DNS-утечку, ни региональную блокировку.' }
            401 { 'Проверьте вход/срок сессии в официальном приложении; пароль/токен в отчёт не включайте. Сброс DNS не обновляет авторизацию.' }
            403 { 'Проверьте текст отказа, права аккаунта и доступ к модели; не объявляйте автоматически региональной блокировкой.' }
            413 { 'Сократите размер запроса/контекст и проверьте ограничение того компонента, который ответил. Изменение DNS не снимает лимит размера.' }
            429 { 'Проверьте квоту/частоту запросов и Retry-After. Не меняйте DNS или Zapret ради снятия серверной квоты.' }
            503 { 'Проверьте сообщение capacity/overload и повторите позже. 503 сам по себе не доказывает локальную сетевую проблему.' }
        }
        $findings.Add((New-AGReportFinding -Code "HTTP_$status" -Summary "В тексте есть HTTP $status." -Action $action -Records $hits))
    }
    $serviceSchema = $null; $expectedSchema = $null; $ageSeconds = $null
    $m = [regex]::Match($Text, '(?im)^Версия службы:\s*(\d+)\s*\(эта программа ждёт\s*(\d+)\)')
    if ($m.Success) {
        $serviceSchema = ConvertTo-AGReportNumber $m.Groups[1].Value; $expectedSchema = ConvertTo-AGReportNumber $m.Groups[2].Value
        if ($null -ne $serviceSchema -and $null -ne $expectedSchema -and $serviceSchema -ne $expectedSchema) {
            $findings.Add([pscustomobject]@{ Code='SERVICE_SCHEMA_MISMATCH'; Context='Snapshot'; Severity='Warning'; Confidence='явное несовпадение'; Summary="Версия протокола службы $serviceSchema, окно ждёт $expectedSchema."; Evidence=@(Protect-AGText $m.Value); Action='Возможны старый ag_dns или окно от другой сборки. Сверьте путь/PID/версии, затем переустановите задачи штатным Unlocker. Не сравнивайте эти числа с версией IDE.' })
        }
    }
    $m = [regex]::Match($Text, '(?im)^Версия службы:[^\r\n]*запись\s+(\d+)\s*(с|сек|мин)\b')
    if ($m.Success) {
        $ageSeconds = ConvertTo-AGReportNumber $m.Groups[1].Value
        if ($null -ne $ageSeconds -and $m.Groups[2].Value -eq 'мин') { $ageSeconds = [Math]::Min([double][long]::MaxValue,[double]$ageSeconds * 60) }
        if ($ageSeconds -gt $StaleAfterSeconds) {
            $findings.Add([pscustomobject]@{ Code='STALE_SERVICE_REPORT'; Context='Snapshot'; Severity='Warning'; Confidence='возраст на момент сохранения отчёта'; Summary="Запись службы старше $StaleAfterSeconds секунд."; Evidence=@(Protect-AGText $m.Value); Action='Это возраст записи на момент создания TXT, не возраст самого TXT сейчас. Снимите новый отчёт и проверьте PID/задачи.' })
        }
    }
    if ($toggles['Сверять TLS'] -eq 'выкл') {
        $findings.Add([pscustomobject]@{ Code='TLS_VERIFICATION_DISABLED'; Context='Snapshot'; Severity='Warning'; Confidence='явный переключатель'; Summary='В Unlocker отключена сверка TLS.'; Evidence=@('Сверять TLS: выкл'); Action='Проверьте причину и восстановите сверку TLS в штатном Unlocker; утилита не отключает её ради успешного теста.' })
    }
    $routes = New-Object 'System.Collections.Generic.List[object]'
    foreach ($line in $lines) {
        $m = [regex]::Match($line, '^\s{2,}(свой прокси|прокси из группы|встроенный выход|резервный релей|напрямую|через ваш VPN)\s*—\s*(.+)$', 'IgnoreCase')
        if (-not $m.Success) { continue }
        $desc = $m.Groups[2].Value
        $latency = $null; $answers = $null; $refusals = $null
        $lm = [regex]::Match($desc, '(?<!\d)(\d+)\s*мс\b'); if ($lm.Success) { $latency=(ConvertTo-AGReportNumber $lm.Groups[1].Value) }
        $am = [regex]::Match($desc, 'ответов\s+(\d+)'); if ($am.Success) { $answers=(ConvertTo-AGReportNumber $am.Groups[1].Value) }
        $rm = [regex]::Match($desc, 'отказов\s+(\d+)'); if ($rm.Success) { $refusals=(ConvertTo-AGReportNumber $rm.Groups[1].Value) }
        $routes.Add([pscustomobject]@{ Name=$m.Groups[1].Value; Inactive=($desc -match 'сейчас не используется'); Delayed=($desc -match 'отложен'); ModelProven=($desc -match 'проверен ответом модели'); LatencyMs=$latency; Answers=$answers; Refusals=$refusals; Note=(Protect-AGText $desc) })
    }
    $m = [regex]::Match($Text, '(?im)^Первый (?:маршрут|путь) сейчас:\s*(.+)$')
    $firstRoute = if ($m.Success) { Protect-AGText $m.Groups[1].Value.Trim() } else { 'неизвестно' }
    $m = [regex]::Match($Text, '(?im)^Antigravity Unlocker(?:\s+2)?\s+v([0-9A-Za-z._-]+)')
    $version = if ($m.Success) { $m.Groups[1].Value } else { 'неизвестно' }
    # A route's model answer is evidence of usefulness; don't label every group proxy slow/broken.
    return [pscustomobject]@{ ReportText=$Text; ReportVersion=$version; ServiceSchema=$serviceSchema; ExpectedServiceSchema=$expectedSchema; RecordAgeSeconds=$ageSeconds; FirstRoute=$firstRoute; Toggles=[pscustomobject]$toggles; Routes=@($routes.ToArray()); Findings=@($findings.ToArray()); Diagnosis=(Get-AGExpressDiagnosis -Text $Text); Scope='События с известным временем: окно 10 минут на время отчёта.' }
}
function Show-AGReportAnalysis {
    param([Parameter(Mandatory=$true)]$Analysis)
    Write-Host $Analysis.Diagnosis.Title -ForegroundColor Yellow
    foreach($issue in @($Analysis.Diagnosis.Issues)){Write-Host $issue.Cause}
    foreach($finding in @($Analysis.Findings)){Write-Host ("[$($finding.Code)] "+$finding.Summary)}
}

. "$PSScriptRoot/smart-diagnostics.ps1"
