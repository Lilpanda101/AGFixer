#Requires -Version 5.1
# Untrusted reports are data only. Never import command text, paths or repair plans as actions.
function ConvertFrom-AGForensicReport {
    param([Parameter(Mandatory=$true)]$Report)
    if($Report -is [array] -or $Report.schema_version -isnot [ValueType] -or $Report.schema_version -ne 1 -or
       [string]$Report.agfixer_version -notmatch '^\d+\.\d+(?:\.\d+)?$' -or
       $null -eq $Report.unlocker -or $null -eq $Report.system -or $null -eq $Report.network_reality){
        throw 'Нужен JSON-отчёт AGFixer (schema_version: 1), а не конфиг или список команд.'
    }
    $version=[string]$Report.unlocker.version
    if($version -notmatch '^\d+(?:\.\d+){1,3}$'){$version='0.0'}
    $lines=@('Antigravity Unlocker v'+$version)
    # Only original capture time is usable, never the later JSON export time.
    $date=[DateTimeOffset]::MinValue
    if($Report.report_timestamp -and [DateTimeOffset]::TryParse([string]$Report.report_timestamp,[ref]$date)){
        $lines+='Время отчёта: '+$date.ToString('o')
    }
    $map=[ordered]@{login_unlock='Разблокировка входа';autopatch='Автопатч';dns_bypass='Обход через DNS';local_proxy='Локальный прокси';builtin_exits='Встроенные выходы';group_proxy='Прокси из группы';custom_proxy='Свой прокси'}
    foreach($name in $map.Keys){
        $value=$Report.unlocker.toggles.$name
        if($value -is [bool]){$lines+=$map[$name]+': '+$(if($value){'вкл'}else{'выкл'})}
    }
    $routes=@('напрямую','встроенный выход','прокси из группы','свой прокси','через ваш VPN')
    if($Report.unlocker.current_first_route -in $routes){$lines+='Первый маршрут сейчас: '+$Report.unlocker.current_first_route}
    # No synthetic log lines or recent successes/errors from aggregate counters.
    # Imported system/NRPT/proxy paths, verdicts and executable strings never reach a repair plan.
    return ($lines -join "`r`n")
}
function Import-AGReportFile {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)
    $path=$Path.Trim()
    # conhost drag/drop quotes paths; PowerShell can prefix & before a quoted file.
    if($path -match '^&\s+(["''])'){$path=$path.Substring(1).TrimStart()}
    if($path.Length -ge 2 -and (($path.StartsWith('"') -and $path.EndsWith('"')) -or ($path.StartsWith("'") -and $path.EndsWith("'")))){$path=$path.Substring(1,$path.Length-2)}
    if([string]::IsNullOrWhiteSpace($path)){throw 'Путь к отчёту пуст.'}
    if($path -match '^(?:https?|ftp)://|^\\\\|^//|^\\[?.]\\'){throw 'Сохраните отчёт на локальном диске и укажите один файл.'}
    $full=[IO.Path]::GetFullPath($path)
    if(-not(Test-Path -LiteralPath $full -PathType Leaf)){throw 'Файл не найден. Перетащите один TXT или JSON в окно и нажмите Enter.'}
    if([IO.Path]::GetExtension($full).ToLowerInvariant() -notin @('.txt','.log','.json')){throw 'Поддерживаются TXT/LOG-отчёты Unlocker и JSON-отчёты AGFixer.'}
    $stream=$null;$reader=$null
    try{
        $stream=[IO.File]::Open($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        if($stream.Length -le 0 -or $stream.Length -gt 10MB){throw 'Нужен непустой отчёт размером не больше 10 МБ.'}
        # Strict UTF-8, or Unicode encoding identified by BOM. No code evaluation.
        $reader=New-Object IO.StreamReader($stream,(New-Object Text.UTF8Encoding($false,$true)),$true)
        $text=$reader.ReadToEnd()
    }finally{if($reader){$reader.Dispose()}elseif($stream){$stream.Dispose()}}
    if([string]::IsNullOrWhiteSpace($text)){throw 'Отчёт пуст.'}
    $format='Unlocker TXT'
    if([IO.Path]::GetExtension($full) -ieq '.json'){
        try{$json=$text|ConvertFrom-Json -ErrorAction Stop}catch{throw 'JSON повреждён. Выберите сохранённый JSON-отчёт AGFixer.'}
        $text=ConvertFrom-AGForensicReport -Report $json;$format='AGFixer JSON (сводка)'
    }elseif($text -notmatch '(?im)^\s*Antigravity Unlocker(?:\s+2)?\s+v[0-9]'){
        throw 'В файле не найден отчёт Antigravity Unlocker. Сохраните полный отчёт, а не фрагмент лога.'
    }
    return [pscustomobject]@{Text=$text;SourcePath=$full;Format=$format}
}
function Read-AGReportFile {
    Show-AGMenuScreen 'Открыть отчёт из файла'
    Write-Host 'Перетащите TXT/LOG Unlocker или JSON AGFixer в это окно.'
    Write-Host 'Можно вставить полный путь. Кавычки вокруг пути допустимы.'
    Write-Host 'Enter без пути — отмена. Файл не запускается и не изменяется.'
    $path=Read-AGInput 'Путь к отчёту'
    if([string]::IsNullOrWhiteSpace($path)){return ''}
    $loaded=Import-AGReportFile -Path $path
    Add-AGUiJournal ('Загружен отчёт: '+$loaded.SourcePath)
    if($loaded.Format -like 'AGFixer JSON*'){
        Show-AGTextPages -Title 'JSON-отчёт загружен' -Lines @('Это сохранённая сводка, а не полный журнал Unlocker.','Используем известные переключатели и маршрут из отчёта.','Перед ремонтом заново проверяем настройки этого компьютера.','Команды, пути и готовые планы из файла не выполняются.')
    }
    return $loaded.Text
}
function Read-AGReportSource {
    $pick=Read-AGListChoice -Title 'Откуда взять отчёт?' -Options @('Из файла — перетащить в окно или вставить путь','Из буфера обмена — скопированный текст Unlocker') -Intro @('После загрузки: результат → «Исправить найденное» → план ремонта.')
    if(-not $pick){return ''}
    if($pick -eq 1){return (Read-AGReportFile)}
    $text=Get-Clipboard -Raw -ErrorAction Stop
    if($text -isnot [string] -or $text.Length -gt 10MB -or $text -notmatch '(?im)^\s*Antigravity Unlocker(?:\s+2)?\s+v[0-9]'){throw 'В буфере нет полного отчёта Unlocker. Выберите файл или скопируйте текст отчёта.'}
    return $text
}
