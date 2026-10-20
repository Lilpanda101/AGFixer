#Requires -Version 5.1
. "$PSScriptRoot/console-input.ps1"
function ConvertTo-AGSafeObject {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return (Protect-AGText $Value) }
    if ($Value -is [System.Collections.IDictionary]) {
        $obj=[ordered]@{}
        foreach ($key in $Value.Keys) { $obj[[string]$key]=ConvertTo-AGSafeObject $Value[$key] }
        return [pscustomobject]$obj
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $items=@(foreach ($item in $Value) { ConvertTo-AGSafeObject $item })
        return ,$items
    }
    if ($Value -is [ValueType]) { return $Value }
    $obj=[ordered]@{}
    foreach ($prop in $Value.PSObject.Properties) { $obj[$prop.Name]=ConvertTo-AGSafeObject $prop.Value }
    return [pscustomobject]$obj
}
function Export-AGSupportBundle {
    [CmdletBinding()]
    param(
        [string]$ReportText,
        [hashtable]$Answers = @{},
        $LocalAudit,
        [switch]$IncludeLogTail,
        [string]$OutputDirectory = $PSScriptRoot
    )
    if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) { throw 'Папка для сохранения не существует.' }
    $name = 'AG-support-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
    $stage = Join-Path ([IO.Path]::GetTempPath()) $name
    $null = New-Item -ItemType Directory -Path $stage -ErrorAction Stop
    $buildingZip=Join-Path $OutputDirectory ('.'+$name+'.partial.zip')
    try {
        $allowedAnswers=[ordered]@{}
        foreach ($key in @('OperatingSystem','Method','VpnClient','VpnLocation','TunMode','ZapretStrategy','Symptom','StartedAfter','Reproduction')) {
            if ($Answers.ContainsKey($key)) { $allowedAnswers[$key]=Protect-AGText ([string]$Answers[$key]) }
        }
        $analysis=$null
        if (-not [string]::IsNullOrWhiteSpace($ReportText)) { $analysis=Get-AGReportAnalysis -Text $ReportText }
        $snapshot=$null
        if ($LocalAudit) {
            $snapshot=[pscustomobject]@{
                CollectedAt=$LocalAudit.CollectedAt; OS=$LocalAudit.OS; PowerShell=$LocalAudit.PowerShell
                Processes=@($LocalAudit.Processes | Select-Object Name,PID,FileVersion,Started)
                Tasks=@($LocalAudit.Tasks | Select-Object Name,State,LastResult)
                Listeners=@($LocalAudit.Listeners | Select-Object Protocol,Port,PID,Owner,IsAG)
                ProxyCandidates=@($LocalAudit.ProxyCandidates | Select-Object Port,PID)
                Adapters=@($LocalAudit.Adapters | Select-Object InterfaceIndex,Status,InterfaceDescription)
                Hosts=@($LocalAudit.Hosts | Select-Object Domain,Note)
                NRPTNamespaces=@($LocalAudit.NRPT | ForEach-Object { $_.Namespace })
                Zapret=$LocalAudit.Zapret
                CollectionIssues=@($LocalAudit.CollectionIssues)
            }
        }
        $payload=[pscustomobject]@{ FormatVersion=1; CreatedAt=(Get-Date).ToUniversalTime().ToString('o'); Answers=[pscustomobject]$allowedAnswers; ReportAnalysis=$analysis; LocalSnapshot=$snapshot; Privacy='Исходные settings.json/gate.json и полный лог не добавляются. Возможные секреты скрываются эвристически, не гарантированно; проверьте файлы вручную до публикации.' }
        $safe=ConvertTo-AGSafeObject $payload
        $safe | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath (Join-Path $stage 'support.json') -Encoding UTF8 -ErrorAction Stop
        $guide=@(
            'AGFixer — пакет для обращения за помощью',
            '',
            'Откройте support.json и проверьте перед отправкой.',
            'Содержит ответы на диагностическую форму и разбор сохранённого отчёта.',
            'Исходные файлы настроек, gate.json и переписки не добавляются. Фильтрация секретов не гарантирует их отсутствие.',
            'Если выбран log-tail.redacted.txt: это эвристически очищенный фрагмент, не гарантия анонимности.',
            'Не публикуйте пакет автоматически. Проверьте собственные имена, приватные домены, пути, проектные данные.',
            'Исторические ошибки в отчёте не доказывают, что проблема сохраняется сейчас.'
        )
        $guide | Set-Content -LiteralPath (Join-Path $stage 'READ-BEFORE-SHARING.txt') -Encoding UTF8 -ErrorAction Stop
        if ($IncludeLogTail) {
            $log=Get-AGPath 'forwarder.log'
            if (Test-Path -LiteralPath $log -PathType Leaf) {
                $tail=(Get-Content -LiteralPath $log -Tail 200 -Encoding UTF8 -ErrorAction Stop) -join "`n"
                Protect-AGText $tail | Set-Content -LiteralPath (Join-Path $stage 'log-tail.redacted.txt') -Encoding UTF8 -ErrorAction Stop
            }
        }
        $zip=Join-Path $OutputDirectory ($name + '.zip')
        Compress-Archive -LiteralPath @((Join-Path $stage 'support.json'),(Join-Path $stage 'READ-BEFORE-SHARING.txt')) -DestinationPath $buildingZip -CompressionLevel Optimal -ErrorAction Stop
        if (Test-Path -LiteralPath (Join-Path $stage 'log-tail.redacted.txt')) { Compress-Archive -LiteralPath (Join-Path $stage 'log-tail.redacted.txt') -DestinationPath $buildingZip -Update -ErrorAction Stop }
        Move-Item -LiteralPath $buildingZip -Destination $zip -ErrorAction Stop
        Write-Host 'Пакет сохранён локально. Перед публикацией распакуйте и проверьте его содержимое.' -ForegroundColor Yellow
        return $zip
    } finally {
        if (Test-Path -LiteralPath $buildingZip) { Remove-Item -LiteralPath $buildingZip -Force -ErrorAction Stop }
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction Stop }
    }
}
function Read-AGSupportAnswers {
    $answers=@{}
    foreach ($pair in @(
        @('OperatingSystem','ОС и версия'), @('Method','Способ: Unlocker/Zapret/VPN/свой прокси/прокси группы'),
        @('VpnClient','VPN-клиент (если применимо)'), @('VpnLocation','Локация VPN'), @('TunMode','TUN/раздельное туннелирование'),
        @('ZapretStrategy','Стратегия Zapret, Game Filter (если применимо)'), @('Symptom','Симптом: вход/400/Working/чёрный экран/другое'),
        @('StartedAfter','После чего появилась проблема: обновление/смена сети/другое'), @('Reproduction','Короткие шаги воспроизведения без личных данных')
    )) { if(Test-AGInteractiveUi){Show-AGMenuScreen -Title 'Подготовка обращения за помощью';Write-Host 'Если не знаете ответ — нажмите Enter.'};$answers[$pair[0]]=Read-AGInput $pair[1] }
    return $answers
}
