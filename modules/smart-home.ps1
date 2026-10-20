#Requires -Version 5.1
. "$PSScriptRoot/report-input.ps1"
function Read-AGSmartHomeAction {
    param($Diagnosis,$Status)
    $items=@(
        [pscustomobject]@{Label='[SPACE] Исправить найденное — показать план';Value='Repair'},
        [pscustomobject]@{Label='[1] Открыть отчёт — файл или буфер';Value='Report'},
        [pscustomobject]@{Label='[2] Свой VPN/TUN — настроить Unlocker';Value='Vpn'},
        [pscustomobject]@{Label='[3] Zapret — списки доменов и стратегия';Value='Zapret'},
        [pscustomobject]@{Label='Гайды сообщества';Value='Guides'},
        [pscustomobject]@{Label='[L] Списки Zapret — проверить домены';Value='Lists'},
        [pscustomobject]@{Label='[S] JSON для поддержки — сохранить в файл';Value='Dump'},
        [pscustomobject]@{Label='[U] Проверить обновления AGFixer';Value='Updates'})
    $card=@(Get-AGSmartCardLines $Diagnosis)
    if(-not(Test-AGTerminalInput)){
        Show-AGMenuScreen 'Диагностика и ремонт'
        foreach($line in $card){Write-Host $line}
        Write-Host '';Write-Host ('-'*([Math]::Max(1,(Get-AGMenuViewport).Width-1)));Write-Host '';foreach($item in $items){if($item.Value -eq 'Guides'){Write-Host ('[4] '+$item.Label)}else{Write-Host $item.Label}};Write-Host '';Write-Host '[T] Для опытных | [R] Обновить состояние | [0] Выход'
        return (ConvertTo-AGSmartHomeAction (Read-AGInput 'Выбор (A — ремонт, Enter — обновить)'))
    }
    $selected=0;$offset=0;$old='';$cursor=$true
    try{
        try{$cursor=[Console]::CursorVisible;[Console]::CursorVisible=$false}catch{}
        while($true){
            $size=Get-AGAuditConsoleSize
            $frame=Get-AGTuiFrame -Title 'Исправления и диагностика' -Items $items -Selected $selected -Offset $offset -Status @($card|Select-Object -First 3) -Hint $card[3] -Journal @($script:AGUiJournal) -Width $size.Width -Height $size.Height -Root
            if(-not $frame.TooSmall){$help=if($size.Width -lt 45){'↑↓ | Enter | T | Esc:выход'}elseif($size.Width -lt 75){'↑↓ | Enter | T:для опытных | Esc:выход'}else{'↑↓ | Enter:выбор | L:домены | T:для опытных | Esc:выход'};$frame.Rows[$frame.Rows.Count-1].Text=Limit-AGAuditLine $help ([Math]::Max(1,$size.Width-1))}
            $keySize="$($size.Width)x$($size.Height)";Write-AGTuiFrame $frame -Reset:($keySize -ne $old);$old=$keySize;$offset=$frame.Offset
            $key=Read-AGTerminalKeyOrResize -Width $size.Width -Height $size.Height
            if($key -in @('ESC','0','Q')){return 'Exit'}
            if($frame.TooSmall){continue}
            if($key -eq 'F1'){Show-AGTextPages -Title 'Карточка состояния' -Lines ($card+@('',$Diagnosis.Scope)+@($(if($Status){Get-AGStatusHeader -Status $Status -Width 500}else{'Состояние программ не прочитано'}))+@($Diagnosis.Verdicts|ForEach-Object{'['+$_.Code+'] '+$_.Title})+@($(if($Status -and $Status.ZapretHealth){Get-AGZapretHealthLines $Status.ZapretHealth})));$old='';continue}
            if($key -eq 'ENTER'){return $items[$selected].Value}
            $action=ConvertTo-AGSmartHomeAction $key
            if($action -ne 'Unknown'){return $action}
            $selected=Move-AGTuiSelection $selected $items.Count $key $frame.Capacity
        }
    }finally{try{[Console]::CursorVisible=$cursor}catch{};Clear-Host}
}
function ConvertTo-AGSmartHomeAction {
    param([string]$Key)
    switch(ConvertTo-AGCommandKey $Key){'SPACE'{'Repair'}'A'{'Repair'}'1'{'Report'}'2'{'Vpn'}'3'{'Zapret'}'S'{'Dump'}'4'{'Guides'}'L'{'Lists'}'T'{'Tools'}'F2'{'Tools'}'U'{'Updates'}'R'{'Refresh'}''{'Refresh'}'0'{'Exit'}'ESC'{'Exit'}'Q'{'Exit'}default{'Unknown'}}
}
function Get-AGSmartContext {
    param([string]$Text)
    $snapshot=$null;$status=$null
    try{$snapshot=Get-AGRepairSnapshot}catch{Add-AGUiJournal 'Не удалось прочитать часть настроек Windows.'}
    try{$status=Get-AGSystemStatus}catch{Add-AGUiJournal 'Не удалось прочитать состояние программ.'}
    if($snapshot -and $env:OS -eq 'Windows_NT'){try{$snapshot|Add-Member NoteProperty WinHttpDump (Invoke-AGRepairNetsh Dump) -Force}catch{}}
    if($status){try{$root=Get-ZapretPath;$status|Add-Member NoteProperty ZapretHealth (Get-AGZapretListHealth $root) -Force;$status|Add-Member NoteProperty GameFilter (Get-AGGameFilterState $root) -Force}catch{}}
    $analysis=$null
    if($Text){try{$analysis=Get-AGReportAnalysis $Text}catch{Add-AGUiJournal 'Отчёт не распознан.'}}
    $diagnosis=Get-AGSmartDiagnosis -Text $Text -Analysis $analysis -Snapshot $snapshot -Status $status
    return [pscustomobject]@{Snapshot=$snapshot;Status=$status;Diagnosis=$diagnosis}
}
function Export-AGForensicReport {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Context,[string]$OutputDirectory=(Join-Path (Split-Path $PSScriptRoot -Parent) 'reports'))
    # The report is written only after explicit S/menu selection. Never change the clipboard.
    if([string]::IsNullOrWhiteSpace($OutputDirectory)){throw 'Не выбрана папка для JSON-отчёта.'}
    $directory=[IO.Path]::GetFullPath($OutputDirectory)
    if(-not(Test-Path -LiteralPath $directory)){$null=New-Item -ItemType Directory -Path $directory -ErrorAction Stop}
    if(-not(Test-Path -LiteralPath $directory -PathType Container)){throw 'Путь отчётов должен быть папкой.'}
    $json=ConvertTo-AGForensicDump -Diagnosis $Context.Diagnosis -Snapshot $Context.Snapshot -Status $Context.Status
    $null=$json|ConvertFrom-Json -ErrorAction Stop
    $name='AGFixer-report-'+[datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N')+'.json'
    $path=Join-Path $directory $name
    $partial=Join-Path $directory ('.'+$name+'.partial')
    $stream=$null;$created=$false
    try{
        $bytes=(New-Object Text.UTF8Encoding($false,$true)).GetBytes(($json -replace "`r?`n","`r`n")+"`r`n")
        $stream=[IO.File]::Open($partial,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$created=$true
        $stream.Write($bytes,0,$bytes.Length);$stream.Flush();$stream.Dispose();$stream=$null
        # Rename only a complete, parseable report; File.Move never overwrites an existing file.
        $null=[IO.File]::ReadAllText($partial,(New-Object Text.UTF8Encoding($false,$true)))|ConvertFrom-Json -ErrorAction Stop
        [IO.File]::Move($partial,$path);$created=$false
        return $path
    }finally{
        if($null -ne $stream){$stream.Dispose()}
        if($created -and [IO.File]::Exists($partial)){[IO.File]::Delete($partial)}
    }
}
function Save-AGForensicDump {
    param([Parameter(Mandatory=$true)]$Context,[string]$OutputDirectory=(Join-Path (Split-Path $PSScriptRoot -Parent) 'reports'))
    $path=Export-AGForensicReport -Context $Context -OutputDirectory $OutputDirectory
    Add-AGUiJournal ('JSON-отчёт сохранён: '+$path)
    Show-AGTextPages -Title 'JSON-отчёт сохранён' -Lines @('Файл:', $path, '', 'Прикрепите этот JSON-файл в сообщении поддержке.', 'Перед отправкой проверьте содержимое отчёта.')
}
function Invoke-AGSmartMain {
    $text=''
    try{$clip=Get-Clipboard -Raw -ErrorAction Stop;if($clip -is [string] -and $clip.Length -le 10MB -and $clip -match '(?im)^\s*Antigravity Unlocker(?:\s+2)?\s+v[0-9]'){$text=$clip};$clip=$null}catch{}
    $context=Get-AGSmartContext $text
    if($text){Add-AGUiJournal 'Найден отчёт в буфере; результат — на время отчёта.'}
    while($true){
        try{
            switch(Read-AGSmartHomeAction -Diagnosis $context.Diagnosis -Status $context.Status){
                'Exit'{return}
                'Report'{
                    $candidate=Read-AGReportSource
                    if($candidate){$text=$candidate;Show-AGReportHelp -Text $text -Paged}
                    $candidate=$null
                }
                'Repair'{Invoke-AGSmartRepair -ReportText $text}
                'Vpn'{. "$PSScriptRoot/vpn-clients.ps1";Invoke-AGVpnClientSetup -ReportText $text}
                'Zapret'{Show-AGZapretProbeMenu -ReportText $text}
                'Dump'{Save-AGForensicDump -Context $context}
                'Guides'{. "$PSScriptRoot/guide-menu.ps1";Show-AGCommunityGuides}
                'Lists'{Show-AGZapretListHealth}
                'Tools'{& "$PSScriptRoot/doctor.ps1" -Advanced}
                'Updates'{. "$PSScriptRoot/updates.ps1";Show-AGUpdateCheck}
                'Refresh'{}
            }
        }catch{Add-AGUiJournal ('Ошибка: '+(Protect-AGText $_.Exception.Message));Show-AGTextPages -Title 'Операция не выполнена' -Lines @((Protect-AGText $_.Exception.Message))}
        $context=Get-AGSmartContext $text
    }
}
