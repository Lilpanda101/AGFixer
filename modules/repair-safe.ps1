#Requires -Version 5.1
function Move-AGGpuCache {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([ValidateSet('Antigravity','Antigravity IDE','Antigravity Manager')][string]$Application='Antigravity',[switch]$Confirmed)
    if(-not $PSCmdlet.ShouldProcess($Application,'Переместить GPUCache в резервную папку')){return}
    if (-not $env:APPDATA) { throw 'APPDATA не определён.' }
    if (Get-Process -Name 'Antigravity*','language_server*','agy' -ErrorAction SilentlyContinue) { throw 'Сначала сохраните работу и полностью закройте IDE через трей. Процессы автоматически не завершаются.' }
    $cache=Join-Path (Join-Path $env:APPDATA $Application) 'GPUCache'
    if (-not (Test-Path -LiteralPath $cache -PathType Container)) { Write-Host 'GPUCache не найден; ничего не изменено.'; return $true }
    Write-Host "Будет перемещена только папка: $cache"
    Write-Warning 'Это не гарантированное исправление чёрного экрана; профиль, авторизация, чаты и workspaceStorage не сбрасываются.'
    if (-not $Confirmed -and -not (Confirm-Change 'Переместить GPUCache в резервную папку рядом?')) { return $false }
    $backup=$cache + '.backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
    Move-Item -LiteralPath $cache -Destination $backup -ErrorAction Stop
    Write-Host 'При следующем старте IDE создаст кэш заново. Для отката закройте IDE, сохраните новый GPUCache отдельно и верните резервной папке имя GPUCache.'
    return $backup
}
function Restore-AGGpuCache {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([ValidateSet('Antigravity','Antigravity IDE','Antigravity Manager')][string]$Application='Antigravity',[Parameter(Mandatory=$true)][string]$BackupPath)
    if(-not $PSCmdlet.ShouldProcess($Application,'Восстановить GPUCache')){return}
    Invoke-AGExclusiveOperation {
        if(-not $env:APPDATA){throw 'APPDATA не определён.'}
        if(Get-Process -Name 'Antigravity*','language_server*','agy' -ErrorAction SilentlyContinue){throw 'Сначала закройте IDE; процессы не завершаются автоматически.'}
        $parent=[IO.Path]::GetFullPath((Join-Path $env:APPDATA $Application))
        $resolved=(Resolve-Path -LiteralPath $BackupPath -ErrorAction Stop).Path
        if([IO.Path]::GetDirectoryName($resolved) -ne $parent -or [IO.Path]::GetFileName($resolved) -notlike 'GPUCache.backup-*' -or -not (Test-Path -LiteralPath $resolved -PathType Container)){throw 'Нужна папка GPUCache.backup-* выбранного приложения.'}
        if(-not (Confirm-Change 'Вернуть выбранный GPUCache? Новый кэш тоже будет сохранён, не удалён.')){return $false}
        $current=Join-Path $parent 'GPUCache';$saved=$null
        if(Test-Path -LiteralPath $current){$saved=$current+'.before-restore-'+[guid]::NewGuid().ToString('N');Move-Item -LiteralPath $current -Destination $saved -ErrorAction Stop}
        try{Move-Item -LiteralPath $resolved -Destination $current -ErrorAction Stop}
        catch{
            $failure=$_.Exception.Message
            if($saved){try{Move-Item -LiteralPath $saved -Destination $current -ErrorAction Stop}catch{throw ($failure+'; возврат нового кэша также не выполнен: '+$_.Exception.Message+'; сохранённый кэш: '+$saved)}}
            throw $failure
        }
        Write-Host "GPUCache восстановлен. Сохранённый новый кэш: $saved"
        return $true
    }
}

. "$PSScriptRoot/repair-engine.ps1"

function Invoke-AGSmartRepair {
    param([string]$ReportText,[ValidateSet('Keep','VpnDirect','Zapret')][string]$Mode='Keep',[string]$StrategyFile)
    if(-not(Get-Command Invoke-AGSetupRepair -ErrorAction SilentlyContinue)){. "$PSScriptRoot/smart-setup.ps1"}
    $analysis=$null;if($ReportText){$analysis=Get-AGReportAnalysis $ReportText}
    if($analysis){
        $snapshot=Get-AGRepairSnapshot;$status=Get-AGSystemStatus
        $smart=Get-AGSmartDiagnosis -Text $ReportText -Analysis $analysis -Snapshot $snapshot -Status $status
        # Only typed actions supported by current observations. Untimed historical errors cannot trigger restart.
        $analysis.Diagnosis.Actions=@($smart.Verdicts|Where-Object{$_.Action -in @('Nrpt','Restart')}|ForEach-Object Action|Select-Object -Unique)
    }
    Invoke-AGSetupRepair -Analysis $analysis -Mode $Mode -StrategyFile $StrategyFile
}
