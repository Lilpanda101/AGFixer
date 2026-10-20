#Requires -Version 5.1
# Mandatory elevation gate. Loading helpers alone does not start anything.
function Get-AGElevationContext {
    if ($env:OS -ne 'Windows_NT') { throw 'Для запуска программы требуется Windows.' }
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal=New-Object Security.Principal.WindowsPrincipal($identity)
        return [pscustomobject]@{
            IsAdministrator=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            UserSid=$identity.User.Value
        }
    } finally { $identity.Dispose() }
}
function Start-AGPrivilegedChild {
    param([switch]$ControlCenter,[Parameter(Mandatory=$true)][string]$ExpectedUserSid)
    $system=[Environment]::GetFolderPath([Environment+SpecialFolder]::System)
    $exe=Join-Path $system 'WindowsPowerShell/v1.0/powershell.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Windows PowerShell не найден. Запуск отменён.' }
    $arguments=@('-NoLogo','-NoProfile','-STA','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'launch.ps1'),'-ElevationAttempted','-ExpectedUserSid',$ExpectedUserSid)
    if ($ControlCenter) { $arguments+='-ControlCenter' }
    $commandLine=(($arguments | ForEach-Object { ConvertTo-WindowsArgument $_ }) -join ' ')
    $child=$null
    try {
        $child=Start-Process -FilePath $exe -ArgumentList $commandLine -WorkingDirectory $PSScriptRoot -Verb RunAs -Wait -PassThru -ErrorAction Stop
        if ($null -eq $child -or $null -eq $child.ExitCode) { throw 'Не удалось получить результат повышенного процесса. Запуск не подтверждён.' }
        return [int]$child.ExitCode
    } finally { if ($child -is [IDisposable]) { $child.Dispose() } }
}
function Invoke-AGProtectedEntry {
    param([switch]$ControlCenter)
    # A second real token check before entering either menu; no flag can replace it.
    Assert-WindowsAdmin
    if ($ControlCenter) { & "$PSScriptRoot/ag-tune.ps1" } else { & "$PSScriptRoot/doctor.ps1" }
}
function Invoke-AGAdminStartup {
    [CmdletBinding()]
    param([switch]$ControlCenter,[switch]$ElevationAttempted,[string]$ExpectedUserSid)
    $context=Get-AGElevationContext
    if ($null -eq $context -or $context.IsAdministrator -isnot [bool] -or [string]::IsNullOrWhiteSpace([string]$context.UserSid)) { throw 'Не удалось проверить токен пользователя; запуск отменён.' }
    if ($ExpectedUserSid -and $context.UserSid -ne $ExpectedUserSid) { throw 'Повышение выполнено под другой Windows-учётной записью. Запуск отменён, чтобы не изменить чужой профиль Unlocker.' }
    if ($context.IsAdministrator) {
        Invoke-AGProtectedEntry -ControlCenter:$ControlCenter
        return
    }
    if ($ElevationAttempted) { throw 'После запроса UAC права администратора не получены. Повторный запрос и запуск меню запрещены.' }
    Write-Host 'Для работы обязательны права администратора. Подтвердите запрос UAC для текущей Windows-учётной записи.' -ForegroundColor Yellow
    try { $code=Start-AGPrivilegedChild -ControlCenter:$ControlCenter -ExpectedUserSid $context.UserSid }
    catch { throw ('Права администратора не предоставлены или повышенный запуск не удался. Программа не запущена. '+$_.Exception.Message) }
    if ($null -eq $code -or $code -isnot [int] -or $code -ne 0) { throw "Повышенный процесс не подтвердил успешное завершение (код: $code). Меню в неповышенном процессе не запускается." }
}
