#Requires -Version 5.1
param([string]$Id,[switch]$Paged)
$ErrorActionPreference='Stop'
function Get-AGScenarioLines {
    param($Scenario)
    $lines=@('Кому подходит',[string]$Scenario.AppliesTo)
    if($Scenario.Before){$lines+='Перед началом';foreach($line in $Scenario.Before){$lines+='- '+$line}}
    foreach($state in @('ВЫКЛ','ВКЛ')){
        $settings=@($Scenario.Switches|Where-Object{$_.State -eq $state})
        if($settings.Count){
            $lines+= $(if($state -eq 'ВЫКЛ'){'Что ВЫКЛЮЧИТЬ в Unlocker'}else{'Что оставить ВКЛЮЧЁННЫМ'})
            foreach($setting in $settings){$lines+="$($setting.Name) — $($setting.State)";$lines+='  '+$setting.Why;$lines+=''}
        }
    }
    $lines+='Пошаговая настройка'
    for($i=0;$i -lt $Scenario.Steps.Count;$i++){$lines+="$($i+1). $($Scenario.Steps[$i])";$lines+=''}
    if($Scenario.Check){$lines+='Как понять, что работает';foreach($line in $Scenario.Check){$lines+='- '+$line}}
    if($Scenario.IfNotWorking){$lines+='Если не заработало';foreach($line in $Scenario.IfNotWorking){$lines+='- '+$line}}
    $lines+='Чего не делать';foreach($line in $Scenario.DoNot){$lines+='- '+$line}
    $lines+='Важно';$lines+=[string]$Scenario.Evidence
    $lines+='Источники'
    if($Scenario.SourceNote){$lines+=$Scenario.SourceNote}
    $lines+=@($Scenario.Sources)
    return $lines
}
$raw=Get-Content -LiteralPath "$PSScriptRoot/scenarios.json" -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
$scenarios=@(foreach($item in $raw){$item})
if(-not $Id){
    for($i=0;$i -lt $scenarios.Count;$i++){Write-Host "$($i+1). $($scenarios[$i].Title)"}
    return
}
$number=0
if([int]::TryParse($Id,[ref]$number) -and $number -ge 1 -and $number -le $scenarios.Count){$match=@($scenarios[$number-1])}else{$match=@($scenarios|Where-Object{$_.Id -eq $Id})}
if($match.Count -ne 1){throw "Выберите номер от 1 до $($scenarios.Count)."}
$s=$match[0]
$lines=@(Get-AGScenarioLines $s)
if($Paged){
    . "$PSScriptRoot/ui.ps1"
    Show-AGTextPages -Title $s.Title -Lines $lines -GuideSections
    return
}
Clear-Host
Write-Host 'AGFixer by txmui' -ForegroundColor DarkRed
Write-Host ''
Write-Host $s.Title -ForegroundColor Cyan
foreach($line in $lines){Write-Host $line}
