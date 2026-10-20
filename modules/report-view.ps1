#Requires -Version 5.1
if(-not(Get-Command Write-AGTextFrame -CommandType Function -ErrorAction SilentlyContinue)){. "$PSScriptRoot/ui.ps1"}
# Compact verdict entry, optional detailed evidence and explicit repair action.
. "$PSScriptRoot/express-verdict.ps1"
if(-not(Get-Command Get-AGAuditFrame -ErrorAction SilentlyContinue)){. "$PSScriptRoot/audit-view.ps1"}
function Format-AGReportValue {
    param([AllowNull()]$Value)
    if($null -eq $Value){return 'не указано'}
    if($Value -is [bool]){if($Value){return 'да'}else{return 'нет'}}
    return [string]$Value
}
function Get-AGReportLines {
    param($Analysis,[string[]]$NextSteps)
    $lines=New-Object 'System.Collections.Generic.List[string]'
    $lines.Add("Unlocker: $($Analysis.ReportVersion)")
    $lines.Add("Первый способ подключения в отчёте: $($Analysis.FirstRoute)")
    if($Analysis.Diagnosis){$lines.Add($Analysis.Diagnosis.Title)}
    $lines.Add('=== Что делать дальше ===')
    for($i=0;$i -lt $NextSteps.Count;$i++){$lines.Add("$($i+1). $($NextSteps[$i])")}
    $lines.Add('=== Найденные признаки ===')
    foreach($finding in @($Analysis.Findings)){
        $lines.Add("[$($finding.Code)] $($finding.Summary)")
        if($finding.EvidenceDetails){
            foreach($detail in @($finding.EvidenceDetails)){$lines.Add($detail.Text)}
        }else{foreach($evidence in @($finding.Evidence)){$lines.Add("Признак: $evidence")}}
        if($finding.EvidenceCount -gt @($finding.Evidence).Count){$lines.Add("Показано $(@($finding.Evidence).Count) из $($finding.EvidenceCount) совпадений.")}
        $lines.Add("Следующий шаг: $($finding.Action)")
    }
    if(-not @($Analysis.Findings).Count){$lines.Add('Известные признаки ошибки не найдены.')}
    $lines.Add('=== Настройки из отчёта ===')
    foreach($property in $Analysis.Toggles.PSObject.Properties){$lines.Add("$($property.Name): $($property.Value)")}
    $lines.Add('=== Маршруты из отчёта ===')
    foreach($route in @($Analysis.Routes)){
        $lines.Add([string]$route.Name)
        $lines.Add("Отключён в отчёте: $(Format-AGReportValue $route.Inactive); временно отложен: $(Format-AGReportValue $route.Delayed)")
        $lines.Add("Есть отметка об ответе модели: $(Format-AGReportValue $route.ModelProven)")
        $lines.Add("Задержка, мс: $(Format-AGReportValue $route.LatencyMs); ответов: $(Format-AGReportValue $route.Answers); отказов: $(Format-AGReportValue $route.Refusals)")
        $lines.Add([string]$route.Note)
    }
    if(-not @($Analysis.Routes).Count){$lines.Add('Маршруты в тексте не распознаны.')}
    return $lines.ToArray()
}
function Get-AGReportFrame {
    param([string[]]$Lines,[int]$Page=0,[int]$Width=80,[int]$Height=24)
    $sections=@([pscustomobject]@{Title='Разбор отчёта';Lines=$Lines})
    $frame=Get-AGAuditFrame -Sections $sections -Section 0 -Page $Page -Width $Width -Height $Height
    if(-not $frame.TooSmall){
        $caption=if($frame.PageCount -gt 1){"Разбор отчёта — стр. $($frame.Page+1) из $($frame.PageCount)"}else{'Разбор отчёта'}
        $frame.Lines[0]=Limit-AGAuditLine $caption ([Math]::Max(1,$Width-1))
        $footer=if($Width -ge 65){'N/P или стрелки: страницы | Home/End | Enter/Esc: назад'}elseif($Width -ge 40){'N/P | Home/End | Enter/Esc:назад'}else{'N/P | Enter/Esc:назад'}
        if($frame.PageCount -eq 1){$footer='Esc/Enter: назад'}
        $frame.Lines[$frame.Lines.Count-1]=Limit-AGAuditLine $footer ([Math]::Max(1,$Width-1))
    }
    return $frame
}
function Show-AGReportDetails {
    param($Analysis,[string[]]$NextSteps)
    $lines=@(Get-AGReportLines -Analysis $Analysis -NextSteps $NextSteps);$page=0;$oldSize=''
    while($true){
        $size=Get-AGAuditConsoleSize
        $frame=Get-AGReportFrame -Lines $lines -Page $page -Width $size.Width -Height $size.Height
        $page=$frame.Page
        $sizeKey="$($size.Width)x$($size.Height)"
        Write-AGTextFrame -Frame $frame -Reset:($sizeKey -ne $oldSize)
        $oldSize=$sizeKey
        switch(Read-AGAuditKey){
            'Q'{return} ''{return}
            'N'{$page=[Math]::Min($frame.PageCount-1,$page+1)}
            'P'{$page=[Math]::Max(0,$page-1)}
            'HOME'{$page=0}
            'END'{$page=$frame.PageCount-1}
        }
    }
}

function Show-AGReportViewer {
    param($Analysis,[string[]]$NextSteps)
    if(-not(Get-Command Invoke-AGSmartRepair -ErrorAction SilentlyContinue)){. "$PSScriptRoot/repair-safe.ps1"}
    if(-not(Get-Command Get-AGSmartContext -ErrorAction SilentlyContinue)){. "$PSScriptRoot/smart-home.ps1"}
    while($true){
        $context=Get-AGSmartContext -Text $Analysis.ReportText
        $intro=@(Get-AGSmartCardLines $context.Diagnosis)+@($context.Diagnosis.Verdicts|ForEach-Object{$_.Title})
        $choice=Read-AGListChoice -Title 'Результат диагностики' -Options @('Исправить найденное — показать план','Открыть технические подробности','Сохранить JSON-отчёт в файл') -Intro $intro
        switch($choice){
            0{return}
            1{Invoke-AGSmartRepair -ReportText $Analysis.ReportText}
            2{Show-AGReportDetails -Analysis $Analysis -NextSteps $NextSteps}
            3{Save-AGForensicDump -Context $context}
        }
    }
}
