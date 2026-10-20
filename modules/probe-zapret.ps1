#Requires -Version 5.1
# TLS probes are transport observations, NOT a Discord voice/video/model acceptance test.
function Get-AGZapretProbeCandidates {
    param([string]$Root)
    if(-not(Get-Command Get-AGStrategyFiles -ErrorAction SilentlyContinue)){. "$PSScriptRoot/config-wizard.ps1"}
    foreach($file in @(Get-AGStrategyFiles $Root)){
        try{$command=Get-StrategyCommand $Root $file.Name;Assert-AGStrategyFiles $command
            [pscustomobject]@{Name=$file.Name;Hash=(Get-AGFileHash $file.FullName);Command=$command}
        }catch{}
    }
}
function Test-AGZapretProbeHost {
    param([string]$HostName)
    return ($HostName -match '^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*googlevideo\.com$' -and $HostName -ne 'googlevideo.com')
}
function Test-AGServiceTlsEndpoint {
    param([ValidateSet('daily-cloudcode-pa.googleapis.com','gateway.discord.gg','www.youtube.com')][string]$ServerName,[string]$VideoHost,[ValidateRange(100,15000)][int]$TimeoutMs=4000)
    $target=$ServerName
    if($VideoHost){if(-not(Test-AGZapretProbeHost $VideoHost)){throw 'Нужен DNS-хост CDN *.googlevideo.com без URL, пути и порта.'};$target=$VideoHost}
    if(-not('AGFixer.ServiceTlsProbe' -as [type])){
        Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Threading.Tasks;
namespace AGFixer {
 public class ServiceTlsResult { public string Host; public bool Success; public double ConnectIncludingDnsMs; public double TlsMs; public string Protocol; public string Error; }
 public static class ServiceTlsProbe {
  public static async Task<ServiceTlsResult> Run(string host, int timeout) {
   var r=new ServiceTlsResult { Host=host }; var sw=new Stopwatch();
   using(var tcp=new TcpClient()) {
    try {
     sw.Start(); var connect=tcp.ConnectAsync(host,443);
     if(await Task.WhenAny(connect,Task.Delay(timeout)).ConfigureAwait(false)!=connect){tcp.Close();Observe(connect);throw new TimeoutException();}
     await connect.ConfigureAwait(false);sw.Stop();r.ConnectIncludingDnsMs=sw.Elapsed.TotalMilliseconds;
     using(var ssl=new SslStream(tcp.GetStream(),false)) {
      sw.Restart();var auth=ssl.AuthenticateAsClientAsync(host,null,SslProtocols.None,true);
      if(await Task.WhenAny(auth,Task.Delay(timeout)).ConfigureAwait(false)!=auth){ssl.Dispose();Observe(auth);throw new TimeoutException();}
      await auth.ConfigureAwait(false);sw.Stop();
      r.TlsMs=sw.Elapsed.TotalMilliseconds;r.Protocol=ssl.SslProtocol.ToString();r.Success=ssl.IsAuthenticated&&ssl.IsEncrypted;
     }
    }catch(Exception ex){r.Error=ex.GetType().Name;}
   } return r;
  }
  static void Observe(Task task){task.ContinueWith(t=>{var e=t.Exception;},TaskContinuationOptions.OnlyOnFaulted);}
 }
}
'@ -ErrorAction Stop
    }
    return [AGFixer.ServiceTlsProbe]::Run($target,$TimeoutMs).GetAwaiter().GetResult()
}
function Get-AGZapretTriad {
    param([string]$YouTubeHost,[ValidateRange(100,15000)][int]$TimeoutMs=4000)
    if($YouTubeHost -and -not(Test-AGZapretProbeHost $YouTubeHost)){throw 'Неверное имя CDN YouTube.'}
    $google=Test-AGServiceTlsEndpoint -ServerName 'daily-cloudcode-pa.googleapis.com' -TimeoutMs $TimeoutMs
    $youtube=Test-AGServiceTlsEndpoint -ServerName 'www.youtube.com' -VideoHost $YouTubeHost -TimeoutMs $TimeoutMs
    $discord=Test-AGServiceTlsEndpoint -ServerName 'gateway.discord.gg' -TimeoutMs $TimeoutMs
    return [pscustomobject]@{Google=$google;YouTube=$youtube;Discord=$discord;AllTlsPassed=($google.Success -and $youtube.Success -and $discord.Success);VideoCdnTested=[bool]$YouTubeHost;Scope='TLS only; no model, video stream or Discord voice test'}
}
function Select-AGZapretProbeWinner {
    param([object[]]$Results)
    # Minimize observed median handshake duration; no artificial 200ms lower bound.
    $eligible=@($Results|Where-Object{$_.AllTlsPassed -and $null -ne $_.GoogleMedianMs -and $_.Samples -ge 3}|Sort-Object -Property GoogleMedianMs, Strategy)
    if(-not $eligible.Count){return $null}
    return $eligible[0]
}
function Get-AGOwnedZapretServiceState {
    param([string]$Root)
    $key='HKLM:\SYSTEM\CurrentControlSet\Services\zapret'
    $cfg=Get-ItemProperty -LiteralPath $key -ErrorAction Stop;$svc=Get-Service -Name zapret -ErrorAction Stop
    $exe=[IO.Path]::GetFullPath((Join-Path $Root 'bin/winws.exe'))
    if([string]$cfg.ImagePath -notmatch ('^\s*"'+[regex]::Escape($exe)+'"(?:\s|$)')){throw 'Служба zapret не принадлежит выбранному winws.exe. Автоперебор запрещён.'}
    if([string]$svc.Status -notin @('Running','Stopped')){throw 'Служба находится в переходном состоянии.'}
    if([int]$cfg.Start -notin @(2,3)){throw 'Тип запуска службы не поддерживается.'}
    $serviceInfo=Get-CimInstance Win32_Service -Filter "Name='zapret'" -ErrorAction Stop
    foreach($process in @(Get-Process winws -ErrorAction SilentlyContinue)){
        if([int]$process.Id -ne [int]$serviceInfo.ProcessId){throw 'winws запущен вне выбранной службы. Сравнение отменено.'}
        if(-not $process.Path -or [IO.Path]::GetFullPath($process.Path) -ine $exe){throw 'Есть другой или недоступный экземпляр winws. Автоперебор запрещён.'}
    }
    return [pscustomobject]@{ImagePath=[string]$cfg.ImagePath;Start=[int]$cfg.Start;DelayedAutoStart=$cfg.DelayedAutoStart;Strategy=$cfg.'zapret-discord-youtube';Status=[string]$svc.Status;ExeHash=(Get-AGFileHash $exe)}
}
function Assert-AGZapretProbeConfig {
    param($State,[string[]]$AllowedImages)
    $cfg=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\zapret' -ErrorAction Stop
    if([string]$cfg.ImagePath -cnotin $AllowedImages -or [int]$cfg.Start -ne $State.Start -or $cfg.DelayedAutoStart -ne $State.DelayedAutoStart -or $cfg.'zapret-discord-youtube' -cne $State.Strategy){throw 'Конфигурация службы изменена извне. Перезапись запрещена; используйте резервную копию.'}
}
function Set-AGZapretProbeImage {
    param([string]$ImagePath)
    $svc=Get-Service zapret -ErrorAction Stop
    if([string]$svc.Status -ne 'Stopped'){Stop-Service zapret -ErrorAction Stop;$svc.WaitForStatus('Stopped',[timespan]::FromSeconds(15))}
    Invoke-ServiceControl -Arguments @('config','zapret','binPath=',$ImagePath)
}
function Restore-AGZapretProbeService {
    param($State,[string[]]$ExpectedImage)
    Assert-AGZapretProbeConfig -State $State -AllowedImages (@($ExpectedImage)+@($State.ImagePath))
    Set-AGZapretProbeImage $State.ImagePath
    if($State.Status -eq 'Running'){Start-Service zapret -ErrorAction Stop;(Get-Service zapret).WaitForStatus('Running',[timespan]::FromSeconds(15))}
    Assert-AGZapretProbeConfig -State $State -AllowedImages @($State.ImagePath)
    if([string](Get-Service zapret).Status -ne $State.Status){throw 'Исходное состояние службы не восстановлено.'}
}
function Invoke-AGZapretStrategyProbe {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([Parameter(Mandatory=$true)][string[]]$Strategies,[string]$YouTubeHost,[switch]$Confirmed)
    Assert-WindowsAdmin
    if(-not $Confirmed){throw 'Сначала покажите план и получите явное согласие на перебор и восстановление службы.'}
    if($Strategies.Count -lt 1 -or $Strategies.Count -gt 12){throw 'Выберите от 1 до 12 локальных стратегий.'}
    if($YouTubeHost -and -not(Test-AGZapretProbeHost $YouTubeHost)){throw 'Неверный CDN-хост.'}
    if(-not $PSCmdlet.ShouldProcess('Служба zapret','Временно сравнить стратегии и восстановить исходную')){return}
    Invoke-AGExclusiveOperation {
        $root=Get-ZapretPath;$state=Get-AGOwnedZapretServiceState $root
        $all=@(Get-AGZapretProbeCandidates $root);$chosen=@(foreach($name in $Strategies){$hit=@($all|Where-Object Name -eq $name);if($hit.Count -ne 1){throw 'Стратегия отсутствует или не прошла разбор.'};$hit[0]})
        $folder=Join-Path $env:LOCALAPPDATA ('AGFixer/zapret-probes/'+[guid]::NewGuid().ToString('N'))
        $null=New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop;$state|Export-Clixml -LiteralPath (Join-Path $folder 'service-before.clixml') -ErrorAction Stop
        $results=New-Object 'Collections.Generic.List[object]';$restored=$false;$errorMessage='';$expected=$state.ImagePath;$attempted=$false;$previous=$state.ImagePath
        try{
            foreach($candidate in $chosen){
                if((Get-AGFileHash (Join-Path $root 'bin/winws.exe')) -ne $state.ExeHash -or (Get-AGFileHash (Join-Path $root $candidate.Name)) -ne $candidate.Hash -or (Get-StrategyCommand $root $candidate.Name) -cne $candidate.Command){throw 'Файлы Zapret изменились; сравнение остановлено.'}
                Assert-AGZapretProbeConfig -State $state -AllowedImages @($expected)
                $attempted=$true;$previous=$expected;$expected=$candidate.Command
                Set-AGZapretProbeImage $candidate.Command
                Assert-AGZapretProbeConfig -State $state -AllowedImages @($expected)
                Start-Service zapret -ErrorAction Stop;(Get-Service zapret).WaitForStatus('Running',[timespan]::FromSeconds(15))
                Start-Sleep -Milliseconds 700
                $samples=@(1..3|ForEach-Object{Get-AGZapretTriad -YouTubeHost $YouTubeHost})
                $times=@($samples|ForEach-Object{$_.Google.TlsMs}|Sort-Object)
                $results.Add([pscustomobject]@{Strategy=$candidate.Name;Samples=$samples.Count;AllTlsPassed=(-not @($samples|Where-Object{-not $_.AllTlsPassed}).Count);GoogleMedianMs=$times[1];Measurements=$samples;StrategyHash=$candidate.Hash})
            }
        }catch{$errorMessage=Protect-AGText $_.Exception.Message}
        finally{try{if($attempted){Restore-AGZapretProbeService -State $state -ExpectedImage @($expected,$previous)}else{Assert-AGZapretProbeConfig -State $state -AllowedImages @($state.ImagePath)};$restored=$true}catch{$errorMessage+=' ВОССТАНОВЛЕНИЕ НЕ ВЫПОЛНЕНО. Копия: '+$folder}}
        $report=[pscustomobject]@{Status=if($restored -and -not $errorMessage){'Compared'}else{'Partial'};OriginalRestored=$restored;Error=$errorMessage;Backup=$folder;Results=@($results.ToArray());Winner=(Select-AGZapretProbeWinner @($results.ToArray()));Scope='TLS only; winner is not automatically installed'}
        $report|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $folder 'comparison.json') -Encoding UTF8 -ErrorAction Stop
        return $report
    }
}
function Show-AGZapretProbeMenu {
    param([string]$ReportText)
    . "$PSScriptRoot/config-wizard.ps1"
    try{$root=Get-ZapretPath}catch{if(-not(Select-AGInstallationFolder Zapret)){return};$root=Get-ZapretPath}
    $pick=Read-AGListChoice -Title 'Zapret: домены и стратегия' -Options @('Выбрать локальную стратегию и настроить Unlocker','Проверить текущие Google / YouTube / Discord (TLS)','Сравнить выбранные стратегии с восстановлением службы','Проверить и дополнить списки доменов') -Intro @('Стратегия не назначается по умолчанию. TLS не проверяет голос Discord и видеопоток.')
    switch($pick){
        4{Show-AGZapretListHealth}
        1{$strategy=Read-AGStrategyChoice;if($strategy){Invoke-AGSmartRepair -ReportText $ReportText -Mode Zapret -StrategyFile $strategy}}
        2{if(Confirm-Change 'Проверить TLS трёх сервисов через текущий системный путь?'){$result=Get-AGZapretTriad;Show-AGTextPages -Title 'Текущий путь: TLS' -Lines @('Это не проверка модели, видеопотока или голоса.',($result|ConvertTo-Json -Depth 6))}}
        3{
            $all=@(Get-AGZapretProbeCandidates $root);if(-not $all.Count){throw 'Нет проверяемых стратегий.'}
            $selected=@()
            while($true){$options=@(foreach($candidate in $all){$mark=if($candidate.Name -in $selected){'x'}else{' '};'['+$mark+'] '+$candidate.Name})
                $n=Read-AGListChoice -Title 'Отметьте стратегии для сравнения' -Options $options -EnterValue -1
                if($n -eq 0){return};if($n -eq -1){break};$name=$all[$n-1].Name
                if($name -in $selected){$selected=@($selected|Where-Object{$_ -ne $name})}else{$selected+=$name}
            }
            if(-not $selected.Count){return}
            $cdn=(Read-AGInput 'Хост CDN *.googlevideo.com (Enter — проверить только сайт YouTube)').Trim()
            if($cdn -and -not(Test-AGZapretProbeHost $cdn)){throw 'Укажите только DNS-имя CDN, без URL.'}
            Show-AGTextPages -Title 'План сравнения Zapret' -Lines (@('Будет несколько перезапусков службы zapret. Связь временно прервётся.','Доверяйте установленному winws.exe. BAT целиком не исполняется.','После сравнения восстановится исходная конфигурация; победитель применяется отдельно.','TLS YouTube/Discord не подтверждает видеопоток/голос.')+@($selected))
            if(-not(Confirm-Change 'Разрешить временно применить выбранные стратегии и восстановить исходную службу?')){return}
            $report=Invoke-AGZapretStrategyProbe -Strategies $selected -YouTubeHost $cdn -Confirmed
            $lines=@('Исходная служба восстановлена: '+$report.OriginalRestored,'Состояние: '+$report.Status,$report.Error)
            foreach($item in $report.Results){$lines+=($item.Strategy+': TLS '+$item.AllTlsPassed+'; медиана Google '+[int]$item.GoogleMedianMs+' мс')}
            if($report.Winner){$lines+='Лучший по этим TLS-пробам: '+$report.Winner.Strategy}
            Show-AGTextPages -Title 'Результат сравнения' -Lines $lines
            if($report.Status -eq 'Compared' -and $report.Winner -and (Confirm-Change ('Открыть план постоянного применения '+$report.Winner.Strategy+'?'))){Invoke-AGSmartRepair -ReportText $ReportText -Mode Zapret -StrategyFile $report.Winner.Strategy}
        }
    }
}
