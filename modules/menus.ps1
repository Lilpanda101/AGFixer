#Requires -Version 5.1
# Dashboard plus retained advanced controls. No changes merely by loading.
. "$PSScriptRoot/express-dashboard.ps1"
function Get-AGMenuCategories {
    param([ValidateSet('Doctor','Control')][string]$Menu)
    if($Menu -eq 'Doctor'){
        return @(
            @{Title='Разобраться с ошибкой';Hint='Добавьте отчёт Unlocker. AGFixer объяснит найденные признаки. Настройки не меняются.';Items=@(@('2','Открыть TXT-отчёт и получить рекомендации'),@('1','Вставить скопированный отчёт'),@('7','Гайды и пошаговые сценарии'))},
            @{Title='Исправления';Hint='Ручной выбор; изменения только после подтверждения.';Items=@(@('4','Изменить подключение Unlocker, Zapret или VPN'),@('8','Чёрный экран: пересоздать графический кэш (с копией)'))},
            @{Title='Проверки сети и состояния';Hint='Узнать, что запущено и проходит ли соединение.';Items=@(@('3','Посмотреть состояние сети и запущенных программ'),@('5','Проверить защищённое соединение с Google'),@('16','Мой путь подключения: Unlocker / VPN / релей'))},
            @{Title='Конфиги';Hint='Сохранить настройки в файл или выборочно загрузить свой/чужой конфиг.';Items=@(@('11','Создать конфиг Zapret или VPN'),@('12','Загрузить конфиг из файла — выбрать настройки'),@('13','Посмотреть конфиг (без применения)'))},
            @{Title='Резервные копии и восстановление';Hint='Вернуть настройки из ранее созданной локальной копии.';Items=@(@('14','Вернуть прежние настройки Unlocker'),@('15','Вернуть прежние DNS-настройки сети'),@('10','Вернуть прежний графический кэш'))},
            @{Title='Помощь';Hint='Диагностический пакет для обращения в чат.';Items=@(@('6','Собрать диагностический ZIP для помощи в чате'))}
        )
    }
    return @(
        @{Title='Unlocker: VPN, прокси и маршрутизация';Hint='Режим VPN — профиль Unlocker, а не установка VPN-клиента.';Items=@(@('1','Выбрать режим: VPN / Zapret / свой прокси / групповой'),@('6','Перезапустить сетевую часть Unlocker'))},
        @{Title='Zapret: стратегия и домены';Hint='Только установленный Zapret. Файлы из интернета не скачиваются.';Items=@(@('3','Выбрать способ работы Zapret (стратегию)'),@('5','Добавить сайты Antigravity в Zapret'),@('4','Удалить службу Zapret (остановит обход)'))},
        @{Title='VPN DNS и сетевые проверки';Hint='IPv4 DNS меняется только на выбранном адаптере.';Items=@(@('7','Поменять DNS у выбранного VPN'),@('8','Обновить сохранённые DNS-адреса Windows'),@('2','Посмотреть состояние сети (без изменений)'))},
        @{Title='Восстановление из резервной копии';Hint='Не путайте локальный откат и переносимый конфиг.';Items=@(@('9','Вернуть настройки Unlocker из копии'),@('10','Вернуть прежние DNS-настройки сети'))},
        @{Title='Конфиги';Hint='Сохранение, выборочная загрузка, предварительный просмотр.';Items=@(@('11','Создать конфиг Zapret или VPN'),@('12','Загрузить конфиг из файла'),@('13','Посмотреть конфиг'))}
    )
}
function Read-AGCategoryAction {
    param([ValidateSet('Doctor','Control')][string]$Menu)
    $categories=@(Get-AGMenuCategories $Menu)
    while($true){
        $choice=Read-AGListChoice -Title 'AGFixer by txmui' -Options @($categories|ForEach-Object{$_.Title}) -Intro @('Что вы хотите сделать? Введите номер из списка.')
        if(-not $choice){return '0'}
        $category=$categories[$choice-1]
        $items=@($category.Items)
        $action=Read-AGListChoice -Title $category.Title -Options @($items|ForEach-Object{$_[1]}) -Intro @($category.Hint)
        if(-not $action){continue}
        Show-AGMenuScreen -Title ([string]$items[$action-1][1])
        return [string]$items[$action-1][0]
    }
}
function Read-AGBuildComponents {
    param([string[]]$Available=@('Unlocker','ZapretStrategy','ZapretLists','VpnDns'))
    $labels=@{Unlocker='Способ подключения Unlocker (без аккаунта и паролей)';ZapretStrategy='Способ работы Zapret (нужен установленный Zapret)';ZapretLists='Сайты для обработки Zapret';VpnDns='DNS вашего VPN — серверы для поиска адресов сайтов'}
    $items=@(@('Unlocker','ZapretStrategy','ZapretLists','VpnDns')|Where-Object{$_ -in $Available})
    if(-not $items.Count){throw 'В этом файле нет настроек, которые можно загрузить.'}
    $selected=@()
    while($true){
        $options=@(foreach($item in $items){$mark=if($item -in $selected){'x'}else{' '};"[$mark] $($labels[$item])"})
        $choice=Read-AGListChoice -Title 'Что загрузить из конфига?' -Options $options -EnterValue -1 -AllowAll -Intro @('Отметьте нужные настройки. Повторный номер снимает отметку.','Enter — закончить выбор. Пока ничего не меняется.')
        if($choice -eq 0){return @()}
        if($choice -eq -1){return @($items|Where-Object{$_ -in $selected})}
        if($choice -eq -2){$selected=@($items);continue}
        $item=$items[$choice-1]
        if($item -in $selected){$selected=@($selected|Where-Object{$_ -ne $item})}else{$selected+=$item}
    }
}
function Read-AGBuildPath {
    param([string]$Prompt='Путь к файлу .agconfig.json (Enter — отмена)')
    return (Read-AGInput $Prompt).Trim().Trim('"')
}
function Invoke-AGBuildMenuAction {
    param([ValidateSet('Export','Import','Preview')][string]$Action)
    if($Action -eq 'Export'){
        . "$PSScriptRoot/config-wizard.ps1"
        return (Invoke-AGConfigExportWizard)
    }
    $path=Read-AGBuildPath;if(-not $path){return $false}
    $build=Read-AGBuild $path;Show-AGBuild $build -Paged:(Test-AGInteractiveUi)
    if($Action -eq 'Preview'){return (-not (Test-AGInteractiveUi))}
    if(-not(Test-AGInteractiveUi)){$null=Read-AGInput 'Enter — перейти к выбору компонентов (применения ещё нет)'}
    $selected=@(Read-AGBuildComponents -Available @($build.Components.PSObject.Properties.Name))
    if(-not $selected.Count){return $false}
    $mode='Merge';$adapter=0;$proxy=''
    if('ZapretLists' -in $selected){
        if(Test-AGInteractiveUi){Show-AGMenuScreen -Title 'Как загрузить список сайтов?'}
        Write-Host '1. Добавить домены из конфига, оставить свои (рекомендуется)'
        Write-Host '2. Заменить выбранные списки целиком — свои записи и комментарии уберутся (с копией)'
        $choice=(Read-AGInput 'Режим списков: 1/2 (Enter — отмена)').Trim()
        if(-not $choice){return $false};if($choice -eq '2'){$mode='Replace'}elseif($choice -ne '1'){throw 'Неверный режим списков.'}
    }
    if('VpnDns' -in $selected){$value=Read-AGBuildAdapter;if($null -eq $value){return $false};$adapter=$value}
    if('Unlocker' -in $selected -and $build.Components.Unlocker.own_proxy_enabled -and $build.Components.Unlocker.ProxyNeedsInput){
        $proxy=(Read-AGInput 'Ваш HTTP/HTTPS/SOCKS5 URL БЕЗ логина/пароля (Enter — отмена)').Trim();if(-not $proxy){return $false}
    }
    $journal=Import-AGBuild -Build $build -Components $selected -DnsInterfaceIndex $adapter -ProxyUrl $proxy -ListMode $mode
    return [bool]$journal
}

function Get-AGReportNextSteps {
    param($Analysis)
    $paths=New-Object 'System.Collections.Generic.List[string]'
    foreach($finding in @($Analysis.Findings)){
        switch -Regex ($finding.Code){
            'TIMEOUT|RESET|TLS_EOF|SILENT_TUNNEL' {$paths.Add('Проверки сети и состояния → Проверить защищённое соединение с Google. Сравните результат без прокси и со своим прокси.');break}
            'DNS_FAILURE|NETWORK_UNREACHABLE|PORT_IN_USE|SOCKET_ACCESS_DENIED|CONNECTION_REFUSED|SERVICE_' {$paths.Add('Проверки сети и состояния → Посмотреть состояние сети и запущенных программ. Начните с этой проверки: она ничего не меняет.');break}
            'REGION_REFUSAL' {$paths.Add('Разобраться с ошибкой → Гайды и пошаговые сценарии: отказ по региону; смена DNS/сброс кэша не гарантирует решение.');break}
            'HTTP_400' {$paths.Add('HTTP 400: прочитайте тело отказа и повторите свежий запрос. Код без текста не доказывает региональную блокировку.');break}
            'HTTP_413' {$paths.Add('HTTP 413: уменьшите размер запроса/контекст; проверьте лимит ответившего компонента. DNS и Zapret не снимают этот лимит.');break}
            'HTTP_503' {$paths.Add('HTTP 503: проверьте сообщение capacity/overload и повторите позже; это не доказательство локального сбоя.');break}
            'PATCH_MISSING|TLS_VERIFICATION_DISABLED' {$paths.Add('Откройте штатный Unlocker: проверьте патч/сверку TLS. AGFixer не подменяет файлы IDE и не отключает TLS.');break}
            'ACCOUNT_SETUP|MODEL_UNAVAILABLE|HTTP_401|HTTP_403|HTTP_429|REQUEST_SIZE' {$paths.Add('Проверьте аккаунт, доступ к модели, лимиты и свежий ответ сервиса. Автоматический локальный «фикс» здесь не доказан.');break}
        }
    }
    $unique=@($paths|Select-Object -Unique)
    if(-not $unique.Count){$unique=@('Начните с «Проверки сети и состояния → Посмотреть состояние сети и запущенных программ» и нового отчёта.')}
    return $unique
}
function Show-AGReportHelp {
    param([string]$Text,[switch]$Paged)
    $analysis=Get-AGReportAnalysis -Text $Text
    $unique=@(Get-AGReportNextSteps $analysis)
    if($Paged){
        if(-not(Get-Command Show-AGReportViewer -ErrorAction SilentlyContinue)){. "$PSScriptRoot/report-view.ps1"}
        Show-AGReportViewer -Analysis $analysis -NextSteps $unique
        return
    }
    Show-AGReportAnalysis $analysis | Out-Host
    Write-Host "`nЧто делать дальше в AGFixer:" -ForegroundColor Yellow
    for($i=0;$i -lt $unique.Count;$i++){Write-Host "$($i+1). $($unique[$i])"}
}

# Short novice dashboard; advanced categories above remain available through T/F2.
. "$PSScriptRoot/smart-home.ps1"
