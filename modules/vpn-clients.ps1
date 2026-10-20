#Requires -Version 5.1
# Offline curated instructions. Never open subscription databases or modify third-party clients.
function Get-AGVpnClientCatalog {
    return @(
        [pscustomobject]@{Id='happ';Name='Happ';Processes=@('happ');Steps=@(
            'Откройте Happ для Windows и подключите уже добавленный профиль вашего провайдера.',
            'Проверьте доступные режимы вашей версии: для прямого профиля AGFixer нужен системный туннель TUN/VPN, а не только системный прокси. Если такого режима нет, выберите вариант HTTP/SOCKS.',
            'Откройте Геонастройки / Routing. Для проверки выберите профиль, отправляющий нужные сайты через Proxy; GlobalProxy определяет выход по умолчанию, но отдельные правила могут его переопределять.',
            'Проверьте DirectSites / DirectIp: Google и адреса модели не должны уходить в Direct. ProxySites предназначен для сайтов через прокси.',
            'Не импортируйте случайные профили маршрутизации поверх рабочего: сохраните исходные настройки. Названия переключателей TUN в Windows зависят от версии; точный путь в опубликованном Routing не описан.'
        );Sources=@('https://www.happ.su/main','https://www.happ.su/main/ru/dev-docs/routing.md');Note='Проверены описание клиента и правила Routing. Точный путь к переключателю TUN для всех версий Windows не подтверждён.'},
        [pscustomobject]@{Id='amnezia';Name='Amnezia VPN';Processes=@('amneziavpn','amnezia','amnezia-service');Steps=@(
            'Откройте AmneziaVPN, выберите уже настроенный сервер и нажмите подключение.',
            'Для первой проверки сохраните текущие настройки и временно отключите раздельное туннелирование по сайтам и приложениям в самом клиенте. Это позволит проверить полный туннель; остальной трафик тоже пойдёт через VPN.',
            'В Windows список приложений Amnezia — исключения: перечисленные приложения идут БЕЗ VPN. Antigravity и его сетевые процессы не должны быть в этих исключениях.',
            'При разделении по IP один домен не покрывает все меняющиеся адреса Google. Запущенное приложение и активный адаптер сами по себе не доказывают путь к модели.',
            'Включать весь IPv6 или отключать его в Windows AGFixer не будет: по документации Amnezia IP-разделение поддерживает IPv4, не IPv6.'
        );Sources=@('https://docs.amnezia.org/documentation/instructions/vpn-split-tunneling/');Note='Инструкция относится к AmneziaVPN на Windows, не к Android и не к отдельному AmneziaWG.'},
        [pscustomobject]@{Id='hiddify';Name='Hiddify';Processes=@('hiddify');Steps=@(
            'Полностью закройте Hiddify через Exit в трее, затем запустите от имени администратора, если этого требует ваша установка.',
            'В официальной инструкции: Settings → Advanced → Config Options → Enable TUN. В новых версиях название может быть VPN / VPN Service.',
            'Выберите ваш профиль и сервер, включите TUN и подключитесь. Один System Proxy не равен системному туннелю.',
            'Проверьте правила маршрутизации выбранного профиля: Google и Antigravity должны идти через выбранный сервер, не через Direct.',
            'Если TUN не запускается, сохраните ошибку клиента и вернитесь к проверке прав/службы; не отключайте антивирус и проверку сертификатов.'
        );Sources=@('https://hiddify.com/app/How-to-use-Hiddify-app/');Note='Путь меню из официального руководства; новые версии могут переименовать VPN/TUN.'},
        [pscustomobject]@{Id='v2rayn';Name='v2rayN';Processes=@('v2rayn');Steps=@(
            'Откройте v2rayN, выберите рабочий сервер из уже добавленной подписки.',
            'Включите TUN mode. При необходимости перезапустите клиент с правами администратора: установка системного туннеля требует соответствующих прав.',
            'Проверьте выбранные правила Routing: Google должен идти через Proxy, а не Direct. Временно менять весь трафик на Global следует только осознанно.',
            'Set system proxy настраивает прокси для приложений, которые его используют; это не замена TUN для прямого профиля AGFixer.',
            'Не меняйте наугад MTU, DNS и ядро одновременно. Сначала подтвердите подключение и маршрут, затем проверяйте запрос к модели.'
        );Sources=@('https://github.com/2dust/v2rayN/wiki/Description-of-some-ui','https://github.com/2dust/v2rayN/wiki/Description-of-system-proxy-routing');Note='Не определяем v2rayN только по общему процессу xray или sing-box.'},
        [pscustomobject]@{Id='clash-verge';Name='Clash Verge Rev / Mihomo';Processes=@('clash-verge','clash-verge-rev','verge-mihomo','verge-mihomo-alpha');Steps=@(
            'Откройте Clash Verge Rev и выберите уже установленную подписку и рабочий сервер.',
            'Для TUN установите и запустите Service Mode в самом клиенте с разрешением администратора либо используйте предусмотренный клиентом запуск с нужными правами.',
            'Включите TUN Mode. System Proxy — другой режим: его не обязаны использовать все приложения.',
            'В Rules проверьте, что Google не попадает в DIRECT/REJECT. Режим Global направляет весь обрабатываемый трафик через выбранную группу; учитывайте влияние на остальные приложения.',
            'Не удаляйте работающий системный прокси Clash как зависший. Если ядро не запускается, исправляйте его ошибку в клиенте, а не очищайте всю сеть.'
        );Sources=@('https://www.clashverge.dev/guide/term.html');Note='Для других оболочек Mihomo меню могут отличаться. Общий процесс mihomo не доказывает, какая оболочка установлена.'},
        [pscustomobject]@{Id='proton';Name='Proton VPN';Processes=@('protonvpn','protonvpn.service','protonvpn.client');Steps=@(
            'Подключитесь к серверу в Proton VPN. AGFixer не меняет тариф, учётную запись или сервер.',
            'Для первой проверки сохраните настройки и отключите Split tunneling в клиенте, если допустимо направить через VPN весь трафик.',
            'Если сохраняете разделение: Exclude исключает приложения из VPN, Include отправляет через VPN только выбранные приложения.',
            'Antigravity и реально работающие сетевые процессы не должны быть исключены в Exclude. В Include их нужно включить; одного браузера недостаточно.',
            'После изменения разделения переподключите VPN и перезапустите приложения, как указано в документации Proton. Не отключайте Kill Switch ради ремонта.'
        );Sources=@('https://protonvpn.com/support/protonvpn-split-tunneling');Note='Нужен клиент Windows. Расширение браузера не направляет через VPN трафик IDE.'},
        [pscustomobject]@{Id='wireguard';Name='WireGuard / AmneziaWG';Processes=@('wireguard','wireguardmanager','amneziawg');Steps=@(
            'Откройте клиент и активируйте уже выданный вашим провайдером туннель. Закрытые ключи и файл конфигурации не отправляйте в поддержку.',
            'В WireGuard поле AllowedIPs определяет маршруты. Полный IPv4-туннель обычно содержит 0.0.0.0/0, IPv6 — ::/0, но работоспособность этих маршрутов зависит от сервера.',
            'Не дописывайте /0 вслепую: в WireGuard для Windows такой маршрут также включает ограничительные правила защиты от утечек.',
            'Если профиль содержит только подсети корпоративной сети, он не обязан направлять Google через VPN. Попросите провайдера профиль с нужными маршрутами.',
            'У AmneziaWG интерфейс и протокол отличаются от обычного WireGuard; не переносите ключи и конфиги между ними автоматически. Проверяйте фактический маршрут.'
        );Sources=@('https://git.zx2c4.com/wireguard-windows/tree/docs/netquirk.md','https://docs.amnezia.org/');Note='WireGuard-маршрутизация из документации Windows. Для конкретной версии AmneziaWG нужен профиль её провайдера.'},
        [pscustomobject]@{Id='openvpn';Name='OpenVPN Connect / OpenVPN GUI';Processes=@('openvpn','openvpn-gui','openvpnconnect','ovpnconnector');Steps=@(
            'Откройте установленный OpenVPN-клиент. Если профиля нет, импортируйте .ovpn или URL только от вашего доверенного провайдера в самом клиенте.',
            'Выберите профиль и нажмите Connect. Запросы логина, сертификата и разрешения Windows выполняйте в клиенте, не в AGFixer.',
            'Профиль организации может включать только внутренние подсети. Надпись Connected ещё не доказывает маршрут к Google.',
            'Проверьте маршруты после соединения. Если Google идёт вне туннеля, нужен подходящий профиль/настройка сервера у провайдера, а не случайная правка .ovpn.',
            'Не отключайте проверку сертификатов и не запускайте одновременно несколько туннелей для проверки одного подключения.'
        );Sources=@('https://openvpn.net/connect-docs/installation-guide-windows.html','https://openvpn.net/as-docs/windows.html');Note='Не все настройки OpenVPN Connect и OpenVPN GUI совпадают.'},
        [pscustomobject]@{Id='throne';Name='Throne';Processes=@('throne');Steps=@(
            'Откройте Throne для Windows из официального throneproj/Throne. Выберите уже добавленный рабочий профиль вашего провайдера и запустите его.',
            'В главном окне включите Tun Mode; в трее тот же режим находится в Operation Mode → Tun Mode. Разрешите запрос прав администратора Windows для создания туннеля.',
            'System Proxy — отдельная настройка. Для прямого VPN/TUN-профиля нужен именно работающий TUN; один System Proxy не направляет через себя все приложения.',
            'Проверьте Routing: Google и сетевые процессы Antigravity не должны попадать в DIRECT, REJECT или обход туннеля. Имя профиля само по себе не подтверждает маршрут.',
            'После изменения режима проверьте свежий запрос модели. Не меняйте DNS и Kill Switch наугад; расположение настроек зависит от версии Throne.'
        );ProxySteps=@(
            'В Throne запустите рабочий профиль. Откройте Settings → Basic Settings → Common → Inbound Settings и посмотрите Listen Address / Listen Port.',
            'По документации mixed-порт по умолчанию 127.0.0.1:2080 принимает HTTP и SOCKS, но порт мог быть изменён или выбран случайно. Используйте фактический адрес из клиента, а не значение по умолчанию.',
            'Disable Mixed Inbound должен быть выключен, если нужен локальный прокси. Не включайте Allow other devices to connect для подключения IDE на том же компьютере.',
            'System Proxy в главном окне / Operation Mode управляет прокси Windows, а не туннелем. При обычном завершении Throne снимает его; после аварии сначала восстановите настройку через сам Throne.'
        );Sources=@('https://github.com/throneproj/Throne','https://throneproj.github.io/guides/proxy_modes/','https://throneproj.github.io/guides/routing/');Note='Инструкция для настольного Throne, не Android и не старого NekoRay. Процесс ThroneCore/sing-box не доказывает наличие работающего GUI или туннеля.'},
        [pscustomobject]@{Id='flclash';Name='FlClash';Processes=@('flclash');Steps=@(
            'Откройте FlClash для Windows из chen08209/FlClash. Выберите уже добавленный профиль и рабочий узел в группе прокси.',
            'Включите TUN Mode в вашей версии клиента. Если клиент запрашивает установку помощника/повышение прав для туннеля, подтвердите только штатный запрос установленного FlClash.',
            'System Proxy и TUN — разные режимы; Global относится к маршрутизации внутри клиента и сам по себе не включает системный туннель.',
            'В правилах и живом списке Connections проверьте, что запросы Google идут в нужную группу/узел, а не DIRECT или REJECT.',
            'Если ядро mihomo не запущено или TUN выдаёт ошибку, сначала исправьте её в FlClash. AGFixer не загружает ядро и не заменяет подписку.'
        );ProxySteps=@(
            'Подключите профиль FlClash и найдите настройки локального слушателя/порта в вашей версии. Запишите адрес, порт и поддерживаемый тип HTTP/SOCKS.',
            'System Proxy включает адрес прокси для поддерживающих его приложений. Для прямого профиля AGFixer этого недостаточно; здесь используйте отдельный HTTP/SOCKS-вариант.',
            'Выберите узел в группе прокси и проверьте правила. Не включайте доступ из LAN для локального подключения Antigravity.'
        );Sources=@('https://github.com/chen08209/FlClash');Note='README подтверждает Windows, System Proxy, TUN и маршрутизацию. Универсальный путь меню и номер порта для всех версий не заявлены; не путать с FlClashX и другими форками.'},
        [pscustomobject]@{Id='clash-nyanpasu';Name='Clash Nyanpasu';Processes=@('clash-nyanpasu','clash nyanpasu');Steps=@(
            'Откройте Clash Nyanpasu из libnyanpasu/clash-nyanpasu. Выберите рабочий профиль и узел/группу.',
            'На панели Proxy status проверьте TUN Mode отдельно от System Proxy. Для прямого VPN/TUN-профиля AGFixer включите и проверьте именно TUN.',
            'Возможность TUN зависит от выбранного ядра и разрешений Windows. Если клиент сообщает об отсутствии службы или прав, исправьте это штатными средствами Nyanpasu.',
            'Проверьте правила и Connections: Google не должен попадать в DIRECT/REJECT. Выбранный Global не заменяет создание TUN-адаптера.',
            'Если TUN в установленной версии/ядре недоступен, выберите HTTP/SOCKS-вариант в AGFixer. Не применяйте прямой TUN-профиль вслепую.'
        );ProxySteps=@(
            'В Clash Nyanpasu выберите профиль и рабочий узел. Найдите локальные proxy/mixed-порты в настройках текущего ядра/профиля; номера не угадывайте.',
            'System Proxy на панели Proxy status и TUN Mode независимы. Один System Proxy обслуживает только приложения, использующие этот адрес.',
            'Для локального HTTP/SOCKS-варианта используйте фактический loopback-адрес и порт. Не заменяйте YAML, скрипты или ядро ради установки одного адреса в Unlocker.'
        );Sources=@('https://github.com/libnyanpasu/clash-nyanpasu','https://nyanpasu.org/');Note='Nyanpasu поддерживает разные ядра, поэтому наличие и параметры TUN проверяются в установленной версии. Это не Clash Verge Rev.'},
        [pscustomobject]@{Id='gui-for-singbox';Name='GUI.for.SingBox';Processes=@('gui.for.singbox');Steps=@(
            'Откройте GUI.for.SingBox из GUI-for-Cores/GUI.for.SingBox. Это оболочка: проверьте наличие и запуск совместимого sing-box-ядра в самом приложении.',
            'Выберите подготовленный профиль, рабочие подписки/узлы и группу прокси. Не заменяйте существующий JSON случайным шаблоном.',
            'Включите TUN в настройках профиля и запустите ядро. Для Windows официальный гайд рекомендует Settings → General → Run As Admin, если иначе туннель не запускается.',
            'Проверьте Routing и DNS профиля: Google должен идти через выбранный выход, а не Direct. DNS-настройки этой оболочки не равны тумблеру DNS-обхода Unlocker.',
            'Открытое окно GUI не доказывает запуск ядра или TUN. Проверьте состояние и свежий запрос Antigravity до применения других изменений.'
        );ProxySteps=@(
            'Откройте подготовленный профиль GUI.for.SingBox и проверьте работающий mixed/HTTP/SOCKS inbound, его loopback-адрес и порт.',
            'Запустите sing-box-ядро средствами оболочки. Одного открытого GUI и импортированной подписки недостаточно для локального слушателя.',
            'Используйте тип и адрес из текущего профиля. Не включайте TUN и не применяйте прямой профиль AGFixer, если выбран только локальный прокси.'
        );Sources=@('https://github.com/GUI-for-Cores/GUI.for.SingBox','https://gui-for-cores.github.io/guide/gfs/community');Note='Оболочка и sing-box-ядро — разные компоненты; общее имя процесса sing-box не позволяет определить оболочку. Не относится к GUI.for.Clash.'},
        [pscustomobject]@{Id='other';Name='Другой клиент / не знаю название';Processes=@();Steps=@(
            'Откройте ваш клиент и определите способ подключения: TUN/системный VPN либо локальный HTTP/SOCKS-прокси.',
            'Если есть только расширение браузера, его недостаточно для Antigravity. Нужен клиент для Windows или поддерживаемый прокси для IDE/Unlocker.',
            'В TUN-режиме проверьте маршрут к нужным адресам и правила исключений. В прокси-режиме найдите точный протокол и адрес слушателя в клиенте.',
            'Если меню вашей версии отличается, не применяйте профиль наугад: сохраните JSON диагностики AGFixer без ключей/подписки и уточните версию клиента.'
        );Sources=@();Note='Универсальная проверка режима, не подтверждённая инструкция конкретного неизвестного клиента.'}
    )
}
function Get-AGVpnClientChoices {
    param($Status)
    $names=@()
    if($Status){
        foreach($p in @($Status.Processes)){if($p.ProcessName){$names+=(([string]$p.ProcessName -replace '(?i)\.exe$','').ToLowerInvariant())}}
        foreach($c in @($Status.Vpn.Clients)){if($c.Process){$names+=(([string]$c.Process -replace '(?i)\.exe$','').ToLowerInvariant())}}
    }
    foreach($c in @(Get-AGVpnClientCatalog)){
        $detected=[bool](@($c.Processes|Where-Object{$_ -in $names}).Count)
        $label=$c.Name;if($detected){$label+=' — процесс найден'}
        [pscustomobject]@{Client=$c;Detected=$detected;Label=$label}
    }
}
function Get-AGVpnClientGuideLines {
    param($Client,[ValidateSet('Tun','Proxy','Unknown')][string]$Mode='Tun')
    $lines=@('Кому подходит',('Windows; '+$Client.Name+'. Инструкция не устанавливает VPN и не покупает сервер.'),'Перед началом',
        'Сохраните настройки клиента и работу в IDE. Используйте свою доверенную подписку/профиль; не публикуйте ключи.',
        'Выбор клиента — подсказка, а не доказательство маршрута или страны выхода. Версии интерфейса могут отличаться.',
        'Пошаговая настройка')
    if($Mode -eq 'Tun'){
        for($i=0;$i -lt $Client.Steps.Count;$i++){$lines+=([string]($i+1)+'. '+$Client.Steps[$i])}
        $lines+=@('Что ВЫКЛЮЧИТЬ в Unlocker','Для прямого VPN/TUN-профиля AGFixer: Обход через DNS, Локальный прокси, Встроенные выходы, Прокси из группы и Свой прокси — ВЫКЛ.',
            'Что оставить ВКЛЮЧЁННЫМ','Разблокировку входа, автопатч для нужной IDE и проверку TLS проверьте в Unlocker. Мастер их не меняет.')
    }elseif($Mode -eq 'Proxy'){
        if($Client.PSObject.Properties.Name -contains 'ProxySteps'){
            foreach($step in @($Client.ProxySteps)){$lines+=([string]$step)}
        }
        $lines+=@('1. Подключите профиль в клиенте и найдите именно локальный HTTP/HTTPS/SOCKS5-адрес и порт.',
            '2. Не используйте VLESS/VMess/ss-ссылку как HTTP/SOCKS-адрес. Не подставляйте 53129 или 7890 наугад.',
            '3. Откройте «Гайды сообщества» → «Свой HTTP/SOCKS-прокси» и настройте этот отдельный вариант. Прямой VPN/TUN-профиль здесь не применяется.',
            '4. Если нужен пароль прокси, не публикуйте его в отчёте. Работающий системный прокси клиента удалять не нужно.')
    }else{
        $lines+=@('1. TUN/VPN создаёт системный туннель; системный прокси только сообщает адрес прокси поддерживающим его приложениям.',
            '2. «Global» описывает правила внутри клиента, а не само наличие TUN. Это независимые настройки.',
            '3. Уточните режим в клиенте и вернитесь к выбору. По одному процессу AGFixer не выберет его за вас.')
    }
    $lines+=@('Как понять, что работает','После подключения обновите состояние AGFixer. Процесс, адаптер и маршрут — разные уровни проверки.',
        'Проверьте свежий запрос в чате Antigravity. Успешный TLS-тест сам по себе не доказывает ответ модели.',
        'Если не заработало','Сохраните свежий отчёт Unlocker и JSON AGFixer. Проверьте страну выхода и правила разделения; не стирайте все NRPT или прокси Windows.',
        'Важно',$Client.Note,'AGFixer не редактирует подписки, ключи, конфигурационные базы или правила VPN-клиента. План меняет только явно перечисленные настройки Unlocker/Windows.')
    if($Client.Sources.Count){$lines+='Источники';$lines+=@($Client.Sources)}
    return $lines
}
function Show-AGVpnClientGuides {
    while($true){
        $status=$null;try{$status=Get-AGSystemStatus}catch{}
        $choices=@(Get-AGVpnClientChoices -Status $status)
        $pick=Read-AGListChoice -Title 'VPN для Windows — выберите клиент' -Options @($choices.Label) -Intro @('Есть отдельные инструкции для популярных клиентов. Для остальных — проверка режима.','Процесс найден ≠ туннель работает. Ничего не изменяется.')
        if(-not $pick){return}
        $client=$choices[$pick-1].Client
        $modePick=Read-AGListChoice -Title ($client.Name+' — какой режим?') -Options @('TUN / системный VPN','Только HTTP/SOCKS или системный прокси','Не знаю — чем отличаются режимы?')
        if(-not $modePick){continue}
        $mode=switch($modePick){1{'Tun'}2{'Proxy'}default{'Unknown'}}
        Show-AGTextPages -GuideSections -Title ($client.Name+' — настройка с AG Unlocker') -Lines @(Get-AGVpnClientGuideLines -Client $client -Mode $mode)
    }
}
function Invoke-AGVpnClientSetup {
    param([string]$ReportText)
    $status=$null;try{$status=Get-AGSystemStatus}catch{}
    $choices=@(Get-AGVpnClientChoices -Status $status)
    $pick=Read-AGListChoice -Title 'Свой VPN — выберите клиент' -Options @($choices.Label) -Intro @('Выбор нужен для правильной инструкции. Подписки, ключи и настройки VPN не читаются.')
    if(-not $pick){return}
    $client=$choices[$pick-1].Client
    while($true){
        $modePick=Read-AGListChoice -Title ($client.Name+' — способ подключения') -Options @('TUN/VPN — инструкция и план настройки Unlocker','HTTP/SOCKS / системный прокси — отдельная инструкция','Не знаю — определить режим') -Intro @('Прямой профиль подходит только для системного туннеля, не для одного прокси-порта.')
        if(-not $modePick){return}
        $mode=switch($modePick){1{'Tun'}2{'Proxy'}default{'Unknown'}}
        Show-AGTextPages -GuideSections -Title ($client.Name+' — инструкция') -Lines @(Get-AGVpnClientGuideLines -Client $client -Mode $mode)
        if($mode -ne 'Tun'){continue}
        $action=Read-AGListChoice -Title ($client.Name+' — после настройки клиента') -Options @('Показать план: настроить Unlocker под VPN/TUN','Прочитать инструкцию ещё раз','Вернуться к выбору режима') -Intro @('Сначала выполните шаги в самом VPN. AGFixer не включает туннель за вас.','План будет показан отдельно: Y — исправить | N — игнорировать.')
        if(-not $action){return}
        if($action -eq 1){Invoke-AGSmartRepair -ReportText $ReportText -Mode VpnDirect;return}
        if($action -eq 2){Show-AGTextPages -GuideSections -Title ($client.Name+' — инструкция') -Lines @(Get-AGVpnClientGuideLines -Client $client -Mode Tun)}
    }
}
