# VPN-клиенты Windows в AGFixer 6.10.7

Это расширяемый офлайн-каталог инструкций, не обещание поддержки каждого VPN на рынке. Клиент и реальный маршрут диагностируются отдельно. Режим TUN и правило Global — не синонимы. Профили подписки могут переопределить GUI-настройки.

| Семейство | Особенность инструкции | Первичный источник |
|---|---|---|
| Happ | Routing, GlobalProxy, DirectSites/ProxySites; точный путь к TUN в разных Windows-версиях не подтверждён | https://www.happ.su/main/ru/dev-docs/routing.md |
| Amnezia VPN | В Windows список приложений — исключения из VPN; разделение по сайтам/IP и приложениям различается | https://docs.amnezia.org/documentation/instructions/vpn-split-tunneling/ |
| Hiddify | Администратор/предусмотренная служба, Enable TUN, версия меню | https://hiddify.com/app/How-to-use-Hiddify-app/ |
| v2rayN | TUN и системный прокси раздельно; настройки ядра/маршрутизации | https://github.com/2dust/v2rayN/wiki/Description-of-some-ui |
| Clash Verge Rev/Mihomo | Service Mode, TUN, Rule/Global/Direct; другие оболочки отличаются | https://www.clashverge.dev/guide/term.html |
| Proton VPN | Exclude и Include имеют противоположный смысл | https://protonvpn.com/support/protonvpn-split-tunneling |
| WireGuard/AmneziaWG | AllowedIPs/маршрут; /0 в WireGuard Windows связан также с защитой от утечек. Не копируем конфиги между протоколами | https://git.zx2c4.com/wireguard-windows/tree/docs/netquirk.md ; https://docs.amnezia.org/ |
| OpenVPN Connect/GUI | Импорт своего профиля в клиенте, подключение не доказывает полный маршрут | https://openvpn.net/connect-docs/installation-guide-windows.html ; https://openvpn.net/as-docs/windows.html |

| Throne | Tun Mode и System Proxy, mixed HTTP/SOCKS, фактический Listen Port/Random port; документация для desktop | https://github.com/throneproj/Throne ; https://throneproj.github.io/guides/proxy_modes/ |
| FlClash | Windows, mihomo, TUN и System Proxy; правила и живые подключения. Без выдуманного универсального пути меню/порта | https://github.com/chen08209/FlClash |
| Clash Nyanpasu | Proxy status: System Proxy и TUN Mode; возможности зависят от выбранного ядра/версии | https://github.com/libnyanpasu/clash-nyanpasu ; https://nyanpasu.org/ |
| GUI.for.SingBox | Оболочка и ядро отдельно; профиль TUN/mixed, Settings → General → Run As Admin, группы и правила | https://github.com/GUI-for-Cores/GUI.for.SingBox ; https://gui-for-cores.github.io/guide/gfs/community |

## Что мастер делает

1. Показывает клиента из списка; метка «процесс найден» означает только совпадение имени процесса. Общий xray/sing-box не назначается конкретному GUI.
2. Уточняет режим: системный туннель, локальный прокси или неизвестный.
3. Открывает инструкцию с разделами и страницами для выбранного клиента/режима.
4. Только для выбранного TUN предлагает перейти к прежнему guarded engine для настройки Unlocker. Просмотр плана, Y/N, сверка свежих настроек, блокировка записи, резервные копии и точечная область операций сохранены.

## Чего мастер не делает

Не покупает подписку, не импортирует ключи и не запускает клиентов. Не меняет их конфиги, DNS/маршруты, Kill Switch или исключения. Не устанавливает корневые сертификаты и не отключает TLS/антивирус. Наличие процесса не доказывает TUN, а маршрут по умолчанию не доказывает прохождение конкретного приложения при split tunneling.

## Проверка материалов

Проверены указанные первичные веб-материалы; сетевой/клавиатурный запуск самих Windows-клиентов в этой Linux-среде не выполнен. Доступность возможностей зависит от версии, тарифа, профиля провайдера и политики устройства. Карточка Happ явно отмечает непроверенный путь к переключателю TUN. Для другого клиента предусмотрена проверка режима, но не выдумана инструкция конкретного интерфейса.

## GitHub-проверка новых клиентов

На момент проверки API GitHub показал неархивированные официальные репозитории Throne (~7,5 тыс. звёзд), FlClash (~57 тыс.), Clash Nyanpasu (~13 тыс.) и GUI.for.SingBox (~8,2 тыс.). Это ориентир распространённости, не гарантия качества/безопасности. Снимок: test-results/v6.10.7-linux/github-repositories.json. Количество звёзд и статус проекта меняются.

MatsuriDayo/nekoray архивирован. Старый процесс NekoRay по-прежнему может показываться в общей диагностике, но не принимается за Throne и не предлагается как новый рекомендуемый клиент. Автообновления/скачивание/миграция не добавлены.

Новые инструкции основаны на первичных документах, а не на фактическом запуске клиентов в Windows. TUN может требовать штатного повышения прав/службы самого клиента. Для GUI.for.SingBox оболочка не заменяет отдельно настроенное ядро. Работающий System Proxy не называется зависшим только по наличию ключа реестра.
