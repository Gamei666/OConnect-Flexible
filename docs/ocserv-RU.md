# Динамическая раздельная маршрутизация ocserv

[English](ocserv.md)

Клиент получает доменные правила в формате Cisco из заголовка сервера `X-CSTP-Post-Auth-XML`. Укажите URL сервера в профиле Android и подключитесь. Ручные доменные правила профиля применяются, если сервер не передал динамическую политику.

## Полный туннель с исключениями

```ini
route = default
no-route = 192.0.2.0/24
custom-header = X-CSTP-Post-Auth-XML: <?xml version="1.0" encoding="UTF-8"?><config-auth client="vpn" type="complete" aggregate-auth-version="2"><config client="vpn" type="private"><opaque is-for="vpn-client"><custom-attr><dynamic-split-exclude-domains><![CDATA[video.example.com,news.example.net]]></dynamic-split-exclude-domains></custom-attr></opaque></config></config-auth>
```

Указанные домены, их поддомены и исключённая подсеть идут напрямую. Если VPN поддерживает только IPv4, маршрутизация IPv6 дополнительно зависит от серверного параметра обхода для неподдерживаемого протокола.

## Раздельный туннель с включениями

Укажите на сервере конкретные маршруты вместо `route = default`. В этом примере домены добавляются к VPN, через который уже направляется частная подсеть.

```ini
route = 10.24.0.0/16
custom-header = X-CSTP-Post-Auth-XML: <?xml version="1.0" encoding="UTF-8"?><config-auth client="vpn" type="complete" aggregate-auth-version="2"><config client="vpn" type="private"><opaque is-for="vpn-client"><custom-attr><dynamic-split-include-domains><![CDATA[example.com]]></dynamic-split-include-domains><dynamic-split-exclude-domains><![CDATA[video.example.com]]></dynamic-split-exclude-domains></custom-attr></opaque></config></config-auth>
```

При раздельном туннеле `example.com` и его поддомены идут через VPN, за исключением `video.example.com` и его поддоменов. При пересечении доменных правил в полном туннеле приоритет у include. Статические исключения по IP имеют приоритет в обоих режимах.

## Ограничения

Клиент сопоставляет IP-адреса из полученных DNS-ответов с доменными правилами на время DNS TTL. На выбор маршрута могут повлиять совпадающие IP-адреса разных доменов, DNS-кэш, Private DNS Android и зашифрованный DNS отдельных приложений. Текущие соединения сохраняют ранее выбранный путь. Прямой выход поддерживает TCP и UDP. Для динамической маршрутизации нужны IPv4-адрес и IPv4 DNS от VPN-сервера, а также MTU не менее 1280. После изменения правил на сервере переподключите профиль.

## Диагностика

Включите **Настройки → Расширенные → Диагностика dynamic split**, откройте новое соединение с проверяемым сайтом или сервисом и перейдите в **Детали подключения → Журнал**. По умолчанию настройка выключена. Её можно менять при активном VPN.

- `DOMAIN: server policy active` подтверждает получение доменных правил от ocserv.
- `SPLIT DNS` показывает IP-адреса, полученные для совпавших доменов, направление по доменному правилу и TTL. Также отмечаются отдельные случаи фильтрации DNS.
- `SPLIT FLOW` показывает путь и причину для нового соединения TCP или UDP. Например, `DIRECT reason=dynamic_exclude` означает прямой выход, а `VPN reason=dynamic_include` — выход через туннель. Запись показывает выбор маршрута. Ошибка прямого подключения может появиться отдельной строкой.

Частота записей ограничена. При проверке правила откройте новое соединение, потому что уже открытое сохраняет ранее выбранный путь. Перед отправкой журнала проверьте содержащиеся в нём домены и IP-адреса назначения.
