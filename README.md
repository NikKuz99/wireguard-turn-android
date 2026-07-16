# CMD WG turn

Это форк клиента [WireGuard Android](https://git.zx2c4.com/wireguard-android) с интегрированной поддержкой **VK TURN Proxy** и AEAD-обфускацией трафика (SRTP-mimicry wrap) для обхода ограничений VK TURN-серверов.

Проект инкапсулирует трафик WireGuard в потоки DTLS/TURN, используя инфраструктуру VK Calls, и применяет дополнительный слой шифрования, имитирующий RTP-пакеты, чтобы избежать троттлинга со стороны VK TURN.

## Важное предупреждение

**Данный проект создан исключительно в учебных и исследовательских целях.**

Использование инфраструктуры VK Calls (TURN-серверов) без явного разрешения со стороны правообладателя может нарушать Условия использования сервиса и правила платформы VK. Авторы проекта не несут ответственности за любой ущерб или нарушение правил, возникшее в результате использования данного программного обеспечения. Проект демонстрирует техническую возможность интеграции протоколов и не предназначен для нецелевого использования ресурсов сторонних сервисов.

## Ключевые особенности

- **Нативная интеграция**: TURN-клиент встроен напрямую в `libwg-go.so` для максимальной производительности и минимального расхода заряда батареи.
- **Два режима авторизации**:
  - **VK Link** — получение учётных данных TURN через анонимные токены VK Calls.
  - **WB** — получение учётных данных TURN через WB Stream API.
- **SRTP-mimicry wrap (AEAD)**: Опциональная обфускация DTLS-пакетов под вид RTP-трафика (RFC 3550) с AEAD-шифрованием ChaCha20-Poly1305. Обходите контент-фильтр VK TURN, который троттлит не-RTP UDP до ~1 Mbit/s. Замеренное ускорение на эмуляторе — 4.9x (с 1.0 до 4.9 Mbit/s).
- **Многопоточная балансировка**: Параллельные потоки DTLS с Round-Robin распределением исходящего трафика.
- **Кастомный DNS-резолвер**: Все HTTP и WebSocket запросы проходят через встроенный резолвер с защитой сокетов через VPN.
- **Оптимизация MTU**: Автоматическая установка MTU 1280 при использовании TURN.
- **Автоматический рестарт при смене сети**: Переподключение при переключении WiFi ↔ 4G/5G с debounce-защитой.
- **WebView-солвер капчи**: Автоматическое прохождение VK-капчи через встроенный WebView (без внешних сервисов).
- **QR-импорт туннелей**: Поддержка сканирования QR-кодов для импорта `.conf` файлов с расширениями `#@wgt:`.
- **Удобная настройка**: Параметры TURN хранятся прямо в `.conf` файлах WireGuard в виде специальных комментариев (`#@wgt:`).

## Режимы PeerType

В UI доступны два режима:

- **Proxy v1** (по умолчанию) — DTLS-хендшейк без session-handshake. Совместим с эталонным сервером [cacggghp/vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy) и форком [NikKuz99/vk-turn-proxy](https://github.com/NikKuz99/vk-turn-proxy). **Рекомендуется для большинства пользователей.**
- **WireGuard** — без DTLS, прямой UDP relay. Только для отладки или прямого подключения без обфускации.

> **Proxy v2** скрыт из UI (см. `info/ANALYSIS_v1_vs_v2.md`). Режим несовместим с эталонным сервером: отправляет 17-байтный session-handshake, который сервер трактует как WG-данные. Существующие конфиги с `#@wgt:PeerType = proxy_v2` автоматически нормализуются в `proxy_v1`.

## Сборка

```bash
# Требуется: Go 1.25+, Android NDK 27+, JDK 21
git clone --recurse-submodules https://github.com/NikKuz99/wireguard-turn-android
cd wireguard-turn-android
./gradlew :ui:assembleDebug
```

APK собирается с поддержкой 4 ABI: `armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`. Универсальный APK работает на всех устройствах.

## Настройка туннеля

Параметры TURN задаются в секции `[Peer]` конфигурационного файла `.conf`:

```ini
[Interface]
Address = 10.99.0.3/32
PrivateKey = <приватный ключ клиента>
MTU = 1280
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = <публичный ключ сервера>
AllowedIPs = 0.0.0.0/0
Endpoint = <ip-сервера>:51830
PersistentKeepalive = 25

# [Peer] TURN extensions
#@wgt:EnableTURN = true
#@wgt:UseUDP = true
#@wgt:IPPort = <ip-сервера>:56001
#@wgt:VKLink = https://vk.com/call/join/<код>
#@wgt:Mode = vk_link
#@wgt:PeerType = proxy_v1
#@wgt:StreamNum = 4
#@wgt:LocalPort = 9000
#@wgt:StreamsPerCred = 4
#@wgt:WrapKey = <64 hex символа>  # 32-байтный ключ AEAD wrap (пусто = wrap отключен)
```

### Поля TURN

| Поле | Описание | По умолчанию |
|------|----------|--------------|
| `EnableTURN` | Включить TURN-проксирование | false |
| `UseUDP` | Использовать UDP (true) или TCP (false) для TURN | false |
| `IPPort` | Арес peer-сервера (ip:port или domain:port) | — |
| `VKLink` | Ссылка на VK-звонок для получения credentials | — |
| `Mode` | Режим авторизации: `vk_link` или `wb` | `vk_link` |
| `PeerType` | `proxy_v1` или `wireguard` | `proxy_v1` |
| `StreamNum` | Количество параллельных TURN-потоков (1-16) | 4 |
| `LocalPort` | Локальный порт для TURN-клиента | 9000 |
| `StreamsPerCred` | Потоков на один кэш credentials (1-16) | 4 |
| `WrapKey` | 32-байтный hex-ключ для SRTP-mimicry AEAD (пусто = отключен) | — |
| `TurnIP` | Переопределить IP TURN-сервера (опционально) | — |
| `TurnPort` | Переопределить порт TURN-сервера (опционально) | — |
| `WatchdogTimeout` | Таймаут неактивности DTLS, сек (0 = отключен, ≥5) | 0 |

### Wrap key

Чтобы включить SRTP-mimicry AEAD:
1. Сгенерируйте 32-байтный hex-ключ (64 символа). Можно командой на сервере:
   ```bash
   vk-turn-proxy-server -gen-wrap-key
   ```
2. Укажите тот же ключ в `#@wgt:WrapKey` в `.conf` файле и в параметрах сервера (`-wrap -wrap-key <hex>`).
3. Без wrap ключа в `.conf` файле — wrap отключен, туннель работает в классическом режиме DTLS.

## Серверная часть

Для работы клиента нужен сервер `vk-turn-proxy-server`. Рекомендуется использовать форк [NikKuz99/vk-turn-proxy](https://github.com/NikKuz99/vk-turn-proxy) (ветка `fix/captcha-tls-auto-solver`) — там добавлены:
- Поддержка HARICA TLS Root CA (VK сменил сертификаты `*.vk.com`)
- Поддержка доменных имён в `-connect` (не только IP)
- Playwright-солвер капчи (опционально)
- Флаги `-wrap` и `-wrap-key` для SRTP-mimicry AEAD

Пример запуска сервера (systemd unit):
```ini
ExecStart=/usr/local/bin/vk-turn-proxy-server \
  -listen 0.0.0.0:56001 \
  -connect 127.0.0.1:51830 \
  -wrap \
  -wrap-key e979270b5240918e9f3764b0daf9bd825f6d95185481926407435665b37e53ca
```

Где `127.0.0.1:51830` — адрес локального WireGuard-сервера.

## Благодарности

Проект построен на базе:
1. **[Official WireGuard Android](https://git.zx2c4.com/wireguard-android)** — основное VPN-приложение и UI.
2. **[cacggghp/vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy)** — автор оригинальной идеи.
3. **[kiper292/wireguard-turn-android](https://github.com/kiper292/wireguard-turn-android)** — базовый форк с интеграцией TURN.

## Участие в проекте

При обнаружении технических ошибок, связанных с интеграцией TURN или wrap, пожалуйста, создавайте Issue в этом репозитории.
