# Подробный гайд: генерация `.conf` файлов для CMD WG turn

Этот документ описывает, **с нуля** сгенерировать рабочий `.conf` файл туннеля для приложения CMD WG turn. Включая: установку WireGuard, генерацию ключей, настройку сервера, настройку приложения, отдачу конфига пользователю.

## Содержание

1. [Архитектура и роли](#1-архитектура-и-роли)
2. [Установка WireGuard на сервер](#2-установка-wireguard-на-сервер)
3. [Генерация ключей сервера](#3-генерация-ключей-сервера)
4. [Настройка wg-сервера](#4-настройка-wg-сервера)
5. [Установка vk-turn-proxy-server](#5-установка-vk-turn-proxy-server)
6. [Генерация wrap-ключа](#6-генерация-wrap-ключа)
7. [Запуск vk-turn-proxy-server](#7-запуск-vk-turn-proxy-server)
8. [Генерация ключей клиента](#8-генерация-ключей-клиента)
9. [Добавление клиента на сервер](#9-добавление-клиента-на-сервер)
10. [Сборка финального `.conf` файла](#10-сборка-финального-conf-файла)
11. [Проверка работоспособности](#11-проверка-работоспособности)
12. [Импорт в приложение](#12-импорт-в-приложение)
13. [QR-код для импорта](#13-qr-код-для-импорта)
14. [Устранение проблем](#14-устранение-проблем)
15. [Справочник полей конфигурации](#15-справочник-полей-конфигурации)

---

## 1. Архитектура и роли

Полный путь трафика в системе:

```
[Телефон с CMD WG turn]
        ↓ WireGuard (UDP)
[Локальный TURN-клиент в приложении]
        ↓ DTLS + SRTP-wrap (UDP)
[VK TURN сервер (90.156.236.96:19302)]
        ↓ TURN relay (UDP)
[vk-turn-proxy-server на вашем VPS, порт 56001]
        ↓ Локальный UDP
[WireGuard сервер на том же VPS, порт 51830]
        ↓ Дешифрованный трафик
[Интернет]
```

### Роли

| Роль | Где | Что делает |
|------|-----|------------|
| **WG-сервер** | VPS (белый IP) | Принимает WG-трафик от клиента, расшифровывает, выпускает в интернет |
| **vk-turn-proxy-server** | Тот же VPS | Принимает DTLS+wrap пакеты из VK TURN, расшифровывает, передаёт WG-серверу |
| **VK TURN** | 90.156.236.96:19302 | Релей между клиентом и вашим VPS (VK-инфраструктура) |
| **Клиент** | Телефон с приложением | Шифрует трафик WG, оборачивает в DTLS+wrap, отправляет в VK TURN |

### Что нужно подготовить

1. **VPS с белым IP** (например, 194.87.131.227) — Linux Ubuntu 22.04+
2. **VK-аккаунт** — чтобы создать звонок и получить ссылку
3. **Телефон на Android 7.0+** — куда ставить приложение

---

## 2. Установка WireGuard на сервер

```bash
# На VPS (Ubuntu/Debian)
sudo apt update
sudo apt install -y wireguard qrencode
```

Проверка:
```bash
wg --version
# wireguard-tools v1.0.20210914 ...
```

---

## 3. Генерация ключей сервера

```bash
# На VPS
cd /etc/wireguard
umask 077
wg genkey | tee server_private.key | wg pubkey > server_public.key
cat server_private.key
cat server_public.key
```

Пример вывода:
```
server_private.key: OGSsxeN/A6AApeOId0FbIpaf2PZShy3sruzOd+L6lXA=
server_public.key:  AIZfPbbOkupBLPm9fDo8v+PDLy2ljWU9vMJqtXzEY1w=
```

**Важно:** `server_private.key` — секретный. Никогда не выкладывайте его в Git или в чат. `server_public.key` — публичный, его можно давать клиентам.

---

## 4. Настройка wg-сервера

Создайте файл `/etc/wireguard/wg0.conf`:

```bash
sudo nano /etc/wireguard/wg0.conf
```

Содержимое:

```ini
[Interface]
Address = 10.99.0.1/24
ListenPort = 51830
PrivateKey = OGSsxeN/A6AApeOId0FbIpaf2PZShy3sruzOd+L6lXA=
PostUp = iptables -I FORWARD 1 -i wg0 -j ACCEPT; iptables -I FORWARD 1 -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Клиенты будут добавлены ниже в секции [Peer]
```

Замените:
- `PrivateKey` — на ваш `server_private.key`
- `eth0` — на имя вашего внешнего интерфейса (`ip route | grep default` покажет)

Включите форвардинг:
```bash
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

Запустите WG-сервер:
```bash
sudo wg-quick up wg0
sudo systemctl enable wg-quick@wg0
```

Проверка:
```bash
sudo wg show
# interface: wg0
#   public key: AIZfPbbOkupBLPm9fDo8v+PDLy2ljWU9vMJqtXzEY1w=
#   private key: (hidden)
#   listening port: 51830
```

---

## 5. Установка vk-turn-proxy-server

Этот сервер принимает DTLS+wrap пакеты из VK TURN и пробрасывает их на локальный WG-порт (51830).

### 5.1. Установка Go

```bash
# На VPS
sudo apt install -y golang
# или скачать свежую версию:
# https://go.dev/dl/
go version  # должно быть 1.21+
```

### 5.2. Клонирование форка

```bash
cd /root
git clone -b fix/captcha-tls-auto-solver https://github.com/NikKuz99/vk-turn-proxy.git
cd vk-turn-proxy
```

### 5.3. Сборка

```bash
go build -o /usr/local/bin/vk-turn-proxy-server ./server
chmod +x /usr/local/bin/vk-turn-proxy-server
```

Проверка:
```bash
vk-turn-proxy-server -h
# Usage of vk-turn-proxy-server:
#   -connect string  — connect to ip:port
#   -listen string   — listen on ip:port (default "0.0.0.0:56000")
#   -wrap            — WRAP mode: SRTP-mimicry AEAD wrap
#   -wrap-key string — 32-byte hex key for -wrap
#   -gen-wrap-key    — print fresh wrap key
```

---

## 6. Генерация wrap-ключа

Wrap-ключ — это 32-байтная случайная последовательность в hex (64 символа). Используется для SRTP-mimicry AEAD обфускации DTLS-пакетов, чтобы VK TURN не троттил скорость.

```bash
vk-turn-proxy-server -gen-wrap-key
# Пример вывода:
# e979270b5240918e9f3764b0daf9bd825f6d95185481926407435665b37e53ca
```

**Сохраните ключ** — он понадобится и для сервера, и для `.conf` клиента. Никогда не выкладывайте его в открытый доступ (хотя он и не даёт прямого доступа к трафику, его утечка снижает защиту).

---

## 7. Запуск vk-turn-proxy-server

### 7.1. Создание systemd-юнита

```bash
sudo nano /etc/systemd/system/vk-turn-proxy-server.service
```

Содержимое (замените `WRAP_KEY_HEX` на ваш ключ из шага 6):

```ini
[Unit]
Description=vk-turn-proxy DTLS server with wrap
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/vk-turn-proxy-server \
  -listen 0.0.0.0:56001 \
  -connect 127.0.0.1:51830 \
  -wrap \
  -wrap-key WRAP_KEY_HEX
Restart=on-failure
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Параметры:
- `-listen 0.0.0.0:56001` — слушать порт 56001 (открыть в firewall)
- `-connect 127.0.0.1:51830` — локальный WG-сервер
- `-wrap -wrap-key ...` — включить SRTP-mimicry AEAD

### 7.2. Активация

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vk-turn-proxy-server
sudo systemctl status vk-turn-proxy-server
```

Должно быть `active (running)`.

### 7.3. Открытие портов в firewall

```bash
# UDP 51830 — WireGuard
# UDP 56001 — vk-turn-proxy-server
sudo ufw allow 51830/udp
sudo ufw allow 56001/udp
```

### 7.4. Проверка

```bash
sudo journalctl -u vk-turn-proxy-server -f
# Должно показать:
# Starting server listen=0.0.0.0:56001 connect=127.0.0.1:51830 vless=false wrap=true
# Listening
```

---

## 8. Генерация ключей клиента

Для каждого клиента нужно сгенерировать свою пару ключей.

```bash
# На любом компьютере с WireGuard (можно на сервере, можно локально)
umask 077
wg genkey | tee client_private.key | wg pubkey > client_public.key
cat client_private.key
cat client_public.key
```

Пример:
```
client_private.key: 0LfXPEP6hQG5tuihRecN/x7K/7AHzO1WOc8NPvf5R1I=
client_public.key:  FMAPU3C+DCIYqlWxlzXHOU2erbLZPeniMnQttIN+AQI=
```

**Каждый клиент**:
- Свой `client_private.key` — пойдёт в `.conf` клиента
- Свой `client_public.key` — добавится в `wg0.conf` сервера

---

## 9. Добавление клиента на сервер

На сервере отредактируйте `/etc/wireguard/wg0.conf`:

```bash
sudo nano /etc/wireguard/wg0.conf
```

Добавьте секцию `[Peer]` (замените `CLIENT_PUBLIC_KEY` на публичный ключ клиента):

```ini
[Peer]
PublicKey = FMAPU3C+DCIYqlWxlzXHOU2erbLZPeniMnQttIN+AQI=
AllowedIPs = 10.99.0.3/32
```

**Важно:** каждому клиенту — уникальный IP. Например:
- Клиент 1: `10.99.0.2/32`
- Клиент 2: `10.99.0.3/32`
- Клиент 3: `10.99.0.4/32`

Перезапустите WG:
```bash
sudo wg-quick down wg0 && sudo wg-quick up wg0
# или проще:
sudo wg syncconf wg0 <(wg-quick strip wg0)
```

Проверка:
```bash
sudo wg show
# interface: wg0
#   ...
# peer: FMAPU3C+DCIYqlWxlzXHOU2erbLZPeniMnQttIN+AQI=
#   allowed ips: 10.99.0.3/32
```

---

## 10. Сборка финального `.conf` файла

Теперь у вас есть все компоненты:

| Компонент | Значение (пример) | Откуда |
|-----------|-------------------|--------|
| Серверный публичный ключ | `AIZfPbbOkupBLPm9fDo8v+PDLy2ljWU9vMJqtXzEY1w=` | Шаг 3 |
| IP и порт WG-сервера | `194.87.131.227:51830` | Ваш VPS |
| Клиентский приватный ключ | `0LfXPEP6hQG5tuihRecN/x7K/7AHzO1WOc8NPvf5R1I=` | Шаг 8 |
| Клиентский IP | `10.99.0.3/32` | Шаг 9 |
| IP и порт vk-turn-proxy | `194.87.131.227:56001` | Ваш VPS |
| VK-ссылка | `https://vk.com/call/join/RqEfzkI9V1sSvwXejxKQr7wpTK_eTY8_RuSXo0J0hKc` | Шаг 10.1 |
| Wrap-ключ | `e979270b5240918e9f3764b0daf9bd825f6d95185481926407435665b37e53ca` | Шаг 6 |

### 10.1. Получение VK-ссылки

1. Зайдите в VK (с любого аккаунта) — на сайт или в приложение
2. Создайте звонок: **Звонки → Создать звонок** (или через диалог с любым контактом → кнопка "Видеозвонок")
3. Как только звонок создастся — скопируйте URL из адресной строки браузера. Он выглядит так:
   ```
   https://vk.com/call/join/RqEfzkI9V1sSvwXejxKQr7wpTK_eTY8_RuSXo0J0hKc
   ```
4. **Не выходите из звонка** — пусть он остаётся активным (можно просто свернуть окно)

> ⚠️ VK-ссылка — это не пароль. Любой, у кого она есть, может подключиться к звонку. Не выкладывайте её в публичный доступ.

### 10.2. Шаблон `.conf` файла

Создайте файл `my-tunnel.conf`:

```ini
[Interface]
Address = 10.99.0.3/32
PrivateKey = 0LfXPEP6hQG5tuihRecN/x7K/7AHzO1WOc8NPvf5R1I=
MTU = 1280
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = AIZfPbbOkupBLPm9fDo8v+PDLy2ljWU9vMJqtXzEY1w=
AllowedIPs = 0.0.0.0/0
Endpoint = 194.87.131.227:51830
PersistentKeepalive = 25

# [Peer] TURN extensions
#@wgt:EnableTURN = true
#@wgt:UseUDP = true
#@wgt:IPPort = 194.87.131.227:56001
#@wgt:VKLink = https://vk.com/call/join/RqEfzkI9V1sSvwXejxKQr7wpTK_eTY8_RuSXo0J0hKc
#@wgt:Mode = vk_link
#@wgt:PeerType = proxy_v1
#@wgt:StreamNum = 4
#@wgt:LocalPort = 9000
#@wgt:StreamsPerCred = 4
#@wgt:WrapKey = e979270b5240918e9f3764b0daf9bd825f6d95185481926407435665b37e53ca
```

### 10.3. Что заменять

| Поле | Что подставить |
|------|----------------|
| `Address` | IP клиента из шага 9 (`10.99.0.X/32`) |
| `PrivateKey` | `client_private.key` из шага 8 |
| `PublicKey` | `server_public.key` из шага 3 |
| `Endpoint` | `<IP-вашего-VPS>:51830` |
| `#@wgt:IPPort` | `<IP-вашего-VPS>:56001` |
| `#@wgt:VKLink` | Ссылка из шага 10.1 |
| `#@wgt:WrapKey` | Wrap-ключ из шага 6 |

### 10.4. Автоматическая генерация (опционально)

Для массовой генерации конфигов (например, ботом) можно использовать скрипт:

```bash
#!/bin/bash
# gen-conf.sh — генерация конфига для клиента
# Использование: ./gen-conf.sh <client_ip> <server_ip> <vk_link>
# Пример: ./gen-conf.sh 10.99.0.5 194.87.131.227 https://vk.com/call/join/ABC123

CLIENT_IP=$1
SERVER_IP=$2
VK_LINK=$3

# Константы (заменить на свои)
SERVER_PUBKEY="AIZfPbbOkupBLPm9fDo8v+PDLy2ljWU9vMJqtXzEY1w="
WRAP_KEY="e979270b5240918e9f3764b0daf9bd825f6d95185481926407435665b37e53ca"

# Генерация клиентских ключей
umask 077
PRIV=$(wg genkey)
PUB=$(echo "$PRIV" | wg pubkey)

# Добавление peer на сервер
sudo wg set wg0 peer "$PUB" allowed-ips "${CLIENT_IP}/32"

# Создание .conf
cat > "client-${CLIENT_IP}.conf" << EOF
[Interface]
Address = ${CLIENT_IP}/32
PrivateKey = ${PRIV}
MTU = 1280
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = ${SERVER_PUBKEY}
AllowedIPs = 0.0.0.0/0
Endpoint = ${SERVER_IP}:51830
PersistentKeepalive = 25

# [Peer] TURN extensions
#@wgt:EnableTURN = true
#@wgt:UseUDP = true
#@wgt:IPPort = ${SERVER_IP}:56001
#@wgt:VKLink = ${VK_LINK}
#@wgt:Mode = vk_link
#@wgt:PeerType = proxy_v1
#@wgt:StreamNum = 4
#@wgt:LocalPort = 9000
#@wgt:StreamsPerCred = 4
#@wgt:WrapKey = ${WRAP_KEY}
EOF

echo "Создан client-${CLIENT_IP}.conf"
echo "Публичный ключ клиента: $PUB"
echo "Клиент добавлен на сервер"
```

Использование:
```bash
chmod +x gen-conf.sh
./gen-conf.sh 10.99.0.5 194.87.131.227 https://vk.com/call/join/ABC123
```

---

## 11. Проверка работоспособности

### 11.1. На сервере

```bash
# Проверка WG
sudo wg show
# Должен показать peer с правильным PublicKey и AllowedIPs

# Проверка vk-turn-proxy-server
sudo systemctl status vk-turn-proxy-server
sudo journalctl -u vk-turn-proxy-server -n 20
# Должен показать "Listening"

# Проверка открытых портов
sudo ss -ulnp | grep -E "51830|56001"
```

### 11.2. Локальный тест трафика

После установки приложения и запуска туннеля:

```bash
# На сервере
sudo wg show
# Должно появиться:
# peer: FMAPU3C+...
#   endpoint: 127.0.0.1:XXXXX
#   latest handshake: X seconds ago
#   transfer: 1.2 KiB received, 3.4 KiB sent

sudo journalctl -u vk-turn-proxy-server -n 20
# Должно показать:
# Connection from 90.156.236.96:XXXXX
# Start handshake
# Handshake done   ← это значит wrap работает
```

---

## 12. Импорт в приложение

### 12.1. Через файл

1. Передайте `.conf` файл на телефон (USB, мессенджер, облако)
2. Откройте приложение CMD WG turn
3. Нажмите **"+"** в правом нижнем углу
4. Выберите **"Импорт из файла"**
5. Выберите ваш `.conf` файл
6. Туннель появится в списке
7. Нажмите **toggle** для включения

### 12.2. Через QR-код

1. Сгенерируйте QR-код из содержимого `.conf` файла (см. раздел 13)
2. Откройте приложение CMD WG turn
3. Нажмите **"+"** в правом нижнем углу
4. Выберите **"Сканировать QR-код"**
5. Наведите камеру на QR-код
6. Туннель автоматически импортируется

### 12.3. Ручной ввод

1. Создайте новый туннель через **"+"** → **"Создать с нуля"**
2. Введите имя туннеля
3. В секции **Interface**: вставьте `Address`, `PrivateKey`, `MTU`, `DNS`
4. В секции **Peer**: вставьте `PublicKey`, `Endpoint`, `AllowedIPs`, `PersistentKeepalive`
5. Включите **TURN**
6. Заполните все поля `#@wgt:` в UI (IPPort, VKLink, WrapKey, и т.д.)
7. Сохраните

---

## 13. QR-код для импорта

### 13.1. Установка qrencode

```bash
sudo apt install -y qrencode
```

### 13.2. Генерация QR-кода из `.conf`

```bash
# Вывод в терминал (ASCII)
qrencode -t ANSIUTF8 < my-tunnel.conf

# Сохранить в PNG
qrencode -t PNG -o my-tunnel-qr.png < my-tunnel.conf

# Большой размер (для печати)
qrencode -t PNG -s 10 -o my-tunnel-qr.png < my-tunnel.conf
```

### 13.3. Скрипт для массовой генерации

```bash
#!/bin/bash
# gen-qr.sh — генерация QR для .conf файлов
for conf in *.conf; do
    name="${conf%.conf}"
    qrencode -t PNG -s 8 -o "${name}.png" < "$conf"
    echo "Создан ${name}.png"
done
```

### 13.4. Проверка QR-кода

Перед отправкой пользователю проверьте, что QR читается:

```bash
# Установка декодера
sudo apt install -y zbar-tools

# Проверка
zbarimg --raw my-tunnel-qr.png
# Должно вывести содержимое .conf
```

---

## 14. Устранение проблем

### 14.1. Туннель не подключается

**Симптом:** Toggle ON, но WG handshake не происходит.

**Что проверить:**

```bash
# 1. Сервер слушает?
sudo ss -ulnp | grep 51830

# 2. vk-turn-proxy-server активен?
sudo systemctl status vk-turn-proxy-server

# 3. Клиент доходит до сервера?
# На сервере смотрим логи:
sudo journalctl -u vk-turn-proxy-server -f
# Если ничего не приходит — проблема в сети или в VK-ссылке

# 4. VK-ссылка ещё жива?
# Откройте её в браузере — должна вести в активный звонок
```

### 14.2. `Handshake failed: AEAD open`

**Симптом:** В логах vk-turn-proxy-server:
```
Handshake failed: handshake error: dtls fatal: wrap: AEAD open: chacha20poly1305: message authentication failed
```

**Причина:** Wrap-ключ на клиенте не совпадает с серверным.

**Решение:**
1. Проверьте `#@wgt:WrapKey` в `.conf` файле клиента
2. Проверьте `-wrap-key` в systemd-юните сервера
3. Они должны быть **идентичны** (64 hex символа)

### 14.3. VK API timeout / captcha loop

**Симптом:** В логах приложения:
```
dial tcp 93.186.237.1:443: i/o timeout
```

**Причина:** VK API заблокировал запросы (rate limit, error_code 29) или VPN захватил трафик к VK.

**Решение:**
1. Подождите 10-30 минут (rate limit снимется)
2. Создайте **новую** VK-ссылку (старая могла быть заблокирована)
3. Не тогглите туннель быстро ON/OFF — это вызывает captcha loop

### 14.4. Скорость низкая (<1 Mbit/s)

**Причина:** Wrap не включён или VK TURN троттлит.

**Решение:**
1. Проверьте, что в логах есть `[STREAM 0] WRAP enabled (SRTP-mimicry)`
2. Проверьте, что `#@wgt:WrapKey` не пустой
3. Проверьте, что сервер запущен с `-wrap -wrap-key ...`

### 14.5. Капча появляется слишком часто

**Симптом:** При каждом запуске туннеля появляется captcha.

**Причина:** TURN credentials протухают каждые 9 минут, при обновлении VK требует captcha.

**Решение:** Это нормальное поведение. WebView-солвер в приложении должен автоматически её проходить. Если не проходит — переключите на ручной режим (в CaptchaActivity появится чекбокс "Я не робот").

### 14.6. Приложение не запускается на Android 7

**Симптом:** На Android 7.x приложение падает с `SIGILL`.

**Причина:** Установлен APK без x86 ABI (если запускаете на эмуляторе).

**Решение:** Используйте универсальный APK с 4 ABI (arm64-v8a + armeabi-v7a + x86 + x86_64). Скачайте с [релиза v1.0.0-cmd](https://github.com/NikKuz99/wireguard-turn-android/releases/tag/v1.0.0-cmd).

---

## 15. Справочник полей конфигурации

### 15.1. Секция `[Interface]`

| Поле | Описание | Обязательное? | Пример |
|------|----------|---------------|--------|
| `Address` | IP клиента в WG-сети | Да | `10.99.0.3/32` |
| `PrivateKey` | Приватный ключ клиента (base64, 44 символа) | Да | `0LfXPEP6hQG5tuihRecN/x7K/7AHzO1WOc8NPvf5R1I=` |
| `MTU` | Maximum Transmission Unit | Рекомендуется 1280 для TURN | `1280` |
| `DNS` | DNS-серверы (через запятую) | Опционально | `1.1.1.1, 8.8.8.8` |

### 15.2. Секция `[Peer]`

| Поле | Описание | Обязательное? | Пример |
|------|----------|---------------|--------|
| `PublicKey` | Публичный ключ WG-сервера | Да | `AIZfPbbOkupBLPm9fDo8v+PDLy2ljWU9vMJqtXzEY1w=` |
| `AllowedIPs` | Какие IP направлять в туннель | Да (для full-tunnel: `0.0.0.0/0`) | `0.0.0.0/0` |
| `Endpoint` | IP:порт WG-сервера | Да (но игнорируется при TURN) | `194.87.131.227:51830` |
| `PersistentKeepalive` | Интервал keepalive, сек | Рекомендуется 25 | `25` |

### 15.3. TURN-расширения (`#@wgt:`)

| Поле | Описание | Обязательное? | По умолчанию |
|------|----------|---------------|--------------|
| `EnableTURN` | Включить TURN-проксирование | Да | `false` |
| `UseUDP` | UDP (true) или TCP (false) для TURN | Рекомендуется true | `false` |
| `IPPort` | Адрес peer-сервера (ip:port или domain:port) | Да | — |
| `VKLink` | Ссылка на VK-звонок | Да (для mode=vk_link) | — |
| `Mode` | Режим: `vk_link` или `wb` | Да | `vk_link` |
| `PeerType` | `proxy_v1` или `wireguard` | Опционально | `proxy_v1` |
| `StreamNum` | Количество параллельных TURN-потоков (1-16) | Опционально | `4` |
| `LocalPort` | Локальный порт TURN-клиента | Опционально | `9000` |
| `StreamsPerCred` | Потоков на один кэш credentials (1-16) | Опционально | `4` |
| `WrapKey` | 32-байтный hex-ключ SRTP-mimicry AEAD | Опционально (пусто = wrap отключен) | — |
| `TurnIP` | Переопределить IP TURN-сервера | Опционально | — |
| `TurnPort` | Переопределить порт TURN-сервера | Опционально | — |
| `WatchdogTimeout` | Таймаут неактивности DTLS, сек (0 = отключен, ≥5) | Опционально | `0` |

### 15.4. Легенда

- **Обязательное** — без этого поле туннель не запустится
- **Рекомендуется** — оптимальное значение для большинства случаев
- **Опционально** — можно не указывать, будет использовано значение по умолчанию

---

## Чек-лист перед отдачей конфига пользователю

- [ ] Серверный `wg0.conf` содержит `[Peer]` с публичным ключом клиента
- [ ] `wg syncconf` выполнен — клиент виден в `wg show`
- [ ] VK-ссылка живая (звонок активен)
- [ ] В `.conf` клиента:
  - [ ] Приватный ключ клиента совпадает с публичным на сервере
  - [ ] IP клиента уникален (не используется другим клиентом)
  - [ ] Endpoint указывает на ваш VPS:51830
  - [ ] `#@wgt:IPPort` указывает на ваш VPS:56001
  - [ ] `#@wgt:WrapKey` совпадает с `-wrap-key` на сервере
  - [ ] `#@wgt:VKLink` — активная ссылка
- [ ] vk-turn-proxy-server активен (`systemctl status`)
- [ ] Порты 51830/udp и 56001/udp открыты в firewall
- [ ] (Опционально) QR-код сгенерирован и проверен через `zbarimg`

После прохождения чек-листа — отдаёте пользователю `.conf` файл (или QR-код), он импортирует и включает туннель. Готово.
