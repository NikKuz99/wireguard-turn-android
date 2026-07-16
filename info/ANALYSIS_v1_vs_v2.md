# Анализ: proxy_v1 vs proxy_v2 (и режим "wireguard")

## Постановка вопроса

В UI-селекторе peer type изначально было 3 варианта: `proxy_v2`, `proxy_v1`, `wireguard`. В текущей версии `proxy_v2` скрыт из UI — см. ниже почему.

## Анализ исходников

### "wireguard" → runNoDTLS
- Без DTLS-обфускации вообще
- Прямой UDP relay через TURN
- WireGuard-пакеты видны VK TURN content-filter'у
- **Использование:** когда сеть доверенная и нужна максимальная скорость (без накладных расходов DTLS)
- VK TURN вероятно сильно троттлит этот режим

### "proxy_v1" → runDTLS(sendHandshake=false)
- DTLS handshake (ECDHE-ECDSA-AES128-GCM-SHA256)
- После DTLS немедленно начинается relay WG-пакетов через DTLS-туннель
- **Без** session/stream ID handshake
- **Совместим с эталонным vk-turn-proxy** (сервер не ожидает session-handshake)
- Поддерживает wrap (SRTP-mimicry AEAD) — измерено 4.9x ускорение vs без wrap

### "proxy_v2" → runDTLS(sendHandshake=true)
- DTLS handshake (как в v1)
- Затем отправляет 17-байтный session+stream handshake: `[16B sessionID | 1B streamID]`
- Сервер должен понимать этот handshake для демультиплексирования потоков по сессии
- **НЕ совместим с эталонным vk-turn-proxy сервером** — он не парсит 17-байтный handshake и трактует его как WG-данные
- Спроектирован под кастомный сервер kiper292 с поддержкой session-based load balancing

## Ключевая находка

`proxy_v2` **не работает** с эталонным vk-turn-proxy сервером:
1. Клиент шлёт 17 байт session handshake после DTLS
2. Сервер передаёт их в WG backend (`-connect 127.0.0.1:51830`)
3. WG видит 17 байт мусора как первый пакет → handshake init message malformed → WG handshake никогда не завершается

Это значит `proxy_v2` — мёртвый код, если только пользователь не запускает кастомный сервер kiper292.

## Тест, подтверждающий работу (iter_05)

Тест скорости с `proxy_v1` + wrap:
- 100 MB файл скачан за 3 мин 28 сек через путь Nox → VK TURN → vk-turn-proxy-server → wg0 → HTTP-сервер
- Средняя скорость: 4.9 Mbit/s (vs 1.0 Mbit/s baseline без wrap)
- 4x ускорение подтверждено

## Рекомендация: СКРЫТЬ v2, не удалять код

**Не удалять код, только убрать из UI-селектора.**

Причины:
1. v2 не работает с эталонным vk-turn-proxy сервером (а именно его использует большинство)
2. v1 + wrap достигает цели по скорости (4.9x измерено)
3. v2 может быть полезен, если пользователь позже запустит сервер kiper292
4. Удаление из UI убирает путаницу (3 опции → 2: "Proxy v1" и "WireGuard")
5. Сохранение кода дёшево; путаница в UI — дорого

### Реализация скрытия v2

- В `strings.xml`: убран `<item>@string/turn_peer_type_proxy_v2</item>` из массива `turn_peer_type_options` (сама строка оставлена)
- В `TunnelEditorFragment.kt`: изменено `when (position)` — теперь 2 опции (proxy_v1=0, wireguard=1)
- В `TurnSettings.kt`: дефолт изменён с `proxy_v2` на `proxy_v1`
- В `TurnSettings.kt`: в `fromComments()` добавлена нормализация `proxy_v2` → `proxy_v1` (обратная совместимость)

### Обратная совместимость

Существующие туннели с `#@wgt:PeerType = proxy_v2`:
- Парсятся в `TurnSettings.fromComments()`
- Молча нормализуются в `proxy_v1` (без ошибки, без потери данных)
- Пользователь может пересохранить туннель — новый конфиг будет содержать `proxy_v1`

## Альтернатива: ПОЛНОЕ удаление v2

**Плюсы:** меньше кода, меньше путаницы
**Минусы:**
- Если kiper292 позже опубликует свой сервер, придётся возвращать v2
- Удаление параметра `sendHandshake` и ветки `runDTLS` — нетривиальный рефакторинг

**Решение:** СКРЫТЬ, не УДАЛЯТЬ. Вернуться к этому, если kiper292 опубликует свой сервер.

## Что насчёт режима "wireguard"?

Оставить. Это легитимный use case (без накладных расходов DTLS) и не конфликтует ни с чем.
Однако, поскольку VK TURN троттлит plain WG-трафик, в UI он должен быть помечен как "advanced/experimental".
