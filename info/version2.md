# WireGuard TURN Android — Версия 2 (реализовано)

## Статус: РЕАЛИЗОВАНО

Все пункты первоначального плана версии 2 выполнены. Документ ниже описывает что было запланировано и что реально сделано.

## 1. Цель
Обновить Android-клиент для совместимости с `vk-turn-proxy` (v2). Это включало:
1. **Session ID (UUID)**: Идентификация всех потоков одной сессии. ✅ Реализовано
2. **Round-Robin балансировка**: Распределение исходящего трафика между всеми активными потоками. ✅ Реализовано

## 2. Реализация нативного слоя (Go)

### Session ID
- В `wgTurnProxyStart` генерируется `sessionID := uuid.New()` ✅
- Session ID передаётся через handshake только в режиме `proxy_v2` (см. `info/ANALYSIS_v1_vs_v2.md`)

### Round-Robin балансировка
- Реализована в цикле `lc.ReadFrom`:
  ```go
  lastUsed = (lastUsed + 1) % nStreams
  ```
- Каждый входящий пакет от WG направляется в следующий поток по кругу
- Все потоки разделяют общий `lc` (listener) для downstream

## 3. Дополнительные улучшения (сверх плана)

В процессе разработки были добавлены:

### SRTP-mimicry AEAD wrap (issue #164)
- Опциональная обфускация DTLS-пакетов под вид RTP-трафика
- AEAD ChaCha20-Poly1305 с 12-байтным RTP-заголовком
- Измеренное ускорение: 4.9x (1.0 → 4.9 Mbit/s на эмуляторе Nox)
- Ключ передаётся через `#@wgt:WrapKey` в `.conf` файле

### WebView-солвер капчи
- Автоматическое прохождение VK-капчи через встроенный WebView
- Без внешних сервисов (Playwright и т.п.)
- Фоллбэк: авто-солвер PoW → slider POC → WebView ручное решение

### Поддержка HARICA TLS Root CA
- VK сменил сертификаты `*.vk.com` на HARICA TLS RSA Root CA 2021
- Добавлен embedded Mozilla CA bundle в `cacert.pem`
- `loadCABundle()` используется в TLSClientConfig

### Поддержка доменных имён
- `-connect` теперь принимает как IP, так и доменное имя
- Резолвинг через cascading DNS (system → DoH → DoT → fallback)

### Оптимизации UI
- Скрыт `proxy_v2` из селектора (несовместим с эталонным сервером)
- Optimistic state update: toggle сразу показывает ON при автозапуске
- Reorder `tunnels.complete()` перед `restoreState()` — UI не ждёт captcha

### Поддержка ABI
- 4 ABI: `armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`
- x86 добавлен для эмуляторов (Nox, BlueStacks) — без него Go-runtime падает с SIGILL через houdini

## 4. Тестирование

### На эмуляторе Nox (Android 7, x86)
- ✅ Туннель поднимается, WG handshake стабилен
- ✅ WRAP работает: `[STREAM 0] WRAP enabled (SRTP-mimicry)`
- ✅ DTLS handshake успешен на сервере
- ✅ Скорость: 4.9 Mbit/s (vs 1.0 Mbit/s без wrap)
- ✅ Captcha auto-solve через WebView

### На реальном телефоне (Redmi Note 5A Prime, Android 7.1.2, ARM64)
- ✅ Туннель поднимается
- ✅ WG handshake каждые 2 минуты
- ⚠️ Иногда TURN allocation требует ретраев (нестабильная мобильная сеть)
- ⚠️ При быстром ON/OFF/ON — VK API может получить timeout (трафик уходит в VPN)

## 5. Известные ограничения

1. **Капча при свайпе приложения**: При свайпе приложения с активным туннелем — туннель автоматически восстанавливается, что вызывает captcha. Это не баг, а особенность `restoreState(true)`.

2. **VK API timeout при быстром тоггле**: Если быстро нажать ON/OFF/ON, VK API может получить timeout, потому что VPN захватил трафик к `login.vk.ru`. Workaround: не тогглить быстро, дать туннелю полностью подняться.

3. **Wrap key UI**: Ключ задаётся через `.conf` файл. В UI нет отдельного поля для редактирования wrap key (но есть Generate кнопка — была добавлена и затем откачена, см. коммиты).

## 6. Коммиты

- `068a518f` — fix(captcha): update parser for new VK format + PoW v2 + auto-click WebView
- `5c6c1e02` — feat: embedded CA bundle + SRTP wrap + initSession + TLS fix
- `10d0feb2` — feat(wrap): integrate SRTP-mimicry AEAD wrap into TURN client (issue #164)
- `50b83615` — feat(ui): WrapKey editor + hide proxy_v2 from selector (issue #164)
- `58e24d69` — Revert "feat(qr): add Show QR button for wrap key sharing"
- (предстоит) — fix(tunnel): optimistic state update + reorder complete() before restoreState()
- (предстоит) — docs: rename to CMD WG turn, update README, remove donations
