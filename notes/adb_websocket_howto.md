# ADB over WebSocket — рабочий стек (WebSockify bridge)

Подключение телефона (POCO M4 Pro, `fleur`, MIUI/HyperOS) к сайту через
WebSocket без WebUSB. **Проверено вживую**: fingerprint и bootloader
читаются с https-деплоя через `ws://localhost:8000`.

## Как это работает

```
браузер (https://tayuluc.github.io/lk-unlock/)
   │  new WebSocket("ws://localhost:8000")
   ▼
websockify (localhost:8000)  ── TCP ──▶  телефон adbd (192.168.1.117:5555)
```

1. `adb tcpip 5555` на телефоне (через USB)
2. `websockify 8000 <ip>:5555` на хосте
3. на сайте: поле `ws://localhost:8000` → «Подключить по WS»
4. модуль делает CNXN → AUTH → CNXN → OPEN(getprop) → данные

## Ключевые факты протокола (не «упрощать»!)

- **`ws://localhost` разрешён с https-страницы.** Chromium НЕ блокирует
  WebSocket к localhost как mixed content (localhost = secure context).
  Поэтому app.webadb.com подключается с https без всякого обхода. Наш
  сайт делает то же самое.
  - НО: `ws://не-локальный-хост` с https блокируется (только `wss://`).
- **CNXN command = `0x4e584e43`** (little-endian «CNXN»). Баговый
  `0x4e58434e` телефон молча дропает.
- **Auth-типы**: Token=1, Signature=2, PublicKey=3 (современный adbd).
- **CNXN_FEATURES** — только device-фичи (AOSP `AdbDeviceFeatures`):
  `shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,apex,abb,
  fixed_push_symlink_timestamp,abb_exec,remount_shell,track_app,
  sendrecv_v2,sendrecv_v2_brotli/lz4/zstd/dry_run_send,devraw,app_info`.
  - Без trailing `;` (игнорируется).
  - **НЕ включать `delayed_ack`**: наш минимальный клиент его не
    реализует, а рекламируя фичу — adbd закрывает OPEN-сокеты CLSE
    вместо OKAY. (Симптом: AUTH проходит, потом CLSE сразу после OPEN.)
  - Серверные фичи (`devicetracker_proto_format`, `server_status`,
    `track_mdns`) устройству не шлём.
- **Маршрутизация сокетов**: для device→host пакетов наш id в `arg1`,
  remote id в `arg0` (не наоборот!).
- **RSA-подпись**: WebCrypto `RSASSA` двойной-хэширует токен → не годится.
  Нужен raw BigInt modular exponentiation (PKCS#1 v1.5, SHA-1).
- **AUTH_PUBLICKEY payload** = base64(mincrypt RSAPublicKey struct, 524
  байта) + " " + comment + NUL, а не SPKI-ключ.

## Источники кода

- **Единственный источник правды** — `web/vendor/adb-daemon-browser.js`
  (самодостаточный ESM, живёт в этом репо). Правка модуля = правка этого
  файла → `web/build.py` встраивает в `index.html` (стриппит `export { }`,
  делает классик-глобалы) → commit → push на `uv-migration`.
- Раньше был inline-самописный модуль в `index.html` и отдельный форк
  `tayuLuc/ya-webadb` как промежуточный склад — оба упразднены, чтобы не
  дублировать источник. Код основан на отладке (см. «Ключевые факты»).

## Обновление модуля

Правка `web/vendor/adb-daemon-browser.js` → `uv run python web/build.py` →
commit + push на `uv-migration` → CI + Pages. Никаких внешних
зависимостей.

## Проверка / отладка

- `lsof -nP -iTCP:8000 -sTCP:LISTEN` — жив ли websockify
- `nc -z -G 2 <ip> 5555` — отвечает ли adbd
- Кнопка «пакеты» в журнале — пошаговый лог CNXN/AUTH/OPEN/OKAY/WRTE
- Апстрим webadb (app.webadb.com) — тот же механизм, можно сравнивать
