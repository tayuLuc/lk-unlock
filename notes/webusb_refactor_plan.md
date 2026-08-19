## 0. Практические выводы из отладки 2026-08-19

Это не план рефактора, а краткая память о том, что реально сломалось на
`POCO M4 Pro / fleur`, как это чинилось, и что важно помнить в новой сессии.

### Что было не так с USB chooser

Мы увидели два разных состояния, которые легко перепутать:

1. **Chooser пустой (`Совместимые устройства не найдены`)**
   - Это не обязательно баг страницы.
   - Реальные причины, которые встретились:
     - после неудачного `claim/reset` на MTK-гаджете chooser иногда пустеет до
       переподключения кабеля;
     - другой клиент держит ADB-интерфейс (`adb`, вторая Chromium-вкладка,
       другой браузерный профиль);
     - автоматизация/CDP-клик не считается нормальным user gesture для
       `requestDevice()`;
     - временный debug-profile Brave вёл себя не так же, как обычный Brave.

2. **Chooser показывает `POCO M4 Pro`**
   - Это означает, что `navigator.usb.requestDevice()` и HTTPS/permissions уже
     в порядке.
   - Если после этого связь не поднимается, проблема уже в ADB handshake после
     выбора устройства.

### Что ломало ADB по USB

На реальном устройстве подтвердились такие причины:

1. **CNXN header + payload нельзя было слать одним куском**
   - При одной URB на `243` байта гаджет уходил в USB disconnect ещё до AUTH.
   - Рабочий вариант: как у `app.webadb.com`, сначала header `24` байта, потом
     payload отдельной URB.

2. **Проверка `magic` для `AUTH` была сломана знаком числа в JS**
   - `cmd ^ 0xffffffff` в JS даёт signed 32-bit.
   - `DataView#getUint32()` возвращает unsigned.
   - Исправление: сравнивать как `(cmd ^ 0xffffffff) >>> 0`.

3. **Нужно читать USB пакет размером endpoint packet size, а не 24**
   - На macOS при `transferIn(24)` ловили babble/нестабильность.
   - Рабочий вариант: `transferIn(endpoint.packetSize)` и уже потом буферизовать
     ADB packet в JS.

4. **MTK лучше переживает, когда IN уже запущен до первого CNXN**
   - Рабочая последовательность:
     - открыть устройство;
     - выбрать конфиг/iface/alt;
     - создать `UsbTransport`;
     - стартовать первый `readPacket(transport)`;
     - только потом слать `CNXN`.

5. **После AUTH device шлёт нормальный ADB flow**
   - Рабочий лог успеха:
     - `CNXN -> AUTH(TOKEN) -> AUTH(PUBKEY) -> CNXN`
     - дальше `OPEN/OKAY/WRTE/CLSE` на `getprop`.

### Что в итоге оказалось рабочим

На рабочем билде `?v=2663bd4` WebUSB в итоге поднялся до конца:

- chooser показал `POCO M4 Pro`;
- USB device успешно выбрался;
- страница получила `AUTH`;
- отправила `PUBKEY`;
- после подтверждения на устройстве пришёл второй `CNXN`;
- `getprop` отработал;
- UI показал:
  - `✓ Данные получены`
  - `Bootloader: Заблокирован`
  - `MI OS: OS1.0.8.0.TKERUXM`
  - fingerprint `POCO/fleur_p_ru/fleur:13/.../TKERUXM:user/release-keys`

### Что именно было исправлено в коде

Итоговая рабочая серия изменений:

- `transferIn(packetSize)` вместо `transferIn(24)`;
- split OUT URBs: header `24`, payload отдельно;
- unsigned compare для `magic`;
- priming `transferIn` до `CNXN`;
- skip junk packets до первого валидного ADB packet вместо немедленного throw;
- `slice()`-копии перед `transferOut`, чтобы не словить проблемы с mutable buffer;
- disconnect listener только для **нашего** `usbDevice`;
- sequential `getprop`, а не агрессивный параллелизм;
- forced packet log на USB connect для реальной диагностики.

### Почему USB то пропадал, то появлялся

Важно запомнить: это были **две разные проблемы**.

1. **Слой chooser/device visibility**
   - Иногда список пустой просто из-за состояния USB gadget или потому, что
     интерфейс уже занят.
   - Лечится не кодом handshake, а освобождением интерфейса / переподключением
     кабеля / новым user gesture.

2. **Слой ADB handshake**
   - Даже когда chooser показывал телефон, handshake раньше ломался на CNXN или
     на `AUTH` из-за сериализации пакетов и signed/unsigned бага.
   - Это уже была реальная ошибка нашей реализации, и она исправлена.

### Что помнить в новой сессии

1. **Актуальная ветка и сайт**
   - Рабочая ветка: `uv-migration`.
   - Live URL: `https://tayuluc.github.io/lk-unlock/`
   - Проверяем конкретный билд по `?v=2663bd4` или новее.

2. **Не путать обычный Brave и debug Brave**
   - `osascript activate "Brave Browser"` поднимает обычный профиль пользователя,
     а не временный профиль.
   - Для отдельного debug-instance нужно ориентироваться по конкретному PID /
     окну, а не по имени приложения.

3. **Нельзя полагаться на CDP-клики для chooser**
   - WebUSB chooser нельзя честно пройти через обычный CDP DOM click.
   - Нужен реальный user gesture или OS-level input.
   - Если chooser пустой, это ещё не доказательство поломки сайта.

4. **Если chooser пустой**
   - проверить, не держит ли интерфейс `adb` или другой Chromium;
   - при необходимости убить фоновые ADB-клиенты;
   - если MTK всё равно пустой, попросить replug кабеля;
   - потом повторить клик `Подключить телефон`.

5. **Если chooser видит телефон, но дальше не работает**
   - смотреть on-page `Журнал`, не только консоль;
   - первый критичный маркер успеха: `First packet: AUTH...`;
   - следующий: после `AUTH(PUBKEY)` должен прийти второй `CNXN`;
   - затем должны пойти `OPEN/OKAY/WRTE` на `getprop`.

6. **Симптом окончательного успеха**
   - статус `✓ Данные получены`;
   - заполненный fingerprint;
   - `MI OS` и lock state показаны в UI.

7. **Не откатывать текущую схему подписи**
   - `signToken` должен подписывать token **as-is** через PKCS#1 SHA-1
     `DigestInfo`;
   - дополнительный SHA-1 поверх токена не нужен и ломает совместимость.

8. **Не менять без причины текущие ADB features**
   - список должен быть webadb-like;
   - `delayed_ack` не включать;
   - banner `host::features=...;` должен иметь завершающий `;`.

### Мини-runbook для следующей сессии

1. Убедиться, что открыта ветка `uv-migration`.
2. Проверить live deploy / нужный `?v=...`.
3. Если тестируется WebUSB:
   - закрыть/убить лишний `adb`, если он держит интерфейс;
   - открыть страницу в Brave/Chromium;
   - кликнуть `Подключить телефон`;
   - если chooser пустой, сделать replug кабеля и повторить;
   - если chooser показывает `POCO M4 Pro`, выбрать его;
   - смотреть `Журнал` до `AUTH`, второго `CNXN`, затем `OPEN/WRTE`.
4. Критерий success:
   - `✓ Данные получены`,
   - fingerprint подставился,
   - UI показал MI OS и состояние bootloader.

## 1. Краткая оценка текущего состояния

Главные архитектурные проблемы:

1. **WebUSB/ADB-логика вшита в UI-код `index.html`**
   - Нет границы между транспортом, доменом и UI.
   - Всё завязано на реальный `navigator.usb` и конкретную библиотеку.
   - Playwright не может протестировать системный USB-chooser, поэтому текущий код практически не тестируется.

2. **Один большой `try/catch` вместо state machine** - Ошибки chooser, ADB auth, disconnect, timeout, повторное подключение смешаны.
   - Нет явных состояний: `idle`, `choosing`, `connecting`, `waiting-auth`, `reading`, `error`.

3. **`authenticate()` может висеть вечно**
   - Нет таймаута.
   - Нет подсказки пользователю.
   - Нет принудительного закрытия USB-сессии при таймауте.
   - Возможны zombie-pending промисы после физического отключения телефона.

4. **Риск потери user gesture**
   - `navigator.usb.requestDevice()` должен вызываться в контексте пользовательского клика.
   - Если перед этим внутри клика долго грузятся модули с `esm.sh`, браузер может посчитать activation потерянным.
   - Модули нужно preload/warmup заранее: hover, focus, idle, либо кнопка должна быть активна только после загрузки модулей.

5. **Concurrency-проблемы**
   - Повторные клики по кнопке. - Отключение телефона во время auth.
   - Повторное подключение после ошибки.
   - Несколько вкладок. - Stale-результаты: старый `connect()` завершился после нового.   - Утечки listener'ов и незакрытых USB-дескрипторов.

6. **Безопасность**
   - ADB-ключ в `sessionStorage` — риск при XSS.
   - Формально ADB даёт доступ к shell; read-only гарантия должна быть обеспечена allowlist'ом команд на уровне приложения.
   - Нельзя давать UI или тестам произвольный `shell()`.

---## 2. Предлагаемая архитектура

Без сборщика, обычные ES-модули:

```text
web/
  index.html
  js/
    adb/
      errors.js
      async.js
      mutex.js
      props.js
      adb-session.js          # контракт + базовые вещи
      webusb-adb-session.js   # реальный WebUSB + yume-chan
      mock-adb-session.js     # mock для Playwright/dev
      factory.js # выбор mock/real
    ui/
      adb-connect-controller.js
```

Если хочется минимум файлов, можно объединить, но ответственность всё равно разделить:

- `Transport/Session` — USB/ADB lifecycle.
- `PropsReader` — read-only `getprop`.
- `Controller` — state machine, mutex, timeout, UI events.
- `UI` — только рендер состояний и вызов контроллера.

### Ответственность

| Модуль | Ответственность |
|---|---|
| `errors.js` | Типизация ошибок: cancel, security, timeout, disconnect |
| `async.js` | timeout, delay, retry helpers |
| `mutex.js` | запрет параллельных подключений |
| `props.js` | allowlist `getprop`, парсинг fingerprint |
| `adb-session.js` | контракт: `preload/open/authenticate/getProp/close` |
| `webusb-adb-session.js` | реальный WebUSB + ADB |
| `mock-adb-session.js` | тестовый double без USB |
| `factory.js` | создаёт mock или real session |
| `adb-connect-controller.js` | orchestration, UI state, timeout RSA |

---

## 3. Ключевые контракты и код

### 3.1 Ошибки

```js
// js/adb/errors.js

export class AdbError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'AdbError';
    this.cause = cause;
  }
}

export class UserCancelledError extends AdbError {
  constructor(message = 'User cancelled device chooser', cause) {
    super(message, cause);
    this.name = 'UserCancelledError';
  }
}

export class PermissionDeniedError extends AdbError {
  constructor(message = 'Permission denied or insecure context', cause) {
    super(message, cause);
    this.name = 'PermissionDeniedError';
  }
}

export class AuthTimeoutError extends AdbError {
  constructor(message = 'ADB RSA authentication timeout', cause) {
    super(message, cause);
    this.name = 'AuthTimeoutError';
  }
}

export class DeviceDisconnectedError extends AdbError {
  constructor(message = 'Device disconnected', cause) {
    super(message, cause);
    this.name = 'DeviceDisconnectedError';
  }
}

export class InvalidStateError extends AdbError {
  constructor(message = 'Invalid state', cause) {
    super(message, cause);
    this.name = 'InvalidStateError';
  }
}

export function mapAdbError(err) {
 if (err instanceof AdbError) return err;

  const name = err?.name;
  const message = err?.message ?? String(err);

  if (name === 'NotFoundError') {
    return new UserCancelledError('Device chooser cancelled', err);
  }

  if (name === 'SecurityError') {
    return new PermissionDeniedError('USB permission or secure context error', err);
  }

  if (name === 'InvalidStateError') {
    return new InvalidStateError('USB device is in invalid state', err);
  }

  if (/disconnect|closed|reset|device lost/i.test(message)) {
    return new DeviceDisconnectedError(message, err);
  }

  return new AdbError(message, err);
}
```

---

### 3.2 Timeout helper

```js
// js/adb/async.js

export function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export async function withTimeout(promise, ms, makeError) {
  let timer;

  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(makeError()), ms);
      })
    ]);
  } finally {
    clearTimeout(timer);
  }
}
```

---

### 3.3 Mutex от повторных кликов

```js
// js/adb/mutex.js

export class Mutex {
  #tail = Promise.resolve();

  async run(fn) {
    let release;
    const gate = new Promise(resolve => {
      release = resolve;
    });

    const prev = this.#tail;
    this.#tail = gate;

    await prev;

    try {
      return await fn();
    } finally {
      release();
    }
  }
}
```

---

### 3.4 Контракт ADB-сессии

В JS нет интерфейсов, поэтому используем duck typing + JSDoc.

```js
// js/adb/adb-session.js

/**
 * @typedef {Object} AdbSession
 *
 * @property {() => Promise<void>} preload
 * Опционально заранее грузит библиотеки.
 *
 * @property {() => Promise<void>} open
 * requestDevice + open USB device.
 * Здесь может быть системный chooser.
 *
 * @property {() => Promise<void>} authenticate
 * ADB RSA authentication.
 * Именно тут телефон показывает confirmation dialog.
 *
 * @property {(name: string) => Promise<string>} getProp
 * Read-only getprop.
 *
 * @property {() => Promise<void>} close
 * Закрывает USB/ADB ресурсы.
 */
```

Важно разделить `open()` и `authenticate()`:

- `open()` — chooser, открытие USB.
- `authenticate()` — ожидание RSA.
- timeout нужен именно на `authenticate()`.

---

## 4. Реальная WebUSB-сессия

Ниже — каркас. Имена методов `@yume-chan/*` нужно сверить с вашей версией, но архитектурно должно быть именно так.

```js
// js/adb/webusb-adb-session.js

import {
  AdbError,
  InvalidStateError,
  DeviceDisconnectedError
} from './errors.js';

import { withTimeout } from './async.js';

const ADB_USB_FILTERS = [
  {
    // ADB interface class: vendor-specific, subclass 0x42, protocol 0x01
    classCode: 0xff,
    subclassCode: 0x42,
    protocolCode: 0x01
  }
];

const SAFE_PROP_NAME = /^[a-z0-9_.]+$/i;

export class WebUsbAdbSession extends EventTarget {
  #libsPromise = null;
  #libs = null;

  #device = null;
  #transport = null;
  #adb = null;
  #credentialStore = null;

  #aborter = new AbortController();
  #closed = false;

  async preload() {
    if (!this.#libsPromise) {
      this.#libsPromise = Promise.all([
        import('@yume-chan/adb'),
        import('@yume-chan/adb-daemon-webusb'),
        import('@yume-chan/adb-credential-web')
      ]).then(modules => {
        this.#libs = {
          adb: modules[0],
          webusb: modules[1],
          credential: modules[2]
        };
        return this.#libs;
      });
    }

    await withTimeout(
      this.#libsPromise,
      15000,
      () => new AdbError('Failed to load ADB modules from CDN')
    );
  } async open() {
    if (this.#closed) {
      throw new InvalidStateError('Session already closed');
    }

    if (this.#device) {
      throw new InvalidStateError('Session already opened');
    }

    await this.preload();

    const { webusb } = this.#libs;

    // Важно: этот вызов должен происходить как можно ближе к user gesture.
    // Желательно, чтобы preload() уже завершился до клика.
    this.#device = await this.#requestDevice(webusb);

    navigator.usb.addEventListener(
      'disconnect',
      this.#handleUsbDisconnect,
      { signal: this.#aborter.signal }
    );

    try {
      await this.#openDevice(webusb);
    } catch (err) {
      await this.close();
      throw err;
    }
  }

  async #requestDevice(webusbModule) {
 // Здесь имя API зависит от версии.
    // Варианты: AdbDaemonWebUsbDevice.requestDevice(...)
    // или менеджер устройств из @yume-chan/adb-daemon-webusb.
    const deviceClass =
      webusbModule.AdbDaemonWebUsbDevice ??
      webusbModule.default?.AdbDaemonWebUsbDevice;

    if (!deviceClass?.requestDevice) {
      throw new AdbError('AdbDaemonWebUsbDevice.requestDevice is unavailable');
    }

    return deviceClass.requestDevice({
      filters: ADB_USB_FILTERS
    });
  }

  async #openDevice(webusbModule) {
    // Псевдокод: сверить с API вашей версии.
    if (typeof this.#device.open === 'function') {
      await this.#device.open();
    }

    // Дальше нужно создать transport для Adb. // Например:
    //
    // const { Adb, AdbDaemonTransport } = this.#libs.adb;
    // this.#transport = new AdbDaemonTransport({ device: this.#device });
    // this.#adb = new Adb(this.#transport);
    //
    // Либо использовать device.createTransport()/AdbDaemonDevice API.
    throw new AdbError('Implement openDevice according to yume-chan API');
  }

  async authenticate() {
    if (this.#closed) {
      throw new InvalidStateError('Session already closed');
    }

    if (!this.#adb) {
      throw new InvalidStateError('ADB is not opened');
    }

    try {
      const { credential } = this.#libs;

      // Пример:
      // const CredentialStore = credential.AdbCredentialWeb;
      // this.#credentialStore = new CredentialStore();
      // await this.#adb.authenticate(this.#credentialStore);

      throw new AdbError('Implement authenticate according to yume-chan API');
    } catch (err) {
      await this.close();
      throw err;
    }
  }

  async getProp(name) {
    if (this.#closed) {
      throw new DeviceDisconnectedError('Session closed');
    }

    if (!SAFE_PROP_NAME.test(name)) {
      throw new AdbError(`Unsafe property name: ${name}`);
    }

    // Только read-only getprop.
    // Никакого произвольного shell.
    return this.#runShell(`getprop ${name}`);
  }

  async #runShell(command) {
    if (!this.#adb) {
      throw new InvalidStateError('ADB is not ready');
    }

    // Псевдокод:
    //
    // const proc = await this.#adb.subprocess.spawn(command);
    // let result = '';
    //
    // for await (const chunk of proc.stdout) {
    //   result += new TextDecoder().decode(chunk);
    // }
    //
    // await proc.exit;
    // return result.trim();

    throw new AdbError('Implement runShell according to yume-chan API');
  }

  #handleUsbDisconnect = event => {
    if (!this.#device) return;

    if (event.device === this.#device) {
      this.dispatchEvent(new CustomEvent('disconnect'));
      this.close().catch(() => {});
    }
  };

  async close() {
    if (this.#closed) return;

    this.#closed = true;
    this.#aborter.abort();

    try {
      await this.#device?.close?.();
    } catch {
      // ignore
    }

    this.#device = null;
    this.#transport = null;
    this.#adb = null;
    this.#credentialStore = null;

    this.dispatchEvent(new CustomEvent('closed'));
  }
}
```

---

## 5. Mock-сессия для Playwright

```js
// js/adb/mock-adb-session.js

import {
  UserCancelledError,
  PermissionDeniedError,
  DeviceDisconnectedError
} from './errors.js';

import { delay } from './async.js';

function makeError(name, message) {
  switch (name) {
    case 'NotFoundError':
      return new DOMException(message ?? 'No device selected', 'NotFoundError');

    case 'SecurityError':
      return new DOMException(message ?? 'Permission denied', 'SecurityError');

    case 'DeviceDisconnectedError':
      return new DeviceDisconnectedError(message);

    default:
      return new Error(message ?? name);
  }
}

export class MockAdbSession extends EventTarget {
  #rejectPendingAuth = null;

  constructor(options = {}) {    super();
    this.options = options;
    this.closed = false;
  }

  async preload() {
    await delay(this.options.preloadDelayMs ?? 0);
  }

  async open() {
    await delay(this.options.openDelayMs ?? 0);

    if (this.options.fail?.open) {
      throw makeError(
        this.options.fail.open,
        this.options.fail.openMessage
      );
    }
  } async authenticate() {
    await delay(this.options.authDelayMs ?? 0);

    if (this.options.auth === 'pending') {
      await new Promise((_, reject) => {
        this.#rejectPendingAuth = reject;
      });
    }

    if (this.options.fail?.authenticate) {
      throw makeError(
        this.options.fail.authenticate,
        this.options.fail.authenticateMessage
      );
    }
  }

  async getProp(name) {
    if (this.closed) {
      throw new DeviceDisconnectedError('Mock session closed');
    }

    await delay(this.options.getPropDelayMs ?? 0);

    return this.options.props?.[name] ?? '';
  }

  async close() {
    if (this.closed) return;

    this.closed = true;

    if (this.#rejectPendingAuth) {
      this.#rejectPendingAuth(new DeviceDisconnectedError('Mock closed')); this.#rejectPendingAuth = null;
    }

    this.dispatchEvent(new CustomEvent('closed'));
  }
}
```

---

## 6. Factory: mock или real```js
// js/adb/factory.js

import { MockAdbSession } from './mock-adb-session.js';
import { WebUsbAdbSession } from './webusb-adb-session.js';

function isMockRequested() {
  const params = new URLSearchParams(location.search);

  return Boolean(
    globalThis.__ADB_MOCK__ ||
    params.has('adb-mock') ||
    params.get('transport') === 'mock'
  );
}

export function createAdbSession() {
  if (isMockRequested()) {
    return new MockAdbSession(globalThis.__ADB_MOCK__ ?? {});
  }

  return new WebUsbAdbSession();
}
```

---

## 7. Контроллер подключения

Это главный orchestrator. UI не должен знать про WebUSB напрямую.

```js
// js/ui/adb-connect-controller.js

import { Mutex } from '../adb/mutex.js';
import { withTimeout } from '../adb/async.js';
import { mapAdbError, AuthTimeoutError } from '../adb/errors.js';

const DEFAULT_AUTH_TIMEOUT_MS = 30000;

export class AdbConnectController extends EventTarget {
  #mutex = new Mutex();
  #generation = 0;

  #createSession;
  #authTimeoutMs;
  #props;

  constructor({
    createSession,
    authTimeoutMs = DEFAULT_AUTH_TIMEOUT_MS,
    props = ['ro.build.fingerprint']
  }) {
    super();
    this.#createSession = createSession;
    this.#authTimeoutMs = authTimeoutMs;
    this.#props = props;
  }

  #setState(state, extra = {}) {
    this.dispatchEvent(new CustomEvent('state', {
      detail: { state, ...extra }
    }));
  }

  async preload() {
    const session = this.#createSession();

    try {
      await session.preload?.();
    } finally {
      await session.close?.().catch(() => {});
    }
  }

  async connectAndReadProps() { return this.#mutex.run(async () => {
      const generation = ++this.#generation;
      const session = this.#createSession();

      try {
        this.#setState('loading');

        await session.preload?.();

        if (generation !== this.#generation) return;

        this.#setState('choosing');

        await session.open();

        if (generation !== this.#generation) return;

        this.#setState('waiting-auth', {
          hint: 'Подтвердите разрешение отладки USB на телефоне'
        });

        await withTimeout(
          session.authenticate(),
          this.#authTimeoutMs,
          () => new AuthTimeoutError('ADB RSA authentication timeout')
        );

        if (generation !== this.#generation) return;

        this.#setState('reading');

        const result = {};

        for (const prop of this.#props) {
          const value = await session.getProp(prop);
          result[prop] = value.trim();
        }

        if (generation !== this.#generation) return;

        this.#setState('done');

        return result;
      } catch (err) {
        if (generation !== this.#generation) return;

        const mapped = mapAdbError(err);

        this.#setState('error', { error: mapped });

        throw mapped;
      } finally {
        await session.close?.().catch(() => {});
      }
    });
  }
}
```

---

## 8. Подключение в `index.html`

Желательно использовать import map:

```html
<script type="importmap">
  {
    "imports": {
      "@yume-chan/adb": "https://esm.sh/@yume-chan/adb@2.6.2",
      "@yume-chan/adb-daemon-webusb": "https://esm.sh/@yume-chan/adb-daemon-webusb@2.3.2",
      "@yume-chan/adb-credential-web": "https://esm.sh/@yume-chan/adb-credential-web@2.1.0"
    }
  }
</script>
```

Подключение UI:

```html
<script type="module">
  import { createAdbSession } from './js/adb/factory.js';
  import { AdbConnectController } from './js/ui/adb-connect-controller.js';

  const params = new URLSearchParams(location.search);

  const controller = new AdbConnectController({
    createSession,
    authTimeoutMs: Number(params.get('auth-timeout')) || 30000,
    props: [
      'ro.build.fingerprint',
      'ro.product.device'
    ]
  });

  const connectButton = document.getElementById('connect-phone');
  const statusEl = document.getElementById('adb-status');
  const fingerprintInput = document.getElementById('fingerprint');

  function renderState(detail) {
    switch (detail.state) {
      case 'loading':
        statusEl.textContent = 'Загрузка модулей…';
        break;

      case 'choosing':
        statusEl.textContent = 'Выберите телефон в системном окне USB…';
        break;

      case 'waiting-auth':
        statusEl.textContent =
          'Авторизация… Подтвердите диалог отладки USB на телефоне.';
        break;

      case 'reading':
        statusEl.textContent = 'Чтение getprop…';        break;

      case 'done':
        statusEl.textContent = 'Готово.';
        break;

      case 'error':
        statusEl.textContent = errorMessage(detail.error);
        break;
    }
  }

  function errorMessage(err) { switch (err?.name) {
      case 'UserCancelledError':
        return 'Подключение отменено.';

      case 'PermissionDeniedError':
        return 'Нет доступа к USB. Проверьте настройки браузера.';

      case 'AuthTimeoutError':
        return 'Не подтверждена ADB-авторизация. Попробуйте снова.';

      case 'DeviceDisconnectedError':
        return 'Телефон отключён.';

      default:
        return `Ошибка: ${err?.message ?? err}`; }
  }

  controller.addEventListener('state', event => {
    renderState(event.detail);
  });

  // Warmup, чтобы не потерять user gesture на динамическом import.
  const warmup = () => controller.preload().catch(() => {});

  connectButton.addEventListener('pointerenter', warmup, { once: true });
  connectButton.addEventListener('focus', warmup, { once: true });

  setTimeout(warmup, 1500);

  connectButton.addEventListener('click', async () => {
    try {
      connectButton.disabled = true;

      const props = await controller.connectAndReadProps();

      if (props?.['ro.build.fingerprint']) {
        fingerprintInput.value = props['ro.build.fingerprint'];
        fingerprintInput.dispatchEvent(new Event('input', { bubbles: true }));
      }
    } catch {
      // Уже обработано через state=error
    } finally {
      connectButton.disabled = false;
    }
  });
</script>
```

---

## 9. Как решить проблему «Авторизация…»

Решение:1. Разделить `open()` и `authenticate()`.
2. После `open()` переводить UI в состояние `waiting-auth`.
3. Показывать явную подсказку:
   - «Подтвердите разрешение отладки USB на телефоне».
   - «Экран должен быть разблокирован».
   - «Если диалог не появляется, отзовите разрешения отладки USB и попробуйте снова».
4. Запускать timeout только на `authenticate()`.
5. По таймауту закрывать сессию:
   ```js
   await session.close().catch(() => {});
   ```
6. Игнорировать поздние результаты через generation counter.

Рекомендуемый таймаут:

- 30 секунд по умолчанию.
- Для тестов можно переопределять через query:
  ```text
  /?adb-mock&auth-timeout=500 ```

---

## 10. Пошаговый план миграции

### Шаг 1. Зафиксировать текущее поведение

Добавить в текущий код только логирование состояний:

- click
- chooser started
- device selected
- authenticate started
- authenticate success
- getprop started
- getprop success
- error type

Ничего не ломает, но сразу даёт диагностику.

---

### Шаг 2. Создать инфраструктуру ошибок и async helpers

Добавить:

```text
js/adb/errors.js
js/adb/async.js
js/adb/mutex.js
```

Пока ничего не подключать или подключить только в новый код.

Тестируемо:
- чистые функции;
- можно проверить через Playwright `page.evaluate`.

---

### Шаг 3. Ввести контракт `AdbSession`

Создать:

```text
js/adb/adb-session.js
js/adb/mock-adb-session.js
js/adb/factory.js
```

UI переводится на:

```js
const session = createAdbSession();
await session.open();
await session.authenticate();
await session.getProp('ro.build.fingerprint');
await session.close();
```

На этом этапе реальный WebUSB ещё можно не подключать.

Тестируемо:
- Playwright с `window.__ADB_MOCK__`;
- без железа;
- проверяются UI-состояния.

---

### Шаг 4. Реализовать `AdbConnectController`

Перенести туда:

- mutex;
- state machine;
- generation guard;
- timeout;
- mapping ошибок;
- чтение props.

UI должен вызывать только:

```js
controller.connectAndReadProps();
```

Тестируемо:
- mock success;
- mock cancel;
- mock auth timeout;
- mock disconnect during read;
- double click.

---

### Шаг 5. Обернуть существующий реальный WebUSB-код

Создать:

```text
js/adb/webusb-adb-session.js
```

Перенести туда текущий код из `index.html`:

- dynamic import `@yume-chan/*`;
- `requestDevice`;
- `open`;
- `authenticate`;
- `getprop`.

Важно:
- не менять поведение;
- пока можно оставить старый код behind flag;
- новый код включать через `?adb=v2`.

---

### Шаг 6. Добавить warmup библиотек

Чтобы не терять user gesture:

```js
button.addEventListener('pointerenter', warmup);
button.addEventListener('focus', warmup);
setTimeout(warmup, 1500);
```

Или использовать:

```html
<link rel="modulepreload" href="https://esm.sh/@yume-chan/adb@2.6.2">
<link rel="modulepreload" href="https://esm.sh/@yume-chan/adb-daemon-webusb@2.3.2">
<link rel="modulepreload" href="https://esm.sh/@yume-chan/adb-credential-web@2.1.0">
```

Для GitHub Pages это допустимо, если CORS на esm.sh разрешён.

---

### Шаг 7. Добавить обработку disconnect

В реальной сессии:

```js
navigator.usb.addEventListener('disconnect', handler);
```

В контроллере:

- если сессия была активна, перевести UI в `error` или `disconnected`;
- очистить pending state;
- запретить применение результатов старой сессии через generation.

---

### Шаг 8. Написать Playwright-тесты на mock

Тесты должны покрывать:

1. success;2. user cancelled chooser;
3. security error;
4. auth timeout;
5. disconnect during auth;
6. disconnect during getprop;
7. double click;
8. stale result ignored;
9. empty fingerprint;
10. CDN/module load failure, если тестируете factory.

---

### Шаг 9. Переключить default на новую архитектуру

Когда тесты зелёные:

- включить новый модуль по умолчанию;
- оставить старый код временно, если нужно;
- удалить старый код после ручного прогона на реальном телефоне.

---

## 11. Playwright-тесты с mock

### Пример success

```ts
// tests/adb-mock.spec.ts
import { test, expect } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    window.__ADB_MOCK__ = {
      props: {
        'ro.build.fingerprint': 'test/device/fp',
        'ro.product.device': 'device'
      },
      openDelayMs: 10,
      authDelayMs: 10,
      getPropDelayMs: 10
    };
  });

  await page.goto('/?adb-mock');
});

test('успешное подключение заполняет fingerprint', async ({ page }) => {
  await page.click('#connect-phone');

  await expect(page.locator('#adb-status')).toContainText('Готово');
  await expect(page.locator('#fingerprint')).toHaveValue('test/device/fp');
});
```

---

### Отмена chooser

```ts
test('отмена системного USB-окна', async ({ page }) => {
  await page.addInitScript(() => {
    window.__ADB_MOCK__ = {
      fail: {
        open: 'NotFoundError'
      }
    };
  });

  await page.goto('/?adb-mock');
  await page.click('#connect-phone');

  await expect(page.locator('#adb-status')).toContainText('Подключение отменено');
});
```

---

### Auth timeout

```ts
test('таймаут ожидания RSA-подтверждения', async ({ page }) => {
  await page.addInitScript(() => {
    window.__ADB_MOCK__ = {
      auth: 'pending'
    };
  });

  await page.goto('/?adb-mock&auth-timeout=500');
  await page.click('#connect-phone');

  await expect(page.locator('#adb-status')).toContainText('Авторизация');

  await expect(page.locator('#adb-status')).toContainText(
    'Не подтверждена ADB-авторизация',
    { timeout: 3000 }
  );
});
```

---

### Disconnect во время чтения

```ts
test('телефон отключился во время getprop', async ({ page }) => {
  await page.addInitScript(() => {
    window.__ADB_MOCK__ = {
      props: {
        'ro.build.fingerprint': 'test/device/fp'
      },
      fail: {
        getProp: 'DeviceDisconnectedError'
      }
    };
  });

  await page.goto('/?adb-mock');
  await page.click('#connect-phone');

  await expect(page.locator('#adb-status')).toContainText('Телефон отключён');
});
```

Для этого mock нужно расширить:

```js
async getProp(name) {
  if (this.options.fail?.getProp) {
    throw makeError(this.options.fail.getProp);
  }

  return this.options.props?.[name] ?? '';
}
```

---

### Низкоуровневый mock `navigator.usb`

Если нужно проверить только feature detection или error mapping:

```ts
await page.addInitScript(() => {
  Object.defineProperty(navigator, 'usb', {
    configurable: true,
    value: {
      devices: [],

      async requestDevice() {
        throw new DOMException('No device selected', 'NotFoundError');
      },

      addEventListener() {},
      removeEventListener() {}
    }
  });
});
```

Но для полноценного ADB-flow лучше мокать не `navigator.usb`, а `AdbSession`. Причина: реальный ADB-протокол, endpoints, credential store и RSA слишком сложны для честного mock в `navigator.usb`.

---

## 12. Обязательные edge cases

Нужно явно обработать:

### USB chooser

- `NotFoundError` — пользователь отменил выбор.
- Должно быть не красной ошибкой, а нейтральным статусом.

### Browser permissions

- `SecurityError` — USB заблокирован браузером.
- `TypeError` / отсутствие `navigator.usb` — браузер не поддерживает WebUSB.
- `!isSecureContext` — страница не в HTTPS и не localhost.

### Device state

- `InvalidStateError` — устройство уже открыто другой вкладкой.
- Телефон заблокирован.
- USB debugging выключен.
- USB mode не ADB.

### Auth

- RSA dialog не подтверждён.
- Пользователь нажал «Отклонить».
- Dialog не появился.- Auth timeout.

### Disconnect

- Физически вынули кабель.
- Телефон перезагрузился.
- USB-порт уснул.
- Отключение во время `authenticate()`.
- Отключение во время `getProp()`.

### Reconnect

- Повторное подключение сразу после ошибки.
- Повторный клик во время активной сессии.
- Stale result от старого подключения.

### Modules

- `esm.sh` недоступен.
- Долгий import.
- Потеря user gesture из-за долгого import.

---

## 13. Concurrency-требования

Обязательно реализовать:

1. **Mutex**
   - только один active connect.

2. **Generation counter**
   - результаты старого подключения игнорируются.

3. **AbortController**
   - удаление `disconnect` listener'ов.
   - отмена вспомогательных операций.

4. **Session per connect**
   - после `close()` сессия больше не используется.
   - новое подключение создаёт новую сессию.

5. **Close in finally**
   - USB device должен освобождаться даже при ошибке.

6. **No unhandled promise rejections**
   - все timeout/close/disconnect пути должны иметь catch.

7. **Credential write only after success**
   - не сохранять ключ, если auth не завершился.

---

## 14. Риски

### Риск 1: API `@yume-chan/*` отличается между версиями

У вас:

```text
@yume-chan/adb@2.6.2
@yume-chan/adb-daemon-webusb@2.3.2
@yume-chan/adb-credential-web@2.1.0
```

Версии разные. Возможен mismatch.

Рекомендация:
- проверить changelog;
- зафиксировать точные URL;
- при необходимости использовать `?deps=` на esm.sh, чтобы избежать дублирования зависимостей.

---

### Риск 2: esm.sh недоступен или медленный

GitHub Pages + runtime import с CDN = runtime dependency.

Минимальное:
- timeout на preload;
- понятная ошибка пользователю;
- retry кнопка.

Лучшее:
- self-host ESM-файлов, если политика проекта позволяет.

---

### Риск 3: Потеря user gesture

Нельзя делать:

```js
button.onclick = async () => {
  await longCdnImport();
  await navigator.usb.requestDevice();
};
```

Если import долгий, user gesture может истечь.

Нужно:

```js
preload on hover/focus/idle
requestDevice as close to click as possible
```

---

### Риск 4: sessionStorage ADB key

`sessionStorage` переживает XSS.

Если есть XSS, атакующий может получить ADB credential.

Минимально:
- строгий CSP;
- не вставлять пользовательский HTML;
- не логировать ключи.

Лучше:
- использовать более безопасное хранение, если библиотека это позволяет.

---

### Риск 5: Read-only — только контракт приложения

ADB сам по себе не read-only.

Гарантия должна быть в коде:

```js
getProp(name) {
  if (!SAFE_PROP_NAME.test(name)) throw ...;
  return run(`getprop ${name}`);
}
```

Нельзя предоставлять:

```js
session.shell(userInput);
```

---

### Риск 6: Firefox/SafariWebUSB — в основном Chromium.

Нужен fallback:

```js
if (!('usb' in navigator) || !isSecureContext) {
  showUnsupportedBrowser();
}
```

---

## 15. Что НЕ трогать

Не нужно ломать:

1. Pyodide-логику патча LK bootloader.
2. Логику токена.
3. Расчёт fingerprint.
4. Валидацию fingerprint.
5. Диагностические экраны.
6. Существующие DOM ID, если на них завязаны тесты или UI.
7. Поведение «только read-only».
8. Текущий пользовательский сценарий:
   - подключил телефон;
   - подтвердил ADB;
   - приложение только читает `getprop`.

---

## 16. Минимальный целевой вариант

Если нужно сделать компактно, минимальная правильная декомпозиция:

```text
web/js/adb-core.js       # errors, timeout, mutex, controller
web/js/adb-webusb.js     # реальный WebUSB session
web/js/adb-mock.js       # mock session
web/js/adb-factory.js    # выбор session
```

Главное не количество файлов, а выполнение условий:

- UI не знает про `navigator.usb`.
- Транспорт можно заменить на mock.
- Есть state machine.
- Есть mutex.
- Есть timeout на RSA.
- Есть явная обработка disconnect/cancel/security.
- Playwright может пройти весь сценарий без физического телефона.
