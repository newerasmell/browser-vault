# Browser Vault — UI и договор с Rust ядрото

Frontend-ът е готов в `app/src/`: vanilla JS (ES modules), без build стъпка и без външни зависимости. Tauri го зарежда директно (`frontendDist: "src"`). В обикновен браузър работи с mock данни (`api.js`) за преглед и UI работа. Скрийншоти: `docs/screens/`.

## Файлове
| Файл | Роля |
|---|---|
| `index.html` | Единствената страница; CSP само `self` + Tauri IPC |
| `app.js` | Hash router + 4 изгледа: `tray`, `unlock`, `wizard`, `settings` |
| `api.js` | `api(cmd, args)` → `__TAURI__.core.invoke`; `on(event, cb)` → `__TAURI__.event.listen`. Извън Tauri: mock |
| `i18n.js` | Текстове BG/EN; езикът се пази в `localStorage` + `settings.language` |
| `styles.css` | macOS стил, светла/тъмна тема по системата, системният accent цвят |

Преглед в браузър: `cd app/src && python3 -m http.server 8765`, после `http://localhost:8765`. Лентата горе превключва изгледи, тема и език. Демо код за аутентикатора: `123456`.

## Прозорци (tauri.conf.json → създават се от Rust)
| Label | URL | Размер | Бележки |
|---|---|---|---|
| `tray` | `index.html#tray` | 360 × auto (fit content) | Без рамка, прозрачен фон, показва се под иконата в menu bar, скрива се при blur. `withGlobalTauri: true` |
| `unlock` | `index.html#unlock?id=<vaultId>` | 400 × 460 | Центриран, always-on-top, не се преоразмерява. Един прозорец на сейф |
| `wizard` | `index.html#wizard` | 580 × 640 | Единичен. Затварянето = `wizard_cancel` |
| `settings` | `index.html#settings[?tab=vaults]` | 760 × 560 | Единичен |
| `cleanup` | `index.html#cleanup?id=<vaultId>` | 520 × 720 | Изтриване на оригиналния профил (SPEC 5.1). Отваря се само от Настройки → Сейфове |

`open_window` фокусира прозореца, ако вече е отворен. Esc затваря всичко освен tray.

## Команди (`#[tauri::command]`)
Грешките се връщат като `{ code: string, retryAfter?: number }`. Кодове: `unlock_failed`, `rate_limited`, `not_found`, `io`, `browser_missing`. **Никога не се връща кой фактор е сгрешен.**

| Команда | Вход | Изход |
|---|---|---|
| `list_vaults` | — | `[{ id, name: string|null, browser: 'brave'|'firefox'|null, mode: 'fido2'|'totp', status: 'locked'|'unlocked'|'error', sizeGb }]` |
| `detect_browsers` | — | `{ brave: { found, path }, firefox: { found, path } }` |
| `open_window` | `{ view, params? }` | — |
| `close_window` | — | затваря текущия прозорец |
| `focus_browser` | `{ id }` | вдига прозореца на браузъра на отворен сейф |
| `quit_app` | — | заключва всичко, после изход |
| `unlock_vault` | `{ id, password, pin?, code? }` | `{ ok }`. При fido2 емитира `fido_touch_needed` / `fido_touch_done`. При успех: mount + стартира браузъра + `vaults_changed` |
| `unlock_with_recovery` | `{ id, phrase }` | `{ ok }` |
| `lock_vault` | `{ id }` | — (+ `vaults_changed`) |
| `lock_all` | — | — (+ `vaults_changed`) |
| `wizard_begin` | `{ name, browser }` | `{ draftId }`. Черновата живее само в паметта на Rust |
| `wizard_set_password` | `{ draftId, password }` | `{ ok }`. Rust пази паролата в `Zeroizing`; UI-ят веднага изчиства полетата |
| `fido_register` | `{ draftId, pin, label }` | `{ label }` (+ touch събития) |
| `totp_begin` | `{ draftId }` | `{ secret, qrSvg }`. SVG от crate `qrcode`, URI по SPEC 4.1 |
| `totp_confirm` | `{ draftId, code }` | `{ ok }` |
| `recovery_generate` | `{ draftId }` | `{ words: string[24] }` |
| `recovery_verify` | `{ draftId, answers: { [index1based]: word } }` | `{ ok }` |
| `wizard_finish` | `{ draftId, name, browser, mode, sizeGb, options: { idleMinutes, lockOnScreenLock, lockOnKeyRemoval, disableFxa, importProfile, importProfileId } }` | `{ vaultId }`. Емитира `create_progress` |
| `wizard_cancel` | `{ draftId }` | изтрива черновата и нулира секретите |
| `get_settings` / `save_settings` | частичен обект | `{ language, launchAtLogin, idleMinutes, lockOnScreenLock, lockOnKeyRemoval, panicHotkey }` |
| `list_factors` | `{ id }` | `[{ type: 'fido2'|'totp'|'recovery', label }]`. Без секрети, само етикети |
| `request_vault_action` | `{ id, action: 'change_password'|'add_fido2'|'replace_totp'|'new_recovery'|'delete' }` | Rust първо изисква отключване (unlock прозорец), после води потока. `delete` иска и системно потвърждение |
| `detect_profiles` | `{ browser }` | `[{ id, name, sizeMb }]` от `Local State` / `profiles.ini` |
| `browser_running` | `{ browser }` | `{ running }`, само обикновената инстанция, не тази на сейфа |
| `cleanup_preview` | `{ id }` | `{ items: string[], sizeMb, reviewed, fileVault, profileName, browser }`. Точните пътища, които ще се изтрият |
| `cleanup_original` | `{ id, password }` | `{ ok }`. Rust **проверява отново** `reviewed`, затворен браузър и паролата (не вярва на UI-я). Грешки: `not_reviewed`, `browser_running`, `unlock_failed`. Емитира `cleanup_progress` |
| `keep_original` | `{ id }` | `original.state = "kept"`, бележката изчезва |
| `pick_browser_path` | `{ browser }` | път или `null` (native file dialog, филтър `.app`) |
| `app_info` | — | `{ version }` |

## Събития (Rust → UI)
| Събитие | Payload | Кой слуша |
|---|---|---|
| `vaults_changed` | — | tray (пререндира) |
| `fido_touch_needed` / `fido_touch_done` | `{ id? }` | unlock, wizard (overlay „Докосни YubiKey“) |
| `create_progress` | `{ stage: 'disk'|'keys'|'profile'|'import'|'done', pct }` | wizard |
| `cleanup_progress` | `{ pct }` | cleanup |

`list_vaults` връща и `original: null | { profileName, sizeMb, reviewed, state: 'pending'|'kept'|'deleted' }`. При `pending` менюто показва бележка „Оригиналният профил още е на диска“. `name`/`browser` са `null` за сейф с криптирани метаданни (header v2), за който този Mac няма запис в локалния индекс: UI-ят показва „Заключен сейф“ с неутрална иконка до първото отключване. `add_vault_from_drive` също връща `name: null`.

## Menu bar иконка
Template image (монохромна, macOS сам я оцветява): щит, затворен при всички заключени; щит с точка при отворен сейф; удивителна при грешка. Клик показва `tray`. Десен клик: „Заключи всички“, „Изход“.

## Правила за UI кода
- Секретите (парола, PIN, код, recovery думи) не се пазят в state по-дълго от една заявка и никога в `localStorage`.
- Recovery думите не могат да се селектират/копират (`user-select: none`), за да не отиват в clipboard.
- Без външни скриптове, шрифтове и CDN. CSP остава строг.
- Нови текстове само през `i18n.js`, и на двата езика.
