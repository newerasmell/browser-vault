# Browser Vault — техническа спецификация (MVP v0.1, macOS)

## 1. Цел

Desktop приложение за macOS, което държи профилите на Brave и Firefox в криптиран контейнер на диска. Профилът е достъпен само след отключване с **парола + втори фактор**:

- **YubiKey** (FIDO2, hmac-secret), основен и най-силен вариант, или
- **Аутентикатор приложение** (TOTP: Google Authenticator, Microsoft Authenticator, Authy, 1Password и др.), за потребители без YubiKey.

Когато сейфът е заключен, на диска няма четими история, cookies, сесии, пароли или кеш.

**Извън обхвата на v0.1:** Windows/Linux, Chrome, облачен sync на сейфове, акаунти/лицензиране, Mac App Store.

## 2. Платформа и стек

- macOS 13 Ventura+, Apple Silicon и Intel (universal binary).
- **Rust** за ядрото (crypto, vault, процеси) като отделен crate `vault-core` с CLI `bvault`, за да се тества без UI. Ядрото после се ползва и за Windows.
- **Tauri 2** за UI: menu bar приложение + прозорец за настройки и setup wizard.
- Crates (може да се заменят само с одобрение):
  - `argon2` (Argon2id), `chacha20poly1305` (XChaCha20-Poly1305), `hkdf` + `sha2`, `rand` (OsRng), `zeroize`
  - `security-framework` (Keychain, Secure Enclave през SecKey)
  - `ctap-hid-fido2` (YubiKey FIDO2 hmac-secret)
  - `totp-rs` (RFC 6238), `qrcode` (QR при setup)
  - `bip39` (recovery фраза)
  - `aes` + `cbc` + `pbkdf2` + `sha1` — одобрени от собственика на 2026-11-04 **само** за преобразуване на криптираните стойности на Brave (cookies, пароли; Chromium „v10“) от ключа на Mac-а към преносимия ключ (`chromium.rs`, `portable.rs`). Не се ползват за собствената криптография на сейфа.
- Дистрибуция: Developer ID подпис + notarization, hardened runtime, DMG. Без sandbox (нужни са `hdiutil` и контрол на процеси).

## 3. Криптиран контейнер (без външни драйвери)

Ползваме **нативния macOS криптиран disk image** (`hdiutil`, APFS, AES-256, sparsebundle). Не се изисква macFUSE или kernel extension, което е ключово за UX на Apple Silicon.

```
hdiutil create -size <N>g -type SPARSEBUNDLE -fs APFS \
  -encryption AES-256 -stdinpass -volname BV-<id> <path>.sparsebundle

hdiutil attach -stdinpass -nobrowse -noautoopen -owners on \
  -mountpoint <mountdir> <path>.sparsebundle

hdiutil detach <mountdir>   # при неуспех: -force
```

- Паролата към `hdiutil` е **Disk Key**: 64 hex символа от VMK (виж т. 4). Подава се само през stdin, никога като аргумент, env променлива или Keychain на hdiutil.
- Mountpoint: `~/Library/Application Support/BrowserVault/mnt/<vault-id>` с права 700.
- След mount: `mdutil -i off <mountdir>` (без Spotlight индекс).
- Default размер 20 GB (sparse, расте реално при ползване). Може да се променя в setup.
- Файлове на сейф: `~/Library/Application Support/BrowserVault/vaults/<vault-id>/` → `image.sparsebundle` + `header.json`.

## 4. Ключова йерархия (keyslots, по модела на LUKS)

- **VMK** (Vault Master Key): 32 случайни байта, генерирани при създаване. От него се извежда Disk Key = HKDF(VMK, "bv-disk-v1").
- VMK се пази **само обвит (wrapped)** в keyslots в `header.json`. Всеки slot е VMK, криптиран с XChaCha20-Poly1305 под KEK, специфичен за slot-а.
- `PW = Argon2id(password, salt_pw, m=256 MiB, t=3, p=1)`. Параметрите се пазят в header-а, за да могат да се вдигат.

| Slot | KEK | Какво е нужно за отключване |
|---|---|---|
| `fido2` (1..n ключа) | HKDF(PW ‖ hmac-secret(YubiKey, salt_fido)) | парола + физически YubiKey + PIN/touch |
| `totp` | HKDF(PW ‖ SE_secret) | парола + този Mac + валиден TOTP код |
| `recovery` | HKDF(Argon2id(24-word BIP39 фраза)) | само recovery фразата |

Правила:
- Може да има няколко YubiKey slot-а (основен + резервен ключ). UI-ят препоръчва поне 2.
- Recovery фразата се показва **веднъж** при setup, с потвърждение (потребителят въвежда 3 случайни думи от нея).
- Смяна на парола или добавяне/махане на фактор преобвива VMK. Контейнерът не се прекриптира.
- Всички ключове в паметта са в `Zeroizing<>`. Без логване на секрети, кодове и пароли, включително в debug.

### 4.1 TOTP режим: как реално работи и какво гарантира

TOTP не може да участва в извеждането на ключа, защото кодът се сменя. Затова:

1. При setup се генерира 160-bit TOTP seed и се показва като QR (`otpauth://totp/BrowserVault:<vault-name>?secret=...&issuer=BrowserVault`), SHA1, 6 цифри, 30 s.
2. Генерира се ключ в **Secure Enclave** (P-256, non-exportable, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`). С него се обвиват `SE_secret` (32 байта) и TOTP seed-ът. Обвитите blob-ове са в header-а.
3. При отключване: парола → Argon2id → app-ът разопакова TOTP seed чрез SE → проверява кода (прозорец ±1 стъпка, отказ на вече използван код, т.е. anti-replay с последен counter) → чак тогава разопакова `SE_secret` → KEK → VMK.
4. Rate limit: след 5 грешни опита изчакване 30 s, после експоненциално нарастване. Броячът се пази в header-а с MAC.

**Какво гарантира (UI-ят го казва ясно при избор на режима):** криптографски сейфът е защитен с парола + хардуерен ключ, заключен в този Mac (Secure Enclave). Копие на диска или Time Machine backup без самия Mac е безполезно. TOTP проверката се налага от приложението. YubiKey режимът е по-силен, защото вторият фактор е и криптографски, и физически отделен от компютъра.

### 4.2 YubiKey режим

- FIDO2 non-resident credential, създаден при setup с `hmac-secret` extension. `credential_id` и `salt_fido` се пазят в header-а.
- Изисква PIN на ключа (ако не е зададен, wizard-ът води потребителя да го зададе) и докосване.
- Поддържани ключове: YubiKey 5 серия, Security Key серия (FIDO2). При неподдържан ключ се показва ясна грешка.

## 5. Стартиране на браузъри

Сейфът е обвързан с един браузър: `brave` или `firefox`. Потребителят може да има няколко сейфа (напр. по един за всяка фирма).

**Brave**
```
"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" \
  --user-data-dir=<mnt>/profile --disk-cache-dir=<mnt>/cache \
  --no-first-run --no-default-browser-check
```
- Стартира се директно binary-то (не `open -a`), за да има PID и отделна инстанция, дори ако обикновен Brave е отворен.

**Firefox**
```
/Applications/Firefox.app/Contents/MacOS/firefox \
  --new-instance -profile <mnt>/profile
```
- При създаване на сейфа се пише `user.js` в профила:
  - `browser.cache.disk.parent_directory` → `<mnt>/cache`
  - `browser.shell.checkDefaultBrowser` = false
  - `browser.sessionstore.resume_from_crash` = true
  - по избор (checkbox в setup): `identity.fxaccounts.enabled` = false

**Общо**
- Път до браузъра: автоматично откриване в `/Applications` и `~/Applications`, с ръчна смяна в настройките.
- Ако браузърът не е инсталиран, се показва ясна грешка с линк за сваляне.
- **Предупреждение за sync:** при първо отключване UI-ят обяснява, че Brave Sync / Firefox Sync изпращат данни извън сейфа.

## 5.1 Импорт на съществуващ профил и изтриване на оригинала

Принцип: **програмата никога не трие оригинала сама.** Потокът е копиране, после преглед от потребителя, после изрично разрешение, после пълно изтриване.

**1. Избор (wizard, стъпка Опции).** Ако импортът е включен, се показва списък с откритите профили на избрания браузър (име, размер):
- Brave: профилите от `~/Library/Application Support/BraveSoftware/Brave-Browser/Local State` (`profile.info_cache`): `Default`, `Profile 1` и т.н.
- Firefox: профилите от `~/Library/Application Support/Firefox/profiles.ini`.

**2. Копиране.** Ако обикновеният браузър работи, програмата моли потребителя да го затвори и изчаква. После копира само избрания профил в сейфа. Оригиналът не се променя. Копието се проверява (брой файлове + размер + SHA-256 на ключовите файлове: `Cookies`, `Login Data`, `Bookmarks`, `Preferences` за Brave; `cookies.sqlite`, `logins.json`, `key4.db`, `places.sqlite` за Firefox). При разминаване импортът се отказва, а сейфът остава празен и работещ.
- Brave cookies/пароли са криптирани с Keychain ключа „Brave Safe Storage“, който е общ за приложението, затова копието работи в сейфа без конвертиране.

**3. Преглед.** В header-а на сейфа се записва `original: { browser, profile_id, profile_name, paths[], size_bytes, imported_at, reviewed: false, state: "pending" }`. `reviewed` става `true` при първото успешно отключване и затваряне на сейфа след импорта, т.е. потребителят реално е видял профила. Докато `state = pending`, в менюто и в Настройки → Сейфове има бележка „Оригиналният профил още е на диска“ с бутон за преглед.

**4. Разрешение.** Изтриването е достъпно само ако:
- `reviewed = true` (иначе бутонът е неактивен и обяснява защо),
- обикновеният браузър е затворен (проверка на живо),
- потребителят е видял точния списък с пътища и размер, които ще се изтрият,
- потребителят е отметнал „Разбирам, че това е окончателно“ и е потвърдил с паролата на сейфа.

**5. Изтриване (окончателно, не в Кошчето).**
- Brave: само папката на избрания профил + нейният кеш в `~/Library/Caches/BraveSoftware/Brave-Browser/<profile>`. Записът се маха от `Local State` (`profile.info_cache`, `profile.last_used`, `profile.last_active_profiles`). Преди промяна се прави backup на `Local State`. Други профили на Brave не се пипат. Ако е бил единствен, Brave създава нов празен профил при следващо пускане.
- Firefox: папката на профила + `~/Library/Caches/Firefox/Profiles/<name>`. Секцията се маха от `profiles.ini` и `installs.ini`, с backup преди промяна. Ако профилът е бил default, default се прехвърля към друг съществуващ профил, ако има такъв.
- `~/Library/Saved Application State/` на съответния браузър.
- Резултатът се записва: `state: "deleted"`, `deleted_at`. Бележката изчезва.

Алтернатива: бутон „Запази оригинала“ (`state: "kept"`). Бележката изчезва, а действието може да се върне от Настройки.

**Честно предупреждение в екрана за изтриване:** на SSD изтритите файлове не могат да се гарантират като физически презаписани. Ако FileVault е изключен (`fdesetup status`), екранът показва препоръка да се включи, защото това прави и остатъците нечетими.

## 6. Заключване (lock)

Тригери:
1. Браузърът е затворен (наблюдение на PID).
2. Неактивност N минути (default 15, настройва се, 0 = изключено) през `CGEventSourceSecondsSinceLastEventType`.
3. Заключване на екрана / sleep (`com.apple.screenIsLocked`, `NSWorkspaceWillSleepNotification`). Настройва се, default включено.
4. Изваждане на YubiKey (IOKit HID removal), само за сейфове в YubiKey режим. Настройва се, default включено.
5. Ръчно: меню „Lock now“ и глобален panic hotkey (default ⌃⌥⌘L).

Процедура:
1. Грациозно спиране на браузъра (SIGTERM), изчакване до 8 s, след това SIGKILL.
2. `hdiutil detach`, при неуспех `-force`, до 3 опита. Ако все пак е неуспешно: червена иконка и известие.
3. Нулиране на всички ключове в паметта.
4. Почистване на следи: `~/Library/Saved Application State/com.brave.Browser.savedState` и `org.mozilla.firefox.savedState`, само ако обикновеният браузър не върви в момента.
5. Известие „Vault locked“.

При краш на приложението или рестарт: при следващо стартиране се проверява за останали mount-ове на BV-* томове и те се демонтират.

## 7. UI (Tauri)

**Menu bar иконка:** сива = всички заключени, зелена = отключен поне един, червена = грешка.
Меню: списък сейфове (име, браузър, статус) → Unlock & Open / Lock, „Lock all“, „New vault…“, Settings, Quit.

**Unlock прозорец:** име на сейфа → поле за парола → според режима „Докоснете YubiKey“ (с поле за PIN) или поле за 6-цифрен код → линк „Използвай recovery фраза“.

**Setup wizard (нов сейф):**
1. Име + браузър (Brave / Firefox)
2. Парола (минимум 12 символа, индикатор за сила, потвърждение)
3. Втори фактор: YubiKey (препоръчано) или Аутентикатор
   - YubiKey: регистрация на ключ, предложение за резервен ключ
   - TOTP: QR код + ръчен ключ за въвеждане + потвърждение с един код
4. Recovery фраза (показване + проверка на 3 думи)
5. Размер на сейфа + опции (sync предупреждение, Firefox: изключване на акаунта)
6. Създаване → по желание импорт на съществуващ профил (копиране по т. 5.1; оригиналът се изтрива само след преглед и изрично разрешение)

**Settings:** таймер за неактивност, тригери за заключване, hotkey, пътища до браузърите, управление на фактори (добавяне/махане на YubiKey, смяна на TOTP, смяна на парола, нова recovery фраза), стартиране при login.

Език на интерфейса: английски + български (i18n файлове от началото).

## 8. Header формат (`header.json`)

```json
{
  "version": 1,
  "vault_id": "uuid",
  "name": "Trade Peak – Brave",
  "browser": "brave",
  "created_at": "ISO8601",
  "kdf": { "alg": "argon2id", "m_kib": 262144, "t": 3, "p": 1, "salt": "b64" },
  "slots": [
    { "type": "fido2", "label": "YubiKey main", "credential_id": "b64", "salt": "b64", "nonce": "b64", "wrapped_vmk": "b64" },
    { "type": "totp", "se_key_tag": "com.browservault.<vault_id>", "wrapped_se_secret": "b64", "wrapped_seed": "b64", "last_counter": 0, "nonce": "b64", "wrapped_vmk": "b64" },
    { "type": "recovery", "salt": "b64", "nonce": "b64", "wrapped_vmk": "b64" }
  ],
  "settings": { "idle_minutes": 15, "lock_on_screen_lock": true, "lock_on_key_removal": true },
  "original": { "browser": "brave", "profile_id": "Profile 1", "profile_name": "Work", "paths": ["..."], "size_bytes": 0, "imported_at": "ISO8601", "reviewed": false, "state": "pending" },
  "mac": "b64"
}
```
- `mac` = HMAC върху целия header с ключ, изведен от VMK. Проверява се след отключване: ако header-ът е подправен, се показва предупреждение.
- Записът е атомарен: temp файл → fsync → rename. Пази се и `header.json.bak`.

## 9. Етапи (milestones)

| # | Етап | Приемане |
|---|---|---|
| M1 | `vault-core` + CLI: create / unlock (само парола, временно) / mount / launch Brave / lock | E2E тест: създаване → отключване → Brave пише в `<mnt>` → заключване → томът не е монтиран, в `~/Library` няма нови данни от профила |
| M2 | Keyslots + recovery фраза + Argon2id | Unit тестове за wrap/unwrap, грешна парола, подправен header |
| M3 | TOTP режим + Secure Enclave | Код от Google Authenticator отключва; повторен код се отказва; rate limit работи |
| M4 | YubiKey режим (FIDO2 hmac-secret), 2 ключа | Отключване с всеки от двата ключа; без ключ е невъзможно; изваждане на ключа заключва |
| M5 | Firefox | Същите E2E проверки като за Brave; кешът е вътре в `<mnt>` |
| M6 | Tauri UI: menu bar, wizard, settings, BG/EN | Ръчен тест по чеклиста в т. 10 |
| M7 | Lock тригери, recovery след краш, почистване на следи | Тест: kill -9 на приложението → рестарт → томът се демонтира |
| M7b | Импорт + изтриване на оригинала (т. 5.1) | Импорт на Brave `Profile 1` при наличен `Default`: след изтриване `Default` е непокътнат и Brave стартира нормално. Firefox: `profiles.ini` е валиден, Firefox стартира. Без `reviewed` изтриването е невъзможно, включително през CLI |
| M8 | Подпис, notarization, DMG, auto-update (Tauri updater) | Инсталира се на чист Mac без предупреждения на Gatekeeper |

## 10. Ръчен тестов чеклист (преди release)

- [ ] Нов сейф Brave + YubiKey; нов сейф Firefox + TOTP
- [ ] Обикновен Brave/Firefox е отворен паралелно, сейф-инстанцията се отваря отделно и не смесва данни
- [ ] Login в сайт → затваряне → отключване → сесията е запазена
- [ ] Заключване при: затваряне, неактивност, заключен екран, изваден ключ, hotkey
- [ ] Със заключен сейф: `find ~/Library -newer <marker>` не показва файлове с данни от сесията
- [ ] Грешна парола / код / ключ дава ясни съобщения без изтичане на информация кой фактор е сгрешен
- [ ] Recovery фраза отключва при „загубени“ YubiKey и телефон
- [ ] Импорт на съществуващ профил: оригиналът е непокътнат след импорта; изтриването е заключено до преглед; след изтриване останалите профили на браузъра работят
- [ ] Apple Silicon + Intel, macOS 13 и последна версия

## 11. Известни ограничения (за README и onboarding)

- Докато сейфът е отворен, данните са декриптирани. Malware на машината може да ги прочете.
- Brave Sync / Firefox Sync изнасят данни извън сейфа.
- TOTP режимът е обвързан с конкретния Mac. За ползване на друг Mac трябва YubiKey или recovery фраза.
- Остават следи на ниво ОС, които не може да се контролират изцяло (DNS кеш, системни логове). Swap на macOS е криптиран по подразбиране.
