# Бележки по реализацията

## Статус

| Етап | Състояние |
|---|---|
| M1 | `vault-core` + `bvault` CLI: create / unlock (парола) / mount / launch Brave / lock. Unit тестовете минават на Linux; E2E (`tests/e2e_macos.rs`) чака ръчно пускане на Mac |
| M2 | Keyslots, recovery фраза (BIP39, 24 думи), Argon2id, MAC на header-а, атомарен запис + `.bak`. Unit тестове: wrap/unwrap, грешна парола, подправен header |
| M5 | Firefox: `-profile <mnt>/profile`, `user.js` (кеш в `<mnt>/cache`). E2E `m5_firefox_acceptance` |
| M7b | Откриване, импорт с проверка, преглед, изтриване на оригинала (`profiles.rs`). Unit тестове с фалшив home; E2E `tests/e2e_import_macos.rs` |

E2E на Mac:
```
cargo test -p vault-core --test e2e_macos -- --ignored --nocapture --test-threads=1
```

## Решения извън буквата на SPEC (за потвърждение)

1. **Временен slot `password`** (KEK = HKDF(PW)). SPEC т. 9 M1 казва „само парола, временно“, но в т. 4 няма такъв slot. Добавен е като `type: "password"`, за да може M1/M2 да се тестват. **Трябва да се махне** при M3/M4, преди release.
2. **HMAC за `mac`** е от `hkdf::hmac` (re-export от вече одобрения `hkdf`), т.е. без нов crate. Ключ: `HKDF(VMK, "bv-header-mac-v1")`. Покрива целия header с празно поле `mac`.
3. **Domain separation:** KEK info = `bv-kek-v1/<type>`. AAD на всеки обвит VMK = `bv-slot-v1|<vault_id>|<type>`, така че slot не може да се пренесе в друг сейф или да се тълкува като друг тип.
4. **Recovery KEK** = HKDF(Argon2id(нормализирана фраза, salt на slot-а)) със същите m/t/p като `kdf`.
5. **Таван на Argon2 параметрите** от header-а (m ≤ 4 GiB, t ≤ 64, p ≤ 16), за да не може подправен header да направи DoS.
6. **Header-ът отхвърля непознати полета** (`deny_unknown_fields`) и версии ≠ 1.
7. **`BVAULT_HOME`** (само път, не секрет) сменя базовата папка; ползва се от тестовете.
8. ~~Firefox сейф се отказва с `Unsupported` до M5.~~ Махнато в M5.
9. `bvault create` пита за 3 случайни думи от фразата само в интерактивен режим (TTY).

## M4: YubiKey (FIDO2 hmac-secret) — решения

1. **Crate:** `ctap-hid-fido2` 3.6 (по подразбиране с `ring`). Тегли `hidapi`, който на Linux линква `libudev` → в CI (`linux` job) се инсталира `libudev-dev`. Бекендът не е ограничен до macOS; unit тестовете ползват само mock-а.
2. **RP id = `browservault.local`** (`fido2::RP_ID`). Никога не се резолвира; трябва само да е стабилен, защото credential-ът работи само под RP id-то, с което е създаден. `.local` е извън реални домейни. Смяна на RP id = всички ключове трябва да се регистрират наново.
3. **Credential:** non-resident (не заема място на ключа), с `hmac-secret`, ES256. В slot-а: `credential_id` + случаен 32-байтов `salt` (OsRng). KEK = `factor_kek(PW, hmac-secret(cred, salt), "fido2")`.
4. **PIN винаги** (user verification) + докосване, както при setup, така и при unlock, затова hmac-secret изходът е винаги „с UV“ (CTAP2.1 дава различен изход с/без UV). PIN се валидира локално (4–63 знака); невалиден PIN при unlock не стига до ключа (не изгаря опит).
5. **Регистрацията иска 2 докосвания:** makeCredential не връща hmac-secret изхода, затова следва getAssertion със salt-а. Събитията са `FidoTouchNeeded`/`FidoTouchDone` около всяко докосване (`Done` идва и при грешка, за да се затвори overlay-ят).
6. **Няколко ключа (основен + резервен), всеки slot със свой salt:** при unlock първо има *тиха* проба (getAssertion с `up=false`, без PIN, allow list = всички `credential_id` на сейфа) към всеки включен ключ, за да се разбере кой slot е негов; после само той се пита за hmac-secret (PIN + докосване). Ако няма включен регистриран ключ, не се иска докосване. Същата проба не позволява един и същ ключ да се регистрира два пъти (плюс exclude list в makeCredential).
7. **Грешки:** при unlock всичко (парола, PIN, блокиран PIN, липсващ/чужд ключ, без докосване) е `UnlockFailed`. Паролата не може да се провери преди докосването. При регистрация грешките са ясни, с константи в `fido2` (`ERR_PIN_NOT_SET` → wizard-ът води към задаване на PIN; `ERR_UNSUPPORTED_KEY` е `Error::Unsupported` за ключ без FIDO2/hmac-secret/clientPin; също грешен PIN, няколко включени ключа, вече регистриран ключ, без докосване). Нов вариант в `Error` не е добавян (`error.rs` е извън обхвата); UI-ят сравнява текста с константите.
8. **`add_key` / `remove_key`** работят върху отключен сейф (`UnlockedKey`), проверяват MAC-а на header-а с VMK-а (отказват чужд ключ или външно променен header) и го запечатват наново. `add_key` иска паролата, но не може да я провери сам (никой slot не проверява паролата без фактор): потокът `add_fido2` трябва да подаде *същата* парола, с която току-що е отключил. `remove_key` не маха последния втори фактор.
9. **SPEC §6 тригер 4 (изваждане на YubiKey):** вместо IOKit HID removal известия, app-ът вика `fido2::key_present(header, auth)` на ~2 s, докато fido2 сейф е отключен (enumeration + тиха проба, без докосване). Заключва при `false`. Просто е и не изисква IOKit код; IOKit може да се добави в M7, ако polling-ът се окаже тежък.
10. **Mock:** `fido2::MockAuthenticator` (`cfg(test)` или feature `test-mocks`) симулира няколко ключа, plug/unplug, PIN с брояч на опитите, отказ на докосване и hmac-secret като HMAC-SHA256 над таен ключ на устройството. Само за тестове.
11. **Hardware E2E:** `crates/vault-core/tests/e2e_fido2.rs` (`#[ignore]`, само macOS, 2 ключа с PIN):
    ```
    BV_FIDO_PIN_A=… BV_FIDO_PIN_B=… cargo test -p vault-core --test e2e_fido2 -- --ignored --nocapture --test-threads=1
    ```
12. `hidapi` прави `panic` ако HID не е достъпен; бекендът го хваща (`catch_unwind`) и връща грешка. Копията на hmac-secret изхода вътре в `ctap-hid-fido2` не се zeroize-ват (извън нашия контрол); нашите са в `Zeroizing`.

## M3: TOTP + Secure Enclave

Статус: `totp.rs` и `se.rs` са реализирани; unit тестовете (с `MockSecureEnclave` и инжектиран `now`) минават. Реалният SE работи и на GitHub runner-а `macos-14` (Apple Silicon VM, неподписан binary): ключ, `toid` blob 314 байта, ECIES round trip, повторно отваряне от blob-а и пълен TOTP сейф минават. CI го пуска; ръчно на Mac:
```
cargo test -p vault-core --test e2e_se -- --ignored --nocapture --test-threads=1
```

1. **SE ключ без keychain.** Приложението не е подписано, а постоянен SE ключ в keychain-а иска entitlement (иначе `errSecMissingEntitlement`, -34018). Затова ключът се създава с `kSecAttrIsPermanent = false` (P-256, `kSecAttrTokenIDSecureEnclave`, `WhenUnlockedThisDeviceOnly` + `PrivateKeyUsage`). От атрибутите му се взима `kSecAttrTokenOID` (`"toid"`, това, което CryptoKit нарича `dataRepresentation`): частният ключ, криптиран от SE с хардуерния ключ на този Mac. Пази се в header-а като `se_key_blob`; ключът се отваря отново със `SecKeyCreateWithData` + `kSecAttrTokenID`/`kSecAttrTokenOID`. На друг Mac blob-ът е безполезен. `delete_key` е no-op (няма какво да се трие извън header-а). Fallback през keychain по таг не е реализиран: неподписан няма как да работи.
2. **ECIES:** `kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM`. Понеже няма AAD, всеки plaintext започва с контекст `bv-totp-v1|<vault_id>|seed|` или `…|se_secret|`, който се проверява при разопаковане (blob не може да се пренесе в друг сейф или да смени ролята си).
3. **Проверка при setup:** `begin` веднага разопакова през SE каквото е обвил и сравнява. Ако SE не работи (VM, Intel без T2, проблем с `toid`), setup-ът се проваля преди потребителят да сканира QR, вместо да се създаде сейф, който не може да се отвори.
4. **Нови полета в `totp` slot-а:** `se_key_blob` (опционално), `failures`, `locked_until` (unix s), `state_mac`. Новите полета имат `serde(default)`.
5. **MAC на броячите:** `last_counter`, `failures`, `locked_until` се променят и при неуспешен опит, когато VMK не е известен. Затова са **изключени** от MAC-а на header-а (`Header::mac_input` ги нулира) и имат собствен `state_mac` = HMAC(HKDF(seed, `bv-totp-state-v1`), `vault_id|last_counter|failures|locked_until`). Seed-ът се разопакова от SE без код, затова този MAC може да се провери и обнови при всеки опит. Резултат: неуспешни опити не правят `header_intact` false.
6. **Невалиден `state_mac` = fail closed:** опитът не се оценява, slot-ът минава в максимално заключване (`MAX_DELAY_SECS` = 1 ч, `last_counter` ≥ текущата стъпка + 1) с нов валиден MAC, връща се `RateLimited`. След изчакване правилните парола + код работят, т.е. подправянето не може да нулира брояча, а повредата не заключва завинаги. `locked_until` по-далеч от 1 ч напред (подправяне или върнат часовник) се ограничава до 1 ч.
7. **Rate limit:** 5 грешни опита без пауза, после 30 s, 60 s, 120 s … до таван 1 ч. Брояч се нулира само при успех. Всеки неуспех след разопаковане на seed-а се брои (грешен код, грешна парола с верен код, повреден slot). Опит на друг Mac (SE не може да разопакова seed-а) не променя нищо.
8. **Anti-replay:** приема се код от стъпки t-1, t, t+1 само ако counter > `last_counter`. Кодът се „изгаря“ и когато паролата се окаже грешна. Кодът от setup-а също се записва като `last_counter`.
9. **Ред на отключване** е точно по SPEC: Argon2id → SE разопакова seed → код → чак тогава SE разопакова `SE_secret` → KEK → VMK (тест с брояч на `decrypt` извикванията).
10. **MAC на header-а при успех** се преподписва само ако е бил валиден, за да не „узакони“ подправен header (UI-ят трябва пак да предупреди).
11. **`totp::change_password(header, key, new_pw, se)`**: нов salt, `SE_secret` през SE, преобвиване на VMK. Отказва се, ако сейфът има и други slot-ове, зависещи от паролата (`fido2`, `password`).
12. **Граници (за README):** TOTP проверката и rate limit-ът се налагат от приложението. Който има този Mac + паролата, може да заобиколи кода, като извика SE директно; може и да върне по-стар `header.json` (rollback на броячите). Това е по SPEC 4.1 („TOTP проверката се налага от приложението“). Rate limit-ът зависи от системния часовник.
13. `totp-rs` 6 (`otpauth`, `zeroize`, без `gen_secret`: seed-ът идва от `OsRng`). URI-то и base32 ключът минават през временни `String`-ове в `totp-rs`, които не се zeroize-ват.
14. **Feature `test-mocks`** прави `se::MockSecureEnclave` достъпен извън crate-а (за CLI/интеграционни тестове). Не се включва в app build-а.

## M5 (Firefox) и M7b (импорт + изтриване на оригинала)

- **Firefox стартиране:** `firefox --new-instance -profile <mnt>/profile`, с env `MOZ_CRASHREPORTER_DISABLE=1` (без crash dump-ове в `~/Library/Application Support/Firefox/Crash Reports`; env-ът е само флаг, не секрет).
- **`user.js`** се пише при създаване (create монтира новия образ веднъж) **и се презаписва при всяко отключване**. Mountpoint-ът е стабилен, но така пътят на кеша остава верен и при преместен store, и се поправя ръчно редактиран `user.js`. Управлява се само блок между `// BEGIN Browser Vault` и `// END Browser Vault`; останалото (напр. от импортиран профил) се запазва. Изборът `identity.fxaccounts.enabled=false` живее само в този блок (без ново поле в header-а); при unlock се пази текущият избор.
- **Brave crash reporter:** добавени `--disable-crash-reporter --disable-breakpad` (crash dump съдържа памет на браузъра). На macos-14 CI Brave 1.94 все пак пипа `Crashpad/settings.dat` (метаданни на клиента, без данни от сърфиране) и E2E тестът позволява само този файл; dump-ове в `Crashpad/pending|completed` пак чупят теста.
- **`Store::create_with(draft, size, settings, &CreateOptions { disable_fxa, import }, notify) -> Created { header, import_error }`**; `Store::create` е непроменен (вика `create_with` с default). При неуспешен импорт сейфът е създаден, празен и работещ, а грешката е в `import_error`.
- **Импорт:** Brave `Profile N` → `<mnt>/profile/Default` (vault инстанцията ползва `<mnt>/profile` като user-data-dir); Firefox профил → `<mnt>/profile`. Копират се само обикновени файлове и папки; symlink-ове и сокети (lock файлове) се пропускат. Проверка: пълен списък относителни пътища + размер на всеки файл (покрива брой и общ размер) + SHA-256 на ключовите файлове (за Brave и `Network/Cookies`, защото Chromium ≥ 96 държи cookies там). При разминаване копието се трие и сейфът остава празен.
- **`reviewed`:** `Store::close(session)` = `lock` + `profiles::mark_reviewed`. Първото затваряне на отключена сесия след импорта поставя `reviewed=true` (затварянето при самия create не се брои). Апът трябва да заключва през `close`, не през `lock(id)`, за да се отбележи прегледът.
- **Проверка на паролата при изтриване:** паролата сама не отваря VMK (нужен е и втори фактор), а hash на паролата на диска би бил offline oracle. Затова `cleanup_original` изисква **отключена сесия**: при unlock на сейф с оригинал (state ≠ deleted) и credential с парола, в паметта се пази `PasswordVerifier` = HMAC(HKDF(VMK, "bv-cleanup-pw-v1"), Argon2id(password)) в `Zeroizing`; на диска не се пише нищо. Цена: един допълнителен Argon2id при unlock, само докато има оригинал. Сесия от recovery фраза няма verifier → `unlock_failed`.
- **`cleanup_original`** проверява наново, в този ред: MAC на прочетения от диска header под VMK на сесията (подправен header не може да насочи изтриването или да вдигне `reviewed`), `reviewed` (`not_reviewed`), обикновеният браузър (`browser_running`), паролата (`unlock_failed`). Пътищата за триене се изчисляват наново от `profile_id` + конфигурацията на браузъра (не от `original.paths`), с валидация срещу `..` и пътища над home. Ред: backup + редакция на `Local State` / `profiles.ini` + `installs.ini` → папка на профила → кеш → Saved Application State → `state: deleted`, `deleted_at`. Backup: `<файл>.bvault-<unix>.bak` до оригинала.
- **Firefox `profiles.ini`:** секциите `[ProfileN]` се преномерират (Firefox спира на първия липсващ номер). Ако изтритият е бил default: `Default=1` и `Default=` в `[Install…]` / `installs.ini` минават към първия останал профил; ако няма останал, install секцията се маха.
- **Обикновен браузър работи ли:** `ps -axo command=`; търси се главният binary (`…/Contents/MacOS/Brave Browser`, не `… Helper`; `…/Contents/MacOS/firefox`), чиито аргументи не сочат `…/mnt/<uuid>/profile`. Ако `ps` не може да се пусне → „работи“ (fail safe).
- **Корени:** `profiles::Roots { home, browser_running, file_vault }` — всички пътища се смятат от `home`; тестовете ползват фалшив home в temp dir. E2E за M7b (`tests/e2e_import_macos.rs`) създава „съществуващите“ профили с истинските браузъри, но в temp home (`--user-data-dir` / `-profile`), така че никога не пипа реалните профили.
- `keep_original` / `undo_keep_original` също искат отключена сесия (за MAC на header-а).

Отворени въпроси:
1. `cleanup_original` и `keep_original` изискват сейфът да е отключен (UI: `request_vault_action` → unlock прозорец → после cleanup). Алтернатива: пълен credential (парола + втори фактор) в cleanup прозореца.
2. Firefox `extensions.json` / `addonStartup.json.lz4` съдържат абсолютни пътища към стария профил; Firefox обикновено ги пресканира, но не е проверено с разширения.

## M6 / M7 / M8 (DMG): Tauri приложение (`app/src-tauri`)

**Локално (на Mac):**
```
cd app/src-tauri
npx @tauri-apps/cli@2 dev            # стартира приложението (иконка в menu bar, без Dock)
npx @tauri-apps/cli@2 build --target universal-apple-darwin   # .app + .dmg в target/universal-apple-darwin/release/bundle/
BVAULT_HOME=/tmp/bv npx @tauri-apps/cli@2 dev   # отделна папка за тестове
```
Иконите се генерират с `python3 app/src-tauri/icons/generate.py` (Pillow); резултатите са в git. На Linux crate-ът се компилира (CI инсталира `libwebkit2gtk-4.1-dev` и др.), за да минават clippy и unit тестовете.

**CI:** `.github/workflows/app.yml` (macos-14) прави universal `.app` + `.dmg` с ad-hoc подпис (`signingIdentity: "-"`, без hardened runtime), пуска приложението 15 s като smoke тест и качва artifact `browser-vault-dmg`. При tag `v*` създава GitHub Release (prerelease) с DMG-то.

**Решения:**
1. Всички команди от `docs/UI.md` са `#[tauri::command]` в `src/commands.rs`. Грешки: `{ code, retryAfter? }`; `Error::Unsupported` → `code: "unsupported"` (останалото е `err.code()`).
2. Секретите от UI-я влизат веднага в `Zeroizing` и се освобождават в края на командата. Черновите на wizard-а са в `HashMap<draftId, Draft>` (draftId: 16 байта от `OsRng`); затварянето на прозореца `wizard` изтрива всички чернови.
3. Argon2 / hdiutil / спиране на браузъра вървят в `spawn_blocking`, никога в main thread.
4. `sizeGb` се чете от `image.sparsebundle/Info.plist` (`size`, байтове → GiB). 0, ако не може да се прочете.
5. `mode`: `fido2`, ако има fido2 slot, иначе `totp`.
6. Настройките са в `<store root>/settings.json` (без секрети, атомарен запис, 600). Освен полетата от UI.md има и `browserPaths` (ръчно избран `.app`).
7. Неактивност: глобалната настройка е главен ключ, стойността на сейфа (от wizard-а) може само да я направи по-строга: лимит = min(глобална, на сейфа); 0 от която и да е страна = изключено. Заключен екран / sleep и изваден ключ: тригерът е активен, ако е включен и глобално, и за сейфа.
8. YubiKey: на всеки 2 s `fido2::key_present(header, auth)` за всеки отворен fido2 сейф; заключва само при преход „има ключ → няма ключ“.
8a. Грешките при регистрация на ключ (`fido2::ERR_*`) стават конкретни кодове `fido_*` (`fido_pin_not_set`, `fido_no_key`, `fido_multiple_keys`…); **поправка във frontend-а:** wizard-ът показва текстовете `err_fido_*` от `i18n.js` (BG/EN) вместо общото „Неуспешно отключване“. Грешките при отключване остават общи.
9. Panic hotkey: UI-ят записва `⌃⌥⌘L`; Rust го парсва (`src/hotkey.rs`). **Поправка във frontend-а:** записът на клавиша ползва `e.code`, защото с ⌥ `e.key` дава друг символ (⌥L → „¬“).
10. Tray прозорецът е 360 px широк, а височината следва съдържанието чрез init script + вътрешната команда `tray_fit` (не е в UI.md). Скрива се при blur.
11. Червената иконка (грешка при detach) не е template image, за да е наистина червена (SPEC §7).
12. Заключване с отворена сесия минава през `lock::close_vault` → `Store::close` (там `profiles::mark_reviewed` вдига `reviewed`), после почистване на следи. `lock::lock_vault(id)` само когато сесия няма (останки след срив, mount от CLI).
12a. Оригиналният профил (`src/original.rs`): `cleanup_preview`/`cleanup_original`/`keep_original`/`restore_original_notice` изискват отворена сесия. Ако сейфът е заключен, се отваря unlock прозорецът и действието продължава автоматично след успешно отключване (същото за `delete`). `open_window('cleanup')` при заключен сейф първо отключва. Сесия от recovery фраза не може да изтрива оригинала (`unlock_failed`).
12b. `wizard_finish` ползва `Store::create_with` (`disableFxa`, импорт). При `import_error` сейфът остава създаден, връща се `importError` и се показва системно съобщение.
13. `lock.rs`: `recover_after_crash` намира останали томове по `<root>/mnt/*` и по `hdiutil info -plist` (image под `<root>/vaults/` или mount под `<root>/mnt/`), спира оцелял браузър само ако командният му ред сочи в mount-а (защита от преизползван PID) и трие остарели pid файлове.
14. `request_vault_action`: `delete` работи (сейфът трябва да е отключен в момента + системно потвърждение); останалите показват „още не е налично“ и връщат `unsupported`.
15. Launch at login: `tauri-plugin-autostart` (LaunchAgent), прилага се при промяна на настройката.

**TODO:**
- `TODO(integrate)`: `change_password` (`totp::change_password` съществува), `add_fido2` (`fido2::add_key`), `replace_totp`, `new_recovery` в `request_vault_action`: API-тата в ядрото ги има, липсват UI екрани (нова парола; парола+PIN+етикет; еднократно показване на фразата). Засега показват „още не е налично“.
- Ако `Store::create` се провали, черновата е загубена (`create` я консумира) и wizard-ът трябва да започне отначало.
- M8: Developer ID подпис, notarization, hardened runtime, Tauri updater: не са направени.

## Преносимост: нов Mac, recovery фраза, логини на Brave

1. **Нови Brave сейфове са „преносими“** (`settings.portable_keys = true` в header-а): Brave се стартира с `--use-mock-keychain` и криптира cookies/паролите с фиксиран ключ, независим от Mac-а (Chromium `mock_password`). Реалната защита е криптираният сейф около профила. Полето се пропуска в JSON, когато е `false`, за да остане MAC-ът на старите header-и валиден.
2. **Импортиран Brave профил** се конвертира при импорта: приложението чете „Brave Safe Storage“ от Keychain (macOS пита веднъж — Allow) и преобразува всяка „v10“ стойност **в копието в сейфа** от ключа на Mac-а към преносимия (`portable::convert_mount`, една SQLite транзакция на база, WAL checkpoint). Оригиналът не се пипа. При отказ на достъпа сейфът остава непреносим, но работи на този Mac.
3. **Съществуващи сейфове:** Settings → Vaults → „Направи логините преносими…“ (сейфът трябва да е заключен; mount без браузър → конвертиране → detach → флаг). Трябва да се направи на **оригиналния** Mac, преди преместване. Конвертирането се пуска само веднъж на сейф (флагът го пази): грешен ключ минава padding проверката ~1/256 и би развалил стойност.
4. **Recovery фраза в Settings** („Използвай recovery фраза…“): за нов Mac или забравена парола. TOTP сейф: нова парола + нов аутентикатор, вързан към Secure Enclave на този Mac (`totp::reset_with_recovery`). YubiKey сейф: нова парола + докосване на всеки ключ.
5. **Нови crates** (`aes`, `cbc`, `pbkdf2`, `sha1`, + `rusqlite` за SQLite) — одобрени изрично само за т. 2–3. Тестов вектор е сверен независимо (Python `hashlib` + `openssl enc`), а E2E тест на macOS проверява, че истински Brave с `--use-mock-keychain` записва cookie, което нашият код декриптира с преносимия ключ.

## Архив на сейф на външен диск и „Добави сейф от диск…“ (`vault-core/src/backup.rs`)

- **Какво се копира:** само **заключен** сейф (`Store::is_unlocked` → отказ `ERR_UNLOCKED`; монтиран sparsebundle се променя под копието). Папка `<избрана>/vault-<първите 8 от id>.bvault/` с `image.sparsebundle/`, `header.json` (+ `.bak`). Всичко вътре вече е криптирано/запечатано, ключове не се пипат. Името на сейфа **не** е в името на папката (header v2 го държи криптирано); стари архиви `<име> (<id>).bvault` се намират по `vault_id` и се обновяват на място.
- **Инкрементално:** ако в избраната папка (или в нейна `*.bvault` подпапка, дори със старо име след преименуване, или ако е избрана самата `.bvault`) има архив със **същия** `vault_id`, се копират само файлове с различен размер или mtime (толеранс 2 s: HFS+ пази цели секунди, FAT32 — 2 s), трият се файлове/папки в `image.sparsebundle/`, които вече ги няма (bands идват и си отиват), `header.json(.bak)` се копират винаги и `header.json` е последен. Папка с **друг** `vault_id` (или непразна без header) → отказ `ERR_OTHER_VAULT`. Папка вътре в store-а → `ERR_DEST_IN_STORE`.
- **Атомарност:** всеки файл: temp `.<име>.bvtmp` → `set_modified` (mtime се пази) → fsync → rename. Първият архив се пише в скрита `.<id>.bvault-partial` и се преименува накрая (прекъснат опит продължава оттам). По време на запис в папката има маркер `.incomplete`; импортът отказва такава папка (`ERR_INCOMPLETE`). Ако сейфът бъде отключен по време на копирането → грешка, маркерът остава, следващото архивиране поправя копието.
- **Проверка след копиране:** всеки файл от източника съществува в целта със същия размер, header-ът се парсва и е със същия `vault_id`. Прогрес по байтове: `Event::BackupProgress { pct }` (0–99 копиране, 100 след проверка).
- **Импорт:** изборът може да е самата `.bvault` папка или папка, в която има точно една такава. Проверки: няма `.incomplete`, header-ът се парсва (версия), `vault_id` е UUID, има `image.sparsebundle/Info.plist`, сейф със същото id още няма (`ERR_ALREADY_ADDED`). Копира се в `<root>/vaults/.<id>.importing` (700/600) → проверка → rename във `vaults/<id>`. Ползва се **копието**, не дискът.
- **Импортиран оригинален профил:** header-ът не се променя (MAC-ът иска VMK). Вместо това във `vaults/<id>/` се записва маркер `restored-from-backup`. За такъв сейф `cleanup_preview` / `cleanup_original` отказват (`profiles::ERR_ORIGINAL_ELSEWHERE`), а `list_vaults` връща `original: null` (няма бележка в менюто/настройките). Причина: пътищата се изчисляват от `profile_id`, а на друг Mac `Profile 1` може да е съвсем различен профил — проверка „пътят съществува“ не е достатъчна.
- **Symlink-ове и специални файлове** не се следват и не се копират (trace). `.DS_Store` и `._*` (AppleDouble на exFAT/FAT) се пропускат.
- **App:** `backup_vault { id }` → native избор на папка (старт `/Volumes`) → `{ path, copiedFiles, unchangedFiles }` или `{ cancelled: true }`, събитие `backup_progress { id, pct }`. `add_vault_from_drive {}` → избор → `{ id, name, mode }` или `{ cancelled: true }` + `vaults_changed`; прогрес `backup_progress { id: null, pct }`. Грешки: `backup_unlocked`, `backup_other_vault`, `backup_dest_in_store`, `backup_not_a_vault`, `backup_incomplete`, `backup_already_added`, `backup_verify_failed`, `backup_io` (текстове `err_backup_*`). Резултатите се показват в прозореца (callout + toast), без системни диалози.
- **Ограничения:** TOTP режимът е вързан за Secure Enclave на Mac-а → на друг Mac сейфът се отключва веднъж с recovery фразата и аутентикаторът се настройва наново (UI-ят го казва след добавяне). Няма предварителна проверка за свободно място (пълен диск → `backup_io`, следващият опит продължава). Прекъснато инкрементално обновяване оставя архива смесен до следващото успешно архивиране (затова `.incomplete`). Импорт обратно на **същия** Mac (след изтриване на сейфа) също скрива бележката за оригинала — изтриването му тогава е ръчно. Отключване по време на архивиране не се блокира, а се хваща при повторната проверка накрая.

## Импорт на всички Brave профили в един сейф

**Решение:** за потребители с много Brave профили wizard-ът (стъпка Опции) предлага първи избор „Всички профили (N) — един сейф“, когато браузърът е Brave и има ≥2 открити профила. Вътре в сейфа работи профилният превключвател на Brave; всички профили се отварят и заключват заедно. Импортът на един профил остава. Firefox: само един профил (`"*"` за Firefox → `Error::Invalid`).

- **Ядро:** `profiles::ALL_PROFILES = "*"` като `profile_id` (`ImportRequest`, `wizard_finish` `importProfileId: "*"`; `store.rs` и `commands.rs` не се променят). Всеки профил от `Local State` `profile.info_cache`, който има папка, се копира в `<mnt>/profile/<същото име>` (`Default` остава `Default`, `Profile 1` остава `Profile 1`). Проверката е същата като при един профил (списък файлове + размери + SHA-256 на ключовите файлове) за всеки профил; при разминаване в който и да е профил целият импорт се отказва и `<mnt>/profile` се изпразва (сейфът остава празен и работещ).
- **`Local State` в сейфа:** пише се нов файл (600) само с `profile`: `info_cache` (само импортираните профили, записите им цели: име, аватар…), `profiles_order` и `last_active_profiles` (филтрирани), `last_used` (ако не е сред импортираните → `Default` или първия) и `profiles_created` (≥ най-големия `Profile N` + 1, за да получи нов профил в сейфа свободно име). Всичко останало нарочно **не** се пренася: `os_crypt` (на macOS ключът е в Keychain), `variations_*` seeds, `user_experience_metrics` / `uninstall_metrics` (client id-та), `brave.stats` / referral / P3A, хардуерни и инсталационни данни, флагове (`browser.enabled_labs_experiments`). Brave създава нужното наново.
- **Header:** `original.profile_id = "*"`, `profile_name = "All profiles (N)"` (`profiles::all_profiles_name`; UI-ят го разпознава и показва преведено), `paths` = всички папки на профилите + кешовете им + Saved Application State, `size_bytes` = общо. Форматът на header-а не се променя.
- **Изтриване (`cleanup_original` за `"*"`):** същите проверки (MAC, `reviewed`, затворен браузър, парола). Id-тата се извличат от `paths` — само имената на папки, които са директно в Brave data dir, валидирани като при един профил (без `..`, `.`, `*`, скрити; съществуващ не-директория като `Local State` → отказ; ако няма нито едно → отказ). Трият се папката и кешът на всеки импортиран профил + Saved Application State. От обикновения `Local State` (backup преди промяната, един за всички) се махат записите им от `info_cache`, `last_active_profiles`, `profiles_order`; `last_used` минава към останал профил (`Default` с предимство), а ако не остане нито един, ключът се маха и Brave създава нов `Default`. Профили, създадени след импорта (не са в `paths`), и всички други ключове не се пипат. `profiles_order` вече се чисти и при един профил.
- **UI:** обяснение под избора; финалният екран, бележката в Настройки и екранът за изтриване показват „Всички профили (N)“ / „Профилите, добавени след импорта, не се пипат“.

Отворени въпроси:
1. Ако след импорта потребителят изтрие профил в Brave и Brave по-късно създаде нов със същото име на папка (на практика не става: Brave брои с `profiles_created`), cleanup ще изтрие и него.
2. Профили, които са в `info_cache`, но нямат папка, не се импортират и записите им остават в обикновения `Local State`.

## Криптирани метаданни на сейфа (header v2)

**Решение:** без отключване `header.json` не издава име, браузър, дата на създаване, настройки и данни за импортирания профил (пътища, име, размер). Формат: SPEC §8.1.

- **В паметта** има един тип `Header`; метаданните (`header::Meta`) са зад `meta()` / `meta_mut()` (грешка `ERR_META_LOCKED`, ако v2 header-ът не е отворен) и `try_meta()` за показване. `Store::load` връща заключен header; `Store::load_open(id, key)` / `Header::open_meta(vmk)` го отварят. `seal_mac` при отворени метаданни ги запечатва наново (нов nonce) и после смята MAC-а; при неотворен v2 header (напр. TOTP броячи при неуспешен опит) запечатаните метаданни остават както са.
- **v1 → v2:** `Store::upgrade_header(id, key)` (MAC-ът трябва да е валиден, иначе отказ: не „узаконяваме“ подправен header). Вика се от `Store::unlock` веднага след успешния фактор (преди mount-а), от `action_auth` / `action_auth_recovery` в Настройки, а `make_portable` също конвертира. Записва се два пъти, за да е и `header.json.bak` v2 (иначе старият чист JSON остава в `.bak`). Стари архиви на външен диск остават v1 до следващото архивиране.
- **Локален индекс** `<store>/index.bin` = nonce ‖ XChaCha20-Poly1305(ключ, AAD `bv-index-v1`, JSON `{vaults: {id: {name, browser, created_at, portable_keys, original: {profile_name, size_bytes, reviewed, state}}}}`). Без пътища. Ключът: 32 байта от `OsRng`, hex, generic password в login Keychain-а — service `com.local.cacheindex`, account `index` (неутрално име), създава се при първия запис. Кешира се в паметта на процеса; при отказ на достъпа не се пита отново до рестарт. Провайдърът е инжектируем (`Store::with_index_key`): тестовете и Linux ползват `index::no_key` / `memory_key`, CLI-то `keychain_read_only` (не създава item-а, за да не стане негов собственик), e2e тестовете `no_key`. Индексът се обновява при всеки `Store::save_header` с отворени метаданни (create, unlock, промени в оригинала/настройките), при `upgrade_header` и при `Store::remove_vault`. Той е само за показване, нищо по сигурността не зависи от него.
- **Без запис в индекса** (сейф от backup, друг Mac, изтрит Keychain item) `list_vaults` връща `name: null, browser: null`; менюто/Настройките показват „Заключен сейф“ с неутрална иконка, бележката за оригинала не се показва, „Направи логините преносими“ се скрива. `lock_vault` без сесия не чисти Saved Application State на непознат браузър.
- **Backup:** папката е `vault-<id8>.bvault` (без име). Импортът не знае името; записът в индекса се появява след първото отключване.
- **`cleanup_preview`** иска отворената сесия (пътищата са в криптираните метаданни).
- **Видимо на диска:** `vault_id` (и името на папката), Argon2 параметрите, типовете slot-ове и етикетите на YubiKey-ите (`label`), размер на sparsebundle-а, mtimes на файловете (≈ дата на създаване/последно ползване), `restored-from-backup` маркерът, наличието на `index.bin`.

Отворени въпроси:
1. Приложението е ad-hoc подписано: след всяко обновяване (нов cdhash) macOS може да попита за достъп до Keychain item-а `com.local.cacheindex` (както за „Brave Safe Storage“). При „Deny“ имената се показват като „Заключен сейф“ до рестарт на приложението.
2. Етикетите на YubiKey slot-овете (`label`, напр. „YubiKey main“) остават видими; могат да се преместят в `meta`, ако е нужно.

## Режим „призрак“ и маскировка (Настройки → Общи → Поверителност)

Цел: защита от **бегъл поглед** към Mac-а (plausible deniability), не криминалистична невидимост. Подсказката в UI-я го казва изрично.

**Режим „призрак“** (`ghostMode`, по подразбиране изключен):
- Иконата в menu bar се скрива (`TrayIcon::set_visible(false)`); Dock икона няма и без това (`LSUIElement`). При изключване иконата се връща.
- Всички известия спират (`lockctl::notify` е единственото място, което ги праща).
- **Клавиш за показване** (`revealHotkey`, по подразбиране `⌃⌥⌘B`): същите правила като panic клавиша (`hotkey::allowed`) и трябва да е различен от него (`hotkey::same`, иначе `hotkey_clash`). Регистрира се само в режим „призрак“; `register_hotkey` регистрира и двата, а handler-ът в `main.rs` ги различава с `hotkey::dispatch`. Показва tray прозореца горе вдясно под menu bar-а (`windows::reveal_tray`, няма икона, спрямо която да се позиционира). Panic клавишът си остава „заключи всички“.
- Повторно стартиране: двоен клик на вече работещото приложение → `RunEvent::Reopen` → в режим „призрак“ нищо; иначе показва менюто. Втори процес (`open -n`) → `tauri-plugin-single-instance`: вторият процес излиза веднага, преди да създаде каквото и да е; първият показва менюто само ако не е „призрак“ или ако е подаден `--reveal`.
- **Ако клавишът е забравен:** в Terminal `open -n -a "<име на приложението>" --args --reveal` (напр. `open -n -a "Font Cache Helper" --args --reveal`). `-n` е нужно: без него macOS само активира работещото приложение и не подава аргументите. Ако приложението не работи, `--reveal` се обработва и при първо стартиране.
- Без фалшиви съобщения за грешка и без имитация на системни диалози.
- Не се скриват: браузърът на отключен сейф (прозорци, Dock), процесът в Activity Monitor, следите на диска.

**Маскировка** (`disguise`; таблицата е в `app/src-tauri/src/disguise.rs`): `none` + „Font Cache Helper“, „Display Profile Tool“, „Archive Index“. Имената и иконите са измислени за това приложение; иконите се рисуват от `app/src-tauri/disguises/generate.py` (Pillow, `.icns` се пише на ръка: `icns` + дължина + записи `ic07..ic10` с PNG) и се пакетират като Tauri resources (`Contents/Resources/disguises/`). `browser-vault.icns` е нормалната иконка, за връщане към „Без“.

Какво прави `apply_disguise` на macOS (`disguise::apply`), по ред:
1. Отказ, ако текущата маскировка е същата (`disguise_same`), ако не работи от `.app` (`disguise_unsupported`), ако има отключен/монтиран сейф, сейф в грешка или отворена чернова в wizard-а (`disguise_unlocked`, плюс проверка на `mount` за нещо под store root-а).
2. Предварителна проверка: непразна папка с данни с новото име → `disguise_data_exists`. Съществуващ `<Име>.app` на целевото място, който не е наш (CFBundleExecutable не е от таблицата) → `disguise_target_exists`; ако е наш (останал от предишен опит) → изтрива се.
3. Копие с `ditto` в `/Applications/<Име>.app` (или до текущия bundle, ако `/Applications` не е writable) → `xattr -cr` (quarantine и др.) → `Contents/MacOS/<exe>` се преименува на неутралното име (напр. `fontcache-helper`) → иконата се копира в `Contents/Resources` → `plutil -replace` на `CFBundleName`, `CFBundleDisplayName`, `CFBundleExecutable`, `CFBundleIdentifier` (напр. `local.fontcache.helper`), `CFBundleIconFile`, `BVStoreName` (за „Без“: `-remove BVStoreName`) → `plutil -convert xml1` → прочитане обратно и сверка (`plist_matches`) → `codesign --force --deep --sign -` → `codesign --verify --deep --strict`. При грешка копието се трие и нищо друго не е пипнато (`disguise_failed`).
4. `settings.disguise` се записва в текущата папка (мести се заедно с нея).
5. Папката с данни `~/Library/Application Support/<старо>` → `<ново>` с един `rename` (същият том; всички сейфове са заключени, mount точките са под root-а). При грешка: настройките се връщат, копието се трие. При `BVAULT_HOME` данните не се местят (env-ът печели).
6. Логът спира да пише (`applog::suspend`) и `~/Library/Logs/<старо>` → `<ново>`.
7. Ако е включено „Стартиране при вход“: старият LaunchAgent се маха; новият процес при старт го регистрира наново със своето име и път (autostart plugin-ът е с `app_name = CFBundleName`, т.е. `~/Library/LaunchAgents/<Име>.plist`).
8. Старият bundle се изтрива (ако може; от DMG или App Translocation не може и остава).
9. Отделен `/bin/sh` (собствена process group) изчаква текущия PID да излезе (single-instance socket-ът се освобождава), трие следите на стария bundle id (`~/Library/{WebKit,Caches,HTTPStorages}/<id>`, `Preferences/<id>.plist`, `Saved Application State/<id>.savedState`) и пуска `open -n <ново>.app`. Текущият процес излиза без да пипа store-а (`AppState::relaunching`).

**Имена:** `vault_core::identity` чете `Contents/Info.plist` на работещия bundle (до изпълнимия файл; XML, затова `-convert xml1`): `BVStoreName` → име на папките с данни и логове (валидира се: един компонент, без `/`, без водеща точка; иначе `BrowserVault`), `CFBundleDisplayName`/`CFBundleName` → заглавие на известия, tooltip и прозорци. Извън bundle (CLI, `tauri dev`, Linux) всичко е по подразбиране; **CLI-ят не намира данните на маскирано приложение** — ползвай `BVAULT_HOME="~/Library/Application Support/<BVStoreName>"`. Името на процеса = името на изпълнимия файл. Crash guard-ът е с `$0 = idle-watch` (`identity::GUARD_NAME`; изключването в `pids_matching` и в самия скрипт ползва същото име).

**Устойчивост при срив по средата:** при старт (`disguise::adopt_on_start`, преди лога и store-а), ако папката с данни на текущото име липсва, а съществува **точно една** друга позната папка от таблицата (и нищо не е монтирано под нея), тя се преименува към текущото име. Същото за папката с логове. Така и прекъснато превключване, и пуснат стар bundle намират данните.

**Изчистени следи:** томът на отключен сейф се казва `Data` (старите `BV-<id>` се преименуват при отключване); identifier-ът на build-а е `local.statusbar.helper`, така че socket-ът на single-instance е `/tmp/local_statusbar_helper_si.sock`; при старт се трият остатъците от стария `com.browservault.app` (~/Library папки и stale socket); заглавията на системните диалози идват от името на текущата маскировка; в header v2 имената на YubiKey ключовете са в криптираните метаданни (на диска полето е празно, заключен сейф показва „YubiKey N“).

**Остават видими (известно):** текстовете в самите прозорци казват „Browser Vault“; в не-„призрак“ режим menu bar иконата е същият щит; записът в authenticator приложението на телефона е с издател „BrowserVault“ (само на телефона); FIDO2 RP ID `browservault.local` не се сменя (non-resident credential — смяната би счупила регистрираните ключове, и не се пази на ключа).

**Тествано само на Linux (unit тестове):** таблицата, plist ключовете и редакциите (`plist_edits` върху модел), пътищата, преместване/осиновяване на папки, `mount` парсване, dispatch на клавишите, настройки (round-trip, стари файлове, reveal ≠ panic). Самото превключване (`ditto`/`plutil`/`codesign`/`open`), `set_visible`, позицията на менюто, single-instance и Reopen трябва да се проверят на истински Mac.

