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
