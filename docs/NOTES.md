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
