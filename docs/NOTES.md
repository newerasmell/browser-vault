# Бележки по реализацията

## Статус

| Етап | Състояние |
|---|---|
| M1 | `vault-core` + `bvault` CLI: create / unlock (парола) / mount / launch Brave / lock. Unit тестовете минават на Linux; E2E (`tests/e2e_macos.rs`) чака ръчно пускане на Mac |
| M2 | Keyslots, recovery фраза (BIP39, 24 думи), Argon2id, MAC на header-а, атомарен запис + `.bak`. Unit тестове: wrap/unwrap, грешна парола, подправен header |

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
8. Firefox сейф се отказва с `Unsupported` до M5.
9. `bvault create` пита за 3 случайни думи от фразата само в интерактивен режим (TTY).

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
8. YubiKey: заключва само при преход „има ключ → няма ключ“ (poll на 2 s), за да не заключва веднага, докато `fido2::system()` е stub.
9. Panic hotkey: UI-ят записва `⌃⌥⌘L`; Rust го парсва (`src/hotkey.rs`). **Поправка във frontend-а:** записът на клавиша ползва `e.code`, защото с ⌥ `e.key` дава друг символ (⌥L → „¬“).
10. Tray прозорецът е 360 px широк, а височината следва съдържанието чрез init script + вътрешната команда `tray_fit` (не е в UI.md). Скрива се при blur.
11. Червената иконка (грешка при detach) не е template image, за да е наистина червена (SPEC §7).
12. При заключване след импорт `original.reviewed = true` се записва от приложението (нужен е VMK за MAC-а), само ако MAC-ът на header-а е валиден.
13. `lock.rs`: `recover_after_crash` намира останали томове по `<root>/mnt/*` и по `hdiutil info -plist` (image под `<root>/vaults/` или mount под `<root>/mnt/`), спира оцелял браузър само ако командният му ред сочи в mount-а (защита от преизползван PID) и трие остарели pid файлове.
14. `request_vault_action`: `delete` работи (сейфът трябва да е отключен в момента + системно потвърждение); останалите показват „още не е налично“ и връщат `unsupported`.
15. Launch at login: `tauri-plugin-autostart` (LaunchAgent), прилага се при промяна на настройката.

**TODO за интеграция:**
- `TODO(integrate M7b)`: `cleanup_preview`, `cleanup_original`, `keep_original`, `restore_original_notice`, импорт при `wizard_finish` (`src/integrate.rs`). `detect_profiles` връща `[]`, докато е `Unsupported`.
- `TODO(integrate M3/M4)`: `change_password`, `add_fido2`, `replace_totp`, `new_recovery` в `request_vault_action` (нужни са API-та за преобвиване на slot-ове и екран за еднократно показване на фразата).
- `TODO(integrate M5)`: `disableFxa` → `user.js`.
- Ако `Store::create` се провали, черновата е загубена (`create` я консумира) и wizard-ът трябва да започне отначало.
- M8: Developer ID подпис, notarization, hardened runtime, Tauri updater: не са направени.
