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
