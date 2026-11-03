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

## M3: TOTP + Secure Enclave

Статус: `totp.rs` и `se.rs` са реализирани; unit тестовете (с `MockSecureEnclave` и инжектиран `now`) минават. Реалният SE се тества ръчно на Mac:
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
