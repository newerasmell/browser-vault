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
