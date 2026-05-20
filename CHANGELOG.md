# Changelog

Все значимые изменения этого проекта документируются в этом файле.

Формат основан на [Keep a Changelog 1.1.0](https://keepachangelog.com/ru/1.1.0/),
проект придерживается [Semantic Versioning](https://semver.org/lang/ru/).

## [Unreleased]

## [2.0.0] - 2026-05-20

Layer 1 — Secure Ship. Functional v1 hardened into a distributable
package: server-side security independent of MCP-client behaviour, four-level
auth model (L0/L1/L2/L3), TOFU send allowlist, HMAC-bound confirmation flow,
JSONL audit log, operational guards (rate limits, protected folders, 2FA
sender redaction, send dedup). Завершены 8 фаз + post-review hardening
(milestone deep-review opus-4.7 / effort=high). Раздаётся через
`npx -y github:nizamchi/yandex-mail-connector#v2.0.0`.

### Добавлено

- **Phase 1 — Build & Deps Hygiene.** Single-file бандл
  `dist/yandex-mail-mcp.js` (~2.5 МБ), `bin`-entry `yandex-mail-mcp`,
  `package-lock.json` под VCS, `ConnectionManager` singleton в `src/imap.ts`
  (Hook 4 — заготовка под IDLE / pooling / reconnect в Layer 2+).
- **Phase 2 — Defensive Boundaries.** Host allowlist для IMAP/SMTP
  (защита от env-poisoning), HTML strip с `YANDEX_STRIP_HTML` (default
  on), `sanitizeForDisplay` для display-name / subject / filename из
  envelope, `wrapUntrusted` BEGIN/END markers вокруг email body (data,
  не instructions), UID-based pagination в `yandex_list_emails`
  (BUG-01 fix — корректная стабильная пагинация при mailbox mutations).
- **Phase 3 — Auth Levels.** Четыре уровня `YANDEX_AUTH_LEVEL`
  (readonly/safe/destructive/auto = L0/L1/L2/L3). Декларативный массив
  `TOOLS[]` с `requires.authLevel` / `requires.capabilities` (Hook 3) —
  единая точка регистрации, без if-else-лестниц. L0 default — write-tools
  не появляются в списке tools, пока пользователь не повысит уровень.
- **Phase 4 — Confirmation Flow.** HMAC-bound confirmation codes для
  destructive операций (`generateCode` / `verifyCode` /
  `actionFingerprint` в `src/confirm.ts`). Hybrid elicit / stderr / toast
  flow зависит от capability клиента (`oninitialized` hook). `SendPlan`
  с `dry_run=true` возвращает структурированный план без отправки.
- **Phase 5 — Allowlist (TOFU).** `src/allowlist.ts` с HMAC-подписью
  файла, `getStateDir()` (Hook 1) — platform-aware каталог состояния
  (`$XDG_CONFIG_HOME`, `%APPDATA%`, `YANDEX_STATE_DIR` override). Новый
  11-й инструмент `yandex_trust_address` (L1+). CLI-бинарь
  `yandex-mail-mcp-trust` (`src/cli-trust.ts`) — оффлайн-управление
  trust-листом через `pending-trust.json`.
- **Phase 6 — Audit Log.** JSON Lines audit в `audit.jsonl`
  (`src/audit.ts`). Message-ID обязателен для email-actions (Hook 2 —
  enforcement на стороне `audit.ts`, handlers пробрасывают
  `envelope.messageId`). `FORBIDDEN_KEYS` редакция: тело письма,
  получатели целиком, password JSON keys никогда не попадают в лог.
  Размер-based ротация с `YANDEX_AUDIT_LOG_MAX_MB` (default 25 МБ).
  `wrapWithAudit` — декларативный hook для каждого хэндлера.
- **Phase 7 — Operational Guards.** `src/guards.ts` с тремя
  singleton-счётчиками: `DailyCounter` (`YANDEX_DAILY_SEND_LIMIT=50`),
  `PerRecipientCounter` (`YANDEX_PER_RECIPIENT_HOURLY=5`), `SendDedup`
  (`YANDEX_DEDUP_WINDOW_SEC=60`). Protected-folder gate
  (`YANDEX_PROTECTED_FOLDERS`) — cyrillic-aware через `getSpecialFolders`
  special-use flags. 2FA-sender redaction в `yandex_get_email` для
  отправителей из `YANDEX_BLOCK_2FA_SENDERS` (полная замена списка, не
  additive — T-07-11). L3 (`auto`) advisory режим — guards возвращают
  warnings вместо блокировки.
- **Phase 8 — Documentation & Release.**
  Token.json permission warning (Unix) с `YANDEX_STRICT_FILE_PERMS=true`
  для hard-fail. `sanitizeError` в `tools.errorResult` — категории
  `[NetworkError|AuthError|ImapError|SmtpError|GuardError|Error]` плюс
  редакция token / email / password JSON / Authorization-header
  значений. `README.md` (auth-levels + security model + file locations).
  `INSTALL.md` (4 MCP-клиента, OAuth alternative с DOC-01 callout про
  галочку IMAP/SMTP-доступ, operator overrides). Signed v2.0.0 git tag
  (или unsigned fallback с note). GitHub release с SHA-256 бандла.

### Изменено

- `package.json` version: 1.0.0 -> 2.0.0. **Breaking:** L0 (readonly)
  теперь default. Клиенты с v1 ожидавшие все 10 tools на старте теперь
  видят только 6 read-tools, пока не задать `YANDEX_AUTH_LEVEL=safe`
  (или выше) явно.
- nodemailer обновлён с 6.9.8 до 8.0.7. API остался байт-совместим.
- esbuild обновлён с 0.21 до 0.25.
- `yandex_list_emails` теперь возвращает UID-based pagination метаданные
  вместо offset-based (Phase 2 BUG-01).

### Безопасность

- Закрыты CVE-2025-14874 и CVE-2025-13033 в nodemailer (Phase 1).
- Закрыт GHSA-67mh-4wv8-2f99 в esbuild (Phase 1).
- `npm audit --omit=dev` = 0 уязвимостей (gate Phase 1 + перепроверка Phase 8).
- **T-02-\*** (Defensive Boundaries) — host allowlist; sanitizeForDisplay
  против prompt-injection через display-name / subject; wrapUntrusted
  boundary вокруг email body; HTML strip default-on.
- **T-03-\*** (Auth Levels) — L0 default; декларативный TOOLS[] закрывает
  риск "забыли добавить guard в новый tool"; capability dummy
  (`authLevel=99`) никогда не регистрируется.
- **T-04-\*** (Confirmation Flow) — HMAC bind кода к
  actionFingerprint (получатели + subject hash + body length);
  one-shot codes; timing-safe сравнение через `crypto.timingSafeEqual`.
- **T-05-\*** (Allowlist) — HMAC-signed файл с `secret.bin`; TOFU
  bootstrap-limit (`YANDEX_ALLOWLIST_BOOTSTRAP_LIMIT=200`);
  pending-trust handoff через CLI с verifySignature gate.
- **T-06-\*** (Audit Log) — FORBIDDEN_KEYS редакция всех sensitive
  полей; Message-ID enforcement Hook-2; log rotation против disk
  exhaustion.
- **T-07-\*** (Operational Guards) — daily/per-recipient rate limits
  против runaway agent; protected folders cyrillic-aware; 2FA sender
  body redaction (REDACTED_STUB ASCII — D-ASCII-REDACTED-MARKER
  deviation); send dedup window; L3 advisory documented.
- **T-08-01** — `sanitizeError` редактит token / email / password JSON
  / Authorization-header значения в текстовых error payload'ах перед
  отдачей в MCP-клиент.
- **T-08-02** — token.json mode warning + STRICT mode hard-fail на Unix.
- **T-08-03 / T-08-04** — SHA-256 бандла в release notes; signed git tag
  через `git tag -s` (или unsigned fallback с расписанным note).
- **Post-review hardening (2026-05-20)** — milestone deep-review
  (opus-4.7 / effort=high) выявил 1 BLOCKER + 2 HIGH дефекта. Все
  закрыты до публикации v2.0.0; см. `.planning/MILESTONE-v2.0.0-DEEP-
  REVIEW.md`:
  - **B-1** allowlist comma-smuggling — parser asymmetry между
    regex-gate'ом и nodemailer addressparser позволяла протащить
    второй адрес в одной строке `to[]`. Fix: Zod refinement через
    addressparser + нормализация recipients перед allowlist и SMTP
    (новый модуль `src/recipients.ts`).
  - **H-1** `in_reply_to` auto-trust inbound bypass — auto-trust
    добавлял отправителя из INBOX в персистентный allowlist по
    attacker-controlled `in_reply_to`. Fix: auto-trust только для
    писем из Sent + `scope='session'` (in-memory, не персистится);
    opt-out env `YANDEX_AUTO_TRUST_REPLY=off`.
  - **H-2** confirmation code burned before guards — code сжигался
    до проверки rate-limit/dedup, что толкало пользователей к
    `YANDEX_AUTH_LEVEL=auto`. Fix: reorder pipeline `allowlist →
    guards-pure → confirmation → smtp → recordSend`; `dry_run`
    теперь возвращает `guard_violation` вместо токена.
  - **L-4** 2FA-sender матчер не покрывал субдомены (e.g.
    `noreply@security.yandex.ru`). Fix: `host === domain ||
    host.endsWith('.' + domain)` с lookalike-safety.
  - **M-2** `findTokenFile` ломался на `npx`-инсталлах. Fix:
    `YANDEX_TOKEN_FILE` env override + `<state_dir>/token.json` как
    preferred location.

### Исправлено

- **BUG-01 (Phase 2)** — `yandex_list_emails` использовал offset-based
  pagination, что давало дубли / пропуски при изменениях mailbox между
  запросами. Перешли на UID-based.
- **B-1 / B-2 / B-3 (Phase 4)** — race в код-генерации (single mutation
  point), 0 await в `verifyCode` body, корректный capability fallback
  при отсутствии elicit.

### Изменено (post-review, не breaking для не-pinned consumers)

- SHA-256 бандла обновлён после hardening: было
  `3441c055341de8b63e5587fa0252d57a184fa99c4192f97fc91b4326810ca6a9`,
  стало `0f08ceb3ef6df11af4da0bc539031457c8d371e7e73d1e9fed4f0bb7bdfd12b3`.
- Тестовая база: 87 → **152** cases (+65 за post-review hardening).

## [1.0.0] — 2026-05-18

Функциональный baseline (Layer 0). Корректный MCP-коннектор без
серверных защит — пригоден для personal use, но не для раздачи.

### Добавлено

- MCP-сервер на TypeScript для Яндекс.Почты через stdio transport.
- 10 MCP-инструментов: чтение (`yandex_list_folders`,
  `yandex_list_emails`, `yandex_get_email`, `yandex_get_special_folders`,
  `yandex_search_emails`) и запись/управление (`yandex_send_email`,
  `yandex_create_draft`, `yandex_move_email`, `yandex_delete_email`,
  `yandex_mark_email`).
- IMAP-клиент через `imapflow` (`imap.yandex.com:993`, TLS).
- SMTP-клиент через `nodemailer` (`smtp.yandex.com:465`, TLS).
- Поддержка SASL PLAIN (пароль приложения) и XOAUTH2.
- Корректная работа на русскоязычных аккаунтах: специальные папки
  («Отправленные», «Удалённые», «Черновики», «Спам») резолвятся через
  IMAP `specialUse` flags, а не по именам.
- Оптимизация `getSpecialFolders`: 4 раздельных `LIST` → 1 `LIST` с
  фильтрацией результата.
- esbuild-сборка проекта (~37.6 КБ на момент v1.0.0, без бандлинга
  тяжёлых зависимостей).

### Исправлено

- 16 функциональных багов исходного прототипа (см.
  `.planning/quick/20260518-yandex-mcp-fixes/PLAN.md` — закрытый архив).
- Корректная сигнатура `imapflow.list('', '*', { specialUse: true })`
  после сверки с `.d.ts` — исходный вызов передавал параметр в
  неправильной позиции.
- Флаг `isError` корректно проставляется в ответах MCP при сбое
  IMAP/SMTP-операций (раньше ошибки маскировались под успех).

[Unreleased]: https://github.com/user/yandex-mail-connector/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/user/yandex-mail-connector/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/user/yandex-mail-connector/releases/tag/v1.0.0
