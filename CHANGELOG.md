# Changelog

Все значимые изменения этого проекта документируются в этом файле.

Формат основан на [Keep a Changelog 1.1.0](https://keepachangelog.com/ru/1.1.0/),
проект придерживается [Semantic Versioning](https://semver.org/lang/ru/).

## [Unreleased]

## [2.1.0] - 2026-05-22

Layer 1.5 — PMLF (Progressive Multi-Layer Filter). Outbound-content-aware DLP
layer over the v2.0.0 secure-ship baseline. Восемь фаз (Policy Module /
Outbound Scanner / Provenance / Risk Scorer / Risk-Adaptive Confirmation /
Send Pipeline Refactor / CLI Extensions / Documentation). Раздаётся через
`npx -y github:nizamchi/yandex-mail-connector#v2.1.0`.

### Добавлено

- **Phase 1 — Policy Module.** `src/policy.ts` + `src/policy-defaults.ts`,
  HMAC-signed `risk-policy.json` (`'policy:'` domain), anti-tamper на
  `thresholds.block` (FATAL при понижении без `override_block_threshold:
  true`), `YANDEX_POLICY_FILE` env override, first-launch defaults write.
- **Phase 2 — Outbound Content Scanner (Layer A).** 11 detectors
  (`payment_cards` / `ru_banking` / `govt_ids` / `credentials_fuzzy` /
  `structural_secrets` / `crypto_web3` / `medical` / `classified_markings` /
  `exfil_phrases` / `data_shapes` / `demographic_pii`), homoglyph
  normalisation, NFKC preprocessing с byte-offset preservation, composite
  scoring с clamp `[0,100]` + cross-category +10 bonus.
- **Phase 3 — Provenance Tracking (Layer B).** RAM-only post-read tracking
  через `src/provenance.ts`; window `provenance_window_sec` (default 30);
  privacy invariant структурный (no `fs.writeFileSync`, no background timer).
- **Phase 4 — Risk Scorer (Layer C).** `src/risk-score.ts` — композит из
  9 сигналов (trust + content + provenance + volume + velocity), clamp
  `[0,100]`, маппинг в 4 tier'а (none/medium/high/block).
- **Phase 5 — Risk-Adaptive Confirmation (Layer D).** Per-tier dispatch в
  `src/confirm.ts`; `src/override-tokens.ts` — HMAC-signed (`'override:'`
  domain) одноразовые override-tokens с cross-process race guard
  (fresh-read on consume, Zod shape gate); CLI `--high-risk-send=<fingerprint>`.
- **Phase 6 — Send Pipeline Refactor.** 10-stage explicit `Stage[]` pipeline
  в `src/send-pipeline.ts`; AllowlistEntry получает `{added, lastUsed,
  useCount, source}` metadata с one-shot auto-migration; `yandex_send_email`
  handler сжимается с ~218 inline LOC до 16-LOC driver.
- **Phase 7 — CLI Extensions.** `yandex-mail-mcp-trust --policy
  show/set/reset/edit`, `--recent`, `--list-trust`, `--revoke-trust`,
  `--high-risk-send`; `src/recent-sends.ts` — 50-record forensics buffer;
  `flushAudit` public export.
- _Документация / Инфраструктура (Phase 8)._ `POLICY.md` (per-weight
  rationale + tier UX + tuning + anti-tamper + recommended subagent
  pattern); README "Layer 1.5" section; INSTALL.md PMLF env vars +
  расширенный state map; documentation-drift gate (`T-DOC-DRIFT-01` +
  `T-DOC-DRIFT-02` — fail при расхождении POLICY.md и `DEFAULT_POLICY`).

### Изменено

- `package.json` version: 2.0.0 → 2.1.0. Backward-compatible: v2.0.0 → v2.1.0
  upgrade автоматический; first launch создаёт `risk-policy.json` с
  дефолтами.
- T-PERF-01-003 HARD cap widened с 10ms → 30ms (outbound-scan oversize-body
  short-circuit benchmark). Standalone run всё ещё <5ms; widened для
  абсорбции Windows parallel-load jitter, документированной в
  `07-DEVIATIONS.md §D4`.
- Bundle size (main `dist/yandex-mail-mcp.js`): 2,624,841 (v2.0.0 tag) →
  **T-08-07 measured** bytes.

### Безопасность

- **HMAC domain separation** — `'policy:'` (Phase 1), `'override:'`
  (Phase 5) добавляются к существующему `'allowlist:'` domain'у;
  cross-domain replay rejected.
- **Single-use override-tokens** (Phase 5) — JSONL-персистированные,
  cross-process race guard через fresh-read on consume, timing-safe
  `token_hash` lookup + `validateRecord` Zod shape gate.
- **Composite outbound risk scoring** (Phase 2 + 4) — 11 content
  detectors над send payload; tier-based confirmation (Phase 5) gates
  medium/high tier'а.
- **Anti-tamper на block-threshold lowering** (Phase 1) —
  `override_block_threshold: true` требуется для понижения
  `thresholds.block` ниже default.
- **Provenance signal** (Phase 3) — `post_read_send` weight применяется
  если отправитель прочитал inbound email и сразу отправляет в окне
  `provenance_window_sec`; RAM-only, no disk persistence.

### Исправлено

- T-PERF-01-003 Windows parallel-load flake (Phase 8 T-08-06; HARD cap
  widened 10ms → 30ms с документированным rationale).

SHA-256 (см. release tag annotation):
  dist/yandex-mail-mcp.js  <BUNDLE-SHA-MAIN>
  dist/cli-trust.js        <BUNDLE-SHA-CLI>

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

[Unreleased]: https://github.com/user/yandex-mail-connector/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/user/yandex-mail-connector/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/user/yandex-mail-connector/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/user/yandex-mail-connector/releases/tag/v1.0.0
