# POLICY.md — Yandex Mail MCP v2.1.0 PMLF Reference

PMLF (Progressive Multi-Layer Filter) — это server-side DLP-надстройка над send-pipeline Yandex Mail MCP. Этот документ — operator-facing справочник: что считается, чем тюнится, и что делать при срабатывании.

Версия модели: v2.1.0. Источник истины по дефолтам — `yandex-mail-mcp-desktop/src/policy-defaults.ts`. Регрессионный gate (`T-DOC-DRIFT-01` + `T-DOC-DRIFT-02`) ловит расхождение значений в этом документе и в коде.

---

## 1. Что такое PMLF и зачем он существует

Стандартные MCP-коннекторы (Gmail MCP, Slack MCP, etc.) полагаются на **клиент** (Claude Desktop / VS Code / Cursor) для подтверждения destructive операций. UX выглядит как inline-промпт "Always allow / Deny" перед каждым вызовом.

Проблема этой модели в нашем threat-model:

1. **Один клик `Always allow` выключает защиту на сессию** (а на некоторых клиентах — постоянно для данного MCP-сервера).
2. **`destructiveHint` — это hint, не enforcement.** Клиент НЕ обязан его уважать; ничего не мешает клиенту вызвать `send_email` без UI-промпта.
3. **Prompt-injection в теле письма** может уговорить LLM "согласиться" от имени пользователя — особенно если у LLM есть автономный режим без UI gating.
4. **Audit живёт только на стороне провайдера** (Google/Slack). У оператора нет локальной forensic trail.

PMLF закрывает этот gap **server-side**: четыре слоя анализа исходящего письма перед SMTP-отправкой, агрегация в композитный risk-score `[0, 100]`, маппинг в четыре tier'а — none (score < 30 augment), medium (score >= augment 30), high (score >= strict 60), block (score >= 100) — с разной confirmation-механикой. Tier mapping и confirmation HMAC-bound — клиент не может proxy/forge без доступа к секрету процесса.

Полная архитектурная мотивация: `.planning/v2.1.0-positioning.md` + `.planning/quick/20260518-yandex-mcp-fixes/THREAT-MODEL.md`.

---

## 2. Layer-by-layer overview (A/B/C/D)

PMLF состоит из четырёх независимых слоёв. Каждый слой выдаёт сигналы, которые потребляет Layer C; Layer D диспетчеризует подтверждение по итоговому score.

| Layer | Что делает | Где живёт |
|-------|------------|-----------|
| A — Outbound Content Scanner | Сканирует subject + body + recipients на 11 категорий контента; emits weighted hits | `src/outbound-scan.ts` + `src/scan/*` |
| B — Provenance Tracker | RAM-only Map: время последнего read; вычисляет `postReadFlag` в окне `provenance_window_sec` | `src/provenance.ts` |
| C — Risk Scorer | Композит из 9 сигналов (trust + content + provenance + volume + velocity); clamp `[0,100]`; cross-category bonus | `src/risk-score.ts` |
| D — Risk-Adaptive Confirmation | Tier dispatch (none/medium/high/block); HMAC code; override-token для block-tier | `src/confirm.ts` + `src/override-tokens.ts` |

**Layer A — Outbound Content Scanner.** 11 категорий детекторов (см. таблицу категорий в §4): платёжные карты, российский банкинг, госIDы, fuzzy credentials, structural secrets (API keys / JWT / base64), crypto/Web3 seed phrases, medical, classified markings, exfil phrases, data shapes (демографические PII), demographic PII. NFKC preprocessing, homoglyph normalisation, byte-offset preservation. Каждое срабатывание — typed hit с весом из `weights`. Cross-category coverage даёт +10 к итоговому score.

**Layer B — Provenance Tracking.** Привязывает событие "пользователь прочитал письмо X в момент T" к последующей send-операции в окне `provenance_window_sec` (default 30 секунд). Структурно RAM-only (нет `fs.writeFileSync`, нет background-таймера) — privacy invariant поддерживается статически, не runtime-чеком. На срабатывание Layer C добавляет `post_read_send` (default 30).

**Layer C — Risk Scorer.** Композит над сигналами из Layer A + Layer B + trust (allowlist / new / first-use / just-auto-trusted) + volume (multi-recipient / large body) + velocity (burst pattern Phase 7). Clamp `[0, 100]`. Cross-category bonus: если в одном send'е срабатывают детекторы из >=2 категорий — добавляется +10 к score (rationale: dual-signal = меньше вероятность ложного срабатывания).

**Layer D — Risk-Adaptive Confirmation.** Маппит итоговый score на четыре tier'а через `thresholds`. Tier определяет UX:

- `none` — отправка без подтверждения (только в L3/auto).
- `medium` — HMAC-bound одноразовый код в чате.
- `high` — то же + развёрнутый список reasons + waiting-period.
- `block` — отправка ОТКЛОНЕНА, требуется CLI-minted override-token из отдельного процесса (out-of-band, через `yandex-mail-mcp-trust --high-risk-send`).

---

## 3. Weight Table — каждый сигнал в композите

**Privacy boundary statement (D15):** Детектор-internals — regex patterns, BIP-39 wordlist для crypto-seed детекции, homoglyph mapping table — намеренно не enumerated в этом документе. Операторы с privileged access к source tree могут читать `src/scan/detectors/*.ts` напрямую. Цель — сохранить detection asymmetry: атакующий, читающий публичную документацию, не должен получать blueprint для evasion.

Таблица описывает каждый ключ из `DEFAULT_POLICY.weights` (источник: `src/policy-defaults.ts`).

| Key | Default | Layer | Rationale | Когда поднимать | Когда снижать |
|-----|---------|-------|-----------|-----------------|---------------|
| `new_trust` | 30 | Trust | Получатель отсутствует в allowlist — первичный сигнал. | Если параноидально относитесь к send'у незнакомым адресам. | Если bulk-уведомления новым адресам — рутина. |
| `first_use` | 20 | Trust | Адрес в allowlist, но это первое использование за длинный промежуток. | Если allowlist редко используется, "first_use" уместно жёстче. | Никогда не опускать ниже 10 — теряется dormant-account signal. |
| `just_auto_trusted` | 40 | Trust | Адрес добавлен в session-allowlist через auto-trust-on-reply в этом же запуске. | Если auto-trust-reply включён и нужен дополнительный gate. | Если auto-trust-reply=off (тогда сигнал не fire). |
| `base64_in_body` | 30 | A (structural) | Большой base64-blob в body — возможный exfil token.json/secret.bin. | Если ваша рабочая переписка не содержит base64. | Если регулярно пересылаете base64-attachments (но лучше использовать attachments API). |
| `api_key_pattern` | 75 | A (credentials) | Сигнатура vendor API key (AWS / GitHub / OpenAI / Yandex etc.). | Высокий вес уже — крайне точный сигнал. | Не снижать — false-positive rate низкий. |
| `emails_in_body` | 20 | A (structural) | Список email-адресов в body (контактные базы, leak'нутые user lists). | Если CRM-операции не входят в scope. | Если рутинно делитесь контактами (signature blocks etc.). |
| `payment_card` | 60 | A (PII) | Маска платёжной карты (Luhn-valid PAN). | Если работа с карт-данными прямо запрещена policy. | Если работаете в платёжной системе и пересылка legitimate. |
| `govt_id` | 60 | A (PII) | Маска СНИЛС / ИНН / Passport / SSN. | Если госID-данные строго regulated. | Если работаете в LegalTech / KYC. |
| `medical_secret` | 40 | A (medical) | Term-set "medical secret" tier: диагнозы общего характера. | Если работа с medical records запрещена. | Если работаете в healthcare provider. |
| `medical_elevated` | 60 | A (medical) | Term-set "elevated medical" tier: HIV / онкология / mental health. | Не снижать — высокая sensitivity. | Только в специализированных healthcare-flow. |
| `classified_marking` | 50 | A (classified) | Marker'ы вроде "CONFIDENTIAL" / "ДСП" / "TOP SECRET" в body или subject. | Если работа с classified-материалами — strict policy. | Если эти marker'ы legitimate (legal docs, internal classification labels). |
| `crypto_seed` | 75 | A (credentials) | BIP-39 mnemonic / private key blob / wallet recovery phrase. | Не поднимать — уже на уровне api_key_pattern. | Не снижать — irreversible-loss угроза. |
| `data_shape_anomaly` | 30 | A (structural) | Body matches "data export shape" (CSV/JSON dump паттерн без attachment). | Если экспорт данных всегда через attachments. | Если рутинно вставляете CSV-like структуры в body. |
| `post_read_send` | 30 | B | В окне `provenance_window_sec` сек после read'а — отправляете другому адресату. | Если экспортно-агентовые flow редки. | Если рутина "прочитал в inbox, переслал коллеге". |
| `cross_thread` | 15 | B | Reply в другой thread в коротком окне после read первого письма. | Если thread-discipline строгая. | Если работаете across many parallel threads. |
| `multi_recipient` | 20 | Volume | Send одновременно >=3 получателям. | Если bulk-операции исключены policy. | Если рассылки — рутина (но лучше через rate-limit). |
| `large_body` | 15 | Volume | Body превышает мягкий порог (~ десятки KB). | Если рассылка длинных текстов — экспортный признак. | Если регулярно пересылаете большие отчёты. |
| `burst_pattern` | 25 | Velocity | >=`burst_threshold` send'ов в окне `burst_window_sec` сек. | Если burst-activity всегда подозрительна. | Не опускать ниже 15 — теряется runaway-agent signal. |
| `outbound_keyword` | 10 | A (cat 2.4) | Per-keyword вес из cat 2.4 credentials_fuzzy (companion-gated). | Не fires standalone; companion-gating — структурное ограничение. | Если cat 2.4 даёт false positives на легитимных терминах. |
| `outbound_keyword_cap` | 40 | A (cat 2.4) | Max aggregate вклад cat 2.4 keyword-pass'а в композит. | Чтобы keyword-stuffing не bypass'ал композит. | Не снижать — теряется ceiling против keyword-flood. |

`thresholds`:

| Threshold | Default | Назначение |
|-----------|---------|------------|
| `augment` | 30 | Lower bound medium-tier'а — augment-сценарий (confirmation, но не блокировка). |
| `strict` | 60 | Lower bound high-tier'а — confirmation + audit-callout. |
| `block` | 100 | Lower bound block-tier'а — требуется override-token. |

Тоnplevel knobs:

| Knob | Default | Назначение |
|------|---------|------------|
| `outbound_keywords` | `[]` | Пользовательский список keyword'ов (companion-gated). Не fires standalone. |
| `blocked_domains` | `[]` | Hard block на send в указанные домены. Mismatch ведёт к block-tier независимо от score. |
| `provenance_window_sec` | 30 | Окно для post-read tracking (Layer B). 0 — disable. |
| `burst_window_sec` | 120 | Окно для velocity tracking (burst_pattern). |
| `burst_threshold` | 3 | Минимум send'ов в окне для срабатывания burst_pattern. |
| `override_block_threshold` | `false` | Anti-tamper: можно ли понизить `thresholds.block` ниже дефолта без FATAL. |

---

## 4. Thresholds + Tier UX

| Tier | Score | UX | Operator action |
|------|-------|----|-----------------|
| `none` | < `augment` (= 30) | Прямая отправка. | Используется в L3/auto или для адресов в allowlist с очень низким комбинированным score. |
| `medium` | `>= augment` && `< strict` (30-59) | HMAC-bound одноразовый код в чате. Reasons выводятся compact'но. | Пользователь подтверждает кодом; код one-shot, HMAC-bound на actionFingerprint. |
| `high` | `>= strict` && `< block` (60-99) | То же + развёрнутый список reasons + audit-callout. | Тоже подтверждение в чате, но с явным "это high-risk" в UI. |
| `block` | `>= block` (100) | Отправка ОТКЛОНЕНА. Возвращается `risk_block_no_override` audit-action. | Out-of-band: оператор runs `yandex-mail-mcp-trust --high-risk-send=<fingerprint>` в отдельном процессе — minted override-token; затем повторный send-call consume'ит токен. |

**`override_block_threshold` mechanics:** если оператор хочет понизить `thresholds.block` (например, до 80 для строгой policy), нормально это FATAL — policy.ts проверяет, не понижен ли block ниже дефолта. Чтобы разрешить понижение, надо явно установить `override_block_threshold: true` в policy.json. Это намеренная trip-wire — операторы не должны случайно отключать защиту понижением threshold.

**Category Toggle Table.** Все 11 категорий из `DEFAULT_POLICY.categories` (все default `true`):

| Category | Default | Что отключает |
|----------|---------|---------------|
| `payment_cards` | true | Luhn-валидные PAN'ы. |
| `ru_banking` | true | Российские банковские реквизиты (БИК, ИНН orgs, номера счетов). |
| `govt_ids` | true | СНИЛС / ИНН / паспорт / SSN / иные госID. |
| `credentials_fuzzy` | true | Cat 2.4 keyword-pass (companion-gated через outbound_keyword). |
| `structural_secrets` | true | API keys / JWT / base64-blobs / private keys. |
| `crypto_web3` | true | BIP-39 mnemonic / wallet seed phrases. |
| `medical` | true | Medical secret + elevated tier'ы. |
| `classified_markings` | true | "CONFIDENTIAL" / "ДСП" / иные classification labels. |
| `exfil_phrases` | true | Phrase-based exfil detection. |
| `data_shapes` | true | CSV / JSON dump shape detection (data_shape_anomaly weight key выше). |
| `demographic_pii` | true | Combinations of name + DOB + address — demographic identifiers. |

Отключение категории отключает соответствующие детекторы Layer A; их вклад в композит не добавляется. Используйте, если категория даёт persistent false positives в вашем workflow и rate-limit'ы Layer A недостаточны.

---

## 5. Tuning Playbook

Концепт: PMLF — это статистический фильтр. Любой weight tuning делается **поэтапно** — не более одного значения за iteration; повторный замер false-positive rate на real-world корпусе писем. Изменения через `yandex-mail-mcp-trust --policy edit` или прямой edit `risk-policy.json` с последующим автоматическим resign HMAC при загрузке.

### 5.1. Сценарий: false positives на credentials_fuzzy

Симптом: легитимные письма про "API integration" поднимают medium/high tier. Reasons содержат `outbound_keyword`.

Действия (в порядке предпочтения):

1. Снизить `outbound_keyword` 10 → 7-8. Cat 2.4 — companion-gated, поэтому снижение не убивает signal полностью.
2. Снизить `outbound_keyword_cap` 40 → 25-30 (ограничивает максимум вклада cat 2.4 в композит).
3. Если оба недостаточны — `categories.credentials_fuzzy: false`. Тогда detector полностью отключён; остальные категории работают.

### 5.2. Сценарий: bulk-уведомления одному адресу

Симптом: рассылка статусов одному и тому же partner@external.com набирает score через `multi_recipient` / `burst_pattern`.

Действия:

1. Если получатель уже в allowlist — score должен быть низкий (no `new_trust`); проверьте через `--list-trust`, что адрес действительно записан.
2. Снизить `burst_pattern` 25 → 15-20 если рассылка legitimate-by-design.
3. Поднять `burst_threshold` 3 → 5 если daily burst > 3 — норма.

### 5.3. Сценарий: post-read signal даёт false positives

Симптом: regular "прочитал в inbox → переслал коллеге" flow трипает post_read_send.

Действия:

1. Снизить `provenance_window_sec` 30 → 10 (более узкое временное окно).
2. Снизить `post_read_send` 30 → 15-20.
3. В крайнем случае `provenance_window_sec: 0` — disable Layer B полностью.

### 5.4. Сценарий: medium-tier confirmation раздражает оператора в L3

Симптом: в L3/auto хочется меньше confirmation-промтов для рутинных операций.

Действия:

1. Поднять `thresholds.augment` 30 → 40. Tier medium запускается выше; больше операций уходит в none.
2. **НЕ** снижать `thresholds.block` (см. anti-tamper §6) без `override_block_threshold: true`.
3. Если block-tier'ы для безопасных доменов — добавить адрес в allowlist через `yandex-mail-mcp-trust --trust`.

### 5.5. Сценарий: новая категория данных (например, classified для legal docs)

Действия:

1. Не отключать `classified_markings` глобально — оставить категорию on.
2. Использовать allowlist + confirmation: trust-адрес legal-team, confirmation-код обрабатывает один-раз.
3. Если объёмы массовые — рассмотреть категорию-specific override (на момент v2.1.0 не реализован; зафиксировать в BACKLOG-v2.2.0).

---

## 6. Anti-tamper + Recovery

PMLF использует **HMAC domain family** для криптографической изоляции трёх state-файлов:

- `'allowlist:'` — TOFU allowlist (Phase 5 v2.0.0).
- `'policy:'` — risk-policy.json (Phase 1 v2.1.0).
- `'override:'` — override-tokens.jsonl (Phase 5 v2.1.0).

Все три используют один и тот же `secret.bin`, но domain prefix предотвращает cross-domain replay (нельзя tamper allowlist HMAC и подставить как policy HMAC).

**Тamper detection — FATAL.** Если HMAC файла не сходится при загрузке — process.exit(1) с recovery banner на stderr. Это intentional: silent degradation скрыл бы attempt.

**3-step recovery (при FATAL):**

1. Stop процесс. Прочитать stderr — там путь к файлу и domain.
2. Если tamper accidental (вы редактировали JSON вручную) — удалить файл. На следующем запуске policy/allowlist/override-tokens создастся с дефолтами; allowlist потеряется (rebuild через CLI).
3. Если tamper не объяснимый — рассматривать как security incident. Скопировать файл для forensics, удалить, перезапустить сервер.

**`override_block_threshold: true` — отдельный anti-tamper.** Этот knob управляет, можно ли понизить `thresholds.block` ниже DEFAULT (100). По умолчанию `false` — попытка понизить block ниже 100 ведёт к FATAL. Чтобы разрешить — явно установить `override_block_threshold: true`. Это trip-wire против operators, которые могли бы "по запросу пользователя" понизить block-tier — теперь это требует осознанного действия.

**Audit actions, добавленные в v2.1.0:** `outbound_scan_match`, `risk_block_no_override`, `override_token_minted`, `override_consume_denied`, `override_token_consumed`, `policy_set`, `policy_reset`, `policy_edit`, `allowlist_revoke`, `allowlist_skip`, `pending_trust_swept`. Все логируются в `audit.jsonl` с FORBIDDEN_KEYS редакцией (никаких body/recipients/code-значений в payload).

---

## 7. Recommended Client-Side Pattern: Subagent-Delegated Verifier

PMLF защищает send-path **server-side**: HMAC код не может быть forged клиентом, override-token mint'ится отдельным процессом. Но remaining attack-surface — **prompt-injection в body**, который при чтении письма (read-path) попадает в context основного агента. Boundary markers + CLAUDE.md ground rule "body=data" — partial mitigation, но **полная server-side изоляция read-path** — задача v2.2.0/Layer 2.

**Рекомендуемый pattern для клиентов уже сейчас:** spawn'ить отдельный verifier subagent (GSD-style, isolated context) для confirmation-диалога. Verifier subagent:

- Получает narrow contract: `{recipients, score, reasons[], code}`.
- НЕ видит email body, conversation history, system prompt основного агента.
- Независимо запрашивает у пользователя подтверждение через chat / out-of-band.
- Verifies user reply matches code (через server `verifyCode` endpoint).
- Returns verdict основному агенту.

**Что это добавляет над текущим PMLF:**

| Defence layer | PMLF v2.1.0 (server HMAC) | + Client subagent isolation |
|---------------|---------------------------|------------------------------|
| Forge code | HMAC catches | same |
| Replay old code | HMAC binding + one-shot | same |
| Bypass через прямой sendmail | verifyCode contract | same |
| Prompt-injection в body манипулирует main agent | partial (boundary markers) | **formal isolation — verifier never sees body** |

**Это паттерн клиента, не server commitment.** PMLF v2.1.0 exports primitives (`generateCode`, `verifyCode`, `mintOverrideToken`) — клиент решает, как изолировать confirmation-диалог. В v2.2.0 / Layer 2 рассматривается server-side enforcement этого pattern'а как часть search-agent layer (см. `.planning/BACKLOG-v2.2.0.md`).

---

## 8. FAQ

**Q: Читает ли PMLF мой inbox?**

A: Нет. PMLF — это send-path фильтр. Single read-event tracking (Layer B) — RAM-only, hash отправителя, никакого content storage. Никакой outbound network traffic, никакого fs.writeFileSync с body. Только audit.jsonl с redacted метаданными.

**Q: Сколько добавляет к bundle size?**

A: Layer 1.5 v2.1.0 добавляет ~85 KB к main bundle (детекторы + регексы + BIP-39 wordlist для crypto-wallet detection). Это разовая стоимость при `npx -y` install. Trade-off в пользу защиты — см. `.planning/v2.1.0-positioning.md`.

**Q: Можно ли отключить PMLF полностью?**

A: Не предусмотрено как "одна кнопка". Идиоматично:

- Поднять все `thresholds` (augment/strict/block) до 200 — все tier'ы недостижимы.
- Или отключить все `categories: {... false}` — Layer A молчит.
- Trust signals (Layer C) всё равно fire — `new_trust=30` для всех адресов вне allowlist.

Если действительно нужен "off" — оставьте `YANDEX_AUTH_LEVEL=readonly` (L0): write-tools не регистрируются вообще, send-path не доступен.

**Q: Что если мой legitimate workflow попадает в block-tier?**

A: Two-process flow: оператор runs `yandex-mail-mcp-trust --high-risk-send=<fingerprint>` в отдельной shell, получает override-token. В чате повторяет send-call; токен consume'ится, отправка проходит. Токен — single-use, HMAC-bound на fingerprint (recipients + subject hash + body length + score).

**Q: PMLF блокирует ВСЕ exfil-сценарии?**

A: Нет. PMLF блокирует automated/agent-driven exfil через send-path. Не блокирует:

- Manual exfil оператором (legitimate access).
- Exfil через attachments на v2.1.0 (attachments scanning — deferred к v2.2.0 / Layer 2; см. BACKLOG).
- Exfil через альтернативные транспорты (другие mail accounts, IM clients, etc.).
- Read-path leakage в LLM context (см. §7 — client-side responsibility пока что).

**Q: Что меняется в block-tier с `override_block_threshold: true`?**

A: Только то, что вы МОЖЕТЕ понизить `thresholds.block` ниже 100 без FATAL'а. Сам tier dispatch не меняется — block-tier по-прежнему требует override-token. То есть `override_block_threshold` НЕ disable'ит block-tier; он disable'ит anti-tamper-trip-wire на edit policy.

---

_Документ ревизируется при изменениях `policy-defaults.ts`. Drift gate: `npm test` запускает `T-DOC-DRIFT-01` и `T-DOC-DRIFT-02`, которые fail'ятся, если ключ или default-значение из `DEFAULT_POLICY` отсутствует / расходится с этим документом._
