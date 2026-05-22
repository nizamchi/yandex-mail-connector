---
description: Configure Yandex Mail connector (auth level) via interactive picker
---

# `/ymc-config` — Yandex Mail connector configuration

You are configuring the Yandex Mail MCP connector for the user. The user wants
an interactive picker (like GSD-style menus) to change settings without editing
JSON by hand.

## Step 1 — Show current state

Read `~/.claude.json` (Windows: `%USERPROFILE%\.claude.json`, macOS/Linux:
`$HOME/.claude.json`). Locate the `mcpServers.yandex-mail` entry. If it does
not exist, tell the user:

> Сервер `yandex-mail` не настроен в `~/.claude.json`.
> Сначала: `claude mcp add yandex-mail --scope user -- node /путь/к/dist/yandex-mail-mcp.js`
> Затем повтори `/ymc-config`.

Otherwise, extract the current `env.YANDEX_AUTH_LEVEL` value (default if
absent: `readonly`). Display it briefly:

```
Текущий уровень доступа: <значение> (auth level <N>)
```

## Step 2 — Interactive picker

Use the `AskUserQuestion` tool with this exact configuration:

- **question:** "Выбери уровень доступа агенту к Яндекс.Почте. Восстанавливается одним перезапуском Claude Code."
- **header:** "Уровень доступа"
- **multiSelect:** false
- **options:**
  1. **label:** "0. Только чтение"  
     **description:** "Чтение писем, поиск, метаданные. По умолчанию. Самый безопасный — destructive операции даже не появляются в списке доступных."
  2. **label:** "1. Безопасное"  
     **description:** "Плюс: перемещение, удаление в Trash, пометка прочитанным, добавление доверенных адресов. Без отправки."
  3. **label:** "2. Отправка"  
     **description:** "Плюс: создание черновиков и отправка писем. Каждая отправка требует одноразового кода подтверждения, который сервер шлёт в чат."
  4. **label:** "3. Автономный (осторожно)"  
     **description:** "Полный доступ без интерактивного подтверждения. Только для доверенной автоматизации (свой VPS, CI-агенты). Не для Claude Desktop/Code в интерактиве."

## Step 3 — Map choice → env value

| label (выбор пользователя) | env value записать |
|---|---|
| "0. Только чтение" | `readonly` |
| "1. Безопасное" | `safe` |
| "2. Отправка" | `destructive` |
| "3. Автономный (осторожно)" | `auto` |

If user picks "Автономный" — show explicit warning:

> ⚠️ Уровень 3 (`auto`) пропускает интерактивное подтверждение отправки.
> Это безопасно ТОЛЬКО в полностью контролируемой среде (личный VPS, CI).
> Для Claude Desktop / Code в интерактиве — НЕ рекомендуется.
> Подтвердить выбор? (AskUserQuestion: "Подтверждаю / Отмена")

If user cancels — exit without changes.

## Step 4 — Update config

Read `~/.claude.json`, parse JSON, set:

```json
mcpServers.yandex-mail.env.YANDEX_AUTH_LEVEL = "<chosen value>"
```

Write back **atomically**:
1. Write to `~/.claude.json.tmp`
2. Rename `~/.claude.json.tmp` → `~/.claude.json` (atomic on POSIX, near-atomic on Windows)

Preserve formatting/indentation if possible (`JSON.stringify(obj, null, 2)`).

## Step 5 — Final message

Tell the user:

```
Готово. Уровень доступа изменён: <old> → <new>.

Чтобы изменения применились — перезапусти Claude Code:
1. Введи `/exit`
2. Запусти `claude` заново

Это намеренное требование безопасности: YANDEX_AUTH_LEVEL читается один раз
при старте MCP-сервера. Защита от prompt-injection-атак, где скомпрометированное
письмо могло бы подменить уровень в середине сессии.

Для смены настроек allowlist / risk-policy / trust перезапуск НЕ нужен —
используй `yandex-mail-mcp-trust --policy / --list-trust / --revoke-trust`
из терминала, они применяются сразу.
```

## Notes for the implementing assistant

- Don't write the chosen value with `process.env` — that affects the CURRENT
  Claude Code process, not the persisted MCP config. Must write to
  `~/.claude.json`.
- If `~/.claude.json` doesn't exist or is malformed JSON — tell the user
  honestly, don't try to repair silently.
- This command does NOT restart Claude Code — restart is the user's action.
  Restarting from inside a slash-command would kill the running session
  before the user sees the success message.
