# Yandex Mail MCP

MCP-сервер для Яндекс.Почты (IMAP+SMTP) на TypeScript. Раздаётся как
single-file бандл через `npx -y github:user/repo#vX.Y.Z`. Цель — безопасный
agentic-доступ к личной почте, защищённый на стороне сервера независимо от
поведения MCP-клиента.

## Быстрая установка

См. [INSTALL.md](INSTALL.md). Минимум: пароль приложения Яндекса +
`token.json` + один JSON-snippet в конфиг MCP-клиента.

## Уровни авторизации (YANDEX_AUTH_LEVEL)

| Level | Значение      | Регистрируется инструментов | Подходит для                              |
|-------|---------------|------------------------------|--------------------------------------------|
| L0    | `readonly`    | 6                            | Только чтение / классификация (по умолчанию) |
| L1    | `safe`        | 9                            | + move / mark / delete / trust              |
| L2    | `destructive` | 11                           | + send / draft с обязательным подтверждением |
| L3    | `auto`        | 11                           | Полностью автономный агент в доверенной среде |

L0 — дефолт. Любые write-инструменты НЕ регистрируются, пока пользователь
явно не задаст `YANDEX_AUTH_LEVEL=safe` (или выше). Конкретный список
инструментов на каждом уровне — см. INSTALL.md "Шаг 4".

## Модель безопасности

- **L0 по умолчанию.** Write-инструменты не появляются в списке tools, пока
  пользователь не повысит уровень осознанно.
- **HMAC-bound confirmation codes для destructive операций.** Коды
  привязаны к конкретному отпечатку действия (получатели, subject hash,
  body length) и одноразовы.
- **TOFU allowlist для send.** Файл `allowlist.json` HMAC-подписан;
  доверие к адресу выдаётся явно через `yandex_trust_address` или CLI
  `yandex-mail-mcp-trust`.
- **JSON Lines audit log.** Каждый tool-call (attempt + result) пишется
  в `audit.jsonl` без sensitive content (FORBIDDEN_KEYS редакция, Message-ID
  для email-actions обязателен).
- **Operational guards.** Daily send limit, per-recipient rate limit,
  protected folders (cyrillic-aware), 2FA-sender redaction, send dedup
  window. Все настраиваются env-переменными.

## Расположение файлов

State-каталог резолвится через `getStateDir()` (Hook 1):

| Платформа | Путь                                                | Файлы                                            |
|-----------|-----------------------------------------------------|--------------------------------------------------|
| macOS     | `$XDG_CONFIG_HOME` или `~/.config/yandex-mail-mcp/` | `allowlist.json`, `secret.bin`, `audit.jsonl`, `pending-trust.json` |
| Linux     | `$XDG_CONFIG_HOME` или `~/.config/yandex-mail-mcp/` | те же                                            |
| Windows   | `%APPDATA%\yandex-mail-mcp\`                        | те же                                            |

Переопределение: `YANDEX_STATE_DIR=/path/to/dir`. На POSIX каталог
создаётся с mode `0o700`. `token.json` лежит рядом с бандлом или
в `cwd`, а не в state-каталоге; на Unix должен быть `chmod 600`.

## Дальше

- [INSTALL.md](INSTALL.md) — пошаговая установка для 4 MCP-клиентов.
- [.planning/MISSION.md](.planning/MISSION.md) — миссия и принципы.
- [.planning/LAYERS.md](.planning/LAYERS.md) — стратегия 7 слоёв.
- [CHANGELOG.md](CHANGELOG.md) — история версий.

## English summary

TypeScript MCP server for Yandex Mail (IMAP+SMTP), shipped as a single-file
bundle via `npx`. Server-side security is independent of the MCP client:
read-only default (L0), HMAC-bound confirmation for destructive ops, TOFU
allowlist for outbound recipients, JSONL audit log, and operational guards
(rate limits, protected folders, 2FA-sender redaction). See
[INSTALL.md](INSTALL.md), [.planning/MISSION.md](.planning/MISSION.md),
[.planning/LAYERS.md](.planning/LAYERS.md).

## License

MIT — see `yandex-mail-mcp-desktop/package.json` and source headers.
