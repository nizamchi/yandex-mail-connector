# Установка Yandex Mail MCP

## Шаг 1: пароль приложения Яндекс

1. Зайти на https://passport.yandex.ru.
2. "Управление аккаунтом" -> "Пароли и авторизация" -> "Пароли приложений".
3. Создать пароль для "Почта" (IMAP/SMTP). Сохранить — Яндекс показывает
   пароль только один раз. Получится строка из 16 строчных латинских букв
   (например `abcdefghijklmnop`).
4. Использовать этот пароль как поле `password` в `token.json` ниже.

OAuth — альтернативный путь, см. раздел "OAuth alternative (advanced)".

## Шаг 2: token.json

**Рекомендуемое расположение** — рядом с остальным state (allowlist, audit,
secret). Это работает для всех способов запуска, включая `npx`:

| Платформа | Путь к state-каталогу | Файлы в каталоге |
|---|---|---|
| Windows | `%APPDATA%\yandex-mail-mcp\` | `token.json`, `risk-policy.json`, `override-tokens.jsonl`, `recent-sends.jsonl`, `allowlist.json`, `audit.jsonl`, `secret.bin`, `pending-trust.json` |
| Linux | `$XDG_CONFIG_HOME/yandex-mail-mcp/` (или `~/.config/yandex-mail-mcp/`) | те же |
| macOS | `~/.config/yandex-mail-mcp/` | те же |

Каталог создаётся автоматически при первом запуске сервера. Можно
переопределить через `YANDEX_STATE_DIR=/custom/path` — тогда `token.json`
ищется по `$YANDEX_STATE_DIR/token.json`.

Формат (v2.1.2+ — рекомендуемый с паролем приложения):

```json
{
  "email": "you@yandex.ru",
  "password": "abcdefghijklmnop"
}
```

Формат (OAuth — для тех у кого есть Яндекс OAuth-приложение):

```json
{
  "email": "you@yandex.ru",
  "access_token": "y0_AgAAA..."
}
```

**Backward compatibility:** если у вас уже стоял token.json от v2.0/v2.1 с
паролем приложения в поле `access_token` — сервер автоматически определит
шейп по содержимому (16 строчных букв → пароль, `y0_...` → OAuth). Но при
любом редактировании рекомендуется явно использовать поле `password`.

На Unix обязательно:

```sh
chmod 600 token.json
```

Сервер на старте проверяет mode `token.json` и пишет stderr-warning, если
он group/other-readable. С `YANDEX_STRICT_FILE_PERMS=true` сервер
завершится с кодом 1 при mode != 600. На Windows эта проверка
пропускается (mode lies on win32).

### Альтернативные расположения

1. **Произвольный путь:** `YANDEX_TOKEN_FILE=/абсолютный/путь/token.json`.
   Полезно для CI / dotfiles / shared secrets.
2. **Project-root** (legacy): `<repo>/token.json` — работает при
   `git clone` + `npm start`. Не работает для `npx -y github:...` (бандл
   живёт в `~/.npm/_npx` и стирается между запусками).
3. **CWD** (legacy): `<cwd>/token.json` — работает при ручном запуске из
   известного каталога. Для Claude Desktop / Cursor cwd непредсказуем.
4. **Без файла (рекомендуется):** environment variables
   `YANDEX_APP_PASSWORD` + `YANDEX_EMAIL`. Подходит для ephemeral сред
   (Docker, GitHub Actions). Альтернатива для OAuth: `YANDEX_OAUTH_TOKEN`
   + `YANDEX_EMAIL`.

## Шаг 3: установка бандла

Структурно `package.json` лежит в подкаталоге `yandex-mail-mcp-desktop/`, что
блокирует `npx -y github:...`. До v2.2.0 (переезд в корень) — устанавливай
руками через git clone:

```bash
git clone https://github.com/nizamchi/yandex-mail-connector.git
cd yandex-mail-connector/yandex-mail-mcp-desktop
npm install --omit=dev --ignore-scripts
# готовый бандл лежит в dist/yandex-mail-mcp.js
```

`--ignore-scripts` нужен потому что у нас есть `prepare: npm run build`,
который пытается пересобрать esbuild'ом — а dev-deps (включая esbuild) при
`--omit=dev` не ставятся. Бандл уже собран и закоммичен в git, пересобирать
не нужно.

Запомни **абсолютный путь** к `dist/yandex-mail-mcp.js` — он понадобится в
Шаге 4.

## Шаг 4: настройка MCP-клиента

### Claude Code (рекомендуется)

Команда `claude mcp add` записывает конфиг по официальному пути
`~/.claude.json` (а не в произвольный `mcp.json`).

```bash
# user scope: сервер доступен во всех проектах
claude mcp add yandex-mail --scope user \
  -e YANDEX_AUTH_LEVEL=readonly \
  -- node /абсолютный/путь/к/dist/yandex-mail-mcp.js
```

Скоупы по [официальной документации Claude Code](https://docs.claude.com/en/docs/claude-code/mcp):

| Скоуп | Где хранится | Когда использовать |
|---|---|---|
| `local` *(по умолчанию)* | `~/.claude.json` под текущим проектом | Личный, один проект |
| `project` | `.mcp.json` в корне проекта (коммитится в git) | Шарить с командой |
| `user` | `~/.claude.json` глобально | Личный, все проекты — типично для почты |

После добавления — `/exit` в Claude Code и запустить заново. Инструменты
`yandex_list_folders` / `yandex_list_emails` / `yandex_get_email` /
`yandex_search_emails` / `yandex_get_special_folders` /
`yandex_folder_status` появятся в чате.

**Tool Search defer:** Claude Code по умолчанию откладывает загрузку MCP
tools и подгружает их по запросу. v2.1.3 добавил `instructions` на сервер,
чтобы Tool Search находил почту по упоминанию ключевых слов («Яндекс»,
«почта», «inbox»). Если что-то не нашлось — попроси явно: «используй
yandex_list_folders для просмотра папок».

### Claude Desktop

Файл config:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

Вставить:

```json
{
  "mcpServers": {
    "yandex-mail": {
      "command": "node",
      "args": ["/абсолютный/путь/к/dist/yandex-mail-mcp.js"],
      "env": { "YANDEX_AUTH_LEVEL": "readonly" },
      "alwaysLoad": true
    }
  }
}
```

`alwaysLoad: true` — отключает Tool Search defer и грузит инструменты сразу
при старте клиента. Полезно если Claude Desktop не находит почтовые tools
автоматически.

Перезапустить Claude Desktop полностью (Quit, не закрытие окна). Пути в
config — строго ASCII, без пробелов с кириллицей, чтобы не было сюрпризов
с экранированием.

### Codex CLI

Файл config: `~/.codex/mcp_servers.json` (или соответствующий config dir
по docs Codex). Snippet аналогичен Claude Desktop. Перезапустить CLI.

### Cursor

Settings → «Cursor Settings» → найти `mcp.servers` (или `mcpServers` в
JSON-режиме). Вставить тот же блок что для Claude Desktop. Перезапустить
Cursor.

## Шаг 5: выбор YANDEX_AUTH_LEVEL

### Choosing YANDEX_AUTH_LEVEL

| Сценарий                                            | Уровень        | Значение                |
|-----------------------------------------------------|----------------|--------------------------|
| Только читать почту, классификация                  | L0             | `readonly` (по умолчанию) |
| Перемещать / удалять / помечать письма, не отправлять | L1             | `safe`                    |
| Отправлять письма с подтверждением                   | L2             | `destructive`             |
| Полностью автономный агент в доверенной среде        | L3             | `auto` (предупреждение)   |

L3 пропускает интерактивное подтверждение для send. Использовать только
в полностью доверенном окружении (например, личный VPS под вашим
контролем). В Claude Desktop / Cursor — НЕ ставить L3.

## OAuth alternative (advanced)

Если у вас есть OAuth-приложение Яндекса с собственным `access_token` —
использовать его вместо пароля приложения. Положить в `token.json` /
env как обычно.

> **ВАЖНО (DOC-01):** В oauth.yandex.ru -> ваше приложение -> "Доступы"
> должна стоять галочка "IMAP/SMTP-доступ" (или аналогичный scope). Без
> неё IMAP отказывает с misleading "Invalid login" / "AUTH failed" message —
> будет потеряно несколько часов на дебаг.

## Operator overrides

Все environment variables, которыми оператор тюнит сервер.

### Phase 7 — operational guards

| Var                            | Default                                   | Назначение                                                | Когда менять                                                  |
|--------------------------------|-------------------------------------------|------------------------------------------------------------|---------------------------------------------------------------|
| `YANDEX_DAILY_SEND_LIMIT`      | `50`                                      | Дневной лимит отправок                                     | Поднять до 200-300 на доверенной автоматике; Яндекс cap ~500/d |
| `YANDEX_PER_RECIPIENT_HOURLY`  | `5`                                       | Лимит писем одному получателю в час                        | Поднять для bulk-уведомлений одному и тому же адресу          |
| `YANDEX_PROTECTED_FOLDERS`     | `INBOX,Sent,Drafts,Important`             | Список папок, на которых move/delete блокируется           | Дополнить кириллическими именами вашего ящика                 |
| `YANDEX_BLOCK_2FA_SENDERS`     | список 2FA-доменов по умолчанию           | **Полная замена** списка (НЕ additive — T-07-11)           | Сменить только если знаете полный набор; иначе оставить       |
| `YANDEX_DEDUP_WINDOW_SEC`      | `60`                                      | Окно дедупликации для одинаковых send (actionFingerprint)  | Уменьшить для частых легитимных повторных отправок            |

### Phase 1-6 + Phase 8 — earlier knobs

| Var                                  | Default                                | Назначение                                                  |
|--------------------------------------|----------------------------------------|-------------------------------------------------------------|
| `YANDEX_AUTH_LEVEL`                  | `readonly`                             | L0/L1/L2/L3 — см. Шаг 4                                      |
| `YANDEX_ALLOW_CUSTOM_HOSTS`          | `false`                                | Пропустить host allowlist — не для production               |
| `YANDEX_STATE_DIR`                   | platform default                       | Переопределить путь к state-каталогу                         |
| `YANDEX_TOKEN_FILE`                  | `<state-dir>/token.json` + legacy paths | Произвольный путь к token.json (M-2)                         |
| `YANDEX_ALLOWLIST_PATH`              | `<state-dir>/allowlist.json`            | Переопределить путь к TOFU allowlist                         |
| `YANDEX_AUDIT_LOG`                   | `<state-dir>/audit.jsonl`               | Переопределить путь к JSONL audit log                        |
| `YANDEX_AUDIT_LOG_MAX_MB`            | `25`                                   | Размер ротации audit log (МБ)                                |
| `YANDEX_STRIP_HTML`                  | `true`                                 | Стрипать HTML из email body перед отдачей в LLM context       |
| `YANDEX_ALLOWLIST_BOOTSTRAP_LIMIT`   | `200`                                  | Сколько Sent адресов прочитать при первом bootstrap allowlist  |
| `YANDEX_STRICT_FILE_PERMS`           | unset                                  | `=true` — process.exit(1) на token.json mode != 600 (Unix)    |

### Layer 1.5 PMLF — risk-policy + override-token knobs

Появились в v2.1.0. См. [POLICY.md](POLICY.md) для подробностей про каждый weight / threshold / category.

| Var | Default | Назначение | Когда менять |
|-----|---------|------------|--------------|
| `YANDEX_POLICY_FILE` | `<state-dir>/risk-policy.json` | Путь к HMAC-подписанной risk-policy.json | Сменить только если разносите state по нескольким каталогам |
| `YANDEX_OVERRIDE_TOKEN` | `<state-dir>/override-tokens.jsonl` | Путь к JSONL с одноразовыми override-токенами для block-tier send | Тот же случай — раздельный state path |
| `YANDEX_SCAN_DEBUG` | unset | `=1` — verbose stderr из outbound scanner (детали скоринга, перформанс) | Включить для post-incident debug; выключить обратно для prod (PII risk в stderr) |
| `YANDEX_TRUST_ASSUME_YES` | unset | `=1` — `yandex-mail-mcp-trust` мутаторы пропускают интерактивный confirm | Только для CI / scripted-операторов |
| `YANDEX_CONFIRMATION_PASSWORD` | unset | Опциональный пользователь-define пароль, который сервер требует ввести вместе с confirmation code (расширение HMAC-binding) | Включить если параноидально относитесь к prompt-injection через тело письма |

## Troubleshooting

- **"Invalid login" / "AUTH failed"** — проверьте пароль приложения. Если
  используете OAuth — проверьте галочку IMAP/SMTP-доступ (см. DOC-01 выше).
- **"ECONNREFUSED imap.yandex.com"** — сеть / TLS / корпоративный
  фаервол. Проверьте, что 993 и 465 не блокируются.
- **"Refused imapHost ..."** — пытаетесь подменить host вне allowlist.
  Не подменяйте без `YANDEX_ALLOW_CUSTOM_HOSTS=true` — это снимает защиту
  от env-poisoning.
- **stderr "token.json at ... has mode 644; expected 600"** — `chmod 600 token.json`.
- **`yandex_send_email` не виден в списке tools** — вы на L0. Поднимите
  `YANDEX_AUTH_LEVEL` до `destructive` или `auto`.
- **`yandex_move_email` отказывает с `protected_folder`** — папка
  назначения в `YANDEX_PROTECTED_FOLDERS`. Уберите её из списка или
  выберите другую.
