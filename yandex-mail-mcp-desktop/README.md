# yandex-mail-mcp-desktop

MCP сервер для Яндекс.Почты — **Claude Desktop / Claude Code, stdio транспорт**.
Никакого деплоя в облако. Работает как локальный процесс, как и твой Яндекс.Диск клиент.

---

## Шаг 1. Регистрация OAuth-приложения

1. [oauth.yandex.ru](https://oauth.yandex.ru) → «Зарегистрировать приложение»
2. Платформы: **Веб-сервисы**, Redirect URI: `https://oauth.yandex.ru/verification_code`
3. Доступы (scopes):
   - `Яндекс.Почта → Чтение и удаление писем` (`mail:imap_full`)
   - `Яндекс.Почта → Отправка писем` (`mail:smtp`)
4. Сохрани **ClientID** (client_secret для нашего сценария не нужен — implicit flow)

---

## Шаг 2. Получить OAuth-токен (implicit grant)

В браузере под нужным аккаунтом:

```
https://oauth.yandex.ru/authorize?response_type=token&client_id=<ТВОЙ_CLIENT_ID>
```

После подтверждения Яндекс редиректнет на URL вида:
```
https://oauth.yandex.ru/verification_code#access_token=y0_AgAAA...&expires_in=...
```

Скопируй `access_token` из URL-фрагмента.

---

## Шаг 3. Сохранить token.json

Создать рядом с `dist/` (в корне проекта):

```json
{
  "access_token": "y0_AgAAA...",
  "email": "you@yandex.ru"
}
```

Файл добавлен в `.gitignore`. Структура идентична `sources/yandex_disk/token.json`.

---

## Шаг 4. Сборка

```bash
npm install
npm run build
```

---

## Шаг 5. Конфиг Claude Desktop

Файл: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)  
или `%APPDATA%\Claude\claude_desktop_config.json` (Windows)

```json
{
  "mcpServers": {
    "yandex-mail": {
      "command": "node",
      "args": ["/абсолютный/путь/до/yandex-mail-mcp-desktop/dist/index.js"]
    }
  }
}
```

> token.json ищется рядом с `dist/index.js` — в корне проекта. Путь указывать не нужно.

Перезапустить Claude Desktop — инструменты появятся в чате.

---

## Инструменты

| Tool | Описание |
|---|---|
| `yandex_list_folders` | Все IMAP-папки |
| `yandex_folder_status` | Кол-во писем и непрочитанных |
| `yandex_list_emails` | Список писем с пагинацией |
| `yandex_get_email` | Полное содержимое по UID |
| `yandex_search_emails` | Поиск по отправителю, теме, тексту, дате, статусу |
| `yandex_send_email` | Отправка письма |
| `yandex_move_email` | Перемещение в папку |
| `yandex_delete_email` | Удаление (в корзину или насовсем) |
| `yandex_mark_email` | Прочитано / непрочитано / звёздочка |

---

## Грабли (аналог таблицы из yandex_disk_connection.md)

| Симптом | Причина | Решение |
|---|---|---|
| `credentials not found` | нет token.json и нет env vars | создать token.json в корне проекта |
| `401 Unauthorized` в IMAP | токен истёк или отозван | перепройти Шаг 2 |
| `AUTHENTICATIONFAILED` | включён 2FA, но IMAP отключён в настройках | Яндекс.Почта → Настройки → Почтовые программы → включить IMAP |
| `Failed to read token.json` | невалидный JSON или не те поля | нужно `access_token` + `email` |
| Большое письмо обрезано | лимит 8000 символов в теле | `truncated: true` — это нормально, тело не теряется |

---

## На будущее

- **Общий `core/yandex_oauth.py`** — когда понадобится refresh-flow, вынести OAuth в общий модуль вместе с диском.
- **Дедупликация с Яндекс.Диском** — письма с PDF-вложениями можно матчить с файлами диска через `sha256`.
- **Claude Code** — работает так же; конфиг через `~/.claude/claude_desktop_config.json` или флаг `--mcp-config`.
