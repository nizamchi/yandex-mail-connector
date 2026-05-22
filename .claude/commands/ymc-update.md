---
description: Check for and apply Yandex Mail connector updates from GitHub
---

# `/ymc-update` — обновление коннектора с GitHub

Скрипт проверяет есть ли на GitHub более свежая версия Yandex Mail коннектора и предлагает обновиться. **НЕ ломает локальные изменения** — если репо в грязном состоянии, останавливается и просит разобраться.

## Что делает

1. Находит локальный clone репозитория. Стратегия поиска:
   - Сначала пробует `~/.claude.json` → `mcpServers.yandex-mail.args[0]` (если конфиг через `claude mcp add` указывает на абсолютный путь к `dist/yandex-mail-mcp.js` — поднимается на 2 каталога к корню репо)
   - Затем `~/yandex-mail-connector/`, `~/projects/yandex-mail-connector/`, `~/Documents/yandex-mail-connector/`
   - Если не нашёл — спрашивает у пользователя путь через AskUserQuestion с одной "Other"-опцией для ввода пути вручную
2. Читает локальную версию из `<repo>/yandex-mail-mcp-desktop/package.json` (`version` field)
3. Делает `git fetch --tags --quiet origin` в найденном репо
4. Сравнивает локальный `git rev-parse HEAD` с `git rev-parse origin/main`. Если идентичны — сообщает «вы уже на свежей версии» и выходит
5. Если ahead/behind — показывает `git log --oneline HEAD..origin/main` (что нового на удалённой)
6. Спрашивает через AskUserQuestion: "Обновиться сейчас?" с опциями:
   - "Да — обновить и перезапустить вручную"
   - "Только показать что изменится (dry-run)"
   - "Отмена"
7. Если «Да» — выполняет:
   - `git status --porcelain` для проверки чистоты working tree
   - Если есть незакоммиченные изменения — НЕ обновляет, выводит warning со списком файлов
   - Иначе `git pull --ff-only origin main` (только fast-forward, чтобы не делать merge-commit'ов без согласия)
   - После pull — `cd yandex-mail-mcp-desktop && npm install --omit=dev --ignore-scripts` чтобы подтянуть обновлённые runtime-deps
   - Сообщает: "Готово. Версия X → Y. Перезапусти Claude Code (/exit и `claude` заново) чтобы новый бандл загрузился."

## Безопасностные правила

- **Не использует `git push` ни в каком виде** — только pull
- **`git pull --ff-only`** — если remote разошёлся с локальным, останавливается. Не делает merge без явного согласия
- **`npm install --ignore-scripts`** — не запускает `prepare`/`postinstall`-скрипты из обновлённых deps (защита от supply-chain атак через npm install hooks)
- **Не трогает token.json, allowlist.json, secret.bin** — они вне `<repo>/`, в `<state-dir>/`
- **Не делает auto-restart Claude Code** — это требование безопасности; перезапуск = осознанное действие пользователя

## Шаги выполнения (для Claude)

### Step 1 — найти repo

Сначала прочти `~/.claude.json`. Найди `mcpServers.yandex-mail.args` — это массив. Первый аргумент типично абсолютный путь к `dist/yandex-mail-mcp.js`. Поднимись на 2 каталога вверх (`dist/..` → `yandex-mail-mcp-desktop` → `..` → repo root).

Если конфиг не найден или args не подходят — попробуй стандартные пути:
- Windows: `%USERPROFILE%\yandex-mail-connector`
- Unix: `$HOME/yandex-mail-connector`, `$HOME/projects/yandex-mail-connector`, `$HOME/Documents/yandex-mail-connector`

Если всё ещё не нашёл — спроси пользователя через AskUserQuestion: "Где у вас локальный clone yandex-mail-connector?" с опциями для типичных путей плюс «Other» для ручного ввода.

### Step 2 — проверить версии

```bash
cd <repo>
git fetch --tags --quiet origin
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)
LOCAL_VER=$(node -p "require('./yandex-mail-mcp-desktop/package.json').version")
```

Дополнительно — получи последний remote tag:
```bash
REMOTE_TAG=$(git ls-remote --tags --refs origin | tail -1 | sed 's|.*/||')
```

Если `LOCAL === REMOTE` — выведи:
```
Вы на свежей версии (v$LOCAL_VER, latest tag: $REMOTE_TAG).
```
И выйди (никаких следующих шагов).

### Step 3 — показать что новое

```bash
git log --oneline HEAD..origin/main
```

Покажи список новых коммитов. Если пусто но HEAD != origin/main — это значит local ahead (юзер сделал свои коммиты) — выведи warning и предложи решить вручную, не пытайся pull.

### Step 4 — спросить подтверждение

AskUserQuestion:
- question: "Обновить локальный clone до $REMOTE_TAG? Будет git pull --ff-only + npm install."
- options:
  1. "Да — обновить и попросить перезапустить Claude Code"
  2. "Dry-run (только показать что изменилось бы)"
  3. "Отмена"

### Step 5 — выполнить (если Да)

```bash
# чистота working tree
DIRTY=$(git status --porcelain)
if [ -n "$DIRTY" ]; then
  echo "Working tree not clean:"
  echo "$DIRTY"
  echo "Сначала закоммить или stash изменения, потом повтори /ymc-update."
  exit 1
fi

git pull --ff-only origin main
cd yandex-mail-mcp-desktop
npm install --omit=dev --ignore-scripts
```

### Step 6 — финальное сообщение

```
Готово. Обновлено: v$OLD → v$NEW.

Чтобы новый бандл загрузился — перезапусти Claude Code:
1. Введи `/exit`
2. Запусти `claude` заново

(Бандл `dist/yandex-mail-mcp.js` обновился в git вместе с pull, restart нужен потому что MCP-процесс грузит файл один раз при старте.)
```

## Edge cases

- **Локальные коммиты (ahead):** покажи `git log origin/main..HEAD`, скажи «у вас есть локальные коммиты, не запушенные — решите вручную (push или reset)».
- **Detached HEAD:** скажи «вы не на ветке (detached HEAD) — переключитесь на main через `git checkout main` и повторите».
- **Не git-репо:** скажи «найденный каталог не является git-репозиторием — возможно, был установлен через скачивание архива. Удалите и клонируйте через `git clone` для будущих обновлений».
- **Offline / fetch fails:** скажи «не удалось связаться с GitHub — проверьте интернет».

## Что НЕ делает

- Не публикует никаких credentials
- Не делает `git push`
- Не перезапускает Claude Code
- Не запускает `prepare`/`postinstall` скрипты при npm install (--ignore-scripts)
- Не пытается обновить если есть uncommitted changes
