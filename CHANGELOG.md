# Changelog

Все значимые изменения этого проекта документируются в этом файле.

Формат основан на [Keep a Changelog 1.1.0](https://keepachangelog.com/ru/1.1.0/),
проект придерживается [Semantic Versioning](https://semver.org/lang/ru/).

## [Unreleased]

## [2.8.0] — 2026-06-22

Релиз надёжности Layer 2: закрытие движка поиска по итогам полного код-ревью
(корректность синхронизации, изоляция аккаунтов, ограничение размера выдачи).
Без breaking changes в модели auth/security; индекс обратно совместим.

### Безопасность

- **`npm audit --omit=dev` снова чистый (0).** Появились новые advisory с момента
  2.7.1: `nodemailer` (≤9.0.0 — подмена заголовков через CRLF в `List-*`, проверка
  TLS-сертификата в OAuth2) поднят с 8.x до **9.0.1** (наш путь отправки использует
  только стабильное ядро `createTransport`/`sendMail`, правок кода не потребовалось);
  override поднимает и вложенные копии под imapflow/mailparser. Транзитивная `hono`
  (HTTP-путь MCP SDK, в бандл не входит) поднята до **4.12.26**.
- **Изоляция почтовых ящиков на чтении.** Поиск и сборка тредов теперь отдают
  только письма настроенного аккаунта. Если каталог состояния случайно делится
  между двумя ящиками, поиск одного аккаунта больше не покажет письма другого.

### Исправлено

- **Удалённые письма вычищаются из индекса.** Раньше инкрементальная синхронизация
  только добавляла письма и никогда не убирала — удалённое/перемещённое письмо
  оставалось в поиске навсегда (и плодило дубли между папками). Теперь после
  досинхронизации число писем сверяется с сервером; при расхождении папка
  пересобирается — **только при реальном расхождении и затем сходится**, без
  лишних пересборок на каждом обновлении. Счётчик писем измеряется, а не
  вычисляется «на бумаге», и больше не уезжает от реальности (накопленный перекос
  сам исправляется при следующей синхронизации).
- **Размер выдачи поиска ограничен.** `yandex_search_fast`/`yandex_get_thread`
  соблюдают лимит ответа (раньше это была лишь подсказка) — длинные темы/адреса
  обрезаются, лишние строки отбрасываются с флагом `truncated`, чтобы большая
  выборка не «съедала» контекст ассистента.
- **Сборка тредов устойчивее.** Письмо-зерно ищется по устойчивому ключу
  (аккаунт+папка+UID), а не по совпадению объекта в кэше; письма без темы больше
  не схлопываются в один ложный тред.
- **Строгий разбор дат.** Фильтры `since`/`before` принимают только ISO-формат
  (`ГГГГ-ММ-ДД`) и отклоняют двусмысленные записи вроде `01/03/2025` или `2025`,
  которые молча превращались в неверную границу.
- **`drop` теперь надёжно очищает индекс на Windows** (опустошает файл записей,
  а не пытается удалить занятый дескриптор).

### Добавлено

- **Пагинация и полный счётчик в быстром поиске.** Ответ возвращает `total` —
  полное число совпадений (а не размер страницы), параметр `offset` листает
  результаты.
- **Устойчивость к сбою отдельной папки.** `index build`/`update` синхронизируют
  исправные папки, даже если одна упала; упавшие перечисляются, а CLI завершается
  с ненулевым кодом — cron-задача увидит частичную синхронизацию.

## [2.7.1] — 2026-06-05

Патч-релиз: устранение шероховатостей v2.7.0. Без изменений API/безопасности.

### Исправлено

- **Склейка тредов теперь не требует ручной пересборки.** v2.7.0 ввёл связи по
  In-Reply-To, но существующие индексы не содержали поля, пока пользователь не
  запускал полный `index build`. Теперь у каждой папки есть версия схемы; обычный
  `index update` сам пересобирает папки со старой схемой при следующей
  синхронизации — связи по Message-ID появляются без ручного `build` и без
  простоя поиска (в промежутке работает откат к склейке по теме). `index status`
  показывает готовность тредов.
- **`npm audit --omit=dev` снова чистый.** Транзитивная `hono` (тянется
  HTTP-транспортом MCP SDK; stdio-сервер её не использует и в бандл она не входит)
  получила moderate-advisory; зафиксирована через `overrides` на патч-версию
  4.12.23. Рантайм не затронут.

## [2.7.0] — 2026-06-05

Minor-релиз: поисковый движок (детерминированный Layer 2, без ИИ). Без breaking
changes. Модель auth/security не менялась; индекс обратно совместим (новые поля
опциональны). Для связей цепочек по In-Reply-To нужен один `index build`.

### Добавлено

- **Фильтры в быстром поиске.** `yandex_search_fast` теперь принимает
  `from / since / before / seen / flagged`. Можно искать **только** по фильтрам
  без текста запроса (например «непрочитанные за март» → `seen=false`,
  `since="2025-03-01"`). Все поля уже были в индексе — пересборка не нужна.

### Исправлено

- **Поиск только по фильтрам возвращал пусто.** Раньше набор кандидатов строился
  исключительно из совпадений по словам, поэтому запрос, где все слова —
  фильтры, не находил ничего. Теперь при наличии фильтров без слов-для-поиска
  сканируются все письма, затем сужаются фильтром и сортируются по свежести.
- **Тест `T-B3-NO-AWAIT-01` падал на Windows** из-за CRLF в `confirm.ts`
  (брейс-матчер `/\n}\n/`). Инвариант не менялся, матчер сделан CRLF-устойчивым.

### Изменено

- **Ранжирование учитывает различимость слова (idf-взвешивание).** Совпадение по
  редкому слову (конкретное имя, «втб») ранжируется выше, чем по частому
  («счёт», «re»). Вес каждого совпавшего слова домножается на idf, нормированный
  в [0.5, 1.5], — масштабы сопоставимы с прежними бонусами при любом размере
  ящика. Без изменения схемы/диска.
- **Цепочки писем связываются по Message-ID.** `yandex_get_thread` теперь ходит
  по графу In-Reply-To (берётся из конверта IMAP бесплатно) — ловит ответы с
  изменённой темой и треды, разбитые между папками (Входящие/Отправленные), —
  плюс прежняя склейка по нормализованной теме в пределах папки. Обход идёт
  только по реальным рёбрам ответов, поэтому общий/битый Message-ID не склеивает
  чужие письма. Старые индексы без `inReplyTo` деградируют к склейке по теме
  (без регресса); полная сборка `index build` включает связи по графу.

### Известно

- Транзитивная зависимость `hono` (тянется HTTP-транспортом MCP SDK; stdio-сервер
  её не использует) имеет moderate-advisory. К коду коннектора отношения не имеет.

## [2.6.0] — 2026-06-04

Minor-релиз: упрочнение (hardening) + фундамент Layer 2 (локальный поисковый
индекс). Без breaking changes. Модель auth/security не менялась.

### Безопасность

- **Утечка пароля в ошибках закрыта (P0).** `sanitizeError` теперь вычищает
  «голый» 16-буквенный пароль приложения Яндекса из строк ошибок — раньше он
  был ниже 32-символьного порога токен-редакции и проскакивал. Это класс утечки
  из инцидента 2026-05-22. +4 теста (синтетические плейсхолдеры).
- **Безвозвратное удаление — за подтверждением.** `yandex_delete_email` с
  `permanent=true` теперь требует одноразовый 6-значный код от сервера (как
  отправка). Восстановимое удаление в Корзину (`permanent=false`) — без
  изменений. Закрывает прямое нарушение правила «destructive только через
  серверное подтверждение».
- Test-seams в `confirm.ts`/`policy.ts` закрыты guard'ом `NODE_ENV=production`.

### Качество

- **Статическая проверка типов: `npm run typecheck`.** Первый type-safety
  gate с момента перехода на esbuild (tsc отключали из-за OOM на типах MCP SDK;
  здесь — увеличенная куча + проверка только нашего кода). Сразу нашла реальный
  баг: `imapflow.search()` возвращает `false | number[]`, а код звал `.length`/
  `.slice` на результате — «работало» лишь по случайности приведения типов.
  Исправлено в `findSenders` + `searchEmails`.

### Добавлено — Layer 2 (фундамент поисковой консоли)

- **Локальный индекс писем без нативных зависимостей.** Живые сканы IMAP
  (800–1500 мс) превращаются в локальные выборки (единицы мс). Хранилище —
  обычные JSON-файлы в каталоге состояния; никакого SQLite/нативных модулей,
  чтобы не сломать единый бандл и установку через `npx -y github:`.
- **CLI: `yandex-mail-mcp index <build|update|status|drop>`.** Полная сборка,
  инкрементальная досинхронизация (по UIDVALIDITY + uidNext), статус, удаление.
- **`yandex_search_fast` (L0):** мгновенный ранжированный поиск по индексу
  (тема + отправитель, с кириллицей), с причинами совпадения.
- **`yandex_get_thread` (L0):** сборка цепочки по нормализованной теме
  (Re:/Fwd: отбрасываются).
- Оба инструмента подсказывают построить индекс, если его ещё нет, и не мешают
  живому `yandex_search_emails`. В каждую запись индекса заложено поле
  «аккаунт» — задел под мультиаккаунт без миграции.
- +20 тестов индекса (415 тестов суммарно по проекту, 0 упавших).

## [2.3.0] — 2026-05-25

Minor-релиз. Один новый L0 MCP-инструмент `yandex_stats` и опциональный
параметр `summary_only` у `yandex_list_emails`. Никаких изменений auth/security,
никаких breaking changes. Бандл вырос на ~11 КБ (2.72 МБ).

### Добавлено

- **`yandex_stats` — серверная агрегация по почтовому ящику.** L0 read-only
  инструмент. Принимает `folder`, `group_by` (массив 1-3 полей композитного
  ключа), опциональные `since`/`until` (ISO даты), `top_n` (1-1000, default 50).
  Доступно 16 полей группировки: `sender`, `sender_name`, `domain`, `year`,
  `month`, `year_month`, `weekday`, `hour`, `date`, `to_first`, `subject_prefix`,
  `subject_normalized`, `size_bucket` (4 интервала), `has_attachments`,
  `flag_seen`, `flag_flagged`. Возвращает только счётчики (несколько КБ)
  вместо envelopes (сотни КБ). Поток envelope-only IMAP-фетчей по 1000 UID
  за раз — память O(chunk), не O(folder size).

  Обнаружено когда агент при запросе «статистика по входящим, кто мне больше
  пишет по годам» исчерпал контекстный бюджет, загружая 3765 писем постранично
  через `yandex_list_emails` ради подсчёта вручную. Бридж-фикс до полноценного
  Layer 2 SQLite-индекса.

- **`summary_only: boolean` у `yandex_list_emails`.** При `true` возвращает
  усечённую форму envelope `{uid, from_email, date, subject_first_50}` вместо
  полного заголовка. Снижает вес в токенах примерно в 3-5 раз — полезно
  когда агенту нужен список писем, но не нужны CC/flags/size.

- **13 unit-тестов агрегатора** в `src/__tests__/stats.test.ts`. Все
  бакетеры, композитные ключи, top_n cap, фильтр по дате, edge cases
  (пустой iterator, отсутствующие поля envelope, цепочки `Re: Fwd: Re:`).

### Известные ограничения

- `has_attachments` всегда `'no'` в v2.3.0. Реальное определение требует
  тяжёлого `bodyStructure` fetch'а, что сломает cost-модель streaming.
  Документировано в описании инструмента. Будет решено в Layer 2 (offline
  индексация с богатой схемой).

## [2.2.1] — 2026-05-25

Patch-релиз. Включает рабочий `npx -y github:...` (раньше не работал
из-за структуры репо) и косметику в документации. Никаких изменений
auth/security, никаких изменений API, ни одного байта кода в бандле.
Полностью обратносовместим с v2.2.0.

### Добавлено

- **Корневой `package.json`-прокси.** Файл `package.json` в корне репо с
  полями `name`, `version`, `bin` (указывает на бандлы в
  `yandex-mail-mcp-desktop/dist/`) и `files`. Без `dependencies` (бандл
  самодостаточен — `esbuild --bundle` инлайнит всё, `node-notifier`
  загружается через optional dynamic import). Без `prepare` script. Это
  снимает оба блокера `npx -y github:...`: и расположение `package.json` в
  подкаталоге, и попытку прогона esbuild на машине пользователя без dev-deps.
- **`npx -y github:nizamchi/yandex-mail-connector#v2.2.1` теперь работает.**
  Удобно для быстрого `--check` или одноразового запуска без `git clone`.
  Документация в README §3 и INSTALL.md §3 (Вариант B).

### Исправлено

- **README §«Где лежат файлы».** Предложение «Файл с паролем token.json лежит
  не там — рядом с бандлом или в текущей рабочей папке» было устаревшим с
  v2.0 эпохи. Фактический resolve-порядок в `src/token.ts:128-158`:
  `YANDEX_TOKEN_FILE` env → `<state_dir>/token.json` (преферд) →
  `<project_root>/token.json` (legacy) → `<cwd>/token.json` (legacy).
  Теперь раздел описывает state-каталог как основной путь, legacy упомянуты
  отдельно.
- **INSTALL.md §3.** Убрано упоминание «структурный блокер `npx`, до v2.2.0
  переезд в корень» — переезд не понадобился, проблема решена прокси.
- **Server version sync.** `src/index.ts` McpServer-конструктор и оба
  `package.json` синхронно бампнуты до 2.2.1.

## [2.2.0] — 2026-05-22

Minor-релиз. Пять новых функций для UX и эксплуатации + смена лицензии с MIT
на PolyForm Noncommercial 1.0.0. Никаких изменений auth/security модели.
Раздаётся через `git clone + npm install --omit=dev --ignore-scripts`
(npx-from-github ещё не работает, см. структурный issue).

### ⚠️ Смена лицензии — MIT → PolyForm Noncommercial 1.0.0

Распространение коннектора теперь регулируется **PolyForm Noncommercial
License 1.0.0** ([polyformproject.org](https://polyformproject.org/licenses/noncommercial/1.0.0/)) — стандартная, написанная юристами лицензия специально для софта, который остаётся
бесплатным для личного и некоммерческого использования, но требует отдельной
платной лицензии для коммерческой перепродажи / встраивания в SaaS / использования
внутри for-profit компании для её коммерческой деятельности.

**Что разрешено бесплатно:**
- Личное использование, домашние проекты, обучение, исследования
- Некоммерческие организации (благотворительные, образовательные, гос. институты)
- Изучение, модификация, форки в некоммерческих целях

**Что теперь требует коммерческой лицензии:**
- Перепродажа коннектора / сервисов на его основе третьим лицам
- Встраивание в платный коммерческий продукт
- Использование внутри коммерческой компании для её коммерческих целей

Контакт для коммерческой лицензии: `nizamidrisov98@gmail.com`.

Существующие форки/копии до этого коммита остаются под прежним MIT — это
стандартная практика смены лицензии вперёд по таймлайну (так делают Redis,
Elastic, MongoDB, Sentry и многие другие).

Полный текст лицензии в [LICENSE](LICENSE). Развёрнутое объяснение мотивации
в секции «Лицензия» в [README.md](README.md).

### Добавлено

- **`--check` CLI flag в бандле.** `node dist/yandex-mail-mcp.js --check` запускает
  non-authenticating health-check за ~3 секунды: проверяет наличие token.json (и
  определяет тип учётных данных — app password / OAuth / heuristic detection),
  существование state-dir, валидность подписи allowlist, parseability policy-файла,
  TLS-reachability `imap.yandex.com:993` и `smtp.yandex.com:465`. **Не делает IMAP
  LOGIN** — не оставляет следов «новый вход в аккаунт» в Яндексе. Exit code 0 если
  все 7 чеков прошли, 1 если хоть один упал, 2 на внутреннюю ошибку. Реализация
  в `src/check-config.ts`.
- **MCP tool `yandex_health_check`** (L0, readonly). Та же диагностика, но
  возвращается JSON'ом изнутри MCP-сессии. Полезно для агента: при «у меня
  что-то не работает» — вызвать первым, понять состояние без коннекта к Яндексу.
- **`bin/install-slash.js` cross-platform helper.** Копирует
  `.claude/commands/*.md` в `~/.claude/commands/` (создаёт каталог если нет;
  работает на Windows/macOS/Linux). Флаги: `--force` (перезаписать), `--uninstall`.
  Используется как `node yandex-mail-mcp-desktop/bin/install-slash.js`.
- **`/ymc-update` slash-команда** для Claude Code. Файл `.claude/commands/ymc-update.md`. Проверяет есть ли на GitHub более свежая версия (`git fetch + rev-parse origin/main`), показывает changelog между HEAD и origin/main, с подтверждением юзера делает `git pull --ff-only` + `npm install --omit=dev --ignore-scripts`. **Не пушит ничего**, **не делает `git reset --hard`**, не запускает postinstall-скрипты (защита от supply-chain). Если working tree грязный — отказывается, просит закоммитить/stash.
- **GitHub Actions CI workflow** (`.github/workflows/ci.yml`). На каждый push в `main` и каждый PR — `npm install` + `npm audit --omit=dev --audit-level=high` + `npm run build` + `npm test` + smoke-test `--check`. Матрица: Node 18/20/22 на Ubuntu + Node 20 на Windows. Отдельный job «bundle drift check» сравнивает закоммиченный `dist/` со свежесобранным (информационный warning, не fail).
- **`/ymc-config` slash-команда** для Claude Code. Файл `.claude/commands/ymc-config.md`. После установки через install-slash — `/ymc-config` в Claude Code открывает интерактивный пикер уровней доступа (4 варианта стрелочками + Enter, как у GSD), записывает выбор в `~/.claude.json`. Перезапуск Claude Code после смены — обязателен (TOCTOU защита). Документация в README + INSTALL.

### Исправлено

- **Server version sync.** Раньше в `src/index.ts` было захардкожено `version:
  '2.0.0'` в McpServer-конструкторе, рассинхронизация с `package.json.version`
  начиная с v2.1.0. Теперь обе строки указывают на 2.2.0 и обновляются при каждом
  релизе.

## [2.1.3] — 2026-05-22

Polish-релиз поверх v2.1.2. Применены находки из официальной документации
Claude Code по работе с MCP-серверами. Никакого изменения auth-логики,
никакого изменения tool API, никакого изменения политики и risk-scoring.
Полностью обратносовместим с v2.1.x. Раздаётся через
`git clone + npm install --omit=dev --ignore-scripts + claude mcp add`
(пути `npx -y github:...` ещё не работают — структурный фикс
запланирован на v2.2.0).

### Добавлено

- **`instructions` на стороне MCP-сервера.** В конструктор `McpServer`
  передаётся короткая прозаическая инструкция о том, когда использовать
  этот сервер: «Yandex Mail connector — read, search, organise, and (with
  explicit auth) send email from a Yandex account…». Это позволяет
  Tool Search (Claude Code, deferred-loading by default) находить
  инструменты по упоминанию «Yandex mail / Яндекс почта / inbox / sent /
  drafts» без `alwaysLoad: true`. (новое поле, не было раньше).
- **`_meta["anthropic/maxResultSizeChars"]` на `list_emails`,
  `search_emails`, `get_email`.** Поднимает per-tool лимит вывода до
  200 000 символов (по умолчанию Claude Code режет на ~25k tokens ≈
  100k chars). Для бэндов с десятками заголовков или полных писем это
  устраняет тихие truncation'ы. Поддержка `_meta` добавлена в
  `ToolDef` interface + проброс в `server.registerTool`.

### Исправлено

- **Версия сервера синхронизирована с package.json.** Раньше в
  `index.ts` было захардкожено `version: '2.0.0'` — конфликт с
  `package.json.version` начиная с v2.1.0. Теперь `version: '2.1.3'`
  и обновляется при каждом релизе (вручную, как и `bin/yandex-mail-mcp.js`
  shebang).

### Документация

- **README.md** полностью переписан в части установки:
  - `claude mcp add` как primary path для Claude Code CLI
  - Таблица скоупов (`local` / `project` / `user`) с указанием куда пишется
    конфиг (`~/.claude.json` vs `.mcp.json`)
  - JSON-конфиг для Claude Desktop с `alwaysLoad: true` как явный
    workaround если Tool Search не находит инструменты
  - Уточнение типа токена: app password (16 строчных букв) **vs** OAuth
    (`y0_AgAAA…` префикс) — это разные механизмы
  - Warning о том что `npx -y github:...` пока не работает (package.json
    в подкаталоге)
- **INSTALL.md** переработан Шаг 3 → 4 → 5:
  - Шаг 3 — установка бандла через `git clone + npm install --omit=dev --ignore-scripts`
  - Шаг 4 — Claude Code (`claude mcp add`) как первый клиент
  - Шаг 5 — выбор YANDEX_AUTH_LEVEL (бывший Шаг 4)

## [2.1.2] — 2026-05-22

Hotfix-релиз: критическое исправление аутентификации. v2.0.0 / v2.1.0 /
v2.1.1 жёстко требовали OAuth XOAUTH2-аутентификации (`auth.accessToken` в
imapflow / `auth.type='OAuth2'` в nodemailer), но `INSTALL.md` рекомендовал
класть в поле `access_token` **пароль приложения** Яндекса (16 строчных
букв). Сервер падал с `unsupported challenge` при попытке IMAP-логина —
пользователи не могли подключиться. Раздаётся через
`npx -y github:nizamchi/yandex-mail-connector#v2.1.2`.

### Исправлено

- **App password как primary auth-путь.** `token.json` теперь поддерживает
  два поля:
  - `password` — пароль приложения Яндекса (16 строчных букв, SASL PLAIN)
  - `access_token` — OAuth-токен (XOAUTH2, для тех у кого есть OAuth-приложение Яндекса)

  `loadCredentials` парсит оба формата. `imap.ts` и `smtp.ts` ветвят
  `auth` объект в зависимости от того что задано. Среды переменных тоже
  поддерживают обе формы: `YANDEX_APP_PASSWORD` (новая) или
  `YANDEX_OAUTH_TOKEN` (legacy).
- **Backward compatibility heuristic.** Если у пользователя уже стоит
  v2.0/v2.1 token.json с паролем приложения в поле `access_token` — сервер
  определяет шейп по содержимому:
  - 16 строчных букв `[a-z]{16}` → SASL PLAIN (пароль приложения)
  - `y0_...` префикс → XOAUTH2 (OAuth token)
  - ambiguous → XOAUTH2 (preserve v2.0/v2.1 behavior)
- **Защита от обоих полей одновременно.** Если в token.json указаны и
  `password` и `access_token` — `loadCredentials` бросает ошибку с
  явным сообщением. Single-source-of-truth для credential.
- **Test isolation в `token-perm.test.ts`.** Тесты permCheck использовали
  cwd-discovery и проваливались если у разработчика стоял реальный
  `<state_dir>/token.json` (приоритет выше). Тесты теперь явно пиннят
  путь через `YANDEX_TOKEN_FILE` env var.

### Документация

- **INSTALL.md обновлён.** Шаг 1 теперь явно описывает что пароль
  приложения = 16 строчных букв, и что это нужно класть в поле
  `password`. OAuth — отдельная альтернативная секция. Env vars
  тоже задокументированы (YANDEX_APP_PASSWORD / YANDEX_OAUTH_TOKEN).
- **token.ts docstring** обновлён с двумя примерами token.json (password,
  OAuth) и legacy compat-блоком.

### Безопасность

- **Никаких изменений в threat model.** Это исправление UX-блокера, не
  security-фикса. Все рейтеры/гарды/policy/audit/HMAC-подпись/allowlist
  работают идентично v2.1.1 (тесты подтверждают: 371/377 pass, 6 skip
  unix-only, 0 fail).
- **Рекомендация ротировать пароль приложения** если он попал в
  логи/чаты при тестировании. Старый пароль отозвать в
  passport.yandex.ru → "Пароли приложений" → нужный → удалить.

## [2.1.1] — 2026-05-22

Косметический patch-релиз поверх v2.1.0. Только мелкие исправления качества
кода и одно укрепление атомарности записи при первом запуске. Никаких новых
функций, никаких изменений API, никаких изменений конфигурации. Полностью
обратносовместим с v2.1.0 — апгрейд бесшовный, переписывать `risk-policy.json`
или `token.json` не нужно. Раздаётся через
`npx -y github:nizamchi/yandex-mail-connector#v2.1.1`.

### Исправлено

- **Деление на бесконечность в подтверждении больших писем.** Если у письма
  оказывался некорректный размер (`Infinity`, `NaN` или отрицательное
  число), в reasons-блоке риска показывалось «body ~Infinity KB». Теперь
  при не-конечном размере соответствующий сигнал просто не добавляется —
  пользователь не видит мусорной строки. (W-3, коммит `f230fa3`)
- **Дублирование валидных одноразовых кодов high-risk send.** Если
  пользователь запрашивал новый код подтверждения для той же операции
  (тот же fingerprint), старый, ещё не использованный код оставался
  валидным наряду с новым. Теперь при выдаче нового кода все предыдущие
  непогашенные коды того же fingerprint автоматически помечаются как
  использованные. Изоляция между разными fingerprint'ами сохранена. Для
  forensics добавлена audit-запись `override_token_superseded`. (WR-03,
  коммит `1935d36`)
- **Удалён мёртвый guard в проверке одноразовых кодов.** В двух местах
  `consumeOverrideToken` стояла дополнительная проверка длины буфера
  перед `timingSafeEqual`, хотя длина уже гарантирована Zod-валидацией
  записи и хешированием входного токена. Guard убран, инвариант
  задокументирован в комментариях, защитный try/catch оставлен. (WR-04,
  коммит `d9f6ba7`)
- **Комментарии и терминология приведены к единому виду.** В `confirm.ts`
  явно описан scope grep-gate на дашевое написание; в `cli-trust.ts`
  отмечено осознанное отсутствие rate-limit на `--high-risk-send` (cap
  на живые токены на fingerprint = 1 уже даёт защиту, отдельный
  rate-limit вынесен в будущий operator-tunable knob); в
  `override-tokens.ts` зафиксирован инвариант lowercase-hex для
  `token_hash`; в тестах подтверждена невозможность коллизий
  module-scoped счётчика. Заголовок `override-tokens.ts` уточнён, чтобы
  «privacy isolation» не читалось как «без audit вообще». Только
  комментарии, байты бандла не изменились. (IN-01..04 + WR-05, коммит
  `c952189`)
- **Замораживание пути к `risk-policy.json` после первой загрузки.**
  `getPolicyPath()` теперь возвращает путь, зафиксированный при первом
  успешном `loadPolicy()`. Если LLM-инструмент или prompt-injection
  поменяет `YANDEX_POLICY_FILE` в середине сессии, обращение к политике
  всё равно пойдёт по исходному пути. Внутренний резолвер для самого
  `loadPolicy()` / `writePolicy()` обходит заморозку — иначе обновлять
  файл было бы нечем. Тесты сбрасывают заморозку через
  `_resetForTests()`. (M-3, коммит `9159cf4`)

### Безопасность

- **Атомарная запись ключей при первом запуске.** В `policy.ts` и
  `allowlist.ts` (а также в `override-tokens.ts` для одноразовых
  кодов) временное имя файла теперь включает `pid` и три байта
  случайных данных вместо фиксированного `<target>.tmp`. Это закрывает
  узкое окно гонки между двумя одновременно стартующими MCP-процессами
  (например, `npx` в двух терминалах или параллельные CI-задания): у
  каждого процесса свой временный файл, который не может быть
  затрётся партнёром в момент записи. Семантика «последний rename
  побеждает» сохранена — это поведение зеркального паттерна записи
  (W-2). Модули с другой моделью конкуренции (`recent-sends.ts` —
  единственный писатель, `cli-trust.ts` — hook на сбое ротации)
  остаются на фиксированном `.tmp` суффиксе, как и было. (M-1, коммит
  `21b3f93`)

### Контрольные суммы

- `dist/yandex-mail-mcp.js` (2,710,564 bytes): SHA-256 `fca1d8a45d735294ec5b420332ce9cf37ab57d17273418e9f9dac474a8eaa4a5`
- `dist/cli-trust.js` (91,919 bytes): SHA-256 `ce9d8fca566f8138b9be6a51b74449f10fbc802747e7b3d9d2c8b55b5092093c`

### Тесты

- `npm test`: 377 / 371 pass / 0 fail / 6 skip (Unix-only permission
  cases). Baseline после v2.1.0 — те же значения; изменений в
  раскладке нет. `npm audit --omit=dev`: 0 уязвимостей.

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
  2710359 bytes.

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
  dist/yandex-mail-mcp.js  97888dc5517f58a292c0903911b1e6585d35eff5081480cf9b131c8eb147fd77
  dist/cli-trust.js        10a006bd78db040533a4d76ff3e456e6c7cdb6917efd6b0475edd4ebea87d486

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

[Unreleased]: https://github.com/user/yandex-mail-connector/compare/v2.1.1...HEAD
[2.1.1]: https://github.com/user/yandex-mail-connector/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/user/yandex-mail-connector/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/user/yandex-mail-connector/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/user/yandex-mail-connector/releases/tag/v1.0.0
