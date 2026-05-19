# Changelog

Все значимые изменения этого проекта документируются в этом файле.

Формат основан на [Keep a Changelog 1.1.0](https://keepachangelog.com/ru/1.1.0/),
проект придерживается [Semantic Versioning](https://semver.org/lang/ru/).

## [Unreleased]

Работа над Layer 1 — milestone «v2 Secure Ship». Цель — превратить
функциональный коннектор v1 в безопасный пакет, пригодный для раздачи
коллегам через `npx`. Завершена 1 из 8 фаз.

### Добавлено

- Single-file бандл `dist/yandex-mail-mcp.js` (~2.5 МБ, tarball ~858 КБ),
  собираемый одной командой `npm run build` через esbuild.
- `bin`-entry `yandex-mail-mcp` в `package.json` — точка запуска для
  `npx -y github:user/repo#vX.Y.Z`.
- npm-скрипт `prepare: npm run build` — бандл собирается автоматически при
  установке из git.
- `package-lock.json` под контролем версий для воспроизводимых сборок.
- Класс `ConnectionManager` и singleton `getConnectionManager()` в
  `src/imap.ts` — единая точка управления IMAP-соединениями (Hook 4,
  подготовка к Layer 2+: IDLE, connection pooling, reconnect).
- 9 внутренних call-site IMAP-операций переведены на
  `getConnectionManager().withClient(fn)`.

### Изменено

- nodemailer обновлён с 6.9.8 до 8.0.7. API остался байт-совместим с
  использованием в `smtp.ts`, кодовых изменений не потребовалось.
- esbuild обновлён с 0.21 до 0.25.

### Безопасность

- Закрыты CVE-2025-14874 и CVE-2025-13033 в nodemailer.
- Закрыт GHSA-67mh-4wv8-2f99 в esbuild.
- `npm audit --omit=dev` теперь показывает 0 уязвимостей.

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

[Unreleased]: https://github.com/user/yandex-mail-connector/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/user/yandex-mail-connector/releases/tag/v1.0.0
