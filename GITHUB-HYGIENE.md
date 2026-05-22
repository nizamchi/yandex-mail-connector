# GitHub Hygiene Checklist

> Чеклист по официальным правилам docs.github.com. Сверять **перед каждым**
> переходом «новый репо» / «первый пуш» / «релиз» / «инцидент с секретом».
>
> Источники:
> - docs.github.com/en/get-started/git-basics/ignoring-files
> - docs.github.com/en/repositories/releasing-projects-on-github/about-releases
> - docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository
> - docs.github.com/en/code-security/getting-started/best-practices-for-preventing-data-leaks-in-your-organization

---

## Pre-Flight — ДО первого `git add` в новом репо

- [ ] **Определена visibility:** public / internal / private. Для private — расслабленнее, для public — строжайший фильтр контента.
- [ ] **Корневой `.gitignore` создан и содержит:**
  - Credentials: `token.json`, `*.pem`, `*.key`, `.env`, `.env.*`, `*.secrets.json`
  - Build artifacts: `node_modules/`, `dist/` (если решено что bundle идёт через release asset; иначе явный whitelist через `files:` в package.json)
  - Runtime state: `*.log`, `audit.jsonl`, `allowlist.json`, локальные DB-файлы
  - OS/editor: `.DS_Store`, `Thumbs.db`, `.vscode/`, `.idea/`, `*.swp`
  - **Если репо public:** `.planning/`, `CLAUDE.md`, `*-PROMPT.md`, любые рабочие docs которые не предназначены для пользователя
- [ ] **`.git/info/exclude`** использован для **личных** ignore-правил, которые не шарятся с командой (вместо subdir-gitignore)
- [ ] **Repo settings проверены:**
  - Secret scanning: **enabled**
  - Push protection: **enabled** (блокирует push с обнаруженными секретами)
  - Branch protection on `main`: enabled (require PR, status checks)
  - Default branch установлен
- [ ] **Один корневой `.gitignore`**, без дубликатов в subdir. Если нужны subdir-specific правила — оформить через `path/*` в root.

---

## Pre-Push — перед `git push origin main` в публичный репо

- [ ] **Audit что трекается:** `git ls-files | grep -E 'planning|PROMPT|CLAUDE|todo|notes|drafts'` — должно быть пусто (если public).
- [ ] **`git diff HEAD~5..HEAD`** на наличие случайных credentials (eyeballed: ничего с `secret`, `password`, `token`, `key`, `api`).
- [ ] **Размер репо измерен:** `du -sh .git/` — должен расти линейно с осмысленным контентом, не от закоммиченных бинарей.
- [ ] **Distribution model понят:**
  - `npx -y github:user/repo#tag` — клонирует репо целиком, нужен `prepare` script. Bundle в git **оправдан** (но потяжелит history).
  - `npm install package` — npm publish с `--provenance`. Bundle в release asset / npm tarball, **не в git**.
  - `gh release download` — bundle строго в release asset.

---

## Release Creation — `gh release create`

- [ ] **Tag — semver vX.Y.Z** (`gh release create v2.0.0 --title "v2.0.0" --notes-file CHANGELOG.md`)
- [ ] **Tag signed:** `git tag -s v2.0.0 -m "Secure release"` с GPG/SSH key (supply-chain hygiene)
- [ ] **Pre-release flag** если beta/RC: `--prerelease`
- [ ] **Draft strategy** для immutable releases: `--draft` → attach assets → publish
- [ ] **Compiled artifacts → release assets**, не в git:
  - `gh release upload v2.0.0 dist/yandex-mail-mcp.js`
  - Лимит: 2 GiB per file, 1000 assets per release
- [ ] **SHA256 sums** компилируемых artifact'ов в release notes (для verification пользователем)
- [ ] **Release notes:** что нового, breaking changes, migration steps, link на CHANGELOG.md и SECURITY.md
- [ ] **`--generate-notes`** если хочется auto-generated changelog из PR titles, иначе `--notes-file`

---

## NPM Publishing (если применимо)

- [ ] **`--provenance` flag:** `npm publish --provenance` (SLSA-3 attestation через GitHub Actions)
- [ ] **`files:` whitelist в package.json:** только `["dist/", "README.md"]`, никаких `src/`, `.planning/`, `node_modules/`
- [ ] **`npm pack --dry-run`** перед `publish` — увидеть точный tarball contents
- [ ] **Версия package.json** соответствует git tag
- [ ] **`.npmignore`** **не** использовать — `files:` whitelist надёжнее (whitelist > blacklist)

---

## Incident Response — credentials/sensitive leaked

⚠️ `git revert` **бесполезен** — original commit остаётся в истории и в reflog. Secret scanning найдёт его всё равно.

- [ ] **Revoke compromised credential immediately** (rotate API key, regenerate token, etc.) — это первый шаг ВСЕГДА
- [ ] **`git filter-repo`** для удаления файла/пути из всей истории:
  ```
  git filter-repo --invert-paths --path .planning/ --force
  git push --force origin main
  ```
- [ ] **`git filter-repo --replace-text`** для удаления конкретной строки/regex (если в большом файле осталась одна строчка с секретом):
  ```
  echo 'sk-XXX==>***REVOKED***' > replacements.txt
  git filter-repo --replace-text replacements.txt
  ```
- [ ] **Force-push** разрешён только если репо новый и нет клонов. Если есть клоны — coordinate с владельцами или soft-removal (commit удаления, не переписка истории)
- [ ] **GitHub secret scanning report API** для credential providers (через partner program) автоматически revoke'нет ключ у вендора
- [ ] **DMCA takedown** если случайно скопирован third-party код и нужна экстренная takedown
- [ ] **Post-incident:** включить push protection если не было, добавить custom secret patterns если scanner не поймал тип ключа

---

## Repository Visibility

- [ ] **Org-level setting:** «Restrict repository creation to private/internal» в org settings (предотвращает случайное создание public)
- [ ] **«Allow changing repository visibility to public»** disabled у новых members — public → private одно-направленная защита
- [ ] **Convert public → private** при первом же сомнении. Лучше избыточно private чем нечаянно public.
- [ ] **Не пушить private repo content в public mirror** без full git audit + filter-repo

---

## Anti-Patterns (никогда не делать)

| ❌ Anti-pattern | ✅ Правильно |
|---|---|
| `git revert` для удаления секрета из истории | `git filter-repo` + force-push (если безопасно) |
| Subdir `.gitignore` дублирует root | Один root `.gitignore`, `.git/info/exclude` для личного |
| Commit `dist/` всё время + `git log` массивно растёт | `prepare: npm run build` + release asset, либо whitelist через `files:` |
| `git add .` без проверки что включается | `git status` → review → targeted `git add path/file` |
| Public push без `git ls-files \| grep -i secret` audit | Pre-push audit обязателен для public |
| Internal docs (`.planning/`, threat models) в public репо | Внутреннее — в `.gitignore` ДО первого пуша |
| Unsigned release tags на security-критичный release | `git tag -s v2.0.0` (GPG/SSH signed) обязательно |
| Bundle 2.5 MB в git вместо release asset | `gh release upload v2.0.0 dist/bundle.js` |
| Polling secret scanning alerts вручную | Webhook → revoke automation |

---

## Project-Specific Notes (Yandex Mail MCP)

- **Distribution model:** `npx -y github:user/repo#tag` — поэтому `dist/yandex-mail-mcp.js` **оправданно** в git. Альтернатива (release asset) требует ручного `gh release download` от пользователя, что ломает npx UX.
- **`prepare: npm run build`** уже добавлен — если решим перейти на npm publish без commit'а dist, prepare триггерится при install у пользователя.
- **`.planning/`** в этом репо коммитится в `main` локально, но **должен** быть в `.gitignore` для публичного зеркала. См. memory `feedback_publication_hygiene` — прецедент 2026-05-22.
- **Signed tag** для каждого release: `git tag -s v2.X.Y -m "..."`.
- **CHANGELOG.md** в release notes ссылается на это файл, плюс SHA256 бандла.

---

## Quick Reference

```bash
# Создать релиз с binary asset
gh release create v2.0.0 \
  --title "v2.0.0 — Secure Foundation" \
  --notes-file CHANGELOG.md \
  --target main

gh release upload v2.0.0 dist/yandex-mail-mcp.js

# Signed tag (если ещё не создан)
git tag -s v2.0.0 -m "Secure Foundation release"
git push origin v2.0.0

# Incident: remove file from full history
git filter-repo --invert-paths --path .planning/ --force
git push --force origin main

# Pre-push audit
git ls-files | grep -iE 'token|secret|password|\.env|\.planning' | head -20

# What npm pack would include (dry run)
npm pack --dry-run
```

---

*Last updated: 2026-05-22. Based on official docs.github.com pages read 2026-05-22.*
