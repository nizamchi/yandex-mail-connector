# Silver Balance — продуманный профиль моделей для GSD

> Универсальный профиль распределения моделей (Opus / Sonnet / Haiku) по
> субагентам [Get Shit Done (GSD)](https://github.com/anthropics/get-shit-done)
> framework. Альтернатива дефолтным `balanced` и `golden`, построенная на
> ROI-анализе: куда вложить opus так, чтобы получить максимум качества за
> разумный токен-бюджет.
>
> **Файл написан как stand-alone отчёт** — можно шейрить любому, кто
> работает с GSD, независимо от проекта.

---

## TL;DR

| Профиль | Opus агентов | Cost vs balanced | Когда брать |
|---|---|---|---|
| `budget` | 0 | 0.7× | прототипы, learning |
| `balanced` (default) | 2 | **1.0×** | non-critical projects |
| **`silver-balance` (этот)** | **13** | **~1.4×** | **универсальный shipping-grade** |
| `golden` | 21 | ~3.5× | text-heavy / research-driven |

Silver Balance — это **golden с исправленной verification-инверсией и
без overspend на research**. 13 точечных оверрайдов поверх `balanced`,
которые поднимают именно те агенты, у которых ROI на opus самый высокий:
**последние гейты перед merge** (verifier, code-reviewer, security-auditor)
и **фундаментальные артефакты** (roadmapper, assumptions-analyzer), плюс
несколько open-ended judgment ролей (debugger, code-fixer, doc-writer).

Конкретно **не поднимаем** `gsd-executor` — он top-1 token-расходчик с
самым слабым opus-edge, защищаем его opus'ом на downstream-гейтах.

---

## Содержание

1. [Почему дефолтные профили не подходят](#1-почему-дефолтные-профили-не-подходят)
2. [Метрический фреймворк](#2-метрический-фреймворк)
3. [Эмпирика: кто сколько токенов жрёт](#3-эмпирика-кто-сколько-токенов-жрёт)
4. [ROI-таблица всех агентов](#4-roi-таблица-всех-агентов)
5. [Финальный silver-balance профиль](#5-финальный-silver-balance-профиль)
6. [Per-agent обоснования](#6-per-agent-обоснования)
7. [Tradeoff vs альтернативы](#7-tradeoff-vs-альтернативы)
8. [Когда отклоняться от silver](#8-когда-отклоняться-от-silver)
9. [Как применить](#9-как-применить)
10. [Effort: вторая ось ROI](#10-effort-вторая-ось-roi-на-которую-тоже-надо-смотреть)

---

## 1. Почему дефолтные профили не подходят

GSD по умолчанию предлагает три профиля: `budget`, `balanced`, `golden`.
Каждый — глобальный rubber-stamp по всем 33 субагентам.

### Проблема №1: balanced слишком экономный для shipping work

В `balanced` opus получают **только 2 агента**: `gsd-planner` и
`gsd-eval-planner`. Всё остальное — sonnet. Это значит, что:

- Создание плана идёт на opus, **но проверка плана** (`gsd-plan-checker`) —
  на sonnet. Если sonnet прощает дырку в плане, opus-executor её исполнит.
- **Финальная верификация фазы** (`gsd-verifier`) — sonnet. Последний
  гейт перед merge на средней модели.
- **Code review** — sonnet. Adversarial bug-hunting лучше делает opus.
- **Security аудит** — sonnet. Для security-critical проектов это
  риск-протокол с дырой.

### Проблема №2: golden содержит явную инверсию

В `golden` opus получают агенты-creators (planner, executor, code-reviewer,
code-fixer, security-auditor), **но verification-агенты остаются sonnet**:
`gsd-verifier`, `gsd-plan-checker`, `gsd-nyquist-auditor`,
`gsd-integration-checker`, `gsd-ui-checker`, `gsd-ui-auditor`,
`gsd-doc-verifier`.

Это парадокс: создание артефакта получает мощную модель, а **проверка
того же артефакта** — слабее. Если creator-opus делает ошибку, sonnet-
verifier её скорее пропустит, чем поймает. Качество системы equal
weakest link, и слабое звено — verification.

### Проблема №3: golden платит за research, где opus бесполезен

В `golden` все `*-researcher` агенты на opus. Researcher читает 20-50
страниц веб-документации и пишет structured summary в RESEARCH.md. Это
**text-synthesis**, а не judgment. Opus здесь даёт минимальный edge при
максимальном token-cost (researchers — top-3 расходчики из-за input
объёма).

### Что нужно

Профиль, который:
1. **Чинит verification-инверсию** — opus туда, где «последний гейт» (нет
   downstream recovery).
2. **Не платит за research** — где opus даёт ~0 edge.
3. **Защищает фундаментальные артефакты** (ROADMAP, CONTEXT, REQUIREMENTS)
   — opus в редких агентах, где ошибка каскадирует во все фазы вперёд.
4. **Балансирует executor** — самого дорогого агента оставляем на sonnet,
   защищая его opus'ом на review/verify.

---

## 2. Метрический фреймворк

ROI для каждого агента считается через три ортогональные оси:

```
ROI = edge(opus vs sonnet) × consequence(error) × (1 - recoverability) / token_cost
```

### Ось 1: Тип работы (edge)

| Тип | Opus edge | Примеры |
|---|---|---|
| **Open-ended judgment** | высокий | debugger, code-reviewer, verifier — нужно сформулировать гипотезы, оценить trade-offs |
| **Generative reasoning** | средне-высокий | planner, executor, doc-writer — создание нового из открытого input |
| **Verification-rubric (open)** | высокий | security-auditor, integration-checker — rubric, но требует judgment |
| **Verification-rubric (closed)** | низкий | doc-verifier, ui-checker — механическая сверка по чек-листу |
| **Text-synthesis** | низкий | researchers, doc-synthesizer — distillation из прочитанного |
| **Classification** | ~0 | doc-classifier, framework-selector — отнесение к категории |

### Ось 2: Стоимость ошибки (consequence)

- **Very high**: ошибка уходит в production, ловится только пользователями
  (security-auditor пропустил CVE, verifier пропустил недоделанный fix).
- **High**: ошибка ломает milestone (roadmapper неправильно разложил фазы,
  planner сделал нерабочий план).
- **Medium**: ошибка тормозит phase (executor споткнулся на edge case,
  doc-writer написал кривой README).
- **Low**: ошибка ловится сразу (classifier неправильно отнёс файл).

### Ось 3: Recoverability (downstream-гейты)

- **None** — это последняя точка контроля. Verifier, code-reviewer на
  merge — после них код идёт в shipping.
- **Low** — есть один downstream-гейт, но он специализированный (например,
  plan-checker → execute → verify, но verify смотрит другую плоскость).
- **Medium** — есть несколько downstream-гейтов (executor → tests +
  code-reviewer + verifier).
- **High** — ошибка ловится автоматически (build fails, tests fail).

### Ось 4: Token cost

Considering total cost per milestone (frequency × tokens per invocation):

- **Very low**: rare agent + small context (security-auditor 30k × 1-2 = 60k)
- **Low**: per-phase agent + small context (verifier 25k × 8 = 200k)
- **Medium**: per-phase agent + medium context (code-reviewer 50k × 8 = 400k)
- **High**: per-phase agent + large context (planner 90k × 8 = 720k)
- **Very high**: per-phase agent + max context + many tool calls
  (**executor 100k × 8 = 800k+** — крупнейший)

---

## 3. Эмпирика: кто сколько токенов жрёт

Замеры из реальных сессий (приблизительно, очень условно):

| Агент | Tokens/invoke | Invokes/milestone | Total | Tier |
|---|---|---|---|---|
| **gsd-executor** | ~100k | per-phase (8-15) | **~800k-1.5M** | **TOP-1** |
| **gsd-planner** | ~90k | per-phase | ~720k-1.4M | **TOP-2** |
| **gsd-phase-researcher** | ~150-300k | rare (если включён) | ~600k | TOP-3 |
| gsd-code-reviewer | ~50k | per-phase | ~400k | high |
| gsd-code-fixer | ~40k | 0-1×/phase | ~200k | medium |
| gsd-verifier | ~25k | per-phase | ~200k | medium |
| gsd-plan-checker | ~15k | per-phase | ~120k | low |
| gsd-roadmapper | ~80k | **1× per milestone** | ~80k | low (rare!) |
| gsd-assumptions-analyzer | ~40k | rare | ~80k | low |
| gsd-doc-writer | ~30k | rare | ~60k | low |
| gsd-security-auditor | ~30k | rare | ~60k | low |
| gsd-nyquist-auditor | ~30k | rare | ~60k | low |
| gsd-debugger | ~50k | per-incident (0-3) | varies | varies |
| gsd-integration-checker | ~30k | per-milestone | ~30k | very-low |
| gsd-ui-auditor / eval-auditor | ~40k | rare (только UI/AI фазы) | varies | conditional |

**Ключевое наблюдение**: executor + planner вместе ≈ 50-60% всего
token-бюджета проекта. Opus на executor поднимает общий cost проекта
**примерно в 1.5-2× раза** относительно sonnet-executor'а.

Opus ratio к sonnet'у — примерно 5× по cost в API. То есть opus-executor
вместо sonnet — добавляет к проекту ~3.2-4M токенов opus-equivalent.

---

## 4. ROI-таблица всех агентов

Полная таблица: 33 агента, что они делают, и почему мы поднимаем или
оставляем.

★★★★★ = критично поднять на opus (low cost × high edge × no recovery)  
★★★★ = стоит поднять (хорошее ROI)  
★★★ = граница, project-dependent  
★★ = низкий ROI, оставить sonnet  
★ = opus здесь почти не даёт edge, sonnet или ниже

| Агент | Что делает | Тип работы | Cost tier | Edge | Consequence | Recover | **ROI** | **Silver** |
|---|---|---|---|---|---|---|---|---|
| `gsd-verifier` | Goal-backward verification фазы → VERIFICATION.md | Verification-open | low | high | high | **none** | ★★★★★ | **opus** |
| `gsd-plan-checker` | Проверка PLAN.md до execution | Verification-open | low | high | high (bad plan = wasted phase) | low | ★★★★★ | **opus** |
| `gsd-code-reviewer` | Adversarial bug/security review исходников | Verification-open | medium | high | high | low | ★★★★★ | **opus** |
| `gsd-security-auditor` | Verify threat mitigations из PLAN | Verification-rubric (open) | low | high | very-high (CVE) | none | ★★★★★ | **opus** |
| `gsd-roadmapper` | Создаёт ROADMAP.md из requirements | Generative | low (1× per milestone) | high | very-high (cascades) | none | ★★★★★ | **opus** |
| `gsd-nyquist-auditor` | Генерация тестов под gaps валидации | Verification-open + generative | low | high | high | low | ★★★★ | **opus** |
| `gsd-integration-checker` | Cross-phase E2E проверка wiring'а | Verification-open | very-low | high | high | low | ★★★★ | **opus** |
| `gsd-debugger` | Scientific-method investigation багов | Verification-open / generative | medium | high | high | medium | ★★★★ | **opus** |
| `gsd-eval-auditor` | Audit AI eval coverage против AI-SPEC | Verification-rubric (open) | rare | high (when fires) | high | low | ★★★★ | **opus** |
| `gsd-ui-auditor` | 6-pillar визуальный audit фронта | Verification-open | rare | high (when fires) | high | low | ★★★★ | **opus** |
| `gsd-assumptions-analyzer` | Анализ codebase'а для discuss-phase | Verification-rubric | low | medium | medium-high (shapes CONTEXT) | medium | ★★★ | **opus** |
| `gsd-code-fixer` | Применяет fix'ы из REVIEW.md | Generative | medium | medium-high | medium | high (re-review) | ★★★ | **opus** |
| `gsd-doc-writer` | Пишет README, ARCHITECTURE, etc | Generative | low | medium | medium-high (libs/CLIs) | high | ★★★ | **opus** |
| `gsd-planner` | Создаёт PLAN.md из CONTEXT.md | Generative | high | medium-high | high | medium (plan-checker ловит) | ★★★ | opus *(в balanced уже)* |
| `gsd-eval-planner` | Designs eval-стратегию для AI-фаз | Generative | rare | high | high | medium | ★★★★ | opus *(в balanced уже)* |
| **`gsd-executor`** | **Пишет код по PLAN, atomic commits** | **Generative** | **very-high** | **medium** (если plan детальный) | high | **medium-high** (tests + reviewer + verifier) | **★★** | **sonnet** |
| `gsd-debug-session-manager` | Оркестратор debug-сессии | Orchestration | medium | low (real thinking в debugger) | medium | high | ★★ | sonnet |
| `gsd-ui-researcher` | UI-SPEC design contract | Generative / structured-extraction | rare | medium | medium | medium | ★★★ | sonnet |
| `gsd-pattern-mapper` | PATTERNS.md из codebase'а | Structured-extraction | low | low | low | high | ★ | sonnet |
| `gsd-phase-researcher` | Research перед planning | Structured-extraction / text-synthesis | very-high (опционален) | low | medium | high | ★★ | sonnet |
| `gsd-project-researcher` | Research перед roadmap | Text-synthesis | very-high | low | medium | high | ★★ | sonnet |
| `gsd-domain-researcher` | Research domain для AI-фаз | Text-synthesis | high | low | medium | high | ★★ | sonnet |
| `gsd-ai-researcher` | Research AI-фреймворка | Structured-extraction | high | low | medium | high | ★★ | sonnet |
| `gsd-advisor-researcher` | Research одного gray-area decision | Text-synthesis | medium | low | low | high | ★ | sonnet |
| `gsd-intel-updater` | Обновляет .planning/intel/ | Structured-extraction | low | low | low | high | ★ | sonnet |
| `gsd-research-synthesizer` | Свод 4 researcher → SUMMARY | Text-synthesis | medium | low | low | high | ★ | sonnet |
| `gsd-doc-synthesizer` | Merge ingested ADR/PRD | Text-synthesis | medium | low | low | high | ★ | sonnet |
| `gsd-doc-classifier` | Classify doc as ADR/PRD/SPEC/DOC | Classification | very-low | ~0 | very-low | high | ★ | sonnet (или haiku) |
| `gsd-doc-verifier` | Сверка doc-утверждений с кодом | Verification-rubric (closed) | low | low | low | high | ★ | sonnet |
| `gsd-codebase-mapper` | Map проекта → STACK/ARCH/QUALITY | Structured-extraction | medium | low | low | high | ★ | sonnet |
| `gsd-ui-checker` | UI-SPEC completeness checklist | Verification-rubric (closed) | low | low | low | high | ★ | sonnet |
| `gsd-framework-selector` | Score AI/LLM frameworks | Classification | low | low | medium | high | ★★ | sonnet |
| `gsd-user-profiler` | Анализ session messages | Classification | rare | low | very-low | high | ★ | sonnet |

---

## 5. Финальный silver-balance профиль

Записать в `.planning/config.json` (или в template'е для всех новых
проектов: `~/.claude/get-shit-done/templates/config.json`):

```json
{
  "model_profile": "balanced",
  "model_overrides": {
    "_profile_name": "silver-balance",
    "_profile_doc": "../SILVER-BALANCE-PROFILE.md",

    "gsd-roadmapper":            "opus",
    "gsd-assumptions-analyzer":  "opus",

    "gsd-verifier":              "opus",
    "gsd-plan-checker":          "opus",
    "gsd-code-reviewer":         "opus",
    "gsd-security-auditor":      "opus",
    "gsd-nyquist-auditor":       "opus",
    "gsd-integration-checker":   "opus",

    "gsd-eval-auditor":          "opus",
    "gsd-ui-auditor":            "opus",

    "gsd-debugger":              "opus",

    "gsd-code-fixer":            "opus",
    "gsd-doc-writer":            "opus"
  }
}
```

**13 overrides** поверх `balanced` (в котором `gsd-planner` и
`gsd-eval-planner` уже на opus → итого 15 агентов на opus, 18 на sonnet).

`model_profile: balanced` остаётся как **fallback** для агентов, не
перечисленных в `models`. Sonnet — дефолт для всего text-synthesis /
classification / structured-extraction.

---

## 6. Per-agent обоснования

### Группа A: Last-line verification gates (★★★★★)

Это агенты, после которых **нет downstream-страховки**. Если они пропустят
ошибку — она уходит в shipping. Edge от opus здесь максимальный (adversarial
reasoning, edge-case detection), а cost минимальный (рare запуск или
короткий context).

- **`gsd-verifier`** — единственная точка где проверяется, что фаза
  **достигла своей цели**, а не просто «таски завершены». Goal-backward
  анализ требует open-ended judgment: «удовлетворяет ли это поведение
  success criteria из ROADMAP?». На sonnet легко прокатывают «формально
  выполнили, но не работает» кейсы.

- **`gsd-plan-checker`** — гейт между PLAN.md и executor'ом. Если план
  плохой, executor (особенно sonnet-executor в silver) исполнит мусор.
  Стоимость пропуска: вся фаза проваливается. Opus здесь страхует
  executor'а.

- **`gsd-code-reviewer`** — adversarial bug + security review исходников
  перед merge. Это последний шанс поймать subtle issues (SQL injection,
  TOCTOU, missing error handling). Opus заметно сильнее sonnet'а в
  hostile-thinking режиме.

- **`gsd-security-auditor`** — verify, что mitigation'ы из threat
  model реально реализованы в коде. Пропущенная mitigation = real CVE.
  Запускается редко (раз на milestone) → opus тут почти бесплатен.

### Группа B: Фундаментальные артефакты (★★★★★)

Эти агенты **создают артефакты, которые цементируют все downstream
решения**. Ошибка в roadmap или CONTEXT.md размножается на все 8 фаз.
Запуск редкий → opus тут бесплатен по cost, и **никакой downstream-гейт
не поправит фундаментальную ошибку**.

- **`gsd-roadmapper`** — генерирует ROADMAP.md (разбивку milestone'а на
  фазы) из REQUIREMENTS.md. Запуск 1× per milestone. Если roadmap'er
  пропустит requirement или неправильно разложит зависимости — это
  каскадирует на всё. ROI огромный: ~80k токенов один раз против
  потерянных недель работы.

- **`gsd-assumptions-analyzer`** — анализирует codebase под фазу и
  формирует assumption-список с confidence-rating'ом. Этот список идёт в
  CONTEXT.md, на основе которого планируется фаза. Если assumption
  неверный, plan строится на воздухе. Sonnet здесь склонен к
  «over-confident» rating'ам.

### Группа C: Conditional critical (★★★★)

Срабатывают только в специализированных фазах (UI / AI). Но когда
срабатывают — последняя проверка дизайн-контракта или eval-strategy.
Если в проекте нет UI/AI фаз — эти агенты не запускаются и не стоят
ничего; включаем заранее, чтобы **когда понадобятся — были на opus**.

- **`gsd-eval-auditor`** — audit AI eval coverage. BLOCKER при провале.
- **`gsd-ui-auditor`** — 6-pillar визуальный audit фронта. Эстетика +
  дизайн-контракт требуют опыта; sonnet может не заметить регрессии
  visual hierarchy или дизайн-токены.

### Группа D: Open-ended judgment (★★★★)

Агенты, где работа — формирование гипотез и причинно-следственный анализ.
Это **canonical opus territory**.

- **`gsd-debugger`** — scientific-method investigation. Формирование
  falsifiable hypotheses, проектирование экспериментов, root-cause
  analysis. Opus заметно сильнее на multi-step causal chains.

- **`gsd-nyquist-auditor`** — генерирует тесты под validation gap'ы.
  Tests требуют понимания, что именно мы проверяем и какие edge cases
  релевантны. Это generative + judgment.

- **`gsd-integration-checker`** — verify cross-phase wiring. «Этот phase
  ожидает X из того phase'а, на самом деле он отдаёт Y». Открытое
  reasoning о data flows.

### Группа E: Generative + shipping consequence (★★★)

Эти агенты пишут output, который **уходит к пользователю или в код**.
Их работа recoverable (можно переписать), но качество влияет на UX/UI/
docs/code напрямую.

- **`gsd-code-fixer`** — применяет fix'ы из REVIEW.md. Когда fix не
  тривиален (требует адаптации под текущее состояние кода), opus заметно
  стабильнее. Re-review всё равно случится, но без opus'а можем уйти в
  ping-pong цикл.

- **`gsd-doc-writer`** — README, ARCHITECTURE.md, INSTALL.md. Для
  libraries/CLIs/API — это **пользовательский интерфейс продукта**.
  Кривая документация = реальный cost (users bounce). Sonnet справляется
  с шаблонами, но opus лучше держит tone и structure для нетривиальных
  кейсов.

### Группа F: Намеренно sonnet (★★)

#### Самое спорное решение: `gsd-executor` остаётся sonnet

**Это центральный tradeoff в silver-balance.** Аргументы:

**За opus (мы НЕ выбираем):**
- Generative reasoning, пишет shipping код
- Handles deviations от плана
- Самая «обычная» работа разработчика — кажется естественным дать opus

**За sonnet (мы выбираем):**
- **Top-1 по token-расходу.** Бамп на opus = +1.5-2× к total cost
  milestone'а. Это самая дорогая ручка во всём конфиге.
- **Самый слабый opus-edge среди ship-load-bearing агентов.** Когда
  PLAN.md от opus-planner'а детальный, executor в основном механически
  следует ему. Tricky decisions выпадают в deviation-handling, но и
  там опыт показывает, что sonnet справляется.
- **Лучше всего ловится downstream-гейтами.** В silver-balance мы уже
  поставили opus на code-reviewer, verifier, plan-checker — три гейта
  поверх каждого executor-output'а. Если executor споткнётся, мы
  поймаем это **тремя независимыми opus-моделями**, а не одной.
- **Tests + build являются automatic recovery.** Failing test ловит
  большую часть classical executor-mistakes до того, как
  code-reviewer вообще доходит до файла.

**Когда поднимать на opus вручную:**
- проект меньше 3 фаз (общий cost маленький, нет смысла экономить)
- distrust к code-reviewer (например, если намеренно отключил)
- kernel / crypto / payment processing — где ошибка ловится только в
  prod, и tests + review недостаточно
- одиночный разработчик без code review — некому ловить за executor'ом

#### Researchers все на sonnet

- `gsd-phase-researcher`, `gsd-project-researcher`, `gsd-domain-researcher`,
  `gsd-ai-researcher`, `gsd-advisor-researcher` — работа = read 20-50
  страниц + написать structured summary. Это **text-synthesis**, не
  judgment. Opus здесь даёт минимальный edge при максимальном cost
  (researchers — top-3 расходчики по token volume из-за input size'а).

#### Classification и synthesis на sonnet

- `gsd-doc-classifier`, `gsd-research-synthesizer`, `gsd-doc-synthesizer`,
  `gsd-framework-selector`, `gsd-user-profiler` — pattern matching и
  template-filling. Opus не даёт edge.

#### Rubric-checkers (closed checklist) на sonnet

- `gsd-doc-verifier`, `gsd-ui-checker` — «существует ли файл X?»,
  «заполнены ли все 6 pillars?». Mechanical. Sonnet справляется.

#### Прочее

- `gsd-pattern-mapper`, `gsd-codebase-mapper`, `gsd-intel-updater` —
  structured-extraction по шаблону. Sonnet достаточно.
- `gsd-debug-session-manager` — orchestrator над `gsd-debugger`. Реальное
  thinking происходит в debugger'е (на opus); manager только
  диспетчеризует.
- `gsd-ui-researcher` — generates UI-SPEC. Hybrid (text-synthesis +
  немного design judgment). Sonnet справляется, opus marginal edge.

---

## 7. Tradeoff vs альтернативы

### Cost (приблизительно)

| Профиль | Opus | Sonnet | Haiku | Cost ratio |
|---|---|---|---|---|
| budget | 0 | 22 | 11 | 0.7× |
| balanced | 2 | 28 | 3 | **1.0×** baseline |
| **silver-balance** | **13 (+2 default = 15)** | **18** | **0** | **~1.4×** |
| golden | 21 | 12 | 0 | ~3.5× |
| all-opus | 33 | 0 | 0 | ~5× |

### Качество по разрезам

| Аспект | balanced | silver | golden | all-opus |
|---|---|---|---|---|
| Plan quality | high | high | high | high |
| **Plan checking** | medium | **high** | medium | high |
| Execution speed | high | high | medium | medium |
| Execution quality | medium | medium | high | high |
| **Code review depth** | medium | **high** | high | high |
| **Verification rigor** | medium | **high** | medium | high |
| Security audit | medium | **high** | high | high |
| Research breadth | high | high | high | high |
| Research depth | medium | medium | high | high |
| Doc quality | medium | high | high | high |

**Silver-balance** — заметно лучше `balanced` по всем «gate» метрикам,
сравним с `golden` по quality, и **в 2.5× дешевле** `golden`.

`Golden` выигрывает только в «execution quality» (opus-executor) и
«research depth» (opus-researchers). Если эти два аспекта критичны для
конкретного проекта — стоит делать точечные оверрайды поверх silver, а
не переключаться на golden целиком.

---

## 8. Когда отклоняться от silver

Silver-balance — универсальный default. Но иногда нужно поправить:

### Поднять `gsd-executor` на opus, если:
- проект small (<3 фаз)
- code review отключён / делается людьми, а не автоматически
- security / safety-critical (kernel, crypto, payment, healthcare)
- ml-pipeline где executor пишет нетривиальные numerical operations

### Опустить агенты обратно на sonnet, если:
- **проект чисто research-driven** (написать paper, исследовать
  framework) — code-fixer, doc-writer можно оставить на sonnet, всё
  равно output читает один человек
- **прототип / spike** — все meta-quality gates на sonnet, важна скорость

### Поднять researcher-ов на opus, если:
- проект **критически зависит от research breadth** — выбор фреймворка
  для production startup'а, оценка нового AI-модели для критического
  use case
- domain-specific knowledge нужен (legal, medical, financial)

### Использовать `haiku` для:
- `gsd-doc-classifier` если ingest'ишь огромную пачку документов
  (классификация per-file, scales linearly)

---

## 9. Как применить

### Project-level (только текущий проект)

В `.planning/config.json` проекта добавить секцию `"model_overrides"` (см.
[раздел 5](#5-финальный-silver-balance-профиль)). GSD читает её при
каждом запуске subagent'а.

### User-level default (для всех новых проектов)

Добавить ту же секцию в template:

```
~/.claude/get-shit-done/templates/config.json
```

Template копируется при `/gsd-new-project`, и новый проект сразу
получает silver-balance.

### Проверка применения

```bash
gsd-sdk query config-get model_overrides
```

Должно вернуть JSON с per-agent оверрайдами. Если возвращает «Key not
found» — overrides не применились.

```bash
gsd-sdk query init.plan-phase 2
```

В выводе JSON смотри поля `planner_model`, `executor_model`,
`verifier_model`, `checker_model` — они должны соответствовать silver-
маппингу.

---

## 10. Effort: вторая ось ROI, на которую тоже надо смотреть

Выбор модели (opus vs sonnet) — это одна ручка. У Claude Code есть
вторая: **`effortLevel`** в `~/.claude/settings.json` (`low | medium |
high`). Управляет thinking budget'ом, который модель тратит **до**
генерации ответа.

**Текущее ограничение харнеса (проверено 2026-05-19):**

- Effort — **глобальная** настройка CC, применяется ко всем
  invocations: main agent + все subagents.
- В каталоге GSD `runtimeTierDefaults.claude` поля `reasoning_effort`
  **нет** (есть только у `codex`, `gpt-5.x`). Это значит **GSD не
  пробрасывает per-agent effort для Claude runtime** — даже если бы мы
  захотели в `model_overrides` написать `"gsd-verifier": "opus@high"`,
  схема такого не поддерживает.
- Frontmatter субагентов (`~/.claude/agents/gsd-*.md`) поля для effort
  тоже не содержит.
- Вывод: **сейчас нельзя задать разный effort разным субагентам.**
  Выбирать приходится один уровень глобально.

Это значит — та же ROI-математика, что и для моделей, но грубее: один
коэффициент thinking budget'а множится на все 33 агента.

### Эффект effort'а на разные типы работы

| Тип работы (см. ось 1) | low | medium | high | best ROI |
|---|---|---|---|---|
| Open-ended judgment (verifier, code-reviewer, debugger) | поверхностно | adequate | реальный edge | **high** |
| Generative shipping (executor, code-fixer) | рискованно | safe | marginal | **medium** |
| Generative planning (planner, roadmapper) | mediocre plan | usable | thorough | **medium-high** |
| Rubric verification (plan-checker rubric items, doc-verifier) | mostly fine | fine | overkill | **low-medium** |
| Text-synthesis (researchers, doc-synthesizer) | fine | fine | **waste** | **low-medium** |
| Classification (doc-classifier, user-profiler) | fine | overkill | waste | **low** |

Картина зеркальна модели: agents, которые выигрывают от opus, выигрывают
и от high effort. Agents, которым достаточно sonnet, от high effort
ничего не получают и просто тратят thinking tokens.

### Token cost effort'а (приблизительно)

`reasoning_effort=high` относительно `medium` повышает **per-call cost**
заметно (точные коэффициенты Anthropic не публикует, но эмпирически
2-4× thinking tokens на сложных задачах). Эффект **компаундируется** с
выбором модели: opus+high — самая дорогая комбинация в CC; sonnet+low —
самая дешёвая.

Для silver-balance это значит:

- На opus-агентах (13 шт.): high effort — это где их edge раскрывается
  максимально, но это самые расходы.
- На sonnet-агентах (20 шт., многие — researchers с большим input'ом):
  high effort — это **двойная переплата** (большой input × больший
  thinking budget × низкий edge).

### ROI таблица для выбора единственного effort'а

Учитывая, что **все 33 агента получают одинаковый effort**:

| Effort | Opus агенты (13) | Sonnet агенты (20) | Net ROI | Когда выбрать |
|---|---|---|---|---|
| **low** | теряем edge на judgment, ради которого подняли модель | подходит большинству | негативный — обнуляет silver-balance | прототипы, дешёвые эксперименты |
| **medium** | adequate, edge большей частью раскрывается | хорошо для researchers + adequate для остального | **положительный, сбалансированный** | **default для silver-balance** |
| **high** | максимум edge на верификации/debug'е/code-review | waste на researchers и classifiers | смешанный — выигрыш от 13 агентов, переплата за 20 | quality-critical work, security audits, release-fazes |

### Рекомендация

**Default для silver-balance: `effortLevel: medium`** в
`~/.claude/settings.json`.

Аргументы:

1. **Силовой множитель уже встроен в выбор модели.** Поднимая 13
   агентов на opus, мы уже купили основной кусок «больше думать там,
   где это важно». Effort даёт инкрементальный edge, не основной.
2. **Sonnet-агенты (researchers, synthesizers) — 20 из 33** — на high
   тратят thinking tokens впустую. На medium они работают так же
   качественно, как на high.
3. **Cost напрямую компаундируется.** medium → high это +2-4× thinking
   tokens на каждом из 33 агентов, а не только на тех, где это
   оправдано.
4. **High окупается только в специфических контекстах:** code-review
   крупного PR, security audit перед release, hardcore debugging
   неуловимого бага. Для таких задач — переключаться вручную через
   `/effort high` перед запуском, потом возвращать `medium`.

**Когда временно переключиться на high:**
- Перед `/gsd-code-review` на security-critical phase'е
- Перед `/gsd-debug` для нетривиального бага
- Перед финальным `/gsd-verify-work` milestone'а
- Если запускаешь `gsd-security-auditor` отдельно
- В режиме `/gsd-audit-milestone` перед закрытием версии

**Когда временно опустить на low:**
- Большой `/gsd-ingest-docs` (50+ файлов) — classification work, high
  только тратит токены
- Map-codebase на крупном репо — heavy read, structured extraction
- Любая чисто-research фаза, где идёт сбор фактов

### Будущая возможность (feature request)

Идеальный мир — это GSD расширяет схему:

```json
"model_overrides": {
  "gsd-verifier":  { "model": "opus",   "effort": "high" },
  "gsd-executor":  { "model": "sonnet", "effort": "medium" },
  "gsd-researcher":{ "model": "sonnet", "effort": "low" }
}
```

Технически у Anthropic API parameter `reasoning_effort` существует
(он применяется к Codex runtime в GSD-каталоге уже). Но в Claude
runtime GSD его не прокидывает. Это **gap в GSD CLI**, не в Anthropic
API. Возможный github issue для GSD core.

До тех пор — **medium как глобальный default** для silver-balance,
manual toggle перед quality-critical задачами.

---

## Авторство и происхождение

Профиль выведен из:
- Анализа GSD `bin/shared/model-catalog.json` (system defaults)
- Чтения всех 33 субагент-описаний в `~/.claude/agents/gsd-*.md`
- Эмпирических замеров token volume в реальных сессиях
- ROI-формулы `edge × consequence × (1 - recoverability) / cost`

Не привязан к конкретному стеку или домену. Должен быть стабильным как
universal default для **shipping-grade GSD projects** независимо от
языка / фреймворка / типа артефакта.

Возможные будущие версии (`gold-balance`, `bronze-balance`) могут
варьироваться вокруг этой основы для специфических workload'ов
(research-heavy, frontend-heavy, etc.).
