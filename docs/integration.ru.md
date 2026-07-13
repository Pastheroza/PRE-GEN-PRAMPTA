# Интеграция сторонних сервисов с PRAMPTA Licensing

Это руководство для сервисов, которые **генерируют контент с участием реальных
людей** (изображения, видео, аудио, текст, 3D) и обязаны убедиться, что
генерация лицензирована, **до** вызова модели.

PRAMPTA отвечает на один вопрос: *«разрешено ли сгенерировать этот subject в
этом контексте?»* — и возвращает **криптографически подписанное решение**,
которое можно проверить и сохранить как доказательство соответствия.

> Subject detection (распознавание, кто изображён в промпте) остаётся на стороне
> вашего сервиса. PRAMPTA проверяет авторизацию, когда вы уже знаете `subject_id`.
> Чтобы не изобретать матчинг самостоятельно, используйте **detection index +
> канонический матчер SDK** (см. раздел ниже «Subject detection: стандартный путь»).

---

## 0. Subject detection: стандартный путь

`GET /v1/subjects/index` — публичный machine-readable индекс всех регистраций:
`subject_id`, `aliases`, `status`, `visibility`. Включены **все** статусы:
withdrawn/disputed обязаны детектиться (это hard refusals), private — тоже
(их обнаружение означает «нужна лицензия»). Поддерживает `ETag` /
`If-None-Match` — кешируйте и обновляйте дёшево (Cache-Control: 5 минут).

Оба SDK содержат канонический матчер с одинаковой семантикой
(нормализация + пословное вхождение имён и алиасов):

```python
# Python
hits = pg.match_subjects(user_prompt)          # TTL-кеш индекса внутри
for h in hits:
    pg.assert_allowed(h["subject_id"], prompt=user_prompt, modality="image")
```

```ts
// TypeScript
const hits = await pg.matchSubjects(userPrompt);
for (const h of hits) {
  await pg.assertAllowed(h.subject_id, { prompt: userPrompt, modality: "image" });
}
```

Это **базовый слой** — точные имена и алиасы в тексте промпта. Fuzzy/semantic
матчинг и распознавание по изображению остаются на вашей стороне (или в
будущем платном Detect API).

---

## 1. Рекомендуемый путь: Connect AI для каждого пользователя

Для пользовательских сервисов вроде `movie.hurated.com` больше не нужно просить
оператора вручную создавать organization, provider/licensee pair или глобальный
`.env` token. Пользователь подключает сервис во вкладке `Connect AI`, а PRAMPTA
автоматически создаёт скрытую provider identity, личную licensee identity
пользователя и active pair для этой связки.

Поток:

```text
1. Сервис отправляет пользователя на prampta.com с connect_provider,
   connect_external_id и connect_return_url.
2. Пользователь логинится в PRAMPTA и нажимает Connect для сервиса.
3. PRAMPTA возвращает пользователя на connect_return_url с:
   - prampta_provider_id
   - prampta_licensee_id
   - prampta_connection_token
   - prampta_external_id
4. Сервис сохраняет prampta_licensee_id и prampta_connection_token на своём
   backend для этого пользователя.
5. Runtime verify использует обычный POST /v1/verify/:
   Authorization: Bearer <prampta_connection_token>
   X-Provider-ID: <prampta_provider_id>
   X-Licensee-ID: <prampta_licensee_id>
```

Пример начала подключения:

```text
https://prampta.com/?connect_provider=hurated-movie&connect_provider_name=Hurated%20Movie&connect_provider_domain=movie.hurated.com&connect_external_id=<service-user-id>&connect_return_url=https%3A%2F%2Fmovie.hurated.com%2Fprampta%2Fconnect
```

`prampta_connection_token` — секрет. Его нельзя хранить в браузере после
callback; сервис должен сразу сохранить его server-side и убрать из URL.

Для конкретного контракта с `movie.hurated.com` см.
[`docs/hurated-movie-handoff.md`](hurated-movie-handoff.md).

## 2. Legacy / advanced: какие учётные данные нужны

Сторонний сервис использует **два разных типа учётных данных** на двух стадиях.
Это не взаимозаменяемые вещи.

| Стадия | Учётные данные | Заголовок | Кто держит |
|---|---|---|---|
| **Настройка / управление** (однократно) | **User JWT** | `Authorization: Bearer <jwt>` | человек/аккаунт |
| **Runtime-проверка** (на каждую генерацию) | **Pair token** + ID-пары | `Authorization: Bearer <pair_token>` + `X-Provider-ID` + `X-Licensee-ID` | бэкенд генерирующего сервиса |

- **User JWT** выдаётся при логине (`POST /v1/auth/login` или `/v1/auth/google`),
  живёт по умолчанию 7 дней. Им создают организации, устанавливают пары и подают
  заявки на лицензии.
- **Pair token** выдаётся **один раз** при активации пары provider↔licensee.
  В базе хранится только его SHA-256 хэш — восстановить токен нельзя, при потере
  пару нужно переустановить.

Нельзя «просто получить токен и звать verify». Pair token существует только
после того, как пара provider↔licensee стала `active`.

---

## 3. Хосты и переменные окружения

```bash
PRAMPTA_V2_API_URL=https://api2.prampta.com     # боевой licensing API (v2)
PRAMPTA_V2_PROVIDER_ID=<provider-organization-id>
PRAMPTA_V2_LICENSEE_ID=<licensee-organization-id>
PRAMPTA_V2_PAIR_TOKEN=<pair-token-issued-on-pair-activation>
```

Эти переменные ставятся **в backend генерирующего сервиса, не в браузере**.
Если по какой-то причине из браузера нужно вызывать API напрямую — добавьте
origin приложения в `CORS_ORIGINS` боевого окружения PRAMPTA.

Публичные MCP endpoints для v2:

```text
Streamable HTTP  https://mcp2.prampta.com/mcp
SSE              https://mcp2.prampta.com/sse
Health           https://mcp2.prampta.com/healthz
```

Не переключайте существующие интеграции с `api.prampta.com`,
`api.prampta.hurated.com`, `mcp.prampta.com` или `mcp.prampta.hurated.com`, пока
эти проекты не мигрированы явно. Эти хосты остаются legacy PRAMPTA stack.

Опциональные переменные для сервисов, которые сами распознают subjects по
конфигу:

```bash
PRAMPTA_V2_SUBJECT_DISCOVERY=1
PRAMPTA_V2_SUBJECTS_JSON='[{"subject_id":"subject-id","aliases":["Display Name","Alias"]}]'
PRAMPTA_V2_SUBJECT_ALIASES='subject-id=Display Name,Alias;other-id=Other Name'
PRAMPTA_V2_DEFAULT_SUBJECT_ID=
```

`PRAMPTA_V2_SUBJECT_DISCOVERY=1` означает: сервис берёт список зарегистрированных
subjects из `GET /v1/subjects/` и сам делает alias matching. Если discovery
выключен, используйте `PRAMPTA_V2_SUBJECTS_JSON` или `PRAMPTA_V2_SUBJECT_ALIASES`
как локальный fallback.

Discovery может возвращать не только имена, но и визуальные описания:

```json
{
  "subject_id": "asset-id",
  "aliases": ["Display Name"],
  "visual_description": "Distinctive visual traits of the asset.",
  "visual_descriptions": ["Distinctive visual traits of the asset."]
}
```

Интеграция должна сначала искать `subject_id`/`aliases`, а если имени нет —
сравнивать визуальное описание промпта с `visual_descriptions` на высоком
пороге уверенности. Визуальное совпадение только выбирает `subject_id`; право на
генерацию всё равно даёт только `POST /v1/verify/`.

> Все пути ниже даны относительно `API_V1_PREFIX = /v1`.

---

## 4. Однократная настройка legacy pair (требует User JWT)

```text
1. Аккаунт        POST /v1/auth/register  →  JWT
2. Организации    POST /v1/organizations/  (provider и licensee)
3. Пара           POST /v1/pairs/establish  →  access_token (pair token)
```

В web UI этот legacy-поток больше не показывается обычным пользователям. Он
оставлен как API-only путь для advanced/server-to-server integrations: создать
organization, создать provider/licensee pair, сохранить выданный runtime token.
Если token потерян, используйте `Rotate token` на активной паре — старый token
сразу перестанет работать, новый будет показан один раз.

### 3.1. Создать организации

Обе стороны пары должны существовать как организации, иначе `establish`
вернёт 404.

```http
POST /v1/organizations/
Authorization: Bearer <jwt>
Content-Type: application/json

{ "org_id": "movie-hurated-com", "display_name": "Hurated Movie",
  "org_type": "provider", "domain": "hurated.com" }
```

`org_type`: `provider` | `licensee` | `both`. Организация с `provider` не может
выступать как licensee и наоборот (`both` — может в обе стороны).

### 3.2. Установить пару

```http
POST /v1/pairs/establish
Authorization: Bearer <jwt>
Content-Type: application/json

{ "provider_id": "movie-hurated-com", "licensee_id": "acme-licensee" }
```

Два сценария:

- **Self-pair** — вы состоите в обеих организациях → пара активна сразу, ответ
  содержит `access_token`.
- **Two-party** — организации разные → создаётся `pending`-пара **без токена**.
  Член организации-контрагента подтверждает:

  ```http
  PATCH /v1/pairs/{pair_id}/confirm
  Authorization: Bearer <counterparty-jwt>
  ```

  и **только этот ответ** содержит `access_token`.

```json
{
  "pair_id": "...",
  "access_token": "64-hex-chars",   // показывается ОДИН раз — сохраните в секрет-менеджер
  "token_type": "bearer",
  "status": "active",
  "provider_id": "movie-hurated-com",
  "licensee_id": "acme-licensee"
}
```

Управление парой: `PATCH /v1/pairs/{id}/reject`, `DELETE /v1/pairs/{id}`
(revoke), `GET /v1/pairs/`, `GET /v1/pairs/pending`.

---

## 4. Runtime-проверка лицензии (требует Pair token)

Перед каждым вызовом модели:

1. Распознайте `subject_id` (на вашей стороне): по имени/alias или по
   высокоуверенному совпадению визуального описания.
2. Посчитайте **SHA-256 hex** от точного текста промпта.
3. Вызовите `POST /v1/verify/`.
4. Генерируйте **только** если `allowed == true`.
5. Сохраните подписанное решение рядом с метаданными ассета.

```bash
PROMPT='Scarlett Johansson walking in the city'
PROMPT_HASH="$(printf '%s' "$PROMPT" | sha256sum | awk '{print $1}')"

curl -sS "$PRAMPTA_V2_API_URL/v1/verify/" \
  -H "Authorization: Bearer $PRAMPTA_V2_PAIR_TOKEN" \
  -H "X-Provider-ID: $PRAMPTA_V2_PROVIDER_ID" \
  -H "X-Licensee-ID: $PRAMPTA_V2_LICENSEE_ID" \
  -H "Content-Type: application/json" \
  -d "{
    \"subject_id\": \"subject-id-from-detection\",
    \"prompt_hash\": \"$PROMPT_HASH\",
    \"model\": \"sora-2\",
    \"modality\": \"video\",
    \"intended_use\": {
      \"channel\": \"commercial\",
      \"product_name\": \"movie.hurated.com\",
      \"categories\": [],
      \"territory\": \"US\"
    }
  }"
```

- `prompt_hash` **обязателен** — без него решение «несвязанное» и отклоняется
  (`PG_MISSING_PROMPT_HASH`). Сам промпт в PRAMPTA не отправляется, только хэш.
- Rate limit: 200 запросов / 60 секунд на пару.

### Ответ — подписанное решение

```json
{
  "schema_version": "pg.decision.v1",
  "decision_id": "dec_...",
  "nonce": "32-hex",                 // одноразовый, см. §6
  "allowed": true,
  "reason": null,
  "subject_id": "...",
  "licensee_id": "...",
  "provider_id": "...",
  "license_id": "lic_...",
  "prompt_hash": "...",
  "obligations": {},
  "watermark_payload": "sha256-hex",
  "is_hard_refusal": false,
  "issued_at": 1780000000,
  "expires_at": 1780000300,          // TTL 300 секунд
  "operator_key_id": "pg-ed25519:...",
  "operator_signature": "..."
}
```

Решение само-верифицируемо: проверьте `operator_signature` против публичного
ключа оператора (`GET /version` или endpoint `/keys`), убедитесь, что
`prompt_hash` совпадает с отправленным, и что `expires_at` не в прошлом.
Готовая проверка есть в SDK (`prampta` для Python, `@prampta/sdk` для TS) —
рекомендуется использовать его, а не делать verify руками.

### Коды отказа (`allowed: false`)

```text
PG_MISSING_PROMPT_HASH  Не передан prompt_hash.
PG_NO_PAIR              Pair token отсутствует / неверен / пара не active.
PG_NO_SUBJECT           Subject не зарегистрирован.
PG_SUBJECT_PENDING      Subject на модерации.
PG_SUBJECT_DISPUTED     Subject оспаривается.            (hard refusal)
PG_SUBJECT_WITHDRAWN    Subject отозван.                 (hard refusal)
PG_SUBJECT_OPTED_OUT    Subject отказался от генерации.  (hard refusal)
PG_NO_LICENSE           Нет активной лицензии под эту пару subject/licensee.
PG_INVALID_SIGNATURE    Подпись хранимой лицензии не прошла проверку. (hard refusal)
PG_SCOPE_VIOLATION      Лицензия есть, но use вне scope/channel/territory/category.
PG_IMMUTABLE_DENIAL     Категория в неотменяемом запрете лицензии. (hard refusal)
PG_EXTENSION_REFUSED    Отказ по расширению (например, volume cap).
```

`is_hard_refusal: true` — жёсткий блок, повторять/обходить нельзя. Прочие отказы
означают «лицензии пока нет» — можно отправить пользователя в поток запроса (§5).

---

## 5. Получение одобрения на новую лицензию

Когда verify вернул `PG_NO_LICENSE`, нужно получить лицензию. Поток состоит из
**двух разных шагов** — важно не путать:

### Шаг 1 — Заявка на лицензию (переговоры)

```http
POST /v1/license-requests/
Authorization: Bearer <user-jwt>          # JWT, НЕ pair token
Content-Type: application/json

{
  "subject_id": "subject-id",
  "use_case": "commercial",                // commercial | editorial | personal | educational | research
  "purpose": "Licensed assets for movie.hurated.com",
  "duration_days": 365,
  "message": "User requested generation with this subject."
}
```

Владелец субъекта одобряет/отклоняет:

```http
PATCH /v1/license-requests/{request_id}
Authorization: Bearer <subject-owner-jwt>

{ "status": "approved", "response_message": "OK" }
```

### Шаг 2 — Выпуск самой лицензии (криптографический)

> **Одобрение заявки само по себе НЕ создаёт действующую лицензию.**
> Это лишь согласие сторон. `verify` пропускает только при наличии активной
> **подписанной** лицензии.

Действующая лицензия — это объект `License`, подписанный **двусторонне**:
- подпись субъекта (Ed25519) над телом лицензии,
- контрподпись оператора PRAMPTA.
- опциональное поле `asset_visual_description` хранит визуальные признаки
  лицензируемого ассета и включается в signed license body, если заполнено.

Выпуск идёт через `POST /v1/licenses/...` (подпись субъекта; реализации
browser-signed и presigned флоу теперь объединены в `backend/app/api/licenses.py`).
После этого `verify` начнёт возвращать `allowed: true`
для покрытого scope.

Итоговая цепочка для новой лицензии:
```
license-request (заявка) → approved (согласие) → подписанная License (выпуск) → verify: allowed
```

---

## 6. Anti-replay (nonce)

Каждое решение содержит одноразовый `nonce`. Если ваша архитектура должна
гарантировать, что одно решение не используется для нескольких генераций,
проверяйте nonce:

```http
POST /v1/verify/check-nonce?nonce=<nonce>
Authorization: Bearer <pair_token>
X-Provider-ID: ...
X-Licensee-ID: ...
```

Возвращает `{ "consumed": true|false }`. Требует валидной пары (защита от
перебора). Rate limit 30/60s.

---

## 7. Метаданные ассета

Для каждого сгенерированного ассета сохраните доказательство:

```json
{
  "prampta_decision_id": "dec_...",
  "prampta_license_id": "lic_...",
  "prampta_subject_id": "subject-id",
  "prampta_prompt_hash": "sha256-hex",
  "prampta_operator_key_id": "pg-ed25519:...",
  "prampta_operator_signature": "...",
  "prampta_watermark_payload": "sha256-hex"
}
```

Этого достаточно, чтобы позже независимо доказать, что генерация была авторизована
(подпись оператора проверяется его публичным ключом даже спустя годы — ключи
хранятся в истории).

---

## 8. Минимальный пример (Node)

```ts
import crypto from "node:crypto";

export async function verifyPramptaLicense(input: {
  subjectId: string;
  prompt: string;
  model: string;
  modality: "image" | "video" | "audio" | "text" | "3d";
  categories?: string[];
}) {
  const promptHash = crypto.createHash("sha256").update(input.prompt).digest("hex");

  const res = await fetch(`${process.env.PRAMPTA_V2_API_URL}/v1/verify/`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${process.env.PRAMPTA_V2_PAIR_TOKEN}`,
      "X-Provider-ID": process.env.PRAMPTA_V2_PROVIDER_ID!,
      "X-Licensee-ID": process.env.PRAMPTA_V2_LICENSEE_ID!,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      subject_id: input.subjectId,
      prompt_hash: promptHash,
      model: input.model,
      modality: input.modality,
      intended_use: { channel: "commercial", product_name: "movie.hurated.com",
                      categories: input.categories ?? [] },
    }),
  });

  if (!res.ok) throw new Error(`PRAMPTA verify failed: HTTP ${res.status}`);
  const decision = await res.json();

  if (!decision.allowed) {
    // PG_NO_LICENSE → отправить пользователя в поток запроса лицензии (§5)
    return { allowed: false, reason: decision.reason, hard: decision.is_hard_refusal, decision };
  }
  return { allowed: true, decision };
}
```

> Для продакшена предпочтительнее официальный SDK — он сам проверяет подпись
> оператора, TTL и привязку prompt_hash, и fail-closed по умолчанию.
