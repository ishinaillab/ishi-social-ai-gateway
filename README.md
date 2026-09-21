# Ishi Social AI Gateway 1.1.0

Secure transport gateway between Ishi Nail Lab's social channels and the existing AI Engine chatbot.

Version 1.1 keeps the original asynchronous ManyChat bridge and adds a production synchronous Chatfuel endpoint. AI Engine remains the single conversational brain; this plugin does not duplicate Ishi's prompt, Knowledge, Easy MCP, or LatePoint logic.

## Architecture

### Chatfuel

```text
Instagram
  ↓
Chatfuel
  ↓
Ishi Chatfuel Bridge (Node)
  ↓ HTTPS + dedicated Bearer token
POST /wp-json/ishi-social-ai/v1/respond
  ↓
AI Engine chatbot
  ↓
Knowledge / Easy MCP / LatePoint
  ↓
JSON reply
  ↓
Chatfuel bridge
  ↓
Instagram
```

### Legacy ManyChat

```text
Social channel
  ↓
ManyChat
  ↓
POST /wp-json/ishi-social-ai/v1/message
  ↓
Action Scheduler / WP-Cron
  ↓
AI Engine chatbot
  ↓
ManyChat sendContent
```

The ManyChat path remains asynchronous because its external-request timeout is shorter than a complete AI/tool turn can be.

## What changed in 1.1

- Added synchronous `POST /respond` for Chatfuel.
- Added a **separate Chatfuel bridge credential**. Do not reuse the Chatfuel API token.
- Added durable, concurrency-safe idempotency backed by a WordPress database table.
- Added persistent handoff state storage.
- Replaced transient-only rate counters for the AI path with atomic database counters.
- Added a stable plugin-owned HMAC secret for opaque conversation/chat identifiers so WordPress salt rotation does not unexpectedly break conversation continuity.
- Added strict JSON and opaque-identifier validation.
- Added `Cache-Control: no-store` / `Pragma: no-cache` on gateway responses.
- Added structured, non-sensitive AI failures.
- Preserved the original ManyChat endpoint and delivery behavior.
- Uses AI Engine's supported PHP chatbot API:
  `simpleChatbotQuery( $botId, $message, [ 'chatId' => $chatId ], true )`.

## Requirements

- WordPress 6.9+
- PHP 8.1+
- AI Engine with the configured Ishi chatbot available
- AI Engine Discussions enabled when persistent conversation history is desired
- Chatfuel bridge app for the synchronous Instagram transport

The production site currently uses PHP 8.3, which satisfies this plugin's requirement.

## Installation / upgrade

1. Back up WordPress and the database.
2. Install/replace the existing **Ishi Social AI Gateway** plugin with v1.1.0.
3. Activate the plugin. The upgrade routine creates/updates the required database tables automatically.
4. Go to **Settings → Ishi Social AI Gateway**.
5. Confirm the exact **AI Engine chatbot ID** used by Ishi.
6. Generate a **Chatfuel Bridge Token** and copy it immediately.
7. Keep the existing legacy gateway token if the ManyChat integration is still in use.

The Chatfuel token is shown only once. WordPress stores only its SHA-256 hash.

## Chatfuel synchronous endpoint

Method:

```text
POST
```

URL:

```text
https://povnailstudio.com/wp-json/ishi-social-ai/v1/respond
```

Headers:

```text
Authorization: Bearer <ISHI CHATFUEL BRIDGE TOKEN>
Content-Type: application/json
Accept: application/json
```

Request:

```json
{
  "channel": "instagram",
  "contact_id": "CHATFUEL_CONTACT_ID",
  "message_id": "CHATFUEL_MESSAGE_ID",
  "message": "Do you have slots tomorrow?"
}
```

For v1, the synchronous route intentionally accepts **Instagram only** and requires `message_id`.

Normal response:

```json
{
  "ok": true,
  "reply": "Ishi's reply",
  "handoff": false
}
```

Handoff response:

```json
{
  "ok": true,
  "reply": "",
  "handoff": true
}
```

### Idempotency

The first request atomically claims `channel + message_id` before rate limiting or AI Engine.

If the same completed message is submitted again within the idempotency TTL, the gateway returns the stored response and does **not** invoke AI Engine again.

A simultaneous duplicate that arrives while the first request is still processing receives HTTP `409`. A failed AI request can be retried safely.

Only HMAC hashes of social identifiers are stored in the idempotency/state/rate tables; message text and AI reply text are not written to normal logs.

## Conversation continuity

The plugin derives an opaque stable AI Engine `chatId` from the social channel + contact ID using HMAC-SHA256 and a plugin-owned server secret.

The raw Chatfuel contact ID is not inserted into AI instructions.

If AI Engine Discussions are enabled, AI Engine can use that stable `chatId` to restore/persist the chatbot discussion using its normal chatbot pipeline.

## Human handoff

The state endpoint remains:

```text
POST /wp-json/ishi-social-ai/v1/state
```

It uses the **legacy gateway token** for backward compatibility.

Body:

```json
{
  "channel": "instagram",
  "contact_id": "123456789",
  "state": "human_active"
}
```

Supported states:

- `ai_active`
- `human_required`
- `human_active`

When the stored state is not `ai_active`, `/respond` returns `handoff: true` without calling AI Engine.

Chatfuel remains the primary authority for live operator takeover. The Node bridge also re-checks Chatfuel conversation status before it sends an AI reply. WordPress state is a secondary fail-safe.

There is also a server-side filter for deterministic escalation rules:

```php
apply_filters( 'ishi_social_ai_handoff_required', false, $payload, $reply );
```

The plugin deliberately does **not** parse free-form AI prose for magic handoff phrases.

## Rate limits

Rate limits are evaluated only after idempotency has been claimed, so harmless duplicate delivery does not consume another paid AI turn.

Defaults:

- 12 AI requests/minute per social contact
- 120 AI requests/minute globally

Both are configurable in **Settings → Ishi Social AI Gateway**.

## Legacy ManyChat endpoint

Existing endpoint:

```text
POST /wp-json/ishi-social-ai/v1/message
```

It continues to accept the legacy social payload and queues AI work through Action Scheduler when available, otherwise WP-Cron.

The final response is still delivered through ManyChat's Public API.

## Health endpoint

```text
GET /wp-json/ishi-social-ai/v1/health
```

Use the legacy gateway token.

It reports non-secret readiness information including:

- plugin/schema version
- AI Engine PHP API readiness
- Chatfuel bridge token readiness
- legacy gateway token readiness
- ManyChat key readiness
- queue backend

## Server-side secrets

Recommended production configuration keeps third-party credentials out of the database where practical.

Supported constants include:

```php
define( 'ISHI_SOCIAL_MANYCHAT_API_KEY', '...' );
define( 'ISHI_SOCIAL_GATEWAY_TOKEN_HASH', 'sha256-hash-here' );
define( 'ISHI_SOCIAL_CHATFUEL_TOKEN_HASH', 'sha256-hash-here' );
define( 'ISHI_SOCIAL_CHAT_ID_SECRET', 'long-random-secret-here' );
```

Do not reuse:

- Chatfuel API token
- OpenAI API key
- Easy MCP token
- PayMongo credentials
- Short.io credentials
- WordPress password

as the Chatfuel bridge token.

## Data/storage

v1.1 creates:

- `{prefix}ishi_social_ai_requests` — hashed durable idempotency ledger
- `{prefix}ishi_social_ai_states` — hashed persistent handoff state
- `{prefix}ishi_social_ai_rates` — hashed rate-limit counters

Expired rows are cleaned lazily at most once per hour when the synchronous endpoint receives traffic.

The plugin does not store raw Chatfuel contact/message IDs in these tables.

## Required pre-production tests

Keep the Node bridge disabled until all of these pass:

1. **Authentication** — missing/wrong Chatfuel bridge token is rejected.
2. **Normal AI request** — valid Instagram payload returns `ok: true`, a non-empty `reply`, and `handoff: false`.
3. **Idempotency** — send the exact same `message_id` twice; the second request returns the stored response without another AI turn.
4. **Concurrent duplicate** — a duplicate while the first is still running is rejected as already processing.
5. **Handoff** — set the conversation to `human_active`; `/respond` returns `handoff: true` with an empty reply and does not invoke AI.
6. **Resume** — set the same conversation back to `ai_active`; new message IDs can reach AI again.
7. **Oversized message** — more than 4,000 characters is rejected before AI Engine.
8. **Unsupported channel** — the Chatfuel synchronous endpoint rejects anything other than Instagram.

Only after these pass should Hostinger set:

```text
ISHI_BRIDGE_ENABLED=true
```
