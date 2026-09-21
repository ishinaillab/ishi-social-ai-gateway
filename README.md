# Ishi Social AI Gateway 1.0.0

Secure asynchronous bridge between ManyChat and the existing Ishi AI Engine chatbot.

## Why it is asynchronous

ManyChat External Request currently has a hard 10-second timeout. A full AI turn may need knowledge retrieval and LatePoint/MCP tool calls, so the inbound request is acknowledged immediately and queued. The worker then calls AI Engine internally and sends the final reply back through the ManyChat Public API.

## Architecture

Instagram / Messenger / WhatsApp → ManyChat → `/wp-json/ishi-social-ai/v1/message` → queue → AI Engine `simpleChatbotQuery()` → Easy MCP / LatePoint as needed → ManyChat `sendContent` → client.

## Security

- Dedicated bearer token for ManyChat → Ishi gateway.
- Gateway token is stored only as a SHA-256 hash.
- ManyChat API key stays server-side.
- Conversation IDs are HMAC-hashed before they are supplied to AI Engine.
- Requests are rate-limited before AI calls.
- Message IDs are de-duplicated when available.
- Full ManyChat contact records are not required.
- Human takeover state can disable AI calls per conversation.

## Install

1. Upload and activate the ZIP in WordPress.
2. Go to **Settings → Ishi Social AI Gateway**.
3. Confirm the AI Engine Bot ID. `default` is correct only if your Ishi chatbot actually uses that ID.
4. Generate the Gateway Token and copy it immediately.
5. Generate a ManyChat Account Public API key in **ManyChat → Settings → API**.
6. Recommended: put the ManyChat key in `wp-config.php` instead of the database:

```php
define( 'ISHI_SOCIAL_MANYCHAT_API_KEY', 'YOUR_MANYCHAT_API_KEY' );
```

7. In AI Engine, enable **Discussions** and set **History Strategy = Automatic** for the Ishi chatbot.

## ManyChat inbound External Request

Use a ManyChat **Make External Request** action.

Method:

`POST`

URL:

`https://povnailstudio.com/wp-json/ishi-social-ai/v1/message`

Headers:

- `Authorization: Bearer YOUR_GATEWAY_TOKEN`
- `Content-Type: application/json`

Body conceptually:

```json
{
  "channel": "instagram",
  "contact_id": "<ManyChat Contact/User ID variable>",
  "message_id": "<incoming message ID when available>",
  "first_name": "<First Name variable>",
  "language": "<Language variable>",
  "message": "<Last Text Input variable>"
}
```

Use ManyChat's variable picker rather than manually guessing variable syntax.

`message_id` is optional. When omitted, the gateway uses a short fallback de-duplication window based on contact + message text.

The endpoint responds quickly with:

```json
{
  "accepted": true,
  "status": "queued",
  "handoff": false
}
```

ManyChat does not need to map an AI reply from this request. The final reply is sent asynchronously through the ManyChat Public API.

## Human handoff state

Endpoint:

`POST /wp-json/ishi-social-ai/v1/state`

Body:

```json
{
  "channel": "instagram",
  "contact_id": "123456789",
  "state": "human_active"
}
```

Set `state` to `ai_active` when AI should resume. Both calls use the same Bearer gateway token.

When `human_active`, inbound messages are acknowledged but no AI query is made.

## Health check

`GET /wp-json/ishi-social-ai/v1/health`

Use the same Bearer token. It reports whether AI Engine is callable, whether the ManyChat API key exists, and whether Action Scheduler or WP-Cron is being used for the queue.

## Queue

The plugin prefers Action Scheduler when available (WooCommerce installs it). Otherwise it falls back to WP-Cron.

## AI context

The gateway injects only trusted, minimal social metadata into AI Engine instructions:

- social channel
- first name, when supplied
- platform language, when supplied

It does not expose the ManyChat contact ID to the model.

## ManyChat policy

ManyChat remains responsible for Meta's messaging-window enforcement. The gateway does not bypass platform restrictions.
