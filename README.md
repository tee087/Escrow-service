# CL-Service

CL-Service is an English-language Telegram Mini App for legitimate escrow marketplace transactions. It never requests recovery phrases, private keys, banking credentials, card numbers, or CVV values.

## Local development

1. Install Node.js 22+, Docker, and a PostgreSQL 16 database (or run `docker compose up postgres -d`).
2. Copy `.env.example` to `.env`, set a high-entropy `SESSION_SECRET`, and fill Telegram values.
3. Run `npm install`, `npm run db:generate`, and `npm run db:migrate`.
4. Start the Mini App and API with `npm run dev`.
5. Open `http://localhost:5173`; Telegram itself requires an HTTPS public URL.

## Telegram setup

1. In BotFather, create a bot and place its token in `BOT_TOKEN`.
2. Configure the Mini App URL with BotFather's `/setmenubutton` or use the `/start` button served by this project. The URL must be HTTPS in production.
3. Register a webhook: `https://api.telegram.org/bot<BOT_TOKEN>/setWebhook?url=https://<your-domain>/telegram/webhook&secret_token=<TELEGRAM_WEBHOOK_SECRET>`.
4. Configure bot commands in BotFather: `start`, `help`, `profile`, `deals`.

## Payments

The included payment endpoint intentionally returns `Payment provider is not configured.` No client can mark a deal funded. Before production, implement a provider adapter that creates payments, validates signed provider webhooks, verifies the provider-side status, and atomically transitions `ACCEPTED` deals to `FUNDED`.

## Official escrow administration

Set `ADMIN_TELEGRAM_ID` to the numeric Telegram ID of the official administrator before registering that Telegram account. Only that verified account receives the `SUPER_ADMIN` role and can release a delivered or disputed deal through the administrator endpoint. Buyers and sellers cannot release funds themselves. A lawful payment provider and any required escrow/payment licensing are required before accepting real customer funds.

## Production checklist

## Vercel + Render + Neon deployment

1. Create a Neon PostgreSQL database and set its pooled connection string as `DATABASE_URL` in Render.
2. Create the Render Blueprint from `render.yaml`; set `MINI_APP_URL` to the Vercel production URL.
3. Import this repository in Vercel. Set `VITE_API_URL` to the Render HTTPS URL, then deploy `frontend` using `vercel.json`.
4. Set the same Vercel HTTPS URL as the BotFather Mini App URL and register the Render `/telegram/webhook` endpoint with Telegram.
5. Add the Vercel hostname to the backend's CORS allow-list before enabling production traffic.

- Use HTTPS, a managed PostgreSQL service, a unique long session secret, and a private `BOT_TOKEN`.
- Run migrations before deploying backend code and restrict database access to the application network.
- Configure a payment provider webhook signature, retention policy, backups, monitoring, and administrator role assignment process.
- Review rate limits, content moderation, dispute operations, refund/release policies, legal terms, privacy policy, and applicable escrow/payment regulation before accepting real funds.
