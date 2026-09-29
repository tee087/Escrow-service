import 'dotenv/config';
import crypto from 'node:crypto';
import argon2 from 'argon2';
import Fastify, { FastifyRequest } from 'fastify';
import cookie from '@fastify/cookie';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import { PrismaClient, DealStatus, Role } from '@prisma/client';
import { z } from 'zod';

const db = new PrismaClient();
const app = Fastify({ logger: true });
const sessionSecret = process.env.SESSION_SECRET || '';
if (sessionSecret.length < 32) throw new Error('SESSION_SECRET must contain at least 32 characters.');
await app.register(cookie, { secret: sessionSecret });
await app.register(helmet);
await app.register(rateLimit, { max: 100, timeWindow: '1 minute' });

type AuthRequest = FastifyRequest & { user: { id: string; role: Role } };
const hashToken = (token: string) => crypto.createHash('sha256').update(token).digest('hex');
const recoveryCodes = () => Array.from({ length: 8 }, () => crypto.randomBytes(5).toString('hex').toUpperCase().match(/.{1,5}/g)!.join('-'));
async function authenticate(request: FastifyRequest, reply: any) {
  const token = request.cookies.session;
  if (!token) return reply.code(401).send({ error: 'Authentication required.' });
  const session = await db.session.findFirst({ where: { tokenHash: hashToken(token), expiresAt: { gt: new Date() } }, select: { user: { select: { id: true, role: true } } } });
  if (!session) return reply.code(401).send({ error: 'Session expired.' });
  (request as AuthRequest).user = session.user;
}
async function createSession(userId: string, reply: any) {
  const token = crypto.randomBytes(32).toString('base64url');
  await db.session.create({ data: { userId, tokenHash: hashToken(token), expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 14) } });
  reply.setCookie('session', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/', maxAge: 60 * 60 * 24 * 14 });
}
function verifyInitData(initData: string) {
  const token = process.env.BOT_TOKEN;
  if (!token) return null;
  const values = new URLSearchParams(initData); const receivedHash = values.get('hash'); values.delete('hash');
  if (!receivedHash) return null;
  const check = [...values.entries()].sort(([a],[b]) => a.localeCompare(b)).map(([key,value]) => `${key}=${value}`).join('\n');
  const key = crypto.createHmac('sha256', 'WebAppData').update(token).digest();
  const calculated = crypto.createHmac('sha256', key).update(check).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(calculated), Buffer.from(receivedHash))) return null;
  const authDate = Number(values.get('auth_date')); if (!authDate || Date.now() / 1000 - authDate > 86400) return null;
  return values.get('user');
}
const registration = z.object({ nickname: z.string().min(3).max(32).regex(/^[a-zA-Z0-9_-]+$/), password: z.string().min(10).max(128), pin: z.string().regex(/^\d{4}$/), acceptedTerms: z.literal(true) });
app.post('/api/auth/register', async (request, reply) => { const data = registration.parse(request.body); const codes = recoveryCodes(); const user = await db.user.create({ data: { nickname: data.nickname, passwordHash: await argon2.hash(data.password, { type: argon2.argon2id }), pinHash: await argon2.hash(data.pin), recoveryCodes: { create: await Promise.all(codes.map(async code => ({ codeHash: await argon2.hash(code, { type: argon2.argon2id }) }))) } } }); await createSession(user.id, reply); return { recoveryCodes: codes }; });
app.post('/api/auth/login', async (request, reply) => { const data = z.object({ nickname: z.string(), password: z.string() }).parse(request.body); const user = await db.user.findUnique({ where: { nickname: data.nickname } }); if (!user || !(await argon2.verify(user.passwordHash, data.password))) return reply.code(401).send({ error: 'Invalid nickname or password.' }); await createSession(user.id, reply); return { ok: true }; });
app.post('/api/auth/telegram', async (request, reply) => { const { initData } = z.object({ initData: z.string() }).parse(request.body); const rawUser = verifyInitData(initData); if (!rawUser) return reply.code(401).send({ error: 'Invalid Telegram authentication data.' }); const telegram = z.object({ id: z.number(), username: z.string().optional() }).parse(JSON.parse(rawUser)); const linked = await db.telegramAccount.findUnique({ where: { telegramId: BigInt(telegram.id) }, include: { user: true } }); if (!linked) return reply.code(404).send({ error: 'No CL-Service account is linked to this Telegram account.' }); await createSession(linked.user.id, reply); return { ok: true }; });
app.post('/api/auth/logout', { preHandler: authenticate }, async (request, reply) => { const token = request.cookies.session!; await db.session.deleteMany({ where: { tokenHash: hashToken(token) } }); reply.clearCookie('session', { path: '/' }); return { ok: true }; });
app.post('/api/auth/recovery', async (request, reply) => { const data = z.object({ nickname: z.string(), code: z.string(), password: z.string().min(10) }).parse(request.body); const user = await db.user.findUnique({ where: { nickname: data.nickname }, include: { recoveryCodes: { where: { usedAt: null } } } }); const record = user && (await Promise.all(user.recoveryCodes.map(async item => await argon2.verify(item.codeHash, data.code) ? item : null))).find(Boolean); if (!user || !record) return reply.code(401).send({ error: 'Invalid recovery details.' }); await db.$transaction([db.user.update({ where: { id: user.id }, data: { passwordHash: await argon2.hash(data.password, { type: argon2.argon2id }) } }), db.recoveryCode.update({ where: { id: record.id }, data: { usedAt: new Date() } }), db.session.deleteMany({ where: { userId: user.id } })]); return { ok: true }; });
app.get('/api/profile', { preHandler: authenticate }, async request => db.user.findUniqueOrThrow({ where: { id: (request as AuthRequest).user.id }, select: { id: true, nickname: true, createdAt: true, role: true, telegram: { select: { username: true } }, _count: { select: { purchases: true, sales: true, ratings: true } } } }));
app.get('/api/listings', async request => { const query = z.object({ q: z.string().optional(), category: z.string().optional() }).parse(request.query); return db.listing.findMany({ where: { active: true, ...(query.category ? { category: { name: query.category } } : {}), ...(query.q ? { OR: [{ title: { contains: query.q, mode: 'insensitive' } }, { description: { contains: query.q, mode: 'insensitive' } }] } : {}) }, include: { seller: { select: { nickname: true } }, category: true }, orderBy: { createdAt: 'desc' } }); });
app.post('/api/listings', { preHandler: authenticate }, async request => { const data = z.object({ title:z.string().min(3), description:z.string().min(10), category:z.string().min(2), price:z.coerce.number().positive(), currency:z.string().length(3), deliveryInfo:z.string().min(3), terms:z.string().min(3) }).parse(request.body); const category = await db.category.upsert({ where: { name: data.category }, create: { name: data.category }, update: {} }); return db.listing.create({ data: { ...data, price: data.price, sellerId: (request as AuthRequest).user.id, categoryId: category.id } }); });
app.post('/api/deals', { preHandler: authenticate }, async (request, reply) => { const data = z.object({ sellerId:z.string(), item:z.string().min(3), amount:z.coerce.number().positive(), currency:z.string().length(3), terms:z.string().min(3), deadline:z.string().datetime() }).parse(request.body); if (data.sellerId === (request as AuthRequest).user.id) return reply.code(400).send({ error: 'You cannot create a deal with yourself.' }); const deal = await db.escrowDeal.create({ data: { ...data, buyerId: (request as AuthRequest).user.id, deadline: new Date(data.deadline) } }); await db.notification.create({ data: { userId: data.sellerId, type:'DEAL_CREATED', body:`New escrow deal ${deal.id} requires your review.` } }); return deal; });
app.get('/api/deals', { preHandler: authenticate }, async request => db.escrowDeal.findMany({ where: { OR: [{ buyerId: (request as AuthRequest).user.id }, { sellerId: (request as AuthRequest).user.id }] }, include: { buyer: { select: { nickname: true } }, seller: { select: { nickname: true } } }, orderBy: { createdAt: 'desc' } }));
async function transition(request: FastifyRequest, reply: any, target: DealStatus, actor: 'buyer'|'seller') { const params = z.object({ id:z.string() }).parse(request.params); const user = (request as AuthRequest).user; const deal = await db.escrowDeal.findUnique({ where:{id:params.id} }); if (!deal || deal[`${actor}Id`] !== user.id) return reply.code(403).send({ error:'You are not authorized for this action.' }); const allowed: Record<DealStatus, DealStatus[]> = { PENDING:['ACCEPTED','CANCELLED'], ACCEPTED:['FUNDED'], FUNDED:['IN_PROGRESS','DISPUTED'], IN_PROGRESS:['DELIVERED','DISPUTED'], DELIVERED:['COMPLETED','DISPUTED'], COMPLETED:[], DISPUTED:['REFUNDED','COMPLETED'], CANCELLED:[], REFUNDED:[] }; if (!allowed[deal.status].includes(target)) return reply.code(409).send({ error:'This action is unavailable for the current deal status.' }); return db.$transaction(async tx => { const updated = await tx.escrowDeal.update({ where:{id:deal.id}, data:{status:target} }); await tx.auditLog.create({ data:{ actorId:user.id, action:`DEAL_${target}`, entityType:'EscrowDeal', entityId:deal.id } }); await tx.notification.create({ data:{ userId: actor === 'buyer' ? deal.sellerId : deal.buyerId, type:'DEAL_UPDATED', body:`Deal ${deal.id} is now ${target.toLowerCase().replace('_',' ')}.` } }); return updated; }); }
app.post('/api/deals/:id/accept', { preHandler: authenticate }, (request,reply) => transition(request,reply,'ACCEPTED','seller'));
app.post('/api/deals/:id/fund', { preHandler: authenticate }, async (_request, reply) => reply.code(503).send({ error: 'Payment provider is not configured.' }));
app.post('/api/deals/:id/deliver', { preHandler: authenticate }, (request,reply) => transition(request,reply,'DELIVERED','seller'));
app.post('/api/deals/:id/confirm', { preHandler: authenticate }, (request,reply) => transition(request,reply,'COMPLETED','buyer'));
app.post('/api/deals/:id/dispute', { preHandler: authenticate }, async (request, reply) => { const data=z.object({reason:z.string().min(3),description:z.string().min(10)}).parse(request.body); const deal=await transition(request,reply,'DISPUTED','buyer'); if (!deal || 'error' in deal) return deal; return db.dispute.create({data:{...data,dealId:deal.id}}); });
app.get('/api/deals/:id/messages', { preHandler: authenticate }, async request => db.message.findMany({ where:{dealId:z.object({id:z.string()}).parse(request.params).id}, include:{sender:{select:{nickname:true}}}, orderBy:{createdAt:'asc'} }));
app.post('/api/deals/:id/messages', { preHandler: authenticate, config:{rateLimit:{max:15,timeWindow:'1 minute'}} }, async (request, reply) => { const body=z.object({message:z.string().min(1).max(2000)}).parse(request.body); const dealId=z.object({id:z.string()}).parse(request.params).id; const deal=await db.escrowDeal.findUniqueOrThrow({where:{id:dealId}}); const user=(request as AuthRequest).user; if (user.id!==deal.buyerId&&user.id!==deal.sellerId) return reply.code(403).send({ error: 'You are not authorized for this action.' }); return db.message.create({data:{dealId,senderId:user.id,body:body.message}}); });
app.get('/api/notifications', { preHandler: authenticate }, request => db.notification.findMany({where:{userId:(request as AuthRequest).user.id},orderBy:{createdAt:'desc'},take:50}));
app.post('/telegram/webhook', async (request, reply) => { const secret = request.headers['x-telegram-bot-api-secret-token']; if (!process.env.TELEGRAM_WEBHOOK_SECRET || secret !== process.env.TELEGRAM_WEBHOOK_SECRET) return reply.code(403).send({ error: 'Forbidden.' }); const update = request.body as { message?: { chat?: { id:number }; text?:string } }; const message = update.message; if (!message?.chat?.id || !message.text) return { ok:true }; const responses:Record<string,string> = { '/help':'CL-Service help\nOpen the Mini App to manage secure escrow deals.', '/profile':'Open CL-Service to view your profile.', '/deals':'Open CL-Service to view your deals.' }; const isStart=message.text.startsWith('/start'); const text=isStart ? 'Welcome to CL-Service\n\nA secure marketplace for escrow-protected transactions.\n\nOpen the application below to get started.' : responses[message.text]; if (!text || !process.env.BOT_TOKEN) return { ok:true }; await fetch(`https://api.telegram.org/bot${process.env.BOT_TOKEN}/sendMessage`, { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({chat_id:message.chat.id,text,reply_markup:isStart?{inline_keyboard:[[{text:'Open CL-Service',web_app:{url:process.env.MINI_APP_URL}}]]}:undefined}) }); return { ok:true }; });
app.setErrorHandler((error, _request, reply) => { if (error instanceof z.ZodError) return reply.code(400).send({ error: error.issues[0]?.message || 'Invalid request.' }); app.log.error(error); return reply.code((error as any).statusCode || 500).send({ error: 'An unexpected error occurred.' }); });
await app.listen({ port: Number(process.env.PORT || 3000), host: '0.0.0.0' });
