import 'dotenv/config';
import crypto from 'node:crypto';
import argon2 from 'argon2';
import Fastify, { FastifyRequest } from 'fastify';
import cookie from '@fastify/cookie';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import { PrismaClient, DealStatus, Role } from '@prisma/client';
import { z } from 'zod';

const db = new PrismaClient();
const app = Fastify({ logger: true });
const sessionSecret = process.env.SESSION_SECRET || '';
if (sessionSecret.length < 32) throw new Error('SESSION_SECRET must contain at least 32 characters.');
await app.register(cookie, { secret: sessionSecret });
await app.register(cors, { origin: process.env.WEB_APP_ORIGIN || false, credentials: true });
await app.register(helmet);
await app.register(rateLimit, { max: 100, timeWindow: '1 minute' });

type AuthRequest = FastifyRequest & { user: { id: string; role: Role } };
const hashToken = (token: string) => crypto.createHash('sha256').update(token).digest('hex');
const recoveryCodes = () => Array.from({ length: 8 }, () => crypto.randomBytes(5).toString('hex').toUpperCase().match(/.{1,5}/g)!.join('-'));
async function authenticate(request: FastifyRequest, reply: any) {
  const authorization = request.headers.authorization;
  const token = authorization?.startsWith('Bearer ') ? authorization.slice(7) : request.cookies.session;
  if (!token) return reply.code(401).send({ error: 'Authentication required.' });
  const session = await db.session.findFirst({ where: { tokenHash: hashToken(token), expiresAt: { gt: new Date() } }, select: { user: { select: { id: true, role: true } } } });
  if (!session) return reply.code(401).send({ error: 'Session expired.' });
  (request as AuthRequest).user = session.user;
}
async function createSession(userId: string, reply: any) {
  const token = crypto.randomBytes(32).toString('base64url');
  await db.session.create({ data: { userId, tokenHash: hashToken(token), expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 14) } });
  reply.setCookie('session', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', path: '/', maxAge: 60 * 60 * 24 * 14 });
  return token;
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
const registration = z.object({
  nickname: z.string().min(3, 'Nickname must contain at least 3 characters.').max(32, 'Nickname cannot exceed 32 characters.').regex(/^[a-zA-Z0-9_-]+$/, 'Nickname can use letters, numbers, underscores, and hyphens only.'),
  password: z.string().min(10, 'Password must contain at least 10 characters.').max(128, 'Password cannot exceed 128 characters.').regex(/[a-z]/, 'Password must contain a lowercase letter.').regex(/[A-Z]/, 'Password must contain an uppercase letter.').regex(/\d/, 'Password must contain a number.'),
  pin: z.string().regex(/^\d{4}$/, 'PIN must contain exactly 4 digits.'),
  marketplaceRole: z.enum(['BUYER', 'SELLER'], { errorMap: () => ({ message: 'Choose whether you will use the marketplace as a buyer or seller.' }) }),
  acceptedTerms: z.literal(true, { errorMap: () => ({ message: 'You must agree to the Terms of Service.' }) })
});
app.get('/api/auth/nickname-availability', async request => {
  const query = z.object({ nickname: z.string().min(3).max(32).regex(/^[a-zA-Z0-9_-]+$/) }).safeParse(request.query);
  if (!query.success) return { available: false, message: 'Use 3–32 letters, numbers, underscores, or hyphens.' };
  const existing = await db.user.findUnique({ where: { nickname: query.data.nickname }, select: { id: true } });
  return existing ? { available: false, message: 'This nickname is already in use.' } : { available: true, message: 'Nickname is available.' };
});
app.post('/api/auth/register', async (request, reply) => {
  const body = z.object({ initData: z.string().optional() }).passthrough().parse(request.body);
  const data = registration.parse(body);
  if (await db.user.findUnique({ where: { nickname: data.nickname }, select: { id: true } })) {
    return reply.code(409).send({ error: 'That nickname is already in use. Please choose another.' });
  }
  const codes = recoveryCodes();
  const rawTelegramUser = body.initData ? verifyInitData(body.initData) : null;
  const telegram = rawTelegramUser ? z.object({ id: z.number(), username: z.string().optional(), photo_url: z.string().url().optional() }).parse(JSON.parse(rawTelegramUser)) : null;
  if (telegram && await db.telegramAccount.findUnique({ where: { telegramId: BigInt(telegram.id) }, select: { id: true } })) return reply.code(409).send({ error: 'This Telegram account is already linked to CL-Service.' });
  const adminTelegramId = process.env.ADMIN_TELEGRAM_ID;
  const isAdmin = Boolean(telegram && adminTelegramId && BigInt(adminTelegramId) === BigInt(telegram.id));
  const user = await db.user.create({ data: { nickname: data.nickname, marketplaceRole: data.marketplaceRole, role: isAdmin ? 'SUPER_ADMIN' : 'USER', passwordHash: await argon2.hash(data.password, { type: argon2.argon2id }), pinHash: await argon2.hash(data.pin), ...(telegram ? { telegram: { create: { telegramId: BigInt(telegram.id), username: telegram.username, photoUrl: telegram.photo_url } } } : {}), recoveryCodes: { create: await Promise.all(codes.map(async code => ({ codeHash: await argon2.hash(code, { type: argon2.argon2id }) }))) } } });
  const sessionToken = await createSession(user.id, reply);
  return { recoveryCodes: codes, sessionToken };
});
app.post('/api/auth/login', async (request, reply) => { const data = z.object({ nickname: z.string(), password: z.string() }).parse(request.body); const user = await db.user.findUnique({ where: { nickname: data.nickname } }); if (!user || !(await argon2.verify(user.passwordHash, data.password))) return reply.code(401).send({ error: 'Nickname or password is incorrect.' }); const sessionToken = await createSession(user.id, reply); return { ok: true, sessionToken }; });
app.post('/api/auth/telegram', async (request, reply) => { const { initData } = z.object({ initData: z.string() }).parse(request.body); const rawUser = verifyInitData(initData); if (!rawUser) return reply.code(401).send({ error: 'Invalid Telegram authentication data.' }); const telegram = z.object({ id: z.number(), username: z.string().optional(), photo_url: z.string().url().optional() }).parse(JSON.parse(rawUser)); const linked = await db.telegramAccount.findUnique({ where: { telegramId: BigInt(telegram.id) }, include: { user: true } }); if (!linked) return reply.code(404).send({ error: 'No CL-Service account is linked to this Telegram account.' }); const isAdmin = Boolean(process.env.ADMIN_TELEGRAM_ID && BigInt(process.env.ADMIN_TELEGRAM_ID) === BigInt(telegram.id)); await db.$transaction([db.telegramAccount.update({ where: { id: linked.id }, data: { username: telegram.username, photoUrl: telegram.photo_url } }), ...(isAdmin ? [db.user.update({ where: { id: linked.user.id }, data: { role: 'SUPER_ADMIN' } })] : [])]); const sessionToken = await createSession(linked.user.id, reply); return { ok: true, sessionToken }; });
app.post('/api/auth/logout', { preHandler: authenticate }, async (request, reply) => { const token = request.cookies.session!; await db.session.deleteMany({ where: { tokenHash: hashToken(token) } }); reply.clearCookie('session', { path: '/' }); return { ok: true }; });
app.post('/api/auth/recovery', async (request, reply) => { const data = z.object({ nickname: z.string(), code: z.string(), password: z.string().min(10) }).parse(request.body); const user = await db.user.findUnique({ where: { nickname: data.nickname }, include: { recoveryCodes: { where: { usedAt: null } } } }); const record = user && (await Promise.all(user.recoveryCodes.map(async item => await argon2.verify(item.codeHash, data.code) ? item : null))).find(Boolean); if (!user || !record) return reply.code(401).send({ error: 'Invalid recovery details.' }); await db.$transaction([db.user.update({ where: { id: user.id }, data: { passwordHash: await argon2.hash(data.password, { type: argon2.argon2id }) } }), db.recoveryCode.update({ where: { id: record.id }, data: { usedAt: new Date() } }), db.session.deleteMany({ where: { userId: user.id } })]); return { ok: true }; });
app.get('/api/profile', { preHandler: authenticate }, async request => {
  const user = await db.user.findUniqueOrThrow({
    where: { id: (request as AuthRequest).user.id },
    select: { id: true, nickname: true, createdAt: true, role: true, marketplaceRole: true, telegram: { select: { username: true, photoUrl: true } } }
  });
  return user;
});
app.patch('/api/profile', { preHandler: authenticate }, async request => {
  const data = z.object({ marketplaceRole: z.enum(['BUYER', 'SELLER']) }).parse(request.body);
  return db.user.update({ where: { id: (request as AuthRequest).user.id }, data, select: { marketplaceRole: true } });
});
app.get('/api/listings', async request => { const query = z.object({ q: z.string().optional(), category: z.string().optional() }).parse(request.query); return db.listing.findMany({ where: { active: true, ...(query.category ? { category: { name: query.category } } : {}), ...(query.q ? { OR: [{ title: { contains: query.q, mode: 'insensitive' } }, { description: { contains: query.q, mode: 'insensitive' } }] } : {}) }, include: { seller: { select: { nickname: true } }, category: true }, orderBy: { createdAt: 'desc' } }); });
app.post('/api/listings', { preHandler: authenticate }, async request => { const data = z.object({ title:z.string().min(3), description:z.string().min(10), category:z.string().min(2), price:z.coerce.number().positive(), currency:z.string().length(3), deliveryInfo:z.string().min(3), terms:z.string().min(3) }).parse(request.body); const category = await db.category.upsert({ where: { name: data.category }, create: { name: data.category }, update: {} }); const { category: _category, ...listing } = data; return db.listing.create({ data: { ...listing, sellerId: (request as AuthRequest).user.id, categoryId: category.id } }); });
app.post('/api/deals', { preHandler: authenticate }, async (request, reply) => { const data = z.object({ sellerId:z.string(), item:z.string().min(3), amount:z.coerce.number().positive(), currency:z.string().length(3), terms:z.string().min(3), deadline:z.string().datetime() }).parse(request.body); const buyer=await db.user.findUniqueOrThrow({where:{id:(request as AuthRequest).user.id},select:{marketplaceRole:true}}); const seller=await db.user.findUnique({where:{id:data.sellerId},select:{marketplaceRole:true}}); if(buyer.marketplaceRole!=='BUYER') return reply.code(403).send({error:'Switch your marketplace role to Buyer before opening an escrow request.'}); if(!seller||seller.marketplaceRole!=='SELLER') return reply.code(400).send({error:'The selected member is not registered as a seller.'}); if (data.sellerId === (request as AuthRequest).user.id) return reply.code(400).send({ error: 'You cannot create a deal with yourself.' }); const deal = await db.escrowDeal.create({ data: { ...data, buyerId: (request as AuthRequest).user.id, deadline: new Date(data.deadline) } }); await db.notification.create({ data: { userId: data.sellerId, type:'ESCROW_ROOM_REQUESTED', body:`A buyer requested a private escrow room for deal ${deal.id}.` } }); return deal; });
app.get('/api/deals', { preHandler: authenticate }, async request => { const user=(request as AuthRequest).user; return db.escrowDeal.findMany({ where: user.role==='SUPER_ADMIN'?{}:{ OR: [{ buyerId:user.id }, { sellerId:user.id }] }, include: { buyer: { select: { nickname: true } }, seller: { select: { nickname: true } } }, orderBy: { createdAt: 'desc' } }); });
async function transition(request: FastifyRequest, reply: any, target: DealStatus, actor: 'buyer'|'seller') { const params = z.object({ id:z.string() }).parse(request.params); const user = (request as AuthRequest).user; const deal = await db.escrowDeal.findUnique({ where:{id:params.id} }); if (!deal || deal[`${actor}Id`] !== user.id) return reply.code(403).send({ error:'You are not authorized for this action.' }); const allowed: Record<DealStatus, DealStatus[]> = { PENDING:['ACCEPTED','CANCELLED'], ACCEPTED:['FUNDED'], FUNDED:['IN_PROGRESS','DISPUTED'], IN_PROGRESS:['DELIVERED','DISPUTED'], DELIVERED:['COMPLETED','DISPUTED'], COMPLETED:[], DISPUTED:['REFUNDED','COMPLETED'], CANCELLED:[], REFUNDED:[] }; if (!allowed[deal.status].includes(target)) return reply.code(409).send({ error:'This action is unavailable for the current deal status.' }); return db.$transaction(async tx => { const updated = await tx.escrowDeal.update({ where:{id:deal.id}, data:{status:target} }); await tx.auditLog.create({ data:{ actorId:user.id, action:`DEAL_${target}`, entityType:'EscrowDeal', entityId:deal.id } }); await tx.notification.create({ data:{ userId: actor === 'buyer' ? deal.sellerId : deal.buyerId, type:'DEAL_UPDATED', body:`Deal ${deal.id} is now ${target.toLowerCase().replace('_',' ')}.` } }); return updated; }); }
app.post('/api/deals/:id/accept', { preHandler: authenticate }, (request,reply) => transition(request,reply,'ACCEPTED','seller'));
app.post('/api/deals/:id/fund', { preHandler: authenticate }, async (_request, reply) => reply.code(503).send({ error: 'Payment provider is not configured.' }));
app.post('/api/deals/:id/deliver', { preHandler: authenticate }, (request,reply) => transition(request,reply,'DELIVERED','seller'));
app.post('/api/deals/:id/confirm', { preHandler: authenticate }, (request,reply) => transition(request,reply,'COMPLETED','buyer'));
app.post('/api/admin/deals/:id/release', { preHandler: authenticate }, async (request, reply) => { const user=(request as AuthRequest).user; if(user.role!=='SUPER_ADMIN') return reply.code(403).send({error:'Only the official escrow administrator can release funds.'}); const id=z.object({id:z.string()}).parse(request.params).id; const deal=await db.escrowDeal.findUnique({where:{id}}); if(!deal) return reply.code(404).send({error:'Deal not found.'}); if(!['DELIVERED','DISPUTED'].includes(deal.status)) return reply.code(409).send({error:'Funds can only be released after delivery or a dispute decision.'}); return db.$transaction(async tx=>{const updated=await tx.escrowDeal.update({where:{id},data:{status:'COMPLETED'}});await tx.auditLog.create({data:{actorId:user.id,action:'ADMIN_ESCROW_RELEASE',entityType:'EscrowDeal',entityId:id}});await tx.notification.createMany({data:[{userId:deal.buyerId,type:'ESCROW_RELEASED',body:`The official escrow administrator released deal ${id}.`},{userId:deal.sellerId,type:'ESCROW_RELEASED',body:`The official escrow administrator released deal ${id}.`} ]});return updated;}); });
app.post('/api/deals/:id/dispute', { preHandler: authenticate }, async (request, reply) => { const data=z.object({reason:z.string().min(3),description:z.string().min(10)}).parse(request.body); const deal=await transition(request,reply,'DISPUTED','buyer'); if (!deal || 'error' in deal) return deal; return db.dispute.create({data:{...data,dealId:deal.id}}); });
app.get('/api/deals/:id/messages', { preHandler: authenticate }, async (request, reply) => { const dealId=z.object({id:z.string()}).parse(request.params).id; const deal=await db.escrowDeal.findUnique({where:{id:dealId}}); const user=(request as AuthRequest).user; if(!deal||(user.id!==deal.buyerId&&user.id!==deal.sellerId&&user.role!=='SUPER_ADMIN')) return reply.code(403).send({error:'This private room is available only to the buyer, seller, and official escrow administrator.'}); return db.message.findMany({where:{dealId},include:{sender:{select:{nickname:true,role:true}}},orderBy:{createdAt:'asc'}}); });
app.post('/api/deals/:id/messages', { preHandler: authenticate, config:{rateLimit:{max:15,timeWindow:'1 minute'}} }, async (request, reply) => { const body=z.object({message:z.string().min(1).max(2000)}).parse(request.body); const dealId=z.object({id:z.string()}).parse(request.params).id; const deal=await db.escrowDeal.findUniqueOrThrow({where:{id:dealId}}); const user=(request as AuthRequest).user; if (user.id!==deal.buyerId&&user.id!==deal.sellerId&&user.role!=='SUPER_ADMIN') return reply.code(403).send({ error: 'This private room is available only to the buyer, seller, and official escrow administrator.' }); return db.message.create({data:{dealId,senderId:user.id,body:body.message}}); });
app.get('/api/community/messages', { preHandler: authenticate }, async () => db.communityMessage.findMany({ take: 100, orderBy: { createdAt: 'asc' }, include: { sender: { select: { nickname: true } } } }));
app.post('/api/community/messages', { preHandler: authenticate, config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async request => {
  const data = z.object({ message: z.string().trim().min(1, 'Message cannot be empty.').max(1000, 'Message cannot exceed 1,000 characters.') }).parse(request.body);
  return db.communityMessage.create({ data: { body: data.message, senderId: (request as AuthRequest).user.id }, include: { sender: { select: { nickname: true } } } });
});
app.post('/api/community/typing', { preHandler: authenticate, config: { rateLimit: { max: 30, timeWindow: '1 minute' } } }, async request => {
  const userId = (request as AuthRequest).user.id;
  await db.communityTyping.upsert({ where: { userId }, create: { userId }, update: {} });
  return { ok: true };
});
app.get('/api/community/typing', { preHandler: authenticate }, async request => {
  const userId = (request as AuthRequest).user.id;
  const activeSince = new Date(Date.now() - 5000);
  const users = await db.communityTyping.findMany({ where: { userId: { not: userId }, updatedAt: { gt: activeSince } }, include: { user: { select: { nickname: true } } }, take: 3 });
  return { users: users.map(entry => entry.user.nickname) };
});
app.get('/api/notifications', { preHandler: authenticate }, request => db.notification.findMany({where:{userId:(request as AuthRequest).user.id},orderBy:{createdAt:'desc'},take:50}));
app.post('/telegram/webhook', async (request, reply) => { const secret = request.headers['x-telegram-bot-api-secret-token']; if (!process.env.TELEGRAM_WEBHOOK_SECRET || secret !== process.env.TELEGRAM_WEBHOOK_SECRET) return reply.code(403).send({ error: 'Forbidden.' }); const update = request.body as { message?: { chat?: { id:number }; from?: { id:number }; text?:string } }; const message = update.message; if (!message?.chat?.id || !message.text) return { ok:true }; const responses:Record<string,string> = { '/help':'CL-Service help\nOpen the Mini App to manage secure escrow deals.', '/profile':'Open CL-Service to view your profile.', '/deals':'Open CL-Service to view your deals.' }; if(message.text==='/id'&&message.from){responses['/id']=`Your Telegram user ID: ${message.from.id}`;} const isStart=message.text.startsWith('/start'); const registered = isStart && message.from ? await db.telegramAccount.findUnique({ where: { telegramId: BigInt(message.from.id) }, select: { id: true } }) : null; const text=isStart ? registered ? 'Welcome back to CL-Service.\n\nOpen Escrow to continue where you left off.' : 'Welcome to CL-Service\n\nA secure marketplace for escrow-protected transactions.\n\nOpen the application below to get started.' : responses[message.text]; if (!text || !process.env.BOT_TOKEN) return { ok:true }; await fetch(`https://api.telegram.org/bot${process.env.BOT_TOKEN}/sendMessage`, { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({chat_id:message.chat.id,text,reply_markup:isStart?{inline_keyboard:[[{text:registered?'Open Escrow':'Open CL-Service',web_app:{url:process.env.MINI_APP_URL}}]]}:undefined}) }); return { ok:true }; });
app.setErrorHandler((error, _request, reply) => { if (error instanceof z.ZodError) return reply.code(400).send({ error: error.issues[0]?.message || 'Invalid request.' }); app.log.error(error); return reply.code((error as any).statusCode || 500).send({ error: 'An unexpected error occurred.' }); });
await app.listen({ port: Number(process.env.PORT || 3000), host: '0.0.0.0' });
