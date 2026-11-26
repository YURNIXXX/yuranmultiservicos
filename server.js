const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const { authenticator } = require('otplib');

const APP_VERSION = require('./package.json').version;
const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const ADMIN_SESSION_MAX_AGE = 1000 * 60 * 60 * 8;
// A sessão profissional expira após 30 dias sem atividade, em vez de durar dez anos.
const PROFESSIONAL_SESSION_MAX_AGE = 1000 * 60 * 60 * 24 * 30;
const ADMIN_RECOVERY_KEY = process.env.ADMIN_RECOVERY_KEY || '';
const SESSION_SECRET_CONFIGURED = Boolean(process.env.SESSION_SECRET);
// A chave de emergência é estável entre instâncias e reinícios. SESSION_SECRET
// própria continua a ser a configuração recomendada para produção.
const SESSION_SECRET = process.env.SESSION_SECRET || (process.env.SUPABASE_SERVICE_ROLE_KEY
  ? crypto.createHmac('sha256', process.env.SUPABASE_SERVICE_ROLE_KEY).update('yuran:session-signing:v1').digest('hex')
  : crypto.randomBytes(48).toString('hex'));
const TOTP_ENCRYPTION_KEY_CONFIGURED = Boolean(process.env.TOTP_ENCRYPTION_KEY);
const TOTP_ENCRYPTION_KEY = process.env.TOTP_ENCRYPTION_KEY || SESSION_SECRET;
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_KEY || '';
const STORAGE_BUCKET = process.env.SUPABASE_STORAGE_BUCKET || 'uploads';
const VERIFICATION_BUCKET = process.env.SUPABASE_VERIFICATION_BUCKET || 'verification-documents';
// Currículos e imagens ainda em moderação ficam fora do bucket público.
const PRIVATE_PREFIX = 'private:';
const PUBLIC_BASE_URL = String(process.env.PUBLIC_BASE_URL || '').replace(/\/$/, '');
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const EMAIL_FROM = process.env.EMAIL_FROM || '';
const GOOGLE_SITE_VERIFICATION = String(process.env.GOOGLE_SITE_VERIFICATION || '').trim();
const IDENTITY_RETENTION_DAYS = Math.min(365, Math.max(1, Number(process.env.IDENTITY_RETENTION_DAYS || 30)));
const IS_PRODUCTION = process.env.NODE_ENV === 'production' || process.env.RENDER === 'true';
const USE_SUPABASE = Boolean(SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY);
const ALLOW_LOCAL_STORAGE = process.env.ALLOW_LOCAL_STORAGE === 'true';

if (IS_PRODUCTION && !SESSION_SECRET_CONFIGURED) {
  console.warn('AVISO DE SEGURANÇA: SESSION_SECRET não configurada. A sessão usa uma chave derivada e estável; configure SESSION_SECRET própria no Render.');
}

// Nunca deixe produção cair silenciosamente para armazenamento local.
// No Render, o sistema de ficheiros da instância é efémero e os dados seriam perdidos
// num restart/redeploy. Para desenvolvimento local, use ALLOW_LOCAL_STORAGE=true.
if (!USE_SUPABASE && !ALLOW_LOCAL_STORAGE) {
  console.error('ERRO FATAL: SUPABASE_URL e SUPABASE_SERVICE_ROLE_KEY não estão configuradas.');
  console.error('O servidor foi interrompido para evitar perda de dados no armazenamento local.');
  process.exit(1);
}

const supabase = USE_SUPABASE ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } }) : null;

const DATA_FILE = path.join(__dirname, 'data', 'site.json');
const IMAGE_DIR = path.join(__dirname, 'public', 'uploads', 'images');
const PRIVATE_DIR = path.join(__dirname, 'data', 'private-uploads');
[IMAGE_DIR, PRIVATE_DIR].forEach(dir => fs.mkdirSync(dir, { recursive: true }));

class SupabaseSessionStore extends session.Store {
  constructor(client) { super(); this.client = client; }
  get(sid, cb) {
    this.client.from('app_sessions').select('sess,expire').eq('sid', sid).maybeSingle().then(({ data, error }) => {
      if (error) return cb(error);
      if (!data) return cb(null, null);
      if (new Date(data.expire).getTime() <= Date.now()) return this.destroy(sid, () => cb(null, null));
      cb(null, data.sess);
    }).catch(cb);
  }
  set(sid, sess, cb = () => {}) {
    const expire = sess?.cookie?.expires ? new Date(sess.cookie.expires) : new Date(Date.now() + 8 * 60 * 60 * 1000);
    this.client.from('app_sessions').upsert({ sid, sess, expire: expire.toISOString(), updated_at: new Date().toISOString() }).then(({ error }) => cb(error || null)).catch(cb);
  }
  destroy(sid, cb = () => {}) {
    this.client.from('app_sessions').delete().eq('sid', sid).then(({ error }) => cb(error || null)).catch(cb);
  }
  touch(sid, sess, cb = () => {}) { this.set(sid, sess, cb); }
}

const cspConnect = ["'self'"];
try { if (SUPABASE_URL) cspConnect.push(new URL(SUPABASE_URL).origin); } catch {}
app.use((req, res, next) => { res.locals.cspNonce = crypto.randomBytes(16).toString('base64'); next(); });
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", 'https://cdn.jsdelivr.net', (req, res) => `'nonce-${res.locals.cspNonce}'`],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
      imgSrc: ["'self'", 'data:', 'blob:', 'https:'],
      fontSrc: ["'self'", 'data:', 'https://cdn.jsdelivr.net'],
      connectSrc: cspConnect,
      frameSrc: ["'self'", 'https://www.youtube-nocookie.com', 'https://www.youtube.com'],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

const sessionStore = USE_SUPABASE ? new SupabaseSessionStore(supabase) : new session.MemoryStore();
// Admin e profissionais podem estar abertos em abas do mesmo navegador.
// Cookies e IDs separados impedem que o login/logout de um apague a sessão do outro.
function sessionSigningSecret(scope) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(`session:${scope}`).digest('hex');
}
function scopedSession(name, scope, maxAge) {
  return session({
    name,
    store: sessionStore,
    secret: sessionSigningSecret(scope),
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: { path: `/api/${scope}`, httpOnly: true, sameSite: 'lax', secure: IS_PRODUCTION, maxAge }
  });
}
app.use('/api/admin', scopedSession('yuran.admin.sid', 'admin', ADMIN_SESSION_MAX_AGE));
app.use('/api/professional', scopedSession('yuran.professional.sid', 'professional', PROFESSIONAL_SESSION_MAX_AGE));
app.use(['/api/admin','/api/professional'], (_req, res, next) => { res.set('Cache-Control', 'private, no-store'); next(); });

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Muitas tentativas. Aguarde alguns minutos e tente novamente.' } });
const registerLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Limite temporário de cadastros atingido neste dispositivo. Tente mais tarde.' } });
const feedbackLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 30, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Muitas ações em pouco tempo. Tente novamente mais tarde.' } });
const emailVerifyLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Muitas tentativas de verificação. Aguarde alguns minutos.' } });

function sameOriginGuard(req, res, next) {
  const origin = req.get('origin');
  const fetchSite = String(req.get('sec-fetch-site') || '').toLowerCase();
  if (fetchSite && !['same-origin', 'none'].includes(fetchSite)) return res.status(403).json({ error: 'Origem da solicitação não autorizada.' });
  // Não aceitar mutações com cookie que omitem ambos os sinais de origem.
  // Pedidos do próprio navegador incluem Origin ou Sec-Fetch-Site: same-origin.
  if (!origin) {
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && fetchSite !== 'same-origin')
      return res.status(403).json({ error: 'Não foi possível verificar a origem da solicitação.' });
    return next();
  }
  try {
    const forwardedProto = String(req.get('x-forwarded-proto') || req.protocol || 'https').split(',')[0].trim();
    const requestOrigin = new URL(`${forwardedProto}://${req.get('host')}`).origin;
    const allowed = new Set([requestOrigin]);
    if (PUBLIC_BASE_URL) { try { allowed.add(new URL(PUBLIC_BASE_URL).origin); } catch {} }
    if (!allowed.has(new URL(origin).origin)) return res.status(403).json({ error: 'Origem da solicitação não autorizada.' });
  } catch { return res.status(403).json({ error: 'Origem inválida.' }); }
  next();
}
app.use('/api/admin', sameOriginGuard);
app.use('/api/professional', sameOriginGuard);
app.use('/api/professionals', sameOriginGuard);
app.use('/api/admin/login', authLimiter);
app.use('/api/admin/login-2fa', authLimiter);
app.use('/api/admin/recover-password', authLimiter);
app.use('/api/admin/recover-2fa', authLimiter);
app.use('/api/professional/login', authLimiter);
app.use('/api/professional/google-login', authLimiter);
app.use('/api/professional/recovery-request', authLimiter);
app.use('/api/professional/reset-password', authLimiter);
app.use('/api/professional/register', registerLimiter);
app.use('/api/professional/email-verification', emailVerifyLimiter);

// Limites partilhados entre instâncias. A função SQL da migração V7.9 é
// obrigatória em produção; falhas de armazenamento bloqueiam mutações.
function distributedLimit({ bucket, limit, seconds, failClosed = true }) {
  return async (req, res, next) => {
    if (!USE_SUPABASE) return next();
    const identity = crypto.createHash('sha256').update(`${SESSION_SECRET}|${req.ip}|${bucket}`).digest('hex');
    try {
      const { data, error } = await supabase.rpc('security_rate_check', { p_key: identity, p_limit: limit, p_window_seconds: seconds });
      if (error) throw error;
      if (!data?.allowed) {
        res.set('Retry-After', String(Math.max(1, Number(data?.retry_after || seconds))));
        return res.status(429).json({ error: 'Muitas solicitações. Aguarde e tente novamente.' });
      }
      next();
    } catch (error) {
      console.error('Limite de segurança indisponível:', error.message);
      if (failClosed) return res.status(503).json({ error: 'Serviço temporariamente indisponível.' });
      next();
    }
  };
}
app.use(['/api/admin/login','/api/admin/login-2fa','/api/admin/recover-password','/api/admin/recover-2fa',
  '/api/professional/login','/api/professional/google-login','/api/professional/recovery-request',
  '/api/professional/reset-password','/api/professional/register','/api/professional/email-verification'],
  (req, res, next) => req.method === 'GET' ? next() : distributedLimit({ bucket: 'auth', limit: 35, seconds: 900 })(req,res,next));
app.use('/api/professionals', (req, res, next) => {
  if (req.method === 'GET') return distributedLimit({ bucket: 'search', limit: 120, seconds: 300 })(req, res, next);
  return distributedLimit({ bucket: 'feedback', limit: 35, seconds: 3600 })(req, res, next);
});

app.get('/', async (req,res)=>{
  const site=await readData().catch(()=>({settings:{}})); const st=site.settings||{}; const org={
    '@context':'https://schema.org','@type':'Organization',name:st.siteName||'Yuran Multicerviços',url:`${baseUrl(req)}/`,
    description:cleanSeoText(st.seoDescription||st.about||'',220),
    logo:st.headerLogoLight||st.headerLogo||st.logo||undefined,
    email:st.email||undefined,telephone:st.phone||undefined
  };
  return sendSeoHtml(req,res,'index.html',{title:st.seoTitle,description:st.seoDescription,canonical:`${baseUrl(req)}/`,image:st.heroBackgroundImage||st.heroLogo,schema:[org,{'@context':'https://schema.org','@type':'WebSite',name:st.siteName||'Yuran Multicerviços',url:`${baseUrl(req)}/`} ]});
});

app.use(express.static(path.join(__dirname, 'public'), { maxAge: 0, etag: true, setHeaders(res, filePath) { if (/\.(?:html|js|css)$/i.test(filePath) || /sw\.js$/i.test(filePath)) res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate'); } }));
app.use('/admin', express.static(path.join(__dirname, 'admin'), { maxAge: 0, etag: true, setHeaders(res, filePath) { if (/\.(?:html|js|css)$/i.test(filePath)) res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate'); } }));

function readLocalData() { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
function writeLocalData(data) { fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8'); }
function uid(prefix = 'item') { return `${prefix}-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`; }
function credentialTag(value) { return crypto.createHmac('sha256', SESSION_SECRET).update(String(value || '')).digest('hex'); }
function adminCredentialTag(data) {
  return credentialTag(`admin:${data._admin?.passwordHash || ADMIN_PASSWORD}`);
}
async function requireAuth(req, res, next) {
  try {
    if (req.session?.admin !== true || !req.session.adminCredentialTag ||
        !safeSecretEqual(req.session.adminCredentialTag, adminCredentialTag(await readData())))
      return res.status(401).json({ error: 'Não autenticado.', code: 'ADMIN_SESSION_REQUIRED' });
    next();
  } catch (error) { next(error); }
}
async function revokeSessions(field, value) {
  if (USE_SUPABASE) {
    const { error } = await supabase.from('app_sessions').delete().contains('sess', { [field]: value });
    if (error) throw error;
  } else {
    for (const [sid, sess] of Object.entries(sessionStore.sessions || {})) {
      try { if (JSON.parse(sess)[field] === value) sessionStore.destroy(sid, () => {}); } catch {}
    }
  }
}
function destroySession(req) { return new Promise((resolve, reject) => req.session.destroy(error => error ? reject(error) : resolve())); }
function regenerateSession(req) { return new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve())); }
function saveSession(req) { return new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve())); }
function readStoredSession(sid) { return new Promise((resolve, reject) => sessionStore.get(sid, (err, stored) => err ? reject(err) : resolve(stored))); }
async function activateAdminSession(req) {
  if (IS_PRODUCTION && !req.secure) throw new Error('HTTPS_PROXY_REQUIRED');
  await regenerateSession(req);
  req.session.admin = true;
  req.session.adminCredentialTag = adminCredentialTag(await readData());
  setAdminSessionLifetime(req);
  await saveSession(req);
  const stored = await readStoredSession(req.sessionID);
  if (stored?.admin !== true || !stored.adminCredentialTag) throw new Error('ADMIN_SESSION_NOT_PERSISTED');
}
// Emite o cookie no próprio login após confirmar a gravação. A sessão também o
// emite automaticamente; este envio explícito cobre respostas onde o hook de
// headers do middleware não o acrescenta antes da confirmação pelo navegador.
function setAdminLoginCookie(req, res) {
  if (!req.sessionID || req.session?.admin !== true && req.session?.admin2faPending !== true) throw new Error('ADMIN_SESSION_NOT_PERSISTED');
  const signature = crypto.createHmac('sha256', sessionSigningSecret('admin'))
    .update(req.sessionID).digest('base64').replace(/=+$/, '');
  res.cookie('yuran.admin.sid', `s:${req.sessionID}.${signature}`, {
    path: '/api/admin', httpOnly: true, sameSite: 'lax', secure: IS_PRODUCTION,
    maxAge: req.session.cookie.maxAge
  });
}
function setAdminSessionLifetime(req) { if (req.session?.cookie) req.session.cookie.maxAge = ADMIN_SESSION_MAX_AGE; }
function setProfessionalSessionLifetime(req) { if (req.session?.cookie) req.session.cookie.maxAge = PROFESSIONAL_SESSION_MAX_AGE; }
function setProfessionalIdentity(req, profileId, passwordHash) {
  req.session.professionalId = profileId;
  req.session.professionalCredentialTag = credentialTag(`professional:${passwordHash}`);
  setProfessionalSessionLifetime(req);
}
function slugify(value = '') { return String(value).normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || uid('servico'); }
function normalizeUrl(value = '') {
  const v = String(value).trim();
  if (!v || v === '#') return v || '#';
  if (/^(https?:)?\/\//i.test(v)) return v.startsWith('//') ? `https:${v}` : v;
  return `https://${v.replace(/^\/+/, '')}`;
}
function normalizeEducation(value = []) {
  let rows = value;
  if (typeof rows === 'string') { try { rows = JSON.parse(rows); } catch { rows = []; } }
  if (!Array.isArray(rows)) rows = [];
  return rows.slice(0, 3).map(x => ({
    institution: String(x?.institution || '').trim().slice(0, 180),
    course: String(x?.course || '').trim().slice(0, 180),
    year: String(x?.year || '').replace(/\D/g, '').slice(0, 4)
  })).filter(x => x.institution || x.course || x.year);
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}
function verifyPassword(password, stored) {
  if (!stored || !stored.startsWith('scrypt$')) return false;
  const [, salt, expectedHex] = stored.split('$');
  if (!salt || !expectedHex) return false;
  const actual = crypto.scryptSync(String(password), salt, 64);
  const expected = Buffer.from(expectedHex, 'hex');
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}
function safeSecretEqual(a, b) {
  const aa = Buffer.from(String(a || '')); const bb = Buffer.from(String(b || ''));
  return aa.length === bb.length && aa.length > 0 && crypto.timingSafeEqual(aa, bb);
}
async function validAdminPassword(password) {
  const data = await readData();
  if (data._admin?.passwordHash) return verifyPassword(password, data._admin.passwordHash);
  if (!ADMIN_PASSWORD) return false;
  return safeSecretEqual(password, ADMIN_PASSWORD);
}
function verifiedGoogleIdentity(user) {
  if (!user?.email || !user.email_confirmed_at) return false;
  return (Array.isArray(user.identities) && user.identities.some(identity => identity.provider === 'google'))
    || (Array.isArray(user.app_metadata?.providers) && user.app_metadata.providers.includes('google'));
}

function secretKey() { return crypto.createHash('sha256').update(String(TOTP_ENCRYPTION_KEY)).digest(); }
function encryptSecret(value = '') {
  const iv = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', secretKey(), iv);
  const encrypted = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
  return `${iv.toString('hex')}.${cipher.getAuthTag().toString('hex')}.${encrypted.toString('hex')}`;
}
function decryptSecret(payload = '') {
  try {
    const [ivHex, tagHex, dataHex] = String(payload).split('.');
    const decipher = crypto.createDecipheriv('aes-256-gcm', secretKey(), Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
    return Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]).toString('utf8');
  } catch { return ''; }
}
function verifyTotpToken(token, secret) {
  const clean = String(token || '').replace(/\s/g, '');
  if (!secret || !/^\d{6}$/.test(clean)) return false;
  const previous = authenticator.options;
  try {
    authenticator.options = { ...previous, window: 1 };
    return authenticator.check(clean, secret);
  } finally { authenticator.options = previous; }
}
function baseUrl(req) { return PUBLIC_BASE_URL || `${req.protocol}://${req.get('host')}`; }
// Links de recuperação não podem ser construídos a partir do cabeçalho Host recebido.
function passwordRecoveryBaseUrl(req) {
  if (!IS_PRODUCTION) return baseUrl(req);
  try { const url = new URL(PUBLIC_BASE_URL); return url.protocol === 'https:' ? url.origin : ''; }
  catch { return ''; }
}
function escapeHtmlMeta(value = '') { return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function cleanSeoText(value = '', max = 170) { return String(value ?? '').replace(/<[^>]*>/g,' ').replace(/\s+/g,' ').trim().slice(0,max); }
function verificationTokenFrom(site = {}) {
  const raw = String(GOOGLE_SITE_VERIFICATION || site?.settings?.googleSearchConsoleVerification || '').trim();
  const match = raw.match(/content=["']([^"']+)["']/i);
  return (match ? match[1] : raw).replace(/[<>"']/g,'').slice(0,300);
}
function jsonLdScript(value, nonce) { return `<script nonce="${nonce}" type="application/ld+json">${JSON.stringify(value).replace(/</g,'\\u003c')}</script>`; }
async function sendSeoHtml(req, res, fileName, seo = {}) {
  try {
    let html = fs.readFileSync(path.join(__dirname, 'public', fileName), 'utf8');
    const site = await readData().catch(()=>({settings:{}}));
    const settings = site.settings || {};
    const siteName = settings.siteName || 'Yuran Multicerviços';
    const title = cleanSeoText(seo.title || settings.seoTitle || `${siteName} | Profissionais e serviços`, 120);
    const description = cleanSeoText(seo.description || settings.seoDescription || 'Encontre profissionais e serviços na Yuran Multicerviços.', 180);
    const canonical = seo.canonical || `${baseUrl(req)}${req.path === '/' ? '/' : req.path}`;
    const image = seo.image || settings.heroBackgroundImage || settings.headerLogoLight || settings.headerLogo || settings.logo || '';
    const robots = seo.robots || 'index,follow,max-image-preview:large,max-snippet:-1,max-video-preview:-1';
    const token = verificationTokenFrom(site);
    const schemas = Array.isArray(seo.schema) ? seo.schema : (seo.schema ? [seo.schema] : [{
      '@context':'https://schema.org','@type':'WebPage',name:title,description,url:canonical,
      isPartOf:{'@type':'WebSite',name:siteName,url:`${baseUrl(req)}/`}
    }]);

    html = html.replace(/<title>[\s\S]*?<\/title>/i, `<title>${escapeHtmlMeta(title)}</title>`);
    if (/<meta\s+name=["']description["'][^>]*>/i.test(html)) html = html.replace(/<meta\s+name=["']description["'][^>]*>/i, `<meta name="description" content="${escapeHtmlMeta(description)}">`);
    else html = html.replace('</head>', `<meta name="description" content="${escapeHtmlMeta(description)}"></head>`);
    html = html.replace(/<link\s+rel=["']canonical["'][^>]*>/ig,'')
      .replace(/<meta\s+(?:property|name)=["'](?:og:[^"']+|twitter:[^"']+)["'][^>]*>/ig,'')
      .replace(/<!-- yuran-seo-start -->[\s\S]*?<!-- yuran-seo-end -->/ig,'');

    const seoHead = `<!-- yuran-seo-start -->
<link rel="canonical" href="${escapeHtmlMeta(canonical)}">
<meta name="robots" content="${escapeHtmlMeta(robots)}">
${token ? `<meta name="google-site-verification" content="${escapeHtmlMeta(token)}">` : ''}
<meta property="og:type" content="${escapeHtmlMeta(seo.ogType || 'website')}">
<meta property="og:site_name" content="${escapeHtmlMeta(siteName)}">
<meta property="og:title" content="${escapeHtmlMeta(title)}">
<meta property="og:description" content="${escapeHtmlMeta(description)}">
<meta property="og:url" content="${escapeHtmlMeta(canonical)}">
${image ? `<meta property="og:image" content="${escapeHtmlMeta(image)}">` : ''}
<meta name="twitter:card" content="${image ? 'summary_large_image' : 'summary'}">
<meta name="twitter:title" content="${escapeHtmlMeta(title)}">
<meta name="twitter:description" content="${escapeHtmlMeta(description)}">
${image ? `<meta name="twitter:image" content="${escapeHtmlMeta(image)}">` : ''}
${schemas.map(schema => jsonLdScript(schema, res.locals.cspNonce)).join('\n')}
<!-- yuran-seo-end -->`;
    html = html.replace('</head>', `${seoHead}</head>`);
    res.set('Cache-Control','public, max-age=0, must-revalidate').type('html').send(html);
  } catch (error) {
    console.error('Falha ao renderizar SEO:', error);
    res.status(500).send('Não foi possível carregar a página.');
  }
}
function isValidImageBuffer(file) {
  const b = file?.buffer; if (!b || b.length < 12) return false;
  const jpg = b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff;
  const png = b.slice(0,8).equals(Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]));
  const webp = b.slice(0,4).toString() === 'RIFF' && b.slice(8,12).toString() === 'WEBP';
  return jpg || png || webp;
}
function isValidPdfBuffer(file) { return !!file?.buffer?.slice(0,5).equals(Buffer.from('%PDF-')); }
function detectedUploadType(file) {
  const b = file?.buffer;
  if (!b) return null;
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return { ext: '.jpg', mime: 'image/jpeg', kind: 'image' };
  if (b.length >= 8 && b.slice(0,8).equals(Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]))) return { ext: '.png', mime: 'image/png', kind: 'image' };
  if (b.length >= 12 && b.slice(0,4).toString() === 'RIFF' && b.slice(8,12).toString() === 'WEBP') return { ext: '.webp', mime: 'image/webp', kind: 'image' };
  if (b.length >= 5 && b.slice(0,5).equals(Buffer.from('%PDF-'))) return { ext: '.pdf', mime: 'application/pdf', kind: 'pdf' };
  return null;
}
function profileCompleteness(p = {}) {
  // V7.6: 100% representa os dados obrigatórios; CV, formação, idiomas e anos de experiência são enriquecimento opcional.
  let score = 0;
  if (String(p.name||'').trim()) score += 5;
  if (String(p.specialty||'').trim()) score += 10;
  if (String(p.bio||'').trim().length >= 80) score += 15;
  if (String(p.neighborhood||p.district||p.province||p.location||'').trim()) score += 10;
  if (String(p.photo||'').trim()) score += 15;
  if (digits(p.phone).length >= 8) score += 10;
  if (digits(p.whatsapp).length >= 8) score += 5;
  if (String(p.service_area||'').trim()) score += 10;
  if (String(p.skills||'').trim()) score += 10;
  if (String(p.address||'').trim()) score += 5;
  if (String(p.birth_date||'').trim()) score += 3;
  if (String(p.id_number||'').trim().length >= 4) score += 2;
  return Math.min(100, score);
}

function profileQualityMissing(p = {}) {
  const missing = [];
  if (!String(p.specialty||'').trim()) missing.push('especialidade');
  if (String(p.bio||'').trim().length < 80) missing.push('apresentação profissional com pelo menos 80 caracteres');
  if (!String(p.location||p.district||p.province||'').trim()) missing.push('localização');
  if (!String(p.photo||'').trim()) missing.push('foto profissional');
  if (!String(p.service_area||'').trim()) missing.push('área de atendimento');
  return missing;
}
function validationRequirements(p = {}) {
  const missing = [];
  if (!String(p.address||'').trim()) missing.push('endereço');
  if (!String(p.location||p.district||p.province||'').trim()) missing.push('cidade / província');
  if (digits(p.phone).length < 8) missing.push('número do celular');
  if (digits(p.whatsapp).length < 8) missing.push('número do WhatsApp');
  if (!String(p.birth_date||'').trim()) missing.push('data de nascimento');
  if (String(p.id_number||'').trim().length < 4) missing.push('número de identificação');
  missing.push(...profileQualityMissing(p));
  if (!String(p.skills||'').trim()) missing.push('competências');
  return [...new Set(missing)];
}
const DEFAULT_CATEGORIES = [
  ['Eletricidade','instalação elétrica, instalações elétricas, fios, cabos, tomadas, disjuntor, quadro elétrico, manutenção elétrica'],
  ['Design Gráfico e Branding','design, logotipo, logo, identidade visual, branding, flyer, cartaz, banner, social media'],
  ['Informática e TI','computador, informática, software, hardware, windows, office, redes, suporte técnico, programação'],
  ['Marketing e Comunicação','marketing, publicidade, tráfego pago, redes sociais, conteúdo, comunicação, anúncios'],
  ['Agropecuária','agricultura, pecuária, plantas, aves, produção, cultivo, criação, campo'],
  ['Jardinagem e Paisagismo','jardim, jardinagem, plantas, relva, paisagismo, poda, manutenção de jardim'],
  ['Construção Civil','obra, construção, pedreiro, alvenaria, reboco, pintura, reforma'],
  ['Canalização','canalizador, tubos, água, torneira, esgoto, canalização'],
  ['Carpintaria e Marcenaria','carpinteiro, madeira, móveis, portas, armários, marcenaria'],
  ['Serralharia','serralheiro, metal, portão, grade, soldadura, alumínio'],
  ['Mecânica Automóvel','mecânico, carro, automóvel, motor, manutenção automóvel, oficina'],
  ['Refrigeração e Climatização','ar condicionado, ac, refrigeração, frio, climatização'],
  ['Energia Solar','solar, painel solar, inversor, bateria, energia renovável'],
  ['Fotografia e Vídeo','fotografia, fotógrafo, vídeo, filmagem, edição de vídeo'],
  ['Eventos e Decoração','evento, casamento, decoração, festa, organização de eventos'],
  ['Beleza e Estética','beleza, estética, cabelo, manicure, maquiagem, maquilhagem'],
  ['Saúde e Bem-estar','saúde, bem-estar, fisioterapia, nutrição, massagem'],
  ['Educação e Formação','aulas, explicador, formação, curso, professor, treinamento'],
  ['Contabilidade e Finanças','contabilidade, contabilista, finanças, impostos, fiscalidade'],
  ['Recursos Humanos','rh, recursos humanos, recrutamento, currículo, gestão de pessoas'],
  ['Administração e Secretariado','administração, secretariado, assistente, documentos'],
  ['Tradução e Idiomas','tradução, tradutor, idiomas, interpretação'],
  ['Limpeza e Manutenção','limpeza, manutenção, conservação, doméstico'],
  ['Segurança e Vigilância','segurança, vigilância, cctv, câmera, alarme'],
  ['Transporte e Logística','transporte, entrega, logística, mudanças, motorista'],
  ['Costura e Moda','costura, alfaiate, roupa, moda, estilista'],
  ['Culinária e Catering','comida, cozinha, catering, buffet, refeições'],
  ['Reparação de Eletrodomésticos','reparação, eletrodoméstico, geladeira, máquina de lavar, televisão'],
  ['Telecomunicações e Redes','internet, rede, router, fibra, telecomunicações, wifi'],
  ['Consultoria e Serviços Profissionais','consultoria, consultor, assessoria, serviços profissionais'],
  ['Outros','outros serviços']
].map(([name,keywords],i)=>({id:`cat-${String(i+1).padStart(2,'0')}-${slugify(name)}`,name,keywords,active:true}));
function normalizeSearchText(value='') { return String(value||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase().replace(/[^a-z0-9]+/g,' ').trim(); }
function searchTokens(value='') { return [...new Set(normalizeSearchText(value).split(/\s+/).filter(x=>x.length>1))]; }
function locationLabel(p={}) { return [p.neighborhood,p.district,p.province].map(x=>String(x||'').trim()).filter(Boolean).join(', ') || String(p.location||'').trim(); }
function categoryMatch(categoryName, categories=[]) { const n=normalizeSearchText(categoryName); return categories.find(c=>normalizeSearchText(c.name)===n); }
function serviceSearchScore(p, term, categories=[]) {
  const tokens=searchTokens(term); if(!tokens.length)return 0;
  let score=0; const services=Array.isArray(p.services)?p.services:[];
  for(const token of tokens){
    const fields=[[p.name,9],[p.specialty,8],[p.headline,7],[p.skills,5],[p.bio,2],[p.service_area,3],[locationLabel(p),2]];
    for(const [value,w] of fields) if(normalizeSearchText(value).includes(token)) score+=w;
    for(const category of p.projectCategories||[]){
      if(normalizeSearchText(category).includes(token))score+=8;
      const match=categoryMatch(category,categories);
      if(match&&normalizeSearchText(match.keywords).includes(token))score+=7;
    }
    for(const svc of services){
      if(normalizeSearchText(svc.title).includes(token))score+=10;
      if(normalizeSearchText(svc.category).includes(token))score+=8;
      if(normalizeSearchText(svc.keywords).includes(token))score+=7;
      if(normalizeSearchText(svc.description).includes(token))score+=4;
      const cat=categoryMatch(svc.category,categories); if(cat&&normalizeSearchText(cat.keywords).includes(token))score+=7;
    }
  }
  return score;
}
function locationSearchScore(p, query, locationAliases=[]) {
  const q=normalizeSearchText(query); if(!q)return 0;
  const hood=normalizeSearchText(p.neighborhood),district=normalizeSearchText(p.district),province=normalizeSearchText(p.province),legacy=normalizeSearchText(p.location),area=normalizeSearchText(p.service_area);
  if(hood&&hood.includes(q))return 8; if(district&&district.includes(q))return 6; if(province&&province.includes(q))return 4; if(legacy.includes(q))return 5; if(area.includes(q))return 3;
  const alias=(locationAliases||[]).find(a=>normalizeSearchText(a.neighborhood).includes(q)||normalizeSearchText(a.alias).includes(q));
  if(alias){ const ad=normalizeSearchText(alias.district),ap=normalizeSearchText(alias.province); if(ad&&district===ad)return 2; if(ap&&province===ap)return 1; }
  return 0;
}

function normalizeEmailFrom(value = '') {
  // Evita um erro comum no Render: colar "EMAIL_FROM = ..." dentro do valor.
  return String(value || '').trim().replace(/^EMAIL_FROM\s*=\s*/i, '').trim();
}
function emailConfigState() {
  const from = normalizeEmailFrom(EMAIL_FROM);
  const issues = [];
  if (!RESEND_API_KEY) issues.push('RESEND_API_KEY não configurada.');
  if (!from) issues.push('EMAIL_FROM não configurado.');
  const match = from.match(/<([^>]+)>/) || from.match(/^([^\s<>]+@[^\s<>]+)$/);
  const sender = String(match?.[1] || '').trim().toLowerCase();
  if (from && !sender) issues.push('EMAIL_FROM inválido. Use: Yuran Multicerviços <email@dominio.com>.');
  if (/@gmail\.com$/i.test(sender)) issues.push('A Resend não pode enviar usando um endereço @gmail.com como remetente. Use onboarding@resend.dev para teste ou um domínio seu verificado na Resend.');
  return {
    configured: issues.length === 0,
    from,
    sender,
    testMode: /@resend\.dev$/i.test(sender),
    warning: issues.join(' ')
  };
}
function emailHtml(title, message, link = '') {
  const safe = (v='') => String(v).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
  const action = link && PUBLIC_BASE_URL ? `${PUBLIC_BASE_URL}${link}` : '';
  return `<!doctype html><html><body style="margin:0;background:#f5f7f6;font-family:Arial,sans-serif;color:#111"><div style="max-width:620px;margin:0 auto;padding:32px 18px"><div style="background:#fff;border:1px solid #e3e7e4;border-radius:18px;padding:28px"><div style="font-size:13px;font-weight:700;letter-spacing:.08em;color:#087f6a;margin-bottom:10px">YURAN MULTICERVIÇOS</div><h1 style="font-size:24px;margin:0 0 16px">${safe(title)}</h1><p style="font-size:16px;line-height:1.65;color:#4d5752;white-space:pre-line">${safe(message)}</p>${action?`<p style="margin:24px 0 0"><a href="${safe(action)}" style="display:inline-block;background:#101813;color:#fff;text-decoration:none;padding:12px 18px;border-radius:10px;font-weight:700">Abrir área profissional</a></p>`:''}</div><p style="font-size:12px;color:#7d8580;text-align:center;margin:18px 0 0">Mensagem automática da Yuran Multicerviços.</p></div></body></html>`;
}
async function sendTransactionalEmail(to, subject, text, link = '') {
  const config = emailConfigState();
  if (!config.configured || !to) return { ok: false, error: !to ? 'Destinatário sem e-mail.' : config.warning, skipped: true };
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: config.from, to: [to], subject, text, html: emailHtml(subject, text, link) }),
      signal: AbortSignal.timeout(15000)
    });
    let payload = {};
    try { payload = await r.json(); } catch {}
    if (!r.ok) {
      const detail = payload?.message || payload?.error || `HTTP ${r.status}`;
      console.error('Resend recusou o e-mail:', detail);
      return { ok: false, error: String(detail), status: r.status };
    }
    return { ok: true, id: payload?.id || '' };
  } catch (e) {
    console.error('E-mail não enviado:', e.message);
    return { ok: false, error: e.message };
  }
}

function emailVerificationHash(userId, code) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(`${userId}:${String(code)}`).digest('hex');
}
function secureCodeEqual(a, b) {
  const aa = Buffer.from(String(a || ''), 'hex');
  const bb = Buffer.from(String(b || ''), 'hex');
  return aa.length === bb.length && aa.length > 0 && crypto.timingSafeEqual(aa, bb);
}
async function issueEmailVerification(userId, email, { force = false } = {}) {
  if (!userId || !email) return { ok: false, error: 'Conta sem e-mail válido.' };
  const config = emailConfigState();
  if (!config.configured) return { ok: false, error: config.warning || 'Envio de e-mail não configurado.' };
  const { data: user, error } = await supabase.from('professional_users').select('email_verified_at,email_verification_sent_at,email_verification_code_hash,email_verification_expires_at,email_verification_attempts').eq('id', userId).maybeSingle();
  if (error) throw error;
  if (user?.email_verified_at) return { ok: true, verified: true, alreadyVerified: true };
  const last = user?.email_verification_sent_at ? new Date(user.email_verification_sent_at).getTime() : 0;
  const waitMs = 60 * 1000 - (Date.now() - last);
  if (!force && waitMs > 0) return { ok: false, retryAfter: Math.ceil(waitMs / 1000), error: `Aguarde ${Math.ceil(waitMs / 1000)} segundos antes de reenviar.` };
  const code = String(crypto.randomInt(100000, 1000000));
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 10 * 60 * 1000).toISOString();
  const codeHash = emailVerificationHash(userId, code);
  const { error: updateError } = await supabase.from('professional_users').update({
    email_verification_code_hash: codeHash,
    email_verification_expires_at: expiresAt,
    email_verification_sent_at: now.toISOString(),
    email_verification_attempts: 0,
    updated_at: now.toISOString()
  }).eq('id', userId);
  if (updateError) throw updateError;
  const result = await sendTransactionalEmail(
    email,
    'Confirme o seu e-mail — Yuran Multicerviços',
    `O seu código de confirmação é: ${code}\n\nEste código expira em 10 minutos. Se não criou uma conta na Yuran Multicerviços, ignore esta mensagem.`
  );
  if (!result.ok) {
    // Um envio recusado não deve deixar um código inutilizável nem bloquear o reenvio.
    // A condição evita restaurar o estado antigo sobre um novo código criado em paralelo.
    const { error: restoreError } = await supabase.from('professional_users').update({
      email_verification_code_hash: user?.email_verification_code_hash || '',
      email_verification_expires_at: user?.email_verification_expires_at || null,
      email_verification_sent_at: user?.email_verification_sent_at || null,
      email_verification_attempts: Number(user?.email_verification_attempts || 0),
      updated_at: new Date().toISOString()
    }).eq('id', userId).eq('email_verification_code_hash', codeHash);
    if (restoreError) console.error('Não foi possível restaurar o estado do código:', restoreError.message);
    return { ok: false, error: result.error || 'Não foi possível enviar o código.' };
  }
  return { ok: true, sent: true, expiresAt };
}
async function notifyProfessional(professionalId, type, title, message, link = '', options = {}) {
  try {
    const { data: profile } = await supabase.from('professional_profiles').select('email,name').eq('id', professionalId).maybeSingle();
    const id = crypto.randomUUID();
    const { error } = await supabase.from('professional_notifications').insert({ id, professional_id: professionalId, type, title, message, link, created_at: new Date().toISOString() });
    if (error) throw error;
    let emailResult = { ok: false, skipped: true, error: 'Envio externo não solicitado para esta notificação.' };
    if (options.sendEmail === true) {
      emailResult = await sendTransactionalEmail(profile?.email, title, message, link);
      if (emailResult.ok) await supabase.from('professional_notifications').update({ email_sent: true }).eq('id', id);
    }
    return { notificationId: id, emailSent: Boolean(emailResult.ok), email: profile?.email || '', emailError: emailResult.error || '' };
  } catch (e) {
    console.error('Notificação não registada:', e.message);
    return { notificationId: '', emailSent: false, email: '', emailError: e.message };
  }
}
async function safeAuditLog({ target_type, target_id, action, reason = '', metadata = {} }) {
  try {
    const { error } = await supabase.from('moderation_logs').insert({
      id: crypto.randomUUID(), target_type, target_id, action, reason,
      metadata, created_at: new Date().toISOString()
    });
    if (error) throw error;
  } catch (e) {
    // A ação administrativa principal nunca deve falhar só porque o log falhou.
    console.error('Falha ao registar auditoria:', e.message);
  }
}
async function purgeExpiredIdentityDocuments() {
  if (!USE_SUPABASE) return;
  const now = new Date().toISOString();
  const { data, error } = await supabase.from('professional_profiles').select('id,id_front_path,id_back_path').not('identity_retention_until','is',null).lt('identity_retention_until', now).is('identity_documents_deleted_at', null);
  if (error) return console.error('Falha ao verificar retenção documental:', error.message);
  for (const p of data || []) {
    if (p.id_front_path) await deletePrivateIdentityUpload(p.id_front_path);
    if (p.id_back_path) await deletePrivateIdentityUpload(p.id_back_path);
    await supabase.from('professional_profiles').update({ id_front_path: '', id_back_path: '', identity_documents_deleted_at: now, updated_at: now }).eq('id', p.id);
  }
}

function normalizeContent(content) {
  content.settings ||= {};
  if (!content.settings.siteName || content.settings.siteName === 'Nexa MultiServiços') content.settings.siteName = 'Yuran Multicerviços';
  content.settings.primaryColor ||= '#151a16';
  content.settings.heroColor ||= '#00C9A7';
  content.settings.navHoverColor ||= '#00C9A7';
  content.settings.logo ||= ''; // legado V4/V6.2
  content.settings.headerLogo ||= content.settings.logo || '';
  content.settings.headerLogoLight ||= content.settings.headerLogo || content.settings.logo || '';
  content.settings.headerLogoDark ||= content.settings.headerLogo || content.settings.logo || '';
  content.settings.heroLogo ||= content.settings.logo || '';
  content.settings.introVideoEnabled = content.settings.introVideoEnabled === true || String(content.settings.introVideoEnabled).toLowerCase() === 'true' || String(content.settings.introVideoEnabled) === '1';
  content.settings.introVideoTitle ||= 'Conheça a Yuran Multicerviços';
  content.settings.introVideoText ||= 'Veja como a plataforma aproxima profissionais e clientes, como funciona a verificação e quais recursos estão disponíveis.';
  content.settings.introVideoUrl ||= '';
  content.settings.address ||= content.settings.location || '';
  content.settings.favicon ||= '';
  content.settings.adminLogo ||= '';
  content.settings.adminLogoBg ||= '#0f1713';
  content.settings.adminLogoTransparent = content.settings.adminLogoTransparent === true || String(content.settings.adminLogoTransparent).toLowerCase() === 'true' || String(content.settings.adminLogoTransparent) === '1';
  content.settings.adminFavicon ||= content.settings.favicon || '';
  if (!String(content.settings.about||'').trim() || /texto editável|brevemente/i.test(String(content.settings.about||''))) content.settings.about = 'A Yuran Multicerviços é uma plataforma moçambicana criada para aproximar pessoas que precisam de serviços e profissionais preparados para realizá-los. Reunimos diferentes áreas profissionais num só espaço, permitindo pesquisar, comparar perfis, conhecer serviços, projetos, experiência e avaliações antes de entrar em contacto. A plataforma promove uma apresentação profissional mais organizada, mecanismos de validação e ferramentas de confiança, sem substituir a verificação que cada utilizador deve fazer antes de contratar. O nosso objetivo é facilitar oportunidades, dar visibilidade a competências locais e tornar a procura por serviços mais simples, transparente e acessível.';
  content.categories = Array.isArray(content.categories) && content.categories.length ? content.categories.map((c,i)=>({id:c.id||`cat-${i+1}-${slugify(c.name||'categoria')}`,name:String(c.name||'').trim(),keywords:String(c.keywords||'').trim(),description:String(c.description||'').trim(),active:c.active!==false})).filter(c=>c.name) : DEFAULT_CATEGORIES.map(x=>({...x}));
  content.locationAliases = Array.isArray(content.locationAliases) ? content.locationAliases.map((x,i)=>({id:x.id||`loc-${i+1}-${slugify(x.neighborhood||'local')}`,neighborhood:String(x.neighborhood||'').trim(),alias:String(x.alias||'').trim(),district:String(x.district||'').trim(),province:String(x.province||'').trim()})).filter(x=>x.neighborhood&&x.district) : [];
  content.settings.heroBackgroundImage ||= '';
  content.settings.heroOverlay = content.settings.heroOverlay ?? '0.24';
  content.settings.seoTitle ||= `${content.settings.siteName || 'Yuran Multicerviços'} | Profissionais e serviços`;
  content.settings.seoDescription ||= 'Encontre profissionais, serviços e trabalhos numa plataforma moderada, transparente e profissional.';
  content.settings.googleSearchConsoleVerification ||= '';
  content._admin ||= {};
  content.socials ||= [];
  if (!content.socials.length) {
    const oldSocials = [
      ['Instagram', 'instagram', 'bi-instagram'],
      ['Facebook', 'facebook', 'bi-facebook'],
      ['LinkedIn', 'linkedin', 'bi-linkedin']
    ];
    content.socials = oldSocials.filter(([, key]) => content.settings[key] && content.settings[key] !== '#').map(([platform, key, iconClass]) => ({ id: uid('social'), platform, url: normalizeUrl(content.settings[key]), iconClass }));
  }
  const presets = {
    'eletricidade': { iconClass: 'bi-lightning-charge', oldColor: '#F28C28', color: '#F28C28' },
    'design-grafico': { iconClass: 'bi-palette', oldColor: '#708D75', color: '#00C9A7' },
    'marketing': { iconClass: 'bi-megaphone', oldColor: '#476C9B', color: '#00C9A7' },
    'agropecuaria': { iconClass: 'bi-flower1', oldColor: '#77966D', color: '#2E8B57' }
  };
  content.services = (content.services || []).map(s => {
    const preset = presets[s.id] || {};
    const next = { ...s };
    if (!next.iconClass) next.iconClass = preset.iconClass || 'bi-briefcase';
    if (preset.oldColor && String(next.color).toUpperCase() === preset.oldColor.toUpperCase()) next.color = preset.color;
    next.iconImage ||= '';
    next.banner ||= '';
    next.details ||= next.description || '';
    return next;
  });
  content.portfolio = (content.portfolio || []).map(p => ({ ...p, images: p.images?.length ? p.images : (p.image ? [p.image] : []), featured: typeof p.featured === 'boolean' ? p.featured : true }));
  content.partners = (content.partners || []).map(p => ({ ...p, logoLight: p.logoLight || p.logo || '', logoDark: p.logoDark || p.logo || '' })); content.links = (content.links || []).map(l => ({ ...l, iconClass: l.iconClass || 'bi-link-45deg' })); content.team ||= [];
  return content;
}

async function readData() {
  if (!USE_SUPABASE) return normalizeContent(readLocalData());
  const { data, error } = await supabase.from('site_content').select('content').eq('id', 'main').maybeSingle();
  if (error) throw error;
  if (!data) {
    const initial = readLocalData();
    const { error: insertError } = await supabase.from('site_content').insert({ id: 'main', content: initial });
    if (insertError) throw insertError;
    return normalizeContent(initial);
  }
  return normalizeContent(data.content);
}

async function writeData(content) {
  if (!USE_SUPABASE) return writeLocalData(content);
  const { error } = await supabase.from('site_content').upsert({ id: 'main', content, updated_at: new Date().toISOString() });
  if (error) throw error;
}

const imageUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024, files: 16, fields: 100, parts: 120, fieldSize: 32 * 1024 },
  fileFilter: (_, file, cb) => cb(null, ['image/jpeg','image/png','image/webp'].includes(file.mimetype))
});
const cvUpload = multer({
  storage: multer.memoryStorage(), limits: { fileSize: 12 * 1024 * 1024, files: 1, fields: 10, parts: 12, fieldSize: 32 * 1024 },
  fileFilter: (_, file, cb) => cb(null, file.mimetype === 'application/pdf')
});
const identityUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 2, fields: 80, parts: 84, fieldSize: 32 * 1024 },
  fileFilter: (_, file, cb) => cb(null, ['image/jpeg','image/png','image/webp','application/pdf'].includes(file.mimetype))
});
function safeName(name) { return name.replace(/[^a-zA-Z0-9._-]/g, '-'); }

async function saveUpload(file, folder) {
  if (!file) return '';
  const detected = detectedUploadType(file);
  if (folder === 'images' && detected?.kind !== 'image') throw new Error('Imagem inválida. Use JPG, PNG ou WebP.');
  if (folder === 'cvs' && detected?.kind !== 'pdf') throw new Error('PDF inválido.');
  if (!detected) throw new Error('Tipo de ficheiro não permitido.');
  // Nunca use a extensão/nome enviados pelo navegador: o tipo real é derivado da assinatura binária.
  const filename = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${detected.ext}`;
  if (USE_SUPABASE) {
    const storagePath = `${folder}/${filename}`;
    const { error } = await supabase.storage.from(STORAGE_BUCKET).upload(storagePath, file.buffer, { contentType: detected.mime, upsert: false });
    if (error) throw error;
    return supabase.storage.from(STORAGE_BUCKET).getPublicUrl(storagePath).data.publicUrl;
  }
  fs.writeFileSync(path.join(IMAGE_DIR, filename), file.buffer);
  return `/uploads/${folder}/${filename}`;
}

function privatePath(ref) {
  if (typeof ref !== 'string' || !ref.startsWith(PRIVATE_PREFIX)) return '';
  const name = ref.slice(PRIVATE_PREFIX.length);
  return /^(?:cvs|projects)\/[a-zA-Z0-9-]+\/[a-zA-Z0-9-]+\.(?:pdf|jpg|png|webp)$/.test(name) ? name : '';
}
async function savePrivateUpload(file, folder, ownerId) {
  const type = detectedUploadType(file);
  if (!type || (folder === 'cvs' ? type.kind !== 'pdf' : type.kind !== 'image')) throw new Error('Ficheiro inválido.');
  const storagePath = `${folder}/${ownerId}/${crypto.randomBytes(20).toString('hex')}${type.ext}`;
  if (USE_SUPABASE) {
    const { error } = await supabase.storage.from(VERIFICATION_BUCKET).upload(storagePath, file.buffer, { contentType: type.mime, upsert: false });
    if (error) throw error;
  } else {
    const local = path.join(PRIVATE_DIR, storagePath);
    fs.mkdirSync(path.dirname(local), { recursive: true });
    fs.writeFileSync(local, file.buffer, { flag: 'wx' });
  }
  return `${PRIVATE_PREFIX}${storagePath}`;
}
async function readPrivateUpload(ref) {
  const storagePath = privatePath(ref);
  if (!storagePath) throw new Error('Ficheiro privado inválido.');
  if (!USE_SUPABASE) return fs.promises.readFile(path.join(PRIVATE_DIR, storagePath));
  const { data, error } = await supabase.storage.from(VERIFICATION_BUCKET).download(storagePath);
  if (error) throw error;
  return Buffer.from(await data.arrayBuffer());
}
async function servePrivateUpload(ref, res) {
  const storagePath = privatePath(ref);
  if (!storagePath) return res.status(404).end();
  const type = storagePath.endsWith('.pdf') ? 'application/pdf' : storagePath.endsWith('.png') ? 'image/png' : storagePath.endsWith('.webp') ? 'image/webp' : 'image/jpeg';
  const buffer = await readPrivateUpload(ref);
  res.set('Cache-Control', 'private, no-store').type(type).send(buffer);
}
async function serveCurrentCv(profile, res) {
  if (!profile?.cv_url) return res.status(404).end();
  if (privatePath(profile.cv_url)) return servePrivateUpload(profile.cv_url, res);
  return res.status(404).end();
}
function ownerProjectRow(project) {
  return { ...project, images: (project.images || []).map((ref, index) => privatePath(ref)
    ? `/api/professional/projects/${encodeURIComponent(project.id)}/images/${index}` : ref) };
}
function adminProjectRow(project) {
  return { ...project, images: (project.images || []).map((ref, index) => privatePath(ref)
    ? `/api/admin/projects/${encodeURIComponent(project.id)}/images/${index}` : ref) };
}
async function publishProjectImages(images) {
  const created = [], privateRefs = [];
  try {
    const output = [];
    for (const ref of images || []) {
      const storagePath = privatePath(ref);
      if (!storagePath) { output.push(ref); continue; }
      const contents = await readPrivateUpload(ref);
      const ext = path.extname(storagePath);
      const type = ext === '.png' ? 'image/png' : ext === '.webp' ? 'image/webp' : 'image/jpeg';
      const destination = `images/${Date.now()}-${crypto.randomBytes(20).toString('hex')}${ext}`;
      if (USE_SUPABASE) {
        const { error } = await supabase.storage.from(STORAGE_BUCKET).upload(destination, contents, { contentType: type, upsert: false });
        if (error) throw error;
        created.push(supabase.storage.from(STORAGE_BUCKET).getPublicUrl(destination).data.publicUrl);
      } else {
        const url = `/uploads/images/${path.basename(destination)}`;
        fs.writeFileSync(path.join(IMAGE_DIR, path.basename(destination)), contents, { flag: 'wx' });
        created.push(url);
      }
      output.push(created[created.length - 1]);
      privateRefs.push(ref);
    }
    return { images: output, created, privateRefs };
  } catch (error) { await Promise.all(created.map(url => deleteUpload(url).catch(()=>{}))); throw error; }
}
async function privatizeProjectImage(ref, ownerId) {
  if (privatePath(ref)) return ref;
  let file;
  let name;
  if (USE_SUPABASE) {
    const prefix = `${supabase.storage.from(STORAGE_BUCKET).getPublicUrl('images/').data.publicUrl}`;
    if (!ref.startsWith(prefix)) throw new Error('Imagem pública do projeto não reconhecida.');
    name = decodeURIComponent(ref.slice(prefix.length));
    if (!/^[a-zA-Z0-9._-]+\.(?:jpe?g|png|webp)$/.test(name)) throw new Error('Caminho de imagem inválido.');
    const { data, error } = await supabase.storage.from(STORAGE_BUCKET).download(`images/${name}`);
    if (error) throw error;
    file = Buffer.from(await data.arrayBuffer());
  } else {
    if (!/^\/uploads\/images\/[a-zA-Z0-9._-]+\.(?:jpe?g|png|webp)$/.test(ref)) throw new Error('Imagem pública do projeto não reconhecida.');
    name = path.basename(ref);
    file = await fs.promises.readFile(path.join(IMAGE_DIR, name));
  }
  if (file.length > 12 * 1024 * 1024) throw new Error('Imagem antiga excede o tamanho permitido.');
  return savePrivateUpload({ buffer: file }, 'projects', ownerId);
}

async function deleteUpload(url) {
  if (!url) return;
  const privateRef = privatePath(url);
  if (privateRef) {
    if (USE_SUPABASE) {
      const { error } = await supabase.storage.from(VERIFICATION_BUCKET).remove([privateRef]);
      if (error) throw error;
    } else await fs.promises.rm(path.join(PRIVATE_DIR, privateRef), { force: true });
    return;
  }
  if (USE_SUPABASE) {
    const marker = `/storage/v1/object/public/${STORAGE_BUCKET}/`;
    const index = url.indexOf(marker);
    if (index >= 0) {
      const { error } = await supabase.storage.from(STORAGE_BUCKET).remove([decodeURIComponent(url.slice(index + marker.length))]);
      if (error) throw error;
    }
    return;
  }
  if (url.startsWith('/uploads/')) {
    const localPath = path.join(__dirname, 'public', url.replace(/^\//, ''));
    if (fs.existsSync(localPath)) fs.unlinkSync(localPath);
  }
}

async function savePrivateIdentityUpload(file, profileId, side) {
  if (!file || !USE_SUPABASE) throw new Error('Documentos de identificação requerem Supabase.');
  const detected = detectedUploadType(file);
  if (!detected || !['image','pdf'].includes(detected.kind)) throw new Error('Documento inválido. Use JPG, PNG, WebP ou PDF.');
  const storagePath = `professionals/${profileId}/${side}-${Date.now()}-${crypto.randomBytes(8).toString('hex')}${detected.ext}`;
  const { error } = await supabase.storage.from(VERIFICATION_BUCKET).upload(storagePath, file.buffer, { contentType: detected.mime, upsert: false });
  if (error) throw error;
  return storagePath;
}
async function deletePrivateIdentityUpload(storagePath) {
  if (!storagePath || !USE_SUPABASE) return;
  await supabase.storage.from(VERIFICATION_BUCKET).remove([storagePath]);
}
function visitorHash(req) {
  return crypto.createHash('sha256').update(`${req.ip || ''}|${req.get('user-agent') || ''}|${SESSION_SECRET}`).digest('hex');
}

app.get('/api/site', async (_, res) => {
  try { const data = await readData(); const { _admin, ...publicData } = data; res.json(publicData); }
  catch (error) { console.error(error); res.status(500).json({ error: 'Não foi possível carregar os dados.' }); }
});

app.get('/api/public-config', (_, res) => res.json({
  supabaseUrl: SUPABASE_URL,
  supabaseAnonKey: SUPABASE_ANON_KEY,
  googleOAuthAvailable: Boolean(SUPABASE_URL && SUPABASE_ANON_KEY)
}));

app.get('/servico/:id', async (req, res) => {
  try{
    const site=await readData();const item=findPublicServiceArea(site,req.params.id);
    if(!item)return res.status(404).send('Serviço não encontrado.');
    return sendSeoHtml(req,res,'service.html',{title:`${item.title||'Serviço'} | ${site.settings?.siteName||'Yuran Multicerviços'}`,description:cleanSeoText(item.details||item.description||'',175),canonical:`${baseUrl(req)}/servico/${encodeURIComponent(item.id)}`,image:item.banner||item.iconImage});
  }catch(error){console.error(error);res.status(500).send('Não foi possível carregar o serviço.')}
});

app.post('/api/admin/login', async (req, res) => {
  try {
    if (typeof req.body?.password !== 'string' || !req.body.password) return res.status(400).json({ error: 'Informe a senha.' });
    if (!(await validAdminPassword(req.body.password))) return res.status(401).json({ error: 'Senha incorreta.' });
    const data = await readData();
    if (data._admin?.totpEnabled && data._admin?.totpSecretEncrypted) {
      if (IS_PRODUCTION && !req.secure) throw new Error('HTTPS_PROXY_REQUIRED');
      await regenerateSession(req);
      req.session.admin2faPending = true;
      req.session.admin2faStartedAt = Date.now();
      req.session.adminCredentialTag = adminCredentialTag(data);
      await saveSession(req);
      if ((await readStoredSession(req.sessionID))?.admin2faPending !== true) throw new Error('ADMIN_SESSION_NOT_PERSISTED');
      setAdminLoginCookie(req, res);
      return res.json({ ok: true, requires2fa: true });
    }
    await activateAdminSession(req);
    setAdminLoginCookie(req, res);
    return res.json({ ok: true, requires2fa: false });
  } catch (error) { console.error('Falha ao autenticar o administrador:', error); res.status(503).json({ error: error.message === 'HTTPS_PROXY_REQUIRED' ? 'O acesso seguro não foi reconhecido pelo servidor. Verifique a configuração HTTPS do Render.' : 'Não foi possível manter a sessão administrativa. Verifique a base de dados de sessões e tente novamente.' }); }
});
app.post('/api/admin/login-2fa', async (req, res) => {
  try {
    if (!req.session.admin2faPending || Date.now() - Number(req.session.admin2faStartedAt || 0) > 10 * 60 * 1000) return res.status(401).json({ error: 'Sessão de autenticação expirada. Entre novamente.' });
    const data = await readData();
    if (!safeSecretEqual(req.session.adminCredentialTag, adminCredentialTag(data))) return res.status(401).json({ error: 'A senha foi alterada. Inicie sessão novamente.' });
    const encryptedSecret = data._admin?.totpSecretEncrypted || '';
    const secret = decryptSecret(encryptedSecret);
    const token = String(req.body?.token || '').replace(/\s/g,'');
    if (encryptedSecret && !secret) return res.status(409).json({ error: 'A configuração 2FA não pode ser lida com a chave atual. Use “Problemas com o 2FA?” para voltar a configurar o autenticador.', code: 'TOTP_SECRET_UNREADABLE' });
    if (!verifyTotpToken(token, secret)) return res.status(401).json({ error: 'Código de autenticação inválido. Confirme a hora automática do telefone e tente o código atual.' });
    await activateAdminSession(req);
    setAdminLoginCookie(req, res);
    res.json({ ok: true });
  } catch (error) { console.error('Falha ao confirmar 2FA:', error); res.status(503).json({ error: error.message === 'HTTPS_PROXY_REQUIRED' ? 'O acesso seguro não foi reconhecido pelo servidor. Verifique a configuração HTTPS do Render.' : 'O código foi aceite, mas a sessão não pôde ser guardada. Tente novamente.' }); }
});
app.post('/api/admin/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!(await validAdminPassword(currentPassword))) return res.status(401).json({ error: 'A senha atual está incorreta.' });
    if (String(newPassword || '').length < 8) return res.status(400).json({ error: 'A nova senha deve ter pelo menos 8 caracteres.' });
    const data = await readData();
    data._admin ||= {}; data._admin.passwordHash = hashPassword(newPassword); data._admin.passwordUpdatedAt = new Date().toISOString();
    await writeData(data);
    await revokeSessions('admin', true);
    await revokeSessions('admin2faPending', true);
    await destroySession(req);
    res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao alterar a senha.' }); }
});
app.post('/api/admin/recover-password', async (req, res) => {
  try {
    if (!ADMIN_RECOVERY_KEY) return res.status(503).json({ error: 'Recuperação ainda não configurada. Defina ADMIN_RECOVERY_KEY no Render.' });
    const { recoveryKey, newPassword } = req.body || {};
    if (!safeSecretEqual(recoveryKey, ADMIN_RECOVERY_KEY)) return res.status(401).json({ error: 'Chave de recuperação incorreta. Use o valor exato de ADMIN_RECOVERY_KEY no Render; SESSION_SECRET é uma chave diferente.' });
    if (String(newPassword || '').length < 8) return res.status(400).json({ error: 'A nova senha deve ter pelo menos 8 caracteres.' });
    const data = await readData();
    data._admin ||= {}; data._admin.passwordHash = hashPassword(newPassword); data._admin.passwordUpdatedAt = new Date().toISOString();
    await writeData(data);
    await revokeSessions('admin', true);
    await revokeSessions('admin2faPending', true);
    await destroySession(req);
    res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao recuperar a senha.' }); }
});
app.post('/api/admin/recover-2fa', async (req, res) => {
  try {
    if (!ADMIN_RECOVERY_KEY) return res.status(503).json({ error: 'Recuperação ainda não configurada. Defina ADMIN_RECOVERY_KEY no Render.' });
    const { recoveryKey, password } = req.body || {};
    if (!safeSecretEqual(recoveryKey, ADMIN_RECOVERY_KEY)) return res.status(401).json({ error: 'Chave de recuperação inválida.' });
    if (!(await validAdminPassword(password))) return res.status(401).json({ error: 'Senha administrativa incorreta.' });
    const data = await readData();
    data._admin ||= {};
    data._admin.totpEnabled = false;
    delete data._admin.totpSecretEncrypted;
    delete data._admin.totpPendingEncrypted;
    data._admin.totpRecoveredAt = new Date().toISOString();
    await writeData(data);
    await safeAuditLog({ target_type: 'admin_security', target_id: 'admin', action: '2fa_recovery_reset', reason: '2FA redefinido com ADMIN_RECOVERY_KEY e senha administrativa.' });
    req.session.admin2faPending = false;
    delete req.session.admin2faStartedAt;
    res.json({ ok: true, message: '2FA redefinido. Entre com a senha e configure novamente no painel.' });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao recuperar o 2FA.' }); }
});
app.post('/api/admin/logout', requireAuth, (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/admin/session', async (req, res, next) => {
  res.set('Cache-Control', 'no-store, private');
  try {
    const data = await readData();
    const valid = Boolean(req.session?.adminCredentialTag && safeSecretEqual(req.session.adminCredentialTag, adminCredentialTag(data)));
    const authenticated = valid && req.session?.admin === true;
    const hasCookie = String(req.headers.cookie || '').split(';').some(c => c.trim().startsWith('yuran.admin.sid='));
    res.json({ authenticated, pending2fa: valid && req.session?.admin2faPending === true,
      passwordSource: authenticated ? (data._admin?.passwordHash ? 'painel' : 'ambiente') : undefined,
      reason: authenticated ? null : hasCookie ? 'expired_or_invalid' : 'cookie_missing' });
  } catch (error) { next(error); }
});
app.get('/api/admin/security-status', requireAuth, async (req, res) => {
  try {
    const data = await readData();
    res.json({ security: { sessionSecretConfigured: SESSION_SECRET_CONFIGURED,
      totpEncryptionKeyConfigured: TOTP_ENCRYPTION_KEY_CONFIGURED,
      passwordSource: data._admin?.passwordHash ? 'painel' : 'ambiente',
      privateBucketVerified: USE_SUPABASE, distributedLimits: USE_SUPABASE } });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Estado de segurança indisponível.' }); }
});

app.put('/api/admin/settings', requireAuth, async (req, res) => {
  try {
    const data = await readData();
    const body = { ...req.body };
    const textFields = ['siteName','tagline','seoTitle','seoDescription','googleSearchConsoleVerification','heroTitle','heroText','whatsapp','phone','email','address','about','introVideoTitle','introVideoText','introVideoUrl'];
    for (const key of textFields) if (body[key] !== undefined) body[key] = String(body[key]).trim().slice(0, key === 'about' || key === 'introVideoText' ? 6000 : 500);
    if (body.heroOverlay !== undefined) body.heroOverlay = String(Math.max(0, Math.min(.8, Number(body.heroOverlay) || 0)));
    if (body.adminLogoBg !== undefined) body.adminLogoBg = /^#[0-9a-f]{6}$/i.test(String(body.adminLogoBg)) ? String(body.adminLogoBg) : '#0f1713';
    if (body.introVideoEnabled !== undefined) body.introVideoEnabled = ['on','true','1','yes'].includes(String(body.introVideoEnabled).toLowerCase());
    if (body.adminLogoTransparent !== undefined) body.adminLogoTransparent = ['on','true','1','yes'].includes(String(body.adminLogoTransparent).toLowerCase());
    data.settings = { ...data.settings, ...body };
    await writeData(data); res.json(data.settings);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao guardar configurações.' }); }
});

app.post('/api/admin/settings/assets', requireAuth, imageUpload.fields([{ name: 'headerLogoLight', maxCount: 1 }, { name: 'headerLogoDark', maxCount: 1 }, { name: 'headerLogo', maxCount: 1 }, { name: 'heroLogo', maxCount: 1 }, { name: 'logo', maxCount: 1 }, { name: 'favicon', maxCount: 1 }, { name: 'adminLogo', maxCount: 1 }, { name: 'adminFavicon', maxCount: 1 }, { name: 'heroBackground', maxCount: 1 }]), async (req, res) => {
  try {
    const data = await readData();
    data.settings ||= {};
    if (req.files?.headerLogoLight?.[0]) {
      if (data.settings.headerLogoLight && data.settings.headerLogoLight !== data.settings.headerLogoDark) await deleteUpload(data.settings.headerLogoLight);
      data.settings.headerLogoLight = await saveUpload(req.files.headerLogoLight[0], 'images');
    }
    if (req.files?.headerLogoDark?.[0]) {
      if (data.settings.headerLogoDark && data.settings.headerLogoDark !== data.settings.headerLogoLight) await deleteUpload(data.settings.headerLogoDark);
      data.settings.headerLogoDark = await saveUpload(req.files.headerLogoDark[0], 'images');
    }
    if (req.files?.headerLogo?.[0]) {
      const legacyHeader = await saveUpload(req.files.headerLogo[0], 'images');
      data.settings.headerLogo = legacyHeader;
      data.settings.headerLogoLight ||= legacyHeader;
      data.settings.headerLogoDark ||= legacyHeader;
    }
    if (req.files?.heroLogo?.[0]) {
      data.settings.heroLogo = await saveUpload(req.files.heroLogo[0], 'images');
    }
    // Compatibilidade com formulários antigos: um logo legado preenche as duas áreas.
    if (req.files?.logo?.[0]) {
      const legacy = await saveUpload(req.files.logo[0], 'images');
      data.settings.logo = legacy; data.settings.headerLogo = legacy; data.settings.headerLogoLight = legacy; data.settings.headerLogoDark = legacy; data.settings.heroLogo = legacy;
    }
    if (req.files?.favicon?.[0]) {
      if (data.settings.favicon) await deleteUpload(data.settings.favicon);
      data.settings.favicon = await saveUpload(req.files.favicon[0], 'images');
      data.settings.adminFavicon ||= data.settings.favicon;
    }
    if (req.files?.adminLogo?.[0]) { if (data.settings.adminLogo) await deleteUpload(data.settings.adminLogo); data.settings.adminLogo = await saveUpload(req.files.adminLogo[0], 'images'); }
    if (req.files?.adminFavicon?.[0]) { if (data.settings.adminFavicon && data.settings.adminFavicon !== data.settings.favicon) await deleteUpload(data.settings.adminFavicon); data.settings.adminFavicon = await saveUpload(req.files.adminFavicon[0], 'images'); }
    if (req.body.removeHeroBackground === '1' && data.settings.heroBackgroundImage) {
      await deleteUpload(data.settings.heroBackgroundImage);
      data.settings.heroBackgroundImage = '';
    }
    if (req.files?.heroBackground?.[0]) {
      if (data.settings.heroBackgroundImage) await deleteUpload(data.settings.heroBackgroundImage);
      data.settings.heroBackgroundImage = await saveUpload(req.files.heroBackground[0], 'images');
    }
    await writeData(data); res.json(data.settings);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao guardar identidade visual e fundo.' }); }
});

// SERVIÇOS: cor, ícone Bootstrap/personalizado, banner e página própria.
// Uma área da pesquisa também é um serviço público, mesmo antes de receber
// identidade visual. Guardar a edição cria a configuração correspondente.
app.put('/api/admin/service-areas/:categoryId', requireAuth, imageUpload.fields([{ name: 'iconImage', maxCount: 1 }, { name: 'banner', maxCount: 1 }]), async (req, res) => {
  try {
    const data = await readData();
    const category = data.categories.find(c => c.id === req.params.categoryId);
    if (!category) return res.status(404).json({ error: 'Área de serviço não encontrada.' });
    const description = String(req.body.description || '').trim().slice(0, 600);
    if (!description) return res.status(400).json({ error: 'Informe a descrição do serviço.' });
    const existing = data.services.find(s => normalizeSearchText(s.title) === normalizeSearchText(category.name));
    if (existing) return res.status(409).json({ error: 'Este serviço já tem um cartão próprio. Atualize-o na lista de serviços.' });
    let id = slugify(category.name), suffix = 2;
    while (data.services.some(s => s.id === id)) id = `${slugify(category.name)}-${suffix++}`;
    const iconImage = req.files?.iconImage?.[0] ? await saveUpload(req.files.iconImage[0], 'images') : '';
    const banner = req.files?.banner?.[0] ? await saveUpload(req.files.banner[0], 'images') : '';
    const item = {
      id, title: category.name, iconClass: String(req.body.iconClass || 'bi-briefcase').trim().slice(0, 80),
      iconImage, color: /^#[0-9a-f]{6}$/i.test(req.body.color) ? req.body.color : '#00c994',
      description, details: String(req.body.details || description).trim().slice(0, 4000), banner,
      featured: req.body.featured === 'on'
    };
    category.description = description;
    data.services.push(item);
    await writeData(data);
    res.json(item);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao guardar a área de serviço.' }); }
});
app.post('/api/admin/services', requireAuth, imageUpload.fields([{ name: 'iconImage', maxCount: 1 }, { name: 'banner', maxCount: 1 }]), async (req, res) => {
  try {
    const data = await readData();
    const baseId = slugify(req.body.title);
    let id = baseId; let n = 2;
    while (data.services.some(s => s.id === id)) id = `${baseId}-${n++}`;
    const item = {
      id,
      title: req.body.title || 'Serviço',
      iconClass: req.body.iconClass || 'bi-briefcase',
      iconImage: req.files?.iconImage?.[0] ? await saveUpload(req.files.iconImage[0], 'images') : '',
      color: req.body.color || '#00A884',
      description: req.body.description || '',
      details: req.body.details || req.body.description || '',
      banner: req.files?.banner?.[0] ? await saveUpload(req.files.banner[0], 'images') : '',
      featured: req.body.featured === 'on' || req.body.featured === 'true' || req.body.featured === '1'
    };
    data.services.push(item); await writeData(data); res.json(item);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao adicionar serviço.' }); }
});

app.put('/api/admin/services/:id', requireAuth, imageUpload.fields([{ name: 'iconImage', maxCount: 1 }, { name: 'banner', maxCount: 1 }]), async (req, res) => {
  try {
    const data = await readData();
    const index = data.services.findIndex(s => s.id === req.params.id);
    if (index < 0) return res.status(404).json({ error: 'Serviço não encontrado.' });
    const old = data.services[index];
    const managedCategory = data.categories.find(c => normalizeSearchText(c.name) === normalizeSearchText(old.title));
    if (managedCategory && normalizeSearchText(req.body.title ?? old.title) !== normalizeSearchText(managedCategory.name))
      return res.status(400).json({ error: 'Para renomear esta área e manter os projetos associados, use a secção Categorias.' });
    let iconImage = old.iconImage || '';
    let banner = old.banner || '';
    if (req.files?.iconImage?.[0]) { if (iconImage) await deleteUpload(iconImage); iconImage = await saveUpload(req.files.iconImage[0], 'images'); }
    if (req.files?.banner?.[0]) { if (banner) await deleteUpload(banner); banner = await saveUpload(req.files.banner[0], 'images'); }
    data.services[index] = {
      ...old,
      title: req.body.title ?? old.title,
      iconClass: req.body.iconClass ?? old.iconClass ?? 'bi-briefcase',
      color: req.body.color ?? old.color,
      description: req.body.description ?? old.description,
      details: req.body.details ?? old.details ?? old.description,
      featured: req.body.featured === 'on' || req.body.featured === 'true' || req.body.featured === '1',
      iconImage, banner
    };
    if (managedCategory)
      managedCategory.description = String(data.services[index].description || '').trim().slice(0, 600);
    await writeData(data); res.json(data.services[index]);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao atualizar serviço.' }); }
});

app.delete('/api/admin/services/:id', requireAuth, async (req, res) => {
  try {
    const data = await readData();
    const item = data.services.find(s => s.id === req.params.id);
    if (item?.iconImage) await deleteUpload(item.iconImage);
    if (item?.banner) await deleteUpload(item.banner);
    data.services = data.services.filter(s => s.id !== req.params.id);
    await writeData(data); res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao remover serviço.' }); }
});

// LIGAÇÕES e REDES SOCIAIS.
['links', 'socials'].forEach(collection => {
  app.post(`/api/admin/${collection}`, requireAuth, async (req, res) => {
    try {
      const data = await readData();
      const prefix = collection === 'socials' ? 'social' : 'link';
      const item = { id: uid(prefix), ...req.body, url: normalizeUrl(req.body.url || '') };
      data[collection] ||= []; data[collection].push(item); await writeData(data); res.json(item);
    } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao adicionar item.' }); }
  });
  app.put(`/api/admin/${collection}/:id`, requireAuth, async (req, res) => {
    try {
      const data = await readData();
      const index = (data[collection] || []).findIndex(i => i.id === req.params.id);
      if (index < 0) return res.status(404).json({ error: 'Item não encontrado.' });
      const current = data[collection][index];
      const update = collection === 'socials'
        ? { ...current, platform: String(req.body.platform ?? current.platform).trim().slice(0,80), url: normalizeUrl(req.body.url ?? current.url), iconClass: String(req.body.iconClass ?? current.iconClass ?? 'bi-link-45deg').trim().slice(0,80) }
        : { ...current, title: String(req.body.title ?? current.title).trim().slice(0,120), url: normalizeUrl(req.body.url ?? current.url), iconClass: String(req.body.iconClass ?? current.iconClass ?? 'bi-link-45deg').trim().slice(0,80) };
      data[collection][index] = update; await writeData(data); res.json(update);
    } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao atualizar item.' }); }
  });
  app.delete(`/api/admin/${collection}/:id`, requireAuth, async (req, res) => {
    try { const data = await readData(); data[collection] = (data[collection] || []).filter(i => i.id !== req.params.id); await writeData(data); res.json({ ok: true }); }
    catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao remover item.' }); }
  });
});

// PARCEIROS: upload de logo + URL externa normalizada.
app.post('/api/admin/partners', requireAuth, imageUpload.fields([{ name: 'logoLight', maxCount: 1 }, { name: 'logoDark', maxCount: 1 }, { name: 'logo', maxCount: 1 }]), async (req, res) => {
  try {
    const data = await readData();
    const legacy = req.files?.logo?.[0] ? await saveUpload(req.files.logo[0], 'images') : '';
    const logoLight = req.files?.logoLight?.[0] ? await saveUpload(req.files.logoLight[0], 'images') : legacy;
    const logoDark = req.files?.logoDark?.[0] ? await saveUpload(req.files.logoDark[0], 'images') : legacy;
    const item = { id: uid('partner'), name: req.body.name || 'Parceiro', logo: legacy, logoLight, logoDark, url: normalizeUrl(req.body.url) };
    data.partners.push(item); await writeData(data); res.json(item);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao adicionar parceiro.' }); }
});
app.put('/api/admin/partners/:id', requireAuth, imageUpload.fields([{ name: 'logoLight', maxCount: 1 }, { name: 'logoDark', maxCount: 1 }]), async (req, res) => {
  try {
    const data = await readData(); const index = data.partners.findIndex(i => i.id === req.params.id);
    if (index < 0) return res.status(404).json({ error: 'Parceiro não encontrado.' });
    const current = data.partners[index]; let logoLight = current.logoLight || current.logo || '', logoDark = current.logoDark || current.logo || '';
    if (req.files?.logoLight?.[0]) { if (logoLight && logoLight !== logoDark) await deleteUpload(logoLight); logoLight = await saveUpload(req.files.logoLight[0], 'images'); }
    if (req.files?.logoDark?.[0]) { if (logoDark && logoDark !== logoLight) await deleteUpload(logoDark); logoDark = await saveUpload(req.files.logoDark[0], 'images'); }
    const updated = { ...current, name: String(req.body.name ?? current.name).trim().slice(0,160), url: normalizeUrl(req.body.url ?? current.url), logoLight, logoDark };
    data.partners[index] = updated; await writeData(data); res.json(updated);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao atualizar parceiro.' }); }
});
app.delete('/api/admin/partners/:id', requireAuth, async (req, res) => {
  try {
    const data = await readData(); const item = data.partners.find(i => i.id === req.params.id);
    for (const url of new Set([item?.logo, item?.logoLight, item?.logoDark].filter(Boolean))) await deleteUpload(url);
    data.partners = data.partners.filter(i => i.id !== req.params.id); await writeData(data); res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao remover parceiro.' }); }
});

// PORTFÓLIO: múltiplas imagens por projeto.
app.post('/api/admin/portfolio', requireAuth, imageUpload.array('images', 12), async (req, res) => {
  try {
    const data = await readData();
    const images = [];
    for (const file of req.files || []) images.push(await saveUpload(file, 'images'));
    const item = { id: uid('portfolio'), title: req.body.title || 'Projeto', service: req.body.service || '', description: req.body.description || '', link: normalizeUrl(req.body.link || ''), images, image: images[0] || '', featured: req.body.featured === 'on' || req.body.featured === 'true' || req.body.featured === '1' };
    data.portfolio.unshift(item); await writeData(data); res.json(item);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao publicar projeto.' }); }
});
app.put('/api/admin/portfolio/:id', requireAuth, imageUpload.array('images', 12), async (req, res) => {
  try {
    const data = await readData(); const index = data.portfolio.findIndex(i => i.id === req.params.id);
    if (index < 0) return res.status(404).json({ error: 'Projeto não encontrado.' });
    const current = data.portfolio[index]; let images = current.images?.length ? [...current.images] : (current.image ? [current.image] : []);
    if (req.body.replaceImages === '1' && (req.files || []).length) { for (const url of images) await deleteUpload(url); images = []; }
    for (const file of req.files || []) images.push(await saveUpload(file, 'images'));
    images = images.slice(0,12);
    const updated = { ...current, title: String(req.body.title ?? current.title).trim().slice(0,180), service: String(req.body.service ?? current.service).trim().slice(0,160), description: String(req.body.description ?? current.description).trim().slice(0,6000), images, image: images[0] || '', featured: req.body.featured === 'on' || req.body.featured === 'true' || req.body.featured === '1' };
    data.portfolio[index] = updated; await writeData(data); res.json(updated);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao atualizar projeto.' }); }
});
app.patch('/api/admin/portfolio/:id/featured', requireAuth, async (req, res) => {
  try {
    const data = await readData();
    const index = data.portfolio.findIndex(i => i.id === req.params.id);
    if (index < 0) return res.status(404).json({ error: 'Projeto não encontrado.' });
    data.portfolio[index].featured = Boolean(req.body.featured);
    await writeData(data); res.json(data.portfolio[index]);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao alterar destaque.' }); }
});

app.delete('/api/admin/portfolio/:id', requireAuth, async (req, res) => {
  try {
    const data = await readData(); const item = data.portfolio.find(i => i.id === req.params.id);
    const imgs = item?.images?.length ? item.images : (item?.image ? [item.image] : []);
    for (const url of imgs) await deleteUpload(url);
    data.portfolio = data.portfolio.filter(i => i.id !== req.params.id); await writeData(data); res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao remover projeto.' }); }
});

// EQUIPA + CV.
app.post('/api/admin/team', requireAuth, imageUpload.single('photo'), async (req, res) => {
  try {
    const data = await readData();
    const item = { id: uid('team'), name: req.body.name || 'Profissional', role: req.body.role || '', bio: req.body.bio || '', photo: req.file ? await saveUpload(req.file, 'images') : '', cv: '' };
    data.team.push(item); await writeData(data); res.json(item);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao adicionar profissional.' }); }
});
app.put('/api/admin/team/:id', requireAuth, imageUpload.single('photo'), async (req, res) => {
  try {
    const data = await readData(); const index = data.team.findIndex(i => i.id === req.params.id);
    if (index < 0) return res.status(404).json({ error: 'Membro da equipa não encontrado.' });
    const current = data.team[index]; let photo = current.photo || '';
    if (req.file) { if (photo) await deleteUpload(photo); photo = await saveUpload(req.file, 'images'); }
    const updated = { ...current, name: String(req.body.name ?? current.name).trim().slice(0,160), role: String(req.body.role ?? current.role).trim().slice(0,160), bio: String(req.body.bio ?? current.bio).trim().slice(0,3000), photo };
    data.team[index] = updated; await writeData(data); res.json(updated);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao atualizar membro da equipa.' }); }
});
app.post('/api/admin/team/:id/cv', requireAuth, (_, res) => res.status(410).json({ error: 'Currículos agora pertencem aos perfis profissionais cadastrados.' }));
app.delete('/api/admin/team/:id', requireAuth, async (req, res) => {
  try {
    const data = await readData(); const item = data.team.find(i => i.id === req.params.id);
    if (item?.photo) await deleteUpload(item.photo); if (item?.cv) await deleteUpload(item.cv);
    data.team = data.team.filter(i => i.id !== req.params.id); await writeData(data); res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao remover profissional.' }); }
});



// ============================================================
// V6.2 — PLATAFORMA DE PROFISSIONAIS
// Identidade, Google, recuperação, métricas, avaliações e denúncias.
// ============================================================
async function requireProfessional(req, res, next) {
  try {
    if (!req.session?.professionalId || !req.session.professionalCredentialTag)
      return res.status(401).json({ error: 'Faça login como profissional.' });
    const { data: profile, error } = await supabase.from('professional_profiles').select('user_id').eq('id', req.session.professionalId).maybeSingle();
    if (error) throw error;
    if (!profile) return res.status(401).json({ error: 'Sessão inválida.' });
    const { data: user, error: userError } = await supabase.from('professional_users').select('password_hash,password_change_required').eq('id', profile.user_id).maybeSingle();
    if (userError) throw userError;
    if (!user || !safeSecretEqual(req.session.professionalCredentialTag, credentialTag(`professional:${user.password_hash}`)))
      return res.status(401).json({ error: 'Sessão expirada após alteração de senha.' });
    if (user.password_change_required && !['GET','HEAD','OPTIONS'].includes(req.method) &&
        !['/api/professional/change-password','/api/professional/logout'].includes(req.path))
      return res.status(403).json({ error: 'Troque a senha temporária em Segurança antes de continuar.', code: 'PASSWORD_CHANGE_REQUIRED' });
    req.passwordChangeRequired = Boolean(user.password_change_required);
    setProfessionalSessionLifetime(req);
    next();
  } catch (error) { next(error); }
}
function professionalSessionRow(p = {}) {
  const { user_id, id_front_path, id_back_path, pre_suspension_status, ...safe } = p;
  const pending = safe.profile_changes_status === 'pending' && safe.pending_profile_changes && typeof safe.pending_profile_changes === 'object' ? safe.pending_profile_changes : {};
  Object.assign(safe, pending);
  safe.has_pending_changes = safe.profile_changes_status === 'pending';
  safe.verified = Boolean(safe.verified && safe.status === 'approved' && safe.verification_status === 'approved');
  if (safe.cv_url) safe.cv_url = '/api/professional/cv';
  delete safe.pending_profile_changes;
  return safe;
}
function digits(value = '') { return String(value).replace(/\D/g, ''); }
async function uniqueProfessionalSlug(name, excludeId = null) {
  const base = slugify(name || 'profissional');
  let candidate = base, n = 2;
  while (true) {
    let q = supabase.from('professional_profiles').select('id').eq('slug', candidate).limit(1);
    if (excludeId) q = q.neq('id', excludeId);
    const { data, error } = await q;
    if (error) throw error;
    if (!data?.length) return candidate;
    candidate = `${base}-${n++}`;
  }
}
async function releaseExpiredSuspensions() {
  if (!USE_SUPABASE) return;
  const now = new Date().toISOString();
  const { data, error } = await supabase.from('professional_profiles').select('id,pre_suspension_status').eq('status', 'suspended').lt('suspended_until', now);
  if (error) return console.error('Erro ao liberar suspensões expiradas:', error.message);
  for (const p of data || []) {
    const restore = ['approved','pending'].includes(p.pre_suspension_status) ? p.pre_suspension_status : 'pending';
    await supabase.from('professional_profiles').update({ status: restore, suspended_until: null, suspension_reason: '', pre_suspension_status: '', updated_at: now }).eq('id', p.id);
  }
}
async function getProfessionalSessionProfile(id) {
  // Não executa manutenção global no caminho crítico de cada visita ao painel.
  // Suspensões expiradas são tratadas periodicamente e nas rotas públicas/admin.
  const { data, error } = await supabase.from('professional_profiles').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return data;
}
function canPublish(profile) {
  return profile && profile.status === 'approved' && profile.verification_status === 'approved';
}
async function recordProfessionalEvent(req, professionalId, eventType, { serviceId = null, channel = '', scopeKey = 'general' } = {}) {
  try {
    const item = { id: crypto.randomUUID(), professional_id: professionalId, service_id: serviceId || null, event_type: eventType, channel, scope_key: scopeKey || 'general', visitor_hash: visitorHash(req), event_day: new Date().toISOString().slice(0,10), created_at: new Date().toISOString() };
    const { error } = await supabase.from('professional_events').insert(item);
    if (error && error.code !== '23505') throw error;
  } catch (error) { console.error('Métrica não registada:', error.message); }
}
async function professionalEventMetrics(professionalId) {
  const { data, error } = await supabase.rpc('professional_event_metrics', { p_professional_id: professionalId });
  if (error) throw error;
  return { views: Number(data?.views || 0), contacts: Number(data?.contacts || 0) };
}

app.post('/api/professional/register', async (req, res) => {
  try {
    if (!USE_SUPABASE) return res.status(503).json({ error: 'O cadastro de profissionais requer Supabase.' });
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const confirmPassword = String(req.body.confirmPassword || '');
    if (name.length < 3) return res.status(400).json({ error: 'Informe o nome completo.' });
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Informe um e-mail válido.' });
    if (password.length < 8) return res.status(400).json({ error: 'A senha deve ter pelo menos 8 caracteres.' });
    if (password !== confirmPassword) return res.status(400).json({ error: 'As duas senhas não coincidem.' });

    const { data: exists, error: existsError } = await supabase.from('professional_users').select('id').eq('email', email).maybeSingle();
    if (existsError) throw existsError;
    if (exists) return res.status(409).json({ error: 'Já existe uma conta com este e-mail.' });

    const userId = crypto.randomUUID(), profileId = crypto.randomUUID(), slug = await uniqueProfessionalSlug(name), now = new Date().toISOString();
    const hashPasswordValue = hashPassword(password);
    const { error: userError } = await supabase.from('professional_users').insert({
      id: userId,
      email,
      password_hash: hashPasswordValue,
      auth_provider: 'password',
      created_at: now,
      updated_at: now
    });
    if (userError) throw userError;

    const seed = { name, specialty: '', bio: '', location: '', province: '', district: '', neighborhood: '', phone: '', whatsapp: '', photo: '', service_area: '', skills: '', years_experience: 0, cv_url: '' };
    const { error: profileError } = await supabase.from('professional_profiles').insert({
      id: profileId,
      user_id: userId,
      name,
      slug,
      email,
      address: '',
      location: '',
      province: '', district: '', neighborhood: '',
      phone: '',
      whatsapp: '',
      status: 'draft',
      verified: false,
      verification_status: 'not_submitted',
      profile_completeness: profileCompleteness(seed),
      last_active_at: now,
      created_at: now,
      updated_at: now
    });
    if (profileError) {
      await supabase.from('professional_users').delete().eq('id', userId);
      throw profileError;
    }

    await regenerateSession(req);
    setProfessionalIdentity(req, profileId, hashPasswordValue);
    const emailVerification = await issueEmailVerification(userId, email, { force: true }).catch(e => ({ ok: false, error: e.message }));
    await notifyProfessional(
      profileId,
      'account',
      'Conta profissional criada',
      'A sua conta foi criada com sucesso. Confirme o e-mail, complete os dados pessoais, o perfil profissional e a verificação de identidade antes de enviar o perfil para análise.',
      '/profissional/dashboard',
      { sendEmail: false }
    );
    res.json({ ok: true, emailVerificationSent: Boolean(emailVerification.ok && emailVerification.sent), emailVerificationError: emailVerification.ok ? '' : 'O código não pôde ser enviado. Tente novamente no painel ou contacte o suporte.', profile: { id: profileId, name, slug, email, status: 'draft', verification_status: 'not_submitted' } });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Não foi possível criar a conta.' });
  }
});

app.post('/api/professional/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase(), password = String(req.body.password || '');
    const { data: user, error } = await supabase.from('professional_users').select('*').eq('email', email).maybeSingle();
    if (error) throw error;
    if (!user || !verifyPassword(password, user.password_hash)) return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
    const { data: profile, error: pError } = await supabase.from('professional_profiles').select('*').eq('user_id', user.id).maybeSingle();
    if (pError) throw pError;
    if (!profile) return res.status(404).json({ error: 'Perfil profissional não encontrado.' });
    await regenerateSession(req);
    setProfessionalIdentity(req, profile.id, user.password_hash);
    await supabase.from('professional_profiles').update({ last_active_at: new Date().toISOString() }).eq('id', profile.id);
    res.json({ ok: true, profile: professionalSessionRow({ ...profile, last_active_at: new Date().toISOString() }) });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Não foi possível iniciar sessão.' }); }
});

app.post('/api/professional/google-login', async (req, res) => {
  try {
    if (!SUPABASE_ANON_KEY) return res.status(503).json({ error: 'Login Google ainda não está configurado no servidor.' });
    const token = String(req.body.accessToken || '');
    if (!token) return res.status(400).json({ error: 'Token Google ausente.' });
    const { data: authData, error: authError } = await supabase.auth.getUser(token);
    const authUser = authData?.user;
    if (authError || !verifiedGoogleIdentity(authUser))
      return res.status(401).json({ error: 'Não foi possível validar a identidade Google e o e-mail confirmado.' });

    const googleUser = authUser, email = googleUser.email.toLowerCase();
    let { data: account, error } = await supabase.from('professional_users').select('*').eq('google_sub', googleUser.id).maybeSingle();
    if (error) throw error;

    if (!account) {
      const byEmail = await supabase.from('professional_users').select('*').eq('email', email).maybeSingle();
      if (byEmail.error) throw byEmail.error;
      account = byEmail.data;
      if (account) {
        await supabase.from('professional_users').update({
          google_sub: googleUser.id,
          auth_provider: account.auth_provider === 'password' ? 'google+password' : 'google',
          email_verified_at: new Date().toISOString(),
          email_verification_code_hash: '',
          email_verification_expires_at: null,
          email_verification_attempts: 0,
          updated_at: new Date().toISOString()
        }).eq('id', account.id);
      }
    }

    if (!account) {
      const now = new Date().toISOString();
      const name = String(googleUser.user_metadata?.full_name || googleUser.user_metadata?.name || email.split('@')[0] || 'Profissional').trim();
      const userId = crypto.randomUUID(), profileId = crypto.randomUUID(), slug = await uniqueProfessionalSlug(name);
      const randomPassword = crypto.randomBytes(32).toString('hex');
      const { error: userError } = await supabase.from('professional_users').insert({
        id: userId,
        email,
        password_hash: hashPassword(randomPassword),
        google_sub: googleUser.id,
        auth_provider: 'google',
        email_verified_at: now,
        created_at: now,
        updated_at: now
      });
      if (userError) throw userError;

      const seed = { name, specialty: '', bio: '', location: '', phone: '', whatsapp: '', photo: '', service_area: '', skills: '', years_experience: 0, cv_url: '' };
      const { error: profileError } = await supabase.from('professional_profiles').insert({
        id: profileId,
        user_id: userId,
        name,
        slug,
        email,
        status: 'draft',
        verified: false,
        verification_status: 'not_submitted',
        profile_completeness: profileCompleteness(seed),
        last_active_at: now,
        created_at: now,
        updated_at: now
      });
      if (profileError) {
        await supabase.from('professional_users').delete().eq('id', userId);
        throw profileError;
      }
      account = { id: userId };
      await notifyProfessional(
        profileId,
        'account',
        'Conta profissional criada com Google',
        'A sua conta foi criada com sucesso. Complete os dados obrigatórios e envie o perfil para validação quando estiver pronto.',
        '/profissional/dashboard',
        { sendEmail: true }
      );
    }

    await supabase.from('professional_users').update({
      email_verified_at: new Date().toISOString(),
      email_verification_code_hash: '',
      email_verification_expires_at: null,
      email_verification_attempts: 0,
      updated_at: new Date().toISOString()
    }).eq('id', account.id);
    const { data: profile, error: pError } = await supabase.from('professional_profiles').select('*').eq('user_id', account.id).maybeSingle();
    if (pError) throw pError;
    if (!profile) return res.status(404).json({ error: 'Perfil profissional não encontrado.' });

    await regenerateSession(req);
    const { data: currentCredentials, error: credentialError } = await supabase.from('professional_users').select('password_hash').eq('id', account.id).single();
    if (credentialError) throw credentialError;
    setProfessionalIdentity(req, profile.id, currentCredentials.password_hash);
    await supabase.from('professional_profiles').update({ last_active_at: new Date().toISOString() }).eq('id', profile.id);
    return res.json({ ok: true, needsRegistration: false, created: profile.status === 'draft' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao entrar com Google.' });
  }
});

app.get('/api/professional/google-pending', (req, res) => res.json({ googleProfile: req.session.googleIdentity ? { email: req.session.googleIdentity.email, name: req.session.googleIdentity.name } : null }));

app.post('/api/professional/logout', requireProfessional, (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/professional/session', async (req, res, next) => {
  res.set('Cache-Control', 'no-store, private');
  if (!req.session?.professionalId || !req.session.professionalCredentialTag) return res.json({ authenticated: false });
  try {
    const { data: profile, error } = await supabase.from('professional_profiles').select('user_id').eq('id', req.session.professionalId).maybeSingle();
    if (error) throw error;
    const { data: user, error: userError } = profile ? await supabase.from('professional_users').select('password_hash').eq('id', profile.user_id).maybeSingle() : { data: null };
    if (userError) throw userError;
    const authenticated = !!user && safeSecretEqual(req.session.professionalCredentialTag, credentialTag(`professional:${user.password_hash}`));
    if (authenticated) setProfessionalSessionLifetime(req);
    res.json({ authenticated });
  } catch (error) { next(error); }
});

app.get('/api/professional/email-verification/status', requireProfessional, async (req, res) => {
  try {
    const profile = await getProfessionalSessionProfile(req.session.professionalId);
    if (!profile) return res.status(401).json({ error: 'Sessão inválida.' });
    const { data: user, error } = await supabase.from('professional_users').select('email,email_verified_at,email_verification_sent_at,email_verification_expires_at,auth_provider').eq('id', profile.user_id).maybeSingle();
    if (error) throw error;
    if (!user) return res.status(404).json({ error: 'Conta não encontrada.' });
    const last = user.email_verification_sent_at ? new Date(user.email_verification_sent_at).getTime() : 0;
    res.json({
      email: user.email,
      verified: Boolean(user.email_verified_at),
      verifiedAt: user.email_verified_at || null,
      provider: user.auth_provider || 'password',
      retryAfter: Math.max(0, Math.ceil((60 * 1000 - (Date.now() - last)) / 1000)),
      expiresAt: user.email_verification_expires_at || null
    });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao consultar a verificação do e-mail.' }); }
});
app.post('/api/professional/email-verification/send', requireProfessional, async (req, res) => {
  try {
    const profile = await getProfessionalSessionProfile(req.session.professionalId);
    if (!profile) return res.status(401).json({ error: 'Sessão inválida.' });
    const { data: user, error } = await supabase.from('professional_users').select('id,email,email_verified_at').eq('id', profile.user_id).maybeSingle();
    if (error) throw error;
    if (!user) return res.status(404).json({ error: 'Conta não encontrada.' });
    if (user.email_verified_at) return res.json({ ok: true, verified: true, message: 'O e-mail já está confirmado.' });
    const result = await issueEmailVerification(user.id, user.email);
    if (!result.ok) return res.status(result.retryAfter ? 429 : 503).json({ error: result.retryAfter ? `Aguarde ${result.retryAfter} segundos antes de reenviar.` : 'Não foi possível enviar o código. Tente novamente mais tarde ou contacte o suporte.', retryAfter: result.retryAfter || 0 });
    res.json({ ok: true, sent: true, expiresAt: result.expiresAt });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Não foi possível enviar o código de confirmação.' }); }
});
app.post('/api/professional/email-verification/confirm', requireProfessional, async (req, res) => {
  try {
    const code = String(req.body.code || '').replace(/\D/g, '');
    if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Introduza o código de 6 dígitos.' });
    const profile = await getProfessionalSessionProfile(req.session.professionalId);
    if (!profile) return res.status(401).json({ error: 'Sessão inválida.' });
    const { data: user, error } = await supabase.from('professional_users').select('id,email,email_verified_at,email_verification_code_hash,email_verification_expires_at,email_verification_attempts').eq('id', profile.user_id).maybeSingle();
    if (error) throw error;
    if (!user) return res.status(404).json({ error: 'Conta não encontrada.' });
    if (user.email_verified_at) return res.json({ ok: true, verified: true });
    if (!user.email_verification_code_hash || !user.email_verification_expires_at) return res.status(400).json({ error: 'Peça um novo código de confirmação.' });
    if (new Date(user.email_verification_expires_at).getTime() < Date.now()) return res.status(400).json({ error: 'O código expirou. Peça um novo código.' });
    const attempts = Number(user.email_verification_attempts || 0);
    if (attempts >= 5) return res.status(429).json({ error: 'Número máximo de tentativas atingido. Peça um novo código.' });
    const actual = emailVerificationHash(user.id, code);
    if (!secureCodeEqual(actual, user.email_verification_code_hash)) {
      await supabase.from('professional_users').update({ email_verification_attempts: attempts + 1, updated_at: new Date().toISOString() }).eq('id', user.id);
      return res.status(400).json({ error: 'Código incorreto.' });
    }
    const now = new Date().toISOString();
    const { error: updateError } = await supabase.from('professional_users').update({
      email_verified_at: now,
      email_verification_code_hash: '',
      email_verification_expires_at: null,
      email_verification_attempts: 0,
      updated_at: now
    }).eq('id', user.id);
    if (updateError) throw updateError;
    await notifyProfessional(profile.id, 'security', 'E-mail confirmado', 'O endereço de e-mail da sua conta foi confirmado com sucesso.', '/profissional/dashboard');
    res.json({ ok: true, verified: true, verifiedAt: now });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Não foi possível confirmar o e-mail.' }); }
});
app.post('/api/professional/change-password', requireProfessional, async (req, res) => {
  try {
    const currentPassword = String(req.body.currentPassword || ''), newPassword = String(req.body.newPassword || ''), confirmPassword = String(req.body.confirmPassword || '');
    if (newPassword.length < 8) return res.status(400).json({ error: 'A nova senha deve ter pelo menos 8 caracteres.' });
    if (newPassword !== confirmPassword) return res.status(400).json({ error: 'As duas novas senhas não coincidem.' });
    const profile = await getProfessionalSessionProfile(req.session.professionalId);
    const { data: user, error } = await supabase.from('professional_users').select('*').eq('id', profile.user_id).single();
    if (error) throw error;
    const googleOnly = user.auth_provider === 'google';
    if (!googleOnly && !verifyPassword(currentPassword, user.password_hash)) return res.status(401).json({ error: 'A senha atual está incorreta.' });
    const { error: updateError } = await supabase.from('professional_users').update({
      password_hash: hashPassword(newPassword),
      password_change_required: false,
      auth_provider: googleOnly ? 'google+password' : user.auth_provider,
      updated_at: new Date().toISOString()
    }).eq('id', user.id);
    if (updateError) throw updateError;
    await revokeSessions('professionalId', profile.id);
    await destroySession(req);
    res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao alterar a senha.' }); }
});
app.post('/api/professional/recovery-request', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase(), whatsapp = digits(req.body.whatsapp || '');
    const generic = { ok: true, message: 'Se os dados coincidirem com uma conta, receberá as instruções de recuperação pelo canal disponível.' };
    if (!email || whatsapp.length < 8) return res.json(generic);
    const recoveryOrigin = passwordRecoveryBaseUrl(req);
    if (!recoveryOrigin) {
      console.error('Recuperação de senha indisponível: configure PUBLIC_BASE_URL com a origem HTTPS pública.');
      return res.status(503).json({ error: 'A recuperação por e-mail está temporariamente indisponível. Contacte o suporte.' });
    }
    const { data: profile, error } = await supabase.from('professional_profiles').select('id,name,whatsapp,email').eq('email', email).maybeSingle();
    if (error) throw error;
    if (!profile || digits(profile.whatsapp) !== whatsapp) return res.json(generic);
    const token = crypto.randomBytes(32).toString('hex'), token_hash = crypto.createHash('sha256').update(token).digest('hex');
    const now = new Date(), expires_at = new Date(now.getTime()+30*60*1000).toISOString();
    const { data: pending } = await supabase.from('password_reset_requests').select('id').eq('professional_id', profile.id).eq('status', 'pending').maybeSingle();
    let requestId;
    if (pending) { requestId=pending.id; await supabase.from('password_reset_requests').update({ email, whatsapp, token_hash, expires_at, used_at:null, created_at:now.toISOString() }).eq('id', pending.id); }
    else { requestId=crypto.randomUUID(); await supabase.from('password_reset_requests').insert({ id:requestId, professional_id:profile.id, email, whatsapp, token_hash, expires_at, status:'pending', created_at:now.toISOString() }); }
    if (RESEND_API_KEY && EMAIL_FROM) {
      const link=`${recoveryOrigin}/profissional?reset=${encodeURIComponent(token)}`;
      await sendTransactionalEmail(email,'Recuperação de acesso — Yuran Multicerviços',`Olá ${profile.name || ''},\n\nRecebemos um pedido para redefinir a senha da sua conta profissional. Use o link abaixo nos próximos 30 minutos:\n\n${link}\n\nSe não fez este pedido, ignore esta mensagem.`);
    }
    res.json(generic);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Não foi possível enviar o pedido de recuperação.' }); }
});
app.post('/api/professional/reset-password', async (req,res)=>{
  try{
    const token=String(req.body.token||''),newPassword=String(req.body.newPassword||''),confirmPassword=String(req.body.confirmPassword||'');
    if(token.length<40)return res.status(400).json({error:'Link de recuperação inválido.'});
    if(newPassword.length<8)return res.status(400).json({error:'A nova senha deve ter pelo menos 8 caracteres.'});
    if(newPassword!==confirmPassword)return res.status(400).json({error:'As duas senhas não coincidem.'});
    const token_hash=crypto.createHash('sha256').update(token).digest('hex'),now=new Date().toISOString();
    const {data:request,error}=await supabase.from('password_reset_requests').select('id,professional_id,professional_profiles(user_id,name)').eq('token_hash',token_hash).eq('status','pending').gt('expires_at',now).maybeSingle();
    if(error)throw error;if(!request)return res.status(400).json({error:'Este link expirou ou já foi utilizado. Solicite uma nova recuperação.'});
    const userId=request.professional_profiles?.user_id;if(!userId)return res.status(400).json({error:'Conta não encontrada.'});
    const {error:ue}=await supabase.from('professional_users').update({password_hash:hashPassword(newPassword),password_change_required:false,updated_at:now}).eq('id',userId);if(ue)throw ue;
    await revokeSessions('professionalId', request.professional_id);
    await supabase.from('password_reset_requests').update({status:'resolved',resolved_at:now,used_at:now,token_hash:''}).eq('id',request.id);
    await notifyProfessional(request.professional_id,'security','Senha alterada','A senha da sua conta foi redefinida através do processo de recuperação. Se não reconhece esta ação, contacte a administração.','/profissional/dashboard');
    res.json({ok:true});
  }catch(error){console.error(error);res.status(500).json({error:'Não foi possível redefinir a senha.'})}
});

app.get('/api/professional/dashboard', requireProfessional, async (req, res) => {
  try {
    const profile = await getProfessionalSessionProfile(req.session.professionalId);
    if (!profile) {
      return req.session.destroy(() => res.status(401).json({ error: 'A sessão já não corresponde a uma conta ativa.' }));
    }
    const plan = await getEffectivePlan(profile.id);
    const [
      { data: services, error: se },
      { data: projects, error: pe },
      eventMetrics,
      { data: ratings },
      { data: notifications },
      { data: reviews },
      { data: user, error: ue }
    ] = await Promise.all([
      supabase.from('professional_services').select('*').eq('professional_id', profile.id).order('created_at', { ascending: false }),
      supabase.from('professional_projects').select('*').eq('professional_id', profile.id).order('created_at', { ascending: false }),
      professionalEventMetrics(profile.id),
      supabase.from('professional_ratings').select('stars,status').eq('professional_id', profile.id).eq('status', 'published'),
      supabase.from('professional_notifications').select('*').eq('professional_id', profile.id).order('created_at', { ascending: false }).limit(50),
      supabase.from('professional_ratings').select('id,stars,comment,scope_key,professional_reply,replied_at,created_at,professional_services(title)').eq('professional_id', profile.id).eq('status','published').order('created_at',{ascending:false}).limit(30),
      supabase.from('professional_users').select('email,email_verified_at,email_verification_sent_at,email_verification_expires_at,auth_provider,password_change_required').eq('id', profile.user_id).maybeSingle()
    ]);
    if (se) throw se;
    if (pe) throw pe;
    if (ue) throw ue;

    const ratingAvg = ratings?.length ? ratings.reduce((a,x)=>a+Number(x.stars||0),0)/ratings.length : 0;
    const uniqueViews = eventMetrics.views;
    const uniqueContacts = eventMetrics.contacts;

    // Para o próprio profissional, alterações pendentes devem contar na completude e no checklist,
    // sem substituir a versão pública aprovada antes da moderação.
    const sessionProfile = professionalSessionRow(profile);
    const completion = profileCompleteness(sessionProfile);
    if (profile.profile_changes_status !== 'pending' && completion !== Number(profile.profile_completeness||0)) {
      supabase.from('professional_profiles').update({ profile_completeness: completion }).eq('id', profile.id).then(()=>{}).catch(()=>{});
    }

    const emailVerified = Boolean(user?.email_verified_at);
    const validationMissing = validationRequirements(sessionProfile);
    if (!emailVerified) validationMissing.unshift('e-mail verificado');

    const lastSent = user?.email_verification_sent_at ? new Date(user.email_verification_sent_at).getTime() : 0;
    res.json({
      profile: { ...sessionProfile, profile_completeness: completion, password_change_required: Boolean(user?.password_change_required) },
      services: services || [],
      projects: (projects || []).map(ownerProjectRow),
      notifications: notifications || [],
      reviews: reviews || [],
      emailVerification: {
        email: user?.email || profile.email || '',
        verified: emailVerified,
        verifiedAt: user?.email_verified_at || null,
        provider: user?.auth_provider || 'password',
        retryAfter: Math.max(0, Math.ceil((60 * 1000 - (Date.now() - lastSent)) / 1000)),
        expiresAt: user?.email_verification_expires_at || null
      },
      onboarding: {
        accountCreated: true,
        emailVerified,
        personalComplete: validationMissing.every(x => !['endereço','cidade / província','número do celular','número do WhatsApp','data de nascimento'].includes(x)),
        professionalComplete: validationMissing.every(x => !['especialidade','apresentação profissional com pelo menos 80 caracteres','localização','foto profissional','área de atendimento','competências'].includes(x)),
        identitySubmitted: Boolean(profile.identity_submitted_at && profile.verification_status !== 'not_submitted'),
        validationSubmitted: profile.status !== 'draft',
        missing: validationMissing
      },
      plan: { code: plan.code, name: plan.name, monthlyPrice: Number(plan.monthly_price||0), annualPrice: Number(plan.annual_price||0), projectLimit: Number(plan.project_limit||0), customServiceLimit: Number(plan.custom_service_limit||0), billingCycle: plan.billing_cycle, status: plan.status, periodEnd: plan.period_end, gracePeriodEnd: plan.grace_period_end },
      metrics: { views: uniqueViews, contacts: uniqueContacts, ratingAvg, ratingCount: ratings?.length || 0, unreadNotifications: (notifications||[]).filter(n=>!n.read_at).length }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao carregar o painel.' });
  }
});

app.put('/api/professional/profile', requireProfessional, imageUpload.fields([{ name: 'photo', maxCount: 1 }]), async (req, res) => {
  try {
    const current = await getProfessionalSessionProfile(req.session.professionalId);
    if (!current) return res.status(404).json({ error: 'Perfil não encontrado.' });
    const phone = String(req.body.phone || '').trim(), whatsapp = String(req.body.whatsapp || '').trim(), address = String(req.body.address || '').trim();
    const previousPending = current.profile_changes_status === 'pending' && current.pending_profile_changes && typeof current.pending_profile_changes === 'object' ? current.pending_profile_changes : {};
    let photo = current.status === 'approved' ? (previousPending.photo || current.photo || '') : (current.photo || '');
    if (req.files?.photo?.[0]) {
      if (current.status === 'approved') {
        if (previousPending.photo && previousPending.photo !== current.photo) await deleteUpload(previousPending.photo);
        photo = await saveUpload(req.files.photo[0], 'images');
      } else {
        if (photo) await deleteUpload(photo);
        photo = await saveUpload(req.files.photo[0], 'images');
      }
    }
    const name = String(req.body.name || current.name).trim();
    const candidate = {
      ...current, name, specialty: String(req.body.specialty || '').trim(), headline: String(req.body.headline || '').trim().slice(0,120), bio: String(req.body.bio || '').trim(), address,
      location: String(req.body.location || '').trim(), province: String(req.body.province || '').trim().slice(0,120), district: String(req.body.district || '').trim().slice(0,120), neighborhood: String(req.body.neighborhood || '').trim().slice(0,160), phone, whatsapp,
      birth_date: String(req.body.birth_date || '').trim() || null,
      id_number: String(req.body.id_number || '').trim().slice(0,120),
      website: normalizeUrl(req.body.website || ''), linkedin: normalizeUrl(req.body.linkedin || ''), instagram: normalizeUrl(req.body.instagram || ''), photo,
      years_experience: Math.max(0, Math.min(80, Number(req.body.years_experience || 0))), service_area: String(req.body.service_area || '').trim(), availability: ['available','limited','unavailable'].includes(String(req.body.availability)) ? String(req.body.availability) : 'available',
      languages: String(req.body.languages || '').trim().slice(0,500), skills: String(req.body.skills || '').trim().slice(0,1000), certifications: String(req.body.certifications || '').trim().slice(0,1500), education: normalizeEducation(req.body.education), response_time_label: String(req.body.response_time_label || '').trim().slice(0,100)
    };
    let update;
    const editableFields = ['name','specialty','headline','bio','address','location','province','district','neighborhood','phone','whatsapp','birth_date','id_number','website','linkedin','instagram','photo','years_experience','service_area','availability','languages','skills','certifications','education','response_time_label'];
    if (current.status === 'approved') {
      const pending = {}; for (const key of editableFields) pending[key] = candidate[key];
      update = { pending_profile_changes: pending, profile_changes_status: 'pending', profile_change_rejection_reason: '', profile_completeness: profileCompleteness(candidate), last_active_at: new Date().toISOString(), updated_at: new Date().toISOString() };
    } else {
      update = { ...candidate, slug: name !== current.name ? await uniqueProfessionalSlug(name, current.id) : current.slug, profile_completeness: profileCompleteness(candidate), last_active_at: new Date().toISOString(), updated_at: new Date().toISOString() };
    }
    delete update.user_id; delete update.id_front_path; delete update.id_back_path; delete update.created_at; delete update.id; delete update.verification_status; delete update.verified; delete update.warning_count; delete update.last_warning; delete update.suspended_until; delete update.suspension_reason; delete update.pre_suspension_status; delete update.identity_submitted_at; delete update.identity_verified_at; delete update.identity_retention_until; delete update.identity_documents_deleted_at; delete update.terms_accepted_at; delete update.privacy_accepted_at; delete update.rejection_reason; delete update.email; delete update.cv_url; delete update.featured;
    const { data, error } = await supabase.from('professional_profiles').update(update).eq('id', current.id).select('*').single();
    if (error) throw error;
    if (current.status === 'approved') await notifyProfessional(current.id, 'moderation', 'Alterações enviadas para revisão', 'As alterações do seu perfil foram guardadas para análise. A versão pública atualmente aprovada permanece visível até a decisão da administração.', '/profissional/dashboard');
    res.json(professionalSessionRow(data));
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao guardar o perfil.' }); }
});


app.post('/api/professional/submit-validation', requireProfessional, identityUpload.fields([{ name: 'idFront', maxCount: 1 }, { name: 'idBack', maxCount: 1 }]), async (req, res) => {
  let frontPath = '', backPath = '';
  try {
    const current = await getProfessionalSessionProfile(req.session.professionalId);
    if (!current) return res.status(404).json({ error: 'Perfil não encontrado.' });
    if (current.status === 'suspended') return res.status(403).json({ error: 'A conta está suspensa e não pode ser enviada para validação.' });

    const { data: account, error: accountError } = await supabase.from('professional_users').select('email,email_verified_at').eq('id', current.user_id).maybeSingle();
    if (accountError) throw accountError;
    if (!account?.email_verified_at) return res.status(400).json({ error: 'Confirme o seu e-mail antes de enviar o perfil para validação.' });

    const legalAccepted = ['on','true','1','yes'].includes(String(req.body.legalAccepted || '').toLowerCase());
    const front = req.files?.idFront?.[0], back = req.files?.idBack?.[0];
    const identityAlreadyApproved = current.verification_status === 'approved';
    const submittedIdNumber = String(req.body.id_number || current.id_number || '').trim().slice(0,120);
    if (!identityAlreadyApproved && !submittedIdNumber) return res.status(400).json({ error: 'Informe o número do BI / documento de identificação.' });
    if (!identityAlreadyApproved && (!front || !back)) return res.status(400).json({ error: 'Carregue a frente e o verso do documento de identificação.' });
    current.id_number = submittedIdNumber;

    const missing = validationRequirements(current);
    if (missing.length) return res.status(400).json({ error: `Complete os dados obrigatórios antes de enviar para validação: ${missing.join(', ')}.` });
    if (!current.terms_accepted_at && !legalAccepted) return res.status(400).json({ error: 'Aceite os Termos de Uso e a Política de Privacidade antes de enviar o perfil.' });

    if (!identityAlreadyApproved) {
      frontPath = await savePrivateIdentityUpload(front, current.id, 'front');
      backPath = await savePrivateIdentityUpload(back, current.id, 'back');
      if (current.id_front_path) await deletePrivateIdentityUpload(current.id_front_path);
      if (current.id_back_path) await deletePrivateIdentityUpload(current.id_back_path);
    }

    const now = new Date().toISOString();
    const update = {
      verification_status: identityAlreadyApproved ? 'approved' : 'pending',
      verification_reason: '',
      status: 'pending',
      verified: identityAlreadyApproved ? Boolean(current.verified) : false,
      identity_submitted_at: identityAlreadyApproved ? current.identity_submitted_at : now,
      validation_submitted_at: now,
      id_number: submittedIdNumber || current.id_number || '',
      updated_at: now
    };
    if (!identityAlreadyApproved) {
      update.id_front_path = frontPath;
      update.id_back_path = backPath;
    }
    if (!current.terms_accepted_at && legalAccepted) {
      update.terms_accepted_at = now;
      update.privacy_accepted_at = now;
    }

    const { data, error } = await supabase.from('professional_profiles').update(update).eq('id', current.id).select('*').single();
    if (error) throw error;
    await notifyProfessional(
      current.id,
      'identity',
      'Perfil e documentação enviados para análise',
      'Recebemos os seus dados obrigatórios e os documentos de identificação. A administração irá analisar a identidade e o perfil profissional antes da publicação.',
      '/profissional/dashboard',
      { sendEmail: true }
    );
    res.json(professionalSessionRow(data));
  } catch (error) {
    console.error(error);
    if (frontPath) await deletePrivateIdentityUpload(frontPath).catch(()=>{});
    if (backPath) await deletePrivateIdentityUpload(backPath).catch(()=>{});
    res.status(500).json({ error: 'Erro ao enviar o perfil para validação.' });
  }
});

app.post('/api/professional/profile/cv', requireProfessional, cvUpload.single('cv'), async (req, res) => {
  let newRef = '';
  let persisted = false;
  try {
    if (!req.file) return res.status(400).json({ error: 'Envie um PDF.' });
    const current = await getProfessionalSessionProfile(req.session.professionalId);
    newRef = await savePrivateUpload(req.file, 'cvs', current.id);
    const candidate = { ...current, cv_url: newRef };
    const { data, error } = await supabase.from('professional_profiles').update({ cv_url: newRef, profile_completeness: profileCompleteness(candidate), last_active_at: new Date().toISOString(), updated_at: new Date().toISOString() }).eq('id', current.id).select('*').single();
    if (error) throw error;
    persisted = true;
    if (current.cv_url && current.cv_url !== newRef) await deleteUpload(current.cv_url).catch(e => console.error('CV anterior:', e));
    res.json({ ...professionalSessionRow(data), cv_url: '/api/professional/cv' });
  } catch (error) { if (newRef && !persisted) await deleteUpload(newRef).catch(()=>{}); console.error(error); res.status(500).json({ error: 'Erro ao guardar CV.' }); }
});
app.get('/api/professional/cv', requireProfessional, async (req, res) => {
  try { await serveCurrentCv(await getProfessionalSessionProfile(req.session.professionalId), res); }
  catch (error) { console.error(error); res.status(500).json({ error: 'Não foi possível abrir o currículo.' }); }
});
app.post('/api/professional/identity', requireProfessional, identityUpload.fields([{ name: 'idFront', maxCount: 1 }, { name: 'idBack', maxCount: 1 }]), async (req, res) => {
  try {
    const front = req.files?.idFront?.[0], back = req.files?.idBack?.[0];
    if (!front || !back) return res.status(400).json({ error: 'Envie novamente a frente e o verso.' });
    const current = await getProfessionalSessionProfile(req.session.professionalId);
    const frontPath = await savePrivateIdentityUpload(front, current.id, 'front');
    const backPath = await savePrivateIdentityUpload(back, current.id, 'back');
    if (current.id_front_path) await deletePrivateIdentityUpload(current.id_front_path);
    if (current.id_back_path) await deletePrivateIdentityUpload(current.id_back_path);
    const now = new Date().toISOString();
    const { data, error } = await supabase.from('professional_profiles').update({ id_front_path: frontPath, id_back_path: backPath, verification_status: 'pending', verification_reason: '', verified: false, status: current.status === 'approved' ? 'approved' : 'pending', identity_submitted_at: now, validation_submitted_at: current.validation_submitted_at || now, updated_at: now }).eq('id', current.id).select('*').single();
    if (error) throw error; res.json(professionalSessionRow(data));
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao reenviar documentos.' }); }
});

// Os serviços legados continuam visíveis no perfil e nas avaliações, sem novas publicações.
async function getEffectivePlan(professionalId) {
  const free = { id: null, code: 'free', name: 'Gratuito', monthly_price: 0, annual_price: 0, project_limit: 5, custom_service_limit: 0, billing_cycle: 'monthly', status: 'active', subscription_id: null, period_end: null, grace_period_end: null };
  const { data: sub, error: se } = await supabase.from('professional_subscriptions')
    .select('id,plan_id,billing_cycle,status,current_period_start,current_period_end,grace_period_end,subscription_plans(*)')
    .eq('professional_id', professionalId)
    .order('created_at', { ascending: false }).limit(1).maybeSingle();
  if (se) throw se;
  if (!sub || !sub.subscription_plans) return free;
  const now = Date.now();
  const end = new Date(sub.current_period_end).getTime();
  const grace = sub.grace_period_end ? new Date(sub.grace_period_end).getTime() : end + 7 * 86400000;
  if (sub.status !== 'expired' && now > end) {
    if (now <= grace) {
      if (sub.status !== 'grace_period') await supabase.from('professional_subscriptions').update({ status: 'grace_period', grace_period_end: new Date(grace).toISOString(), updated_at: new Date().toISOString() }).eq('id', sub.id);
      return { ...sub.subscription_plans, billing_cycle: sub.billing_cycle, status: 'grace_period', subscription_id: sub.id, period_end: sub.current_period_end, grace_period_end: new Date(grace).toISOString() };
    }
    await applyPlanDowngrade(professionalId, 5, 0);
    await supabase.from('professional_subscriptions').update({ status: 'expired', updated_at: new Date().toISOString() }).eq('id', sub.id);
    await supabase.from('subscription_history').insert({ professional_id: professionalId, subscription_id: sub.id, from_plan: sub.subscription_plans.code, to_plan: 'free', action: 'downgrade_after_grace', reason: 'Período de tolerância terminado.' });
    return free;
  }
  if (sub.status !== 'expired' && sub.status !== 'cancelled') await restorePlanContent(professionalId, Number(sub.subscription_plans.project_limit || 5), Number(sub.subscription_plans.custom_service_limit || 0));
  return { ...sub.subscription_plans, billing_cycle: sub.billing_cycle, status: sub.status, subscription_id: sub.id, period_end: sub.current_period_end, grace_period_end: sub.grace_period_end };
}

async function applyPlanDowngrade(professionalId, projectLimit, customServiceLimit) {
  const { data: projects, error: pe } = await supabase.from('professional_projects').select('id,created_at').eq('professional_id', professionalId).order('created_at', { ascending: false });
  if (pe) throw pe;
  const keep = new Set((projects || []).slice(0, projectLimit).map(x => x.id));
  if (projects?.length) {
    const active = projects.filter(x => keep.has(x.id)).map(x => x.id);
    const archived = projects.filter(x => !keep.has(x.id)).map(x => x.id);
    if (active.length) await supabase.from('professional_projects').update({ plan_visibility: 'active' }).in('id', active);
    if (archived.length) await supabase.from('professional_projects').update({ plan_visibility: 'archived_plan_limit' }).in('id', archived);
  }
  const { data: customServices, error: se } = await supabase.from('professional_services').select('id,created_at').eq('professional_id', professionalId).eq('is_custom', true).order('created_at', { ascending: false });
  if (se) throw se;
  const serviceKeep = new Set((customServices || []).slice(0, customServiceLimit).map(x => x.id));
  if (customServices?.length) {
    const active = customServices.filter(x => serviceKeep.has(x.id)).map(x => x.id);
    const archived = customServices.filter(x => !serviceKeep.has(x.id)).map(x => x.id);
    if (active.length) await supabase.from('professional_services').update({ plan_visibility: 'active' }).in('id', active);
    if (archived.length) await supabase.from('professional_services').update({ plan_visibility: 'archived_plan_limit' }).in('id', archived);
  }
}

async function restorePlanContent(professionalId, projectLimit, customServiceLimit) {
  const { count: activeProjectCount } = await supabase.from('professional_projects').select('id',{count:'exact',head:true}).eq('professional_id',professionalId).eq('plan_visibility','active');
  const projectSlots=Math.max(0, Number(projectLimit||0)-(activeProjectCount||0));
  if(projectSlots>0){
    const { data: projects } = await supabase.from('professional_projects').select('id,created_at').eq('professional_id', professionalId).eq('plan_visibility','archived_plan_limit').order('created_at', { ascending: false }).limit(projectSlots);
    if (projects?.length) await supabase.from('professional_projects').update({ plan_visibility: 'active' }).in('id', projects.map(x => x.id));
  }
  const { count: activeServiceCount } = await supabase.from('professional_services').select('id',{count:'exact',head:true}).eq('professional_id',professionalId).eq('is_custom',true).eq('plan_visibility','active');
  const serviceSlots=Math.max(0, Number(customServiceLimit||0)-(activeServiceCount||0));
  if(serviceSlots>0){
    const { data: services } = await supabase.from('professional_services').select('id,created_at').eq('professional_id', professionalId).eq('is_custom',true).eq('plan_visibility','archived_plan_limit').order('created_at', { ascending: false }).limit(serviceSlots);
    if (services?.length) await supabase.from('professional_services').update({ plan_visibility: 'active' }).in('id', services.map(x => x.id));
  }
}

async function requireProjectCapacity(professionalId, plan) {
  const { count, error } = await supabase.from('professional_projects').select('id', { count: 'exact', head: true }).eq('professional_id', professionalId).eq('plan_visibility','active');
  if (error) throw error;
  if ((count || 0) >= Number(plan.project_limit || 0)) return false;
  return true;
}

app.get('/api/plans', async (req,res) => {
  try {
    const { data, error } = await supabase.from('subscription_plans').select('id,code,name,monthly_price,annual_price,project_limit,custom_service_limit,active').eq('active',true).order('monthly_price',{ascending:true});
    if(error) throw error;
    res.json({plans:data||[]});
  } catch(error) { console.error(error); res.status(500).json({error:'Não foi possível carregar os planos.'}); }
});

app.get('/api/professional/plans', requireProfessional, async (req,res) => {
  try {
    const [{ data: plans, error: pe }, current] = await Promise.all([
      supabase.from('subscription_plans').select('*').eq('active',true).order('monthly_price',{ascending:true}),
      getEffectivePlan(req.session.professionalId)
    ]);
    if (pe) throw pe;
    const { count: projectCount } = await supabase.from('professional_projects').select('id',{count:'exact',head:true}).eq('professional_id',req.session.professionalId).eq('plan_visibility','active');
    const { count: customServiceCount } = await supabase.from('professional_services').select('id',{count:'exact',head:true}).eq('professional_id',req.session.professionalId).eq('is_custom',true).eq('plan_visibility','active');
    res.json({ plans: plans || [], current, usage: { projects: projectCount || 0, customServices: customServiceCount || 0 } });
  } catch (error) { console.error(error); res.status(500).json({error:'Não foi possível carregar os planos.'}); }
});

app.post('/api/professional/services', requireProfessional, async (req,res) => {
  try {
    const profile = await getProfessionalSessionProfile(req.session.professionalId);
    const plan = await getEffectivePlan(profile.id);
    if (plan.code !== 'business_plus') return res.status(403).json({error:'Serviços personalizados estão disponíveis apenas no Empresarial + 5 Serviços.'});
    const { count } = await supabase.from('professional_services').select('id',{count:'exact',head:true}).eq('professional_id',profile.id).eq('is_custom',true).eq('plan_visibility','active');
    if ((count || 0) >= Number(plan.custom_service_limit || 5)) return res.status(403).json({error:'Você atingiu o limite de 5 serviços personalizados.'});
    const title=String(req.body.title||'').trim();
    if(!title) return res.status(400).json({error:'Informe o nome do serviço.'});
    const description=String(req.body.description||'').trim();
    const item={id:crypto.randomUUID(),professional_id:profile.id,title,slug:`${slugify(title)}-${crypto.randomBytes(2).toString('hex')}`,category:'Serviço personalizado',description,custom_description:description,keywords:String(req.body.keywords||'').trim(),availability:['available','limited','unavailable'].includes(String(req.body.availability))?String(req.body.availability):'available',service_area:String(req.body.service_area||profile.service_area||'').trim(),price_mode:String(req.body.price_mode||'').trim().slice(0,40),price_amount:String(req.body.price_amount||'').trim().slice(0,40),price:String(req.body.price||'').trim().slice(0,120),cover_image:'',status:'approved',featured:false,is_custom:true,plan_visibility:'active',created_at:new Date().toISOString(),updated_at:new Date().toISOString()};
    const {data,error}=await supabase.from('professional_services').insert(item).select('*').single();
    if(error)throw error;
    res.json(data);
  } catch(error){console.error(error);res.status(500).json({error:'Não foi possível publicar o serviço personalizado.'});}
});

app.put('/api/professional/services/:id', requireProfessional, async (req,res)=>{
  try {
    const profile=await getProfessionalSessionProfile(req.session.professionalId), plan=await getEffectivePlan(profile.id);
    const {data:current,error:ce}=await supabase.from('professional_services').select('*').eq('id',req.params.id).eq('professional_id',profile.id).eq('is_custom',true).maybeSingle(); if(ce)throw ce;if(!current)return res.status(404).json({error:'Serviço personalizado não encontrado.'});
    if(plan.code!=='business_plus' && current.plan_visibility!=='active')return res.status(403).json({error:'Faça upgrade para reativar este serviço.'});
    const update={title:String(req.body.title||current.title).trim(),description:String(req.body.description??current.description).trim(),custom_description:String(req.body.description ?? (current.custom_description || '')).trim(),keywords:String(req.body.keywords ?? (current.keywords || '')).trim(),availability:['available','limited','unavailable'].includes(String(req.body.availability))?String(req.body.availability):current.availability,service_area:String(req.body.service_area ?? (current.service_area || '')).trim(),price_mode:String(req.body.price_mode ?? (current.price_mode || '')).trim().slice(0,40),price_amount:String(req.body.price_amount ?? (current.price_amount || '')).trim().slice(0,40),price:String(req.body.price ?? (current.price || '')).trim().slice(0,120),updated_at:new Date().toISOString()};
    const {data,error}=await supabase.from('professional_services').update(update).eq('id',current.id).select('*').single();if(error)throw error;res.json(data);
  }catch(error){console.error(error);res.status(500).json({error:'Não foi possível atualizar o serviço personalizado.'});}
});

app.delete('/api/professional/services/:id', requireProfessional, async (req,res)=>{
  try { const {error}=await supabase.from('professional_services').delete().eq('id',req.params.id).eq('professional_id',req.session.professionalId).eq('is_custom',true);if(error)throw error;res.json({ok:true}); }
  catch(error){console.error(error);res.status(500).json({error:'Não foi possível remover o serviço personalizado.'}); }
});
app.post('/api/professional/projects', requireProfessional, imageUpload.array('images', 8), async (req, res) => {
  const newImages = [];
  let persisted = false;
  try {
    const profile = await getProfessionalSessionProfile(req.session.professionalId);
    if (!canPublish(profile)) return res.status(403).json({ error: profile.verification_status !== 'approved' ? 'Aguarde a autenticação dos seus documentos antes de publicar.' : 'Esta conta não pode publicar neste momento.' });
    if (profileCompleteness(profile) < 60) return res.status(403).json({ error: 'Complete pelo menos 60% do seu perfil antes de enviar projetos.' });
    const plan = await getEffectivePlan(profile.id);
    if (!(await requireProjectCapacity(profile.id, plan))) return res.status(403).json({ error: `Você atingiu o limite de ${plan.project_limit} projetos do plano ${plan.name}. Faça upgrade para publicar mais.` });
    const title = String(req.body.title || '').trim();
    if (!title) return res.status(400).json({ error: 'Informe o título do projeto.' });
    const site = await readData();
    const category = categoryMatch(req.body.category, (site.categories || []).filter(c => c.active !== false))?.name;
    if (!category) return res.status(400).json({ error: 'Selecione uma categoria válida para o projeto.' });
    for (const f of req.files || []) newImages.push(await savePrivateUpload(f, 'projects', profile.id));
    const item = { id: crypto.randomUUID(), professional_id: profile.id, category, title, slug: `${slugify(title)}-${crypto.randomBytes(2).toString('hex')}`, description: String(req.body.description || '').trim(), project_url: normalizeUrl(req.body.project_url || ''), images: newImages, status: 'pending', rejection_reason: '', featured: false, plan_visibility: 'active', created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
    const { data, error } = await supabase.from('professional_projects').insert(item).select('*').single();
    if (error) throw error;
    persisted = true;
    await notifyProfessional(profile.id, 'moderation', 'Projeto enviado para análise', `O projeto “${title}” foi recebido e está aguardando revisão.`, '/profissional/dashboard').catch(e => console.error('Notificação do projeto:', e));
    res.json(ownerProjectRow(data));
  } catch (error) { if (!persisted) await Promise.all(newImages.map(ref => deleteUpload(ref).catch(()=>{}))); console.error(error); res.status(500).json({ error: 'Erro ao enviar projeto.' }); }
});
app.put('/api/professional/projects/:id', requireProfessional, imageUpload.array('images', 8), async (req, res) => {
  const newImages = [];
  const publicImages = [];
  const queuedImages = [];
  let persisted = false;
  try {
    const profile = await getProfessionalSessionProfile(req.session.professionalId);
    if (!canPublish(profile)) return res.status(403).json({ error: 'Esta conta não pode editar projetos neste momento.' });
    const { data: current, error: ce } = await supabase.from('professional_projects').select('*').eq('id', req.params.id).eq('professional_id', profile.id).maybeSingle(); if (ce) throw ce; if (!current) return res.status(404).json({ error: 'Projeto não encontrado.' });
    if (current.plan_visibility === 'archived_plan_limit') return res.status(403).json({ error: 'Este projeto está arquivado porque excede o limite do plano atual. Faça upgrade para o editar ou reativar.' });
    const site = await readData();
    const category = categoryMatch(req.body.category, (site.categories || []).filter(c => c.active !== false))?.name;
    if (!category) return res.status(400).json({ error: 'Selecione uma categoria válida para o projeto.' });
    if ((current.images || []).length + (req.files || []).length > 12) return res.status(400).json({ error: 'Máximo de 12 imagens por projeto.' });
    const images = [];
    for (const old of current.images || []) {
      if (privatePath(old)) { images.push(old); continue; }
      const ref = await privatizeProjectImage(old, profile.id);
      newImages.push(ref); publicImages.push(old); images.push(ref);
    }
    for (const f of req.files || []) { const ref = await savePrivateUpload(f, 'projects', profile.id); newImages.push(ref); images.push(ref); }
    const update = { category, title: String(req.body.title || current.title).trim(), description: String(req.body.description ?? current.description).trim(), project_url: normalizeUrl(req.body.project_url ?? current.project_url ?? ''), images: images.slice(0,12), status: 'pending', rejection_reason: '', featured: false, updated_at: new Date().toISOString() };
    if (USE_SUPABASE) for (const url of publicImages) {
      const marker = `/storage/v1/object/public/${STORAGE_BUCKET}/`;
      const public_path = decodeURIComponent(url.slice(url.indexOf(marker) + marker.length));
      const { error } = await supabase.from('security_media_cleanup').upsert({ public_path, public_url: url, kind: 'project' }, { onConflict: 'public_path' });
      if (error) throw error;
      queuedImages.push(public_path);
    }
    const { data, error } = await supabase.from('professional_projects').update(update).eq('id', current.id).select('*').single(); if (error) throw error;
    persisted = true;
    if (queuedImages.length) {
      const pending = await require('./scripts/migrate-private-files.cjs').drainQueue().catch(e => { console.error('Remoção pública em fila:', e); return queuedImages.length; });
      if (pending) console.error('Remoção de imagem pública pendente; a rotina periódica voltará a tentar.');
    }
    await notifyProfessional(profile.id, 'moderation', 'Alteração de projeto enviada', `As alterações em “${update.title}” estão aguardando nova revisão.`, '/profissional/dashboard').catch(e => console.error('Notificação da alteração:', e));
    res.json(ownerProjectRow(data));
  } catch (error) {
    if (!persisted) {
      await Promise.all(newImages.map(ref => deleteUpload(ref).catch(()=>{})));
      if (queuedImages.length) await supabase.from('security_media_cleanup').delete().in('public_path', queuedImages);
    }
    console.error(error); res.status(500).json({ error: 'Erro ao atualizar projeto.' });
  }
});
app.get('/api/professional/projects/:id/images/:index', requireProfessional, async (req, res) => {
  try {
    const { data: project, error } = await supabase.from('professional_projects').select('images').eq('id', req.params.id).eq('professional_id', req.session.professionalId).maybeSingle();
    if (error) throw error;
    const image = project?.images?.[Number(req.params.index)];
    if (!privatePath(image)) return res.status(404).end();
    await servePrivateUpload(image, res);
  } catch (error) { console.error(error); res.status(500).end(); }
});

app.delete('/api/professional/projects/:id', requireProfessional, async (req, res) => {
  try {
    const { data: item } = await supabase.from('professional_projects').select('images').eq('id', req.params.id).eq('professional_id', req.session.professionalId).maybeSingle();
    for (const url of item?.images || []) await deleteUpload(url);
    const { error } = await supabase.from('professional_projects').delete().eq('id', req.params.id).eq('professional_id', req.session.professionalId); if (error) throw error; res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao remover projeto.' }); }
});

// Público: perfis aprovados. O selo `verified` é um distintivo manual da administração.
let directoryCache = { expires: 0, value: null, pending: null };
async function directoryRows(build) {
  const rows = [];
  for (let offset = 0; offset < 10000; offset += 500) {
    const { data, error } = await build().order('id').range(offset, offset + 499);
    if (error) throw error;
    rows.push(...(data || []));
    if ((data || []).length < 500) return rows;
  }
  throw new Error('Limite de catálogo atingido; paginação de base de dados necessária.');
}
async function directorySnapshot() {
  if (directoryCache.value && directoryCache.expires > Date.now()) return directoryCache.value;
  if (directoryCache.pending) return directoryCache.pending;
  directoryCache.pending = Promise.all([
    directoryRows(() => supabase.from('professional_profiles').select('id,name,slug,photo,specialty,headline,bio,location,province,district,neighborhood,verified,featured,years_experience,service_area,availability,languages,skills,response_time_label,profile_completeness,verification_status,profile_type,institutional_role,official_profile,founder_message,created_at,last_active_at').eq('status', 'approved')),
    directoryRows(() => supabase.from('professional_services').select('id,professional_id,title,category,description,keywords,availability,service_area,price_mode,price_amount,price').eq('status', 'approved')),
    directoryRows(() => supabase.from('professional_ratings').select('id,professional_id,stars,status').eq('status','published')),
    directoryRows(() => supabase.from('professional_projects').select('id,professional_id,category,title,description,professional_services(category)').eq('status','approved').eq('plan_visibility','active'))
  ]).then(([profiles,services,ratings,projects]) => {
    const value = { profiles, services, ratings, projects };
    directoryCache = { value, expires: Date.now() + 30000, pending: null };
    return value;
  }).catch(error => { directoryCache.pending = null; throw error; });
  return directoryCache.pending;
}
app.get('/api/professionals', async (req, res) => {
  try {
    const { profiles, services, ratings, projects } = await directorySnapshot();
    const term = String(req.query.q || '').trim().toLowerCase().slice(0, 120);
    const category = String(req.query.category || '').trim().toLowerCase().slice(0, 120);
    const location = String(req.query.location || '').trim().toLowerCase().slice(0, 120);
    const availability = String(req.query.availability || '').trim();
    const verified = String(req.query.verified || '') === 'true';
    const minRating = Math.max(0, Math.min(5, Number(req.query.minRating || 0)));
    const groupByOwner = rows => rows.reduce((map, row) => { const key = row.professional_id; if (!map.has(key)) map.set(key, []); map.get(key).push(row); return map; }, new Map());
    const servicesByOwner = groupByOwner(services), ratingsByOwner = groupByOwner(ratings), projectsByOwner = groupByOwner(projects);
    let result = profiles.map(p => {
      const ps = (servicesByOwner.get(p.id) || []).map(({professional_id,...rest})=>rest);
      const rr = ratingsByOwner.get(p.id) || [];
      const avg = rr.length ? rr.reduce((a,x)=>a+Number(x.stars||0),0)/rr.length : 0;
      const projectCategories=(projectsByOwner.get(p.id)||[]).map(x=>x.category||x.professional_services?.category).filter(Boolean);
      return { ...p, verified: Boolean(p.verified && p.verification_status === 'approved'), identityValidated: p.verification_status === 'approved', verification_status: undefined, services: ps, projectCategories, ratingAvg: avg, ratingCount: rr.length };
    });
    const site = await readData(); const managedCategories=(site.categories||[]).filter(c=>c.active!==false);
    if (term) result = result.map(p=>({...p,searchScore:serviceSearchScore(p,term,managedCategories)})).filter(p=>p.searchScore>0).sort((a,b)=>b.searchScore-a.searchScore||Number(b.featured)-Number(a.featured));
    if (category) result = result.filter(p => p.services.some(s=>normalizeSearchText(s.category)===normalizeSearchText(category)) || p.projectCategories.some(c=>normalizeSearchText(c)===normalizeSearchText(category)) || normalizeSearchText(p.specialty).includes(normalizeSearchText(category)));
    if (location) result = result.map(p=>({...p,locationScore:locationSearchScore(p,location,site.locationAliases||[])})).filter(p=>p.locationScore>0).sort((a,b)=>b.locationScore-a.locationScore||Number(b.searchScore||0)-Number(a.searchScore||0));
    if (availability) result = result.filter(p => p.availability === availability);
    if (verified) result = result.filter(p => p.verified);
    if (minRating) result = result.filter(p => p.ratingAvg >= minRating);
    result.sort((a,b)=>Number(b.locationScore||0)-Number(a.locationScore||0) || Number(b.searchScore||0)-Number(a.searchScore||0) || Number(b.featured)-Number(a.featured) || String(b.created_at).localeCompare(String(a.created_at)));
    if (term || category || location) supabase.from('search_analytics').insert({ id: crypto.randomUUID(), query_text: term, category: String(req.query.category||''), location_query: String(req.query.location||''), result_count: result.length, created_at: new Date().toISOString() }).then(()=>{}).catch(()=>{});
    const page = Math.max(1, Math.min(500, Number.parseInt(req.query.page, 10) || 1));
    res.set('X-Total-Count', String(result.length));
    res.set('X-Next-Page', page * 24 < result.length ? String(page + 1) : '');
    res.json(result.slice((page - 1) * 24, page * 24));
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao carregar profissionais.' }); }
});

app.get('/api/professionals/:slug', async (req, res) => {
  try {
    await releaseExpiredSuspensions();
    const { data: profile, error } = await supabase.from('professional_profiles').select('id,name,slug,photo,specialty,headline,bio,location,province,district,neighborhood,phone,whatsapp,email,website,linkedin,instagram,cv_url,verified,verification_status,featured,years_experience,service_area,availability,languages,skills,certifications,education,response_time_label,profile_completeness,profile_type,institutional_role,official_profile,founder_message,created_at,last_active_at').eq('slug', req.params.slug).eq('status', 'approved').maybeSingle();
    if (error) throw error; if (!profile) return res.status(404).json({ error: 'Profissional não encontrado.' });
    const [{ data: services, error: se }, { data: projects, error: pe }, { data: ratings, error: re }, eventMetrics] = await Promise.all([
      supabase.from('professional_services').select('id,title,slug,category,description,keywords,price,price_mode,price_amount,service_area,availability,delivery_time,cover_image').eq('professional_id', profile.id).eq('status', 'approved').eq('plan_visibility','active').order('featured',{ascending:false}).order('created_at', { ascending: false }),
      supabase.from('professional_projects').select('id,title,slug,description,project_url,images,service_id,category').eq('professional_id', profile.id).eq('status', 'approved').eq('plan_visibility','active').order('featured',{ascending:false}).order('created_at', { ascending: false }),
      supabase.from('professional_ratings').select('id,stars,comment,scope_key,professional_reply,replied_at,verified_interaction,created_at,professional_services(title)').eq('professional_id', profile.id).eq('status', 'published').order('created_at', { ascending: false }),
      professionalEventMetrics(profile.id)
    ]);
    if (se) throw se; if (pe) throw pe; if (re) throw re;
    await recordProfessionalEvent(req, profile.id, 'view');
    const avg = ratings?.length ? ratings.reduce((a,x)=>a+Number(x.stars||0),0)/ratings.length : 0;
    const views = eventMetrics.views;
    const contacts = eventMetrics.contacts;
    const publicProfile = { ...profile, verified: Boolean(profile.verified && profile.verification_status === 'approved'), identityValidated: profile.verification_status === 'approved' }; delete publicProfile.verification_status; delete publicProfile.cv_url;
    res.json({ profile: publicProfile, services: services || [], projects: projects || [], trust: { views, contacts, memberSince: profile.created_at, identityValidated: publicProfile.identityValidated }, rating: { average: avg, count: ratings?.length || 0, reviews: ratings || [] } });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao carregar profissional.' }); }
});

app.post('/api/professionals/:slug/contact', feedbackLimiter, async (req, res) => {
  try {
    const { data: profile, error } = await supabase.from('professional_profiles').select('id').eq('slug', req.params.slug).eq('status', 'approved').maybeSingle();
    if (error) throw error; if (!profile) return res.status(404).json({ error: 'Profissional não encontrado.' });
    const serviceId = req.body.serviceId || null, channel = String(req.body.channel || 'whatsapp').slice(0,30), scopeKey = `${channel}:${serviceId || 'general'}`;
    await recordProfessionalEvent(req, profile.id, 'contact', { serviceId, channel, scopeKey });
    res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao registar contacto.' }); }
});
app.post('/api/professionals/:slug/rating', feedbackLimiter, async (req, res) => {
  try {
    const stars = Number(req.body.stars), scopeKey = String(req.body.scopeKey || 'general'), comment = String(req.body.comment || '').trim().slice(0,1000);
    if (![1,2,3,4,5].includes(stars)) return res.status(400).json({ error: 'Escolha de 1 a 5 estrelas.' });
    const { data: profile, error } = await supabase.from('professional_profiles').select('id,name').eq('slug', req.params.slug).eq('status', 'approved').maybeSingle();
    if (error) throw error; if (!profile) return res.status(404).json({ error: 'Profissional não encontrado.' });
    let serviceId = null;
    if (scopeKey !== 'general') {
      const { data: service } = await supabase.from('professional_services').select('id').eq('id', scopeKey).eq('professional_id', profile.id).eq('status', 'approved').maybeSingle();
      if (!service) return res.status(400).json({ error: 'Serviço inválido.' });
      serviceId = service.id;
    }
    const vh = visitorHash(req);
    let contactQuery = supabase.from('professional_events').select('id').eq('professional_id', profile.id).eq('event_type','contact').eq('visitor_hash',vh).limit(1);
    if (serviceId) contactQuery = contactQuery.eq('service_id', serviceId);
    const { data: contactEvents, error: contactError } = await contactQuery; if (contactError) throw contactError;
    if (!contactEvents?.length) return res.status(403).json({ error: 'Para avaliar, entre primeiro em contacto com este profissional através da plataforma.' });
    const now = new Date().toISOString();
    const { data: existing } = await supabase.from('professional_ratings').select('id').eq('professional_id', profile.id).eq('scope_key', scopeKey).eq('visitor_hash', vh).maybeSingle();
    const rating = { stars, comment, service_id: serviceId, status: 'pending', verified_interaction: false, updated_at: now };
    const { error: ratingError } = existing
      ? await supabase.from('professional_ratings').update(rating).eq('id', existing.id)
      : await supabase.from('professional_ratings').insert({ id: crypto.randomUUID(), professional_id: profile.id, scope_key: scopeKey, visitor_hash: vh, created_at: now, ...rating });
    if (ratingError) throw ratingError;
    res.json({ ok: true, pending: true, message: 'Avaliação recebida e enviada para moderação.' });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao guardar avaliação.' }); }
});

app.post('/api/professionals/:slug/report', feedbackLimiter, async (req, res) => {
  try {
    const reason = String(req.body.reason || '').trim(), details = String(req.body.details || '').trim().slice(0,2000), reporterContact = String(req.body.reporterContact || '').trim().slice(0,250);
    const allowed = ['fraude','informacao_falsa','conteudo_copiado','conduta','spam','outro'];
    if (!allowed.includes(reason)) return res.status(400).json({ error: 'Selecione o motivo da denúncia.' });
    const { data: profile, error } = await supabase.from('professional_profiles').select('id').eq('slug', req.params.slug).eq('status', 'approved').maybeSingle();
    if (error) throw error; if (!profile) return res.status(404).json({ error: 'Profissional não encontrado.' });
    const protocol = `YR-${new Date().toISOString().slice(0,10).replace(/-/g,'')}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    await supabase.from('professional_reports').insert({ id: crypto.randomUUID(), professional_id: profile.id, reason, details, reporter_contact: reporterContact, visitor_hash: visitorHash(req), protocol, status: 'open', created_at: new Date().toISOString() });
    res.json({ ok: true, protocol });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao enviar denúncia.' }); }
});
app.get('/api/featured-professional-projects', async (_, res) => {
  try {
    const { data, error } = await supabase.from('professional_projects').select('id,title,description,project_url,images,category,professional_services(title,status),professional_profiles!inner(name,slug,status)').eq('status', 'approved').eq('featured', true).eq('professional_profiles.status', 'approved').order('updated_at', { ascending: false }).limit(12);
    if (error) throw error;
    res.json((data || []).map(x => ({ id: x.id, title: x.title, description: x.description, link: x.project_url, images: x.images || [], image: x.images?.[0] || '', service: x.category || x.professional_services?.title || 'Projeto', professionalName: x.professional_profiles?.name || '', professionalSlug: x.professional_profiles?.slug || '' })));
  } catch (error) { console.error(error); res.json([]); }
});

app.get('/api/site-service-projects/:id', async (req, res) => {
  try {
    const site = await readData();
    const area = findPublicServiceArea(site,req.params.id);
    if (!area) return res.status(404).json({ error: 'Serviço não encontrado.' });
    const categories = (site.categories || DEFAULT_CATEGORIES).filter(c => c.active !== false && siteServiceMatchesCategory(area, c.name)).map(c => c.name);
    if (!categories.length) return res.json([]);
    const { data, error } = await supabase.from('professional_projects')
      .select('id,title,description,project_url,images,category,professional_services(title,category,status),professional_profiles!inner(name,slug,status)')
      .eq('status', 'approved').eq('professional_profiles.status', 'approved')
      .order('created_at', { ascending: false }).limit(1000);
    if (error) throw error;
    res.json((data || []).filter(x => categories.some(c => normalizeSearchText(c) === normalizeSearchText(x.category || x.professional_services?.category))).map(x => ({ id: x.id, title: x.title, description: x.description, link: x.project_url, images: x.images || [], image: x.images?.[0] || '', service: x.category || x.professional_services?.title || '', professionalName: x.professional_profiles?.name || '', professionalSlug: x.professional_profiles?.slug || '' })));
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao carregar projetos do serviço.' }); }
});

app.get('/profissionais', (req, res) => sendSeoHtml(req,res,'professionals.html',{title:'Profissionais | Yuran Multicerviços',description:'Pesquise profissionais por serviço, categoria, localização, disponibilidade e avaliação na Yuran Multicerviços.'}));
app.get('/planos',(req,res)=>sendSeoHtml(req,res,'plans.html',{title:'Planos para profissionais | Yuran Multicerviços',description:'Compare os planos Gratuito, PRO, PRO+, Empresarial e Empresarial + 5 Serviços da Yuran Multicerviços.'}));

app.get('/servicos', (req, res) => sendSeoHtml(req,res,'services.html',{title:'Todos os serviços | Yuran Multicerviços',description:'Explore todos os serviços e encontre profissionais de cada área na Yuran Multicerviços.'}));
app.get('/profissional', (_, res) => res.sendFile(path.join(__dirname, 'public', 'professional-login.html')));
app.get('/profissional/google-callback', (_, res) => res.sendFile(path.join(__dirname, 'public', 'professional-google-callback.html')));
app.get('/profissional/dashboard', (_, res) => res.sendFile(path.join(__dirname, 'professional', 'dashboard.html')));
app.get('/profissional/:slug', async (req, res) => {
  try{
    const {data:p,error}=await supabase.from('professional_profiles').select('name,slug,photo,specialty,headline,bio,location,province,district,neighborhood,service_area,website,linkedin,instagram,verified,verification_status').eq('slug',req.params.slug).eq('status','approved').maybeSingle();
    if(error)throw error;if(!p)return res.status(404).send('Profissional não encontrado.');
    const location=[p.neighborhood,p.district,p.province,p.location].find(Boolean)||p.service_area||'Moçambique';
    const description=cleanSeoText(p.headline||p.bio||`${p.name} — ${p.specialty||'profissional'} em ${location}.`,170);
    const sameAs=[p.website,p.linkedin,p.instagram].filter(Boolean);
    const schema={'@context':'https://schema.org','@type':'Person',name:p.name,jobTitle:p.specialty||undefined,description,url:`${baseUrl(req)}/profissional/${encodeURIComponent(p.slug)}`,image:p.photo||undefined,homeLocation:location,sameAs:sameAs.length?sameAs:undefined};
    return sendSeoHtml(req,res,'professional-profile.html',{title:`${p.name}${p.specialty?` — ${p.specialty}`:''} | Yuran Multicerviços`,description,canonical:`${baseUrl(req)}/profissional/${encodeURIComponent(p.slug)}`,image:p.photo,ogType:'profile',schema});
  }catch(error){console.error(error);res.status(500).send('Não foi possível carregar o perfil.')}
});
app.use('/professional-assets', express.static(path.join(__dirname, 'professional'), { maxAge: 0, etag: true, setHeaders(res, filePath) { if (/\.(?:html|js|css)$/i.test(filePath)) res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate'); } }));

// Moderação administrativa.
app.get('/api/admin/moderation', requireAuth, async (req, res) => {
  try {
    await releaseExpiredSuspensions();
    const [{ data: professionals, error: pe }, { data: services, error: se }, { data: projects, error: pre }] = await Promise.all([
      // Rascunhos recém-criados também pertencem à lista administrativa.
      supabase.from('professional_profiles').select('*').order('created_at', { ascending: false }),
      supabase.from('professional_services').select('*, professional_profiles(name,slug)').order('created_at', { ascending: false }),
      supabase.from('professional_projects').select('*, professional_profiles(name,slug)').order('created_at', { ascending: false })
    ]); if (pe) throw pe; if (se) throw se; if (pre) throw pre;
    res.json({ professionals: (professionals || []).map(p => ({ ...p, cv_url: p.cv_url ? `/api/admin/professionals/${encodeURIComponent(p.id)}/cv` : '' })), services: services || [], projects: (projects || []).map(adminProjectRow) });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao carregar moderação.' }); }
});
app.patch('/api/admin/moderation/:type/:id', requireAuth, async (req, res) => {
  let publishing = null, published = false;
  try {
    const map = { professionals: 'professional_profiles', services: 'professional_services', projects: 'professional_projects' }, table = map[req.params.type];
    if (!table) return res.status(400).json({ error: 'Tipo inválido.' });
    const allowed = ['pending','approved','rejected','suspended'], status = String(req.body.status || '');
    if (!allowed.includes(status)) return res.status(400).json({ error: 'Estado inválido.' });
    let targetProfile = null;
    if (table === 'professional_profiles') {
      const { data: profile } = await supabase.from('professional_profiles').select('*').eq('id', req.params.id).maybeSingle(); targetProfile=profile;
      if(!profile)return res.status(404).json({error:'Profissional não encontrado.'});
      if (status === 'approved') {
        if (profile.verification_status !== 'approved') return res.status(400).json({ error: 'Valide primeiro o documento de identificação.' });
        const candidate={...profile,...(profile.profile_changes_status==='pending'&&profile.pending_profile_changes&&typeof profile.pending_profile_changes==='object'?profile.pending_profile_changes:{})};
        const missing = profileQualityMissing(candidate); if (missing.length) return res.status(400).json({ error: `Perfil incompleto para publicação: ${missing.join(', ')}.` });
      }
    }
    const reviewingPendingChanges = table === 'professional_profiles' && targetProfile?.status === 'approved' && targetProfile.profile_changes_status === 'pending' && status !== 'suspended';
    let update = { status, rejection_reason: status === 'rejected' ? String(req.body.rejection_reason || '').trim() : '', updated_at: new Date().toISOString() };
    if (reviewingPendingChanges) {
      if(status==='approved'){ const pending=targetProfile.pending_profile_changes||{}; update={...pending,status:'approved',profile_changes_status:'none',pending_profile_changes:{},profile_change_rejection_reason:'',rejection_reason:'',profile_completeness:profileCompleteness({...targetProfile,...pending}),updated_at:new Date().toISOString()}; if(pending.name&&pending.name!==targetProfile.name)update.slug=await uniqueProfessionalSlug(pending.name,targetProfile.id); }
      else if(status==='rejected'){ update={status:'approved',profile_changes_status:'rejected',profile_change_rejection_reason:String(req.body.rejection_reason||'').trim(),rejection_reason:'',updated_at:new Date().toISOString()}; }
      else { update={status:'approved',profile_changes_status:'pending',updated_at:new Date().toISOString()}; }
    }
    if (table === 'professional_profiles' && status !== 'suspended') Object.assign(update, { suspended_until: null, suspension_reason: '', pre_suspension_status: '' });
    if (table === 'professional_projects' && status === 'approved') {
      const { data: project, error: projectError } = await supabase.from(table).select('images').eq('id', req.params.id).maybeSingle();
      if (projectError) throw projectError;
      if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
      publishing = await publishProjectImages(project.images);
      update.images = publishing.images;
    }
    const { data, error } = await supabase.from(table).update(update).eq('id', req.params.id).select('*').single(); if (error) throw error;
    published = true;
    if (publishing) await Promise.all(publishing.privateRefs.map(ref => deleteUpload(ref).catch(e => console.error('Limpeza de imagem privada:', e))));
    if (reviewingPendingChanges) {
      const pendingPhoto=targetProfile.pending_profile_changes?.photo||'';
      if (status==='approved' && pendingPhoto && targetProfile.photo && pendingPhoto!==targetProfile.photo) await deleteUpload(targetProfile.photo).catch(()=>{});
      if (status==='rejected' && pendingPhoto && pendingPhoto!==targetProfile.photo) await deleteUpload(pendingPhoto).catch(()=>{});
    }
    await safeAuditLog({ target_type: req.params.type, target_id: req.params.id, action: status, reason: String(req.body.rejection_reason || ''), metadata: { admin: true } });
    let professionalId = table === 'professional_profiles' ? data.id : data.professional_id;
    const typeLabel = table === 'professional_profiles' ? 'perfil' : table === 'professional_services' ? 'serviço' : 'projeto';
    const reasonText=String(req.body.rejection_reason || 'Consulte o painel.');
    const pendingChangeTitle = status==='approved' ? 'Alterações do perfil aprovadas' : status==='rejected' ? 'Alterações do perfil precisam de ajustes' : 'Alterações do perfil em análise';
    const pendingChangeMessage = status==='approved' ? 'As alterações solicitadas foram aprovadas e já substituíram a versão anterior do seu perfil público.' : status==='rejected' ? `As alterações solicitadas não foram aplicadas. A versão pública anteriormente aprovada continua visível. Motivo: ${reasonText}` : 'As alterações do perfil continuam em análise. A versão pública aprovada permanece visível.';
    const message = reviewingPendingChanges ? pendingChangeMessage : status === 'approved' ? (table === 'professional_profiles' ? 'A sua documentação já foi validada e o seu perfil profissional foi aprovado. O perfil pode agora ficar disponível ao público, de acordo com as regras da plataforma.' : `O seu ${typeLabel} foi aprovado.`) : status === 'rejected' ? `O seu ${typeLabel} foi rejeitado. Motivo: ${reasonText}` : status === 'suspended' ? `O seu ${typeLabel} foi suspenso pela administração.` : `O seu ${typeLabel} voltou para análise.`;
    const notificationTitle = reviewingPendingChanges ? pendingChangeTitle : table === 'professional_profiles' && status === 'approved' ? 'Conta profissional aprovada — 100%' : `${typeLabel[0].toUpperCase()+typeLabel.slice(1)}: ${status === 'approved' ? 'aprovado' : status === 'rejected' ? 'rejeitado' : status === 'suspended' ? 'suspenso' : 'em análise'}`;
    await notifyProfessional(professionalId, 'moderation', notificationTitle, reviewingPendingChanges ? pendingChangeMessage : (table === 'professional_profiles' && status === 'approved' ? 'A sua identidade e o seu perfil profissional foram aprovados. A sua conta está agora totalmente aprovada e pode utilizar as funcionalidades de publicação da plataforma.' : message), '/profissional/dashboard', { sendEmail: table === 'professional_profiles' });
    res.json(data);
  } catch (error) {
    if (publishing && !published) await Promise.all(publishing.created.map(url => deleteUpload(url).catch(()=>{})));
    console.error(error); res.status(500).json({ error: 'Erro ao moderar item.' });
  }
});
app.patch('/api/admin/featured/:type/:id', requireAuth, async (req, res) => {
  try {
    const map = { professionals: 'professional_profiles', services: 'professional_services', projects: 'professional_projects' }, table = map[req.params.type];
    if (!table) return res.status(400).json({ error: 'Tipo inválido.' });
    const featured = Boolean(req.body.featured);
    const { data, error } = await supabase.from(table).update({ featured, updated_at: new Date().toISOString() }).eq('id', req.params.id).eq('status', 'approved').select('*').single();
    if (error) throw error;
    await safeAuditLog({ target_type: req.params.type, target_id: req.params.id, action: featured ? 'featured_on' : 'featured_off', reason: 'Destaque editorial alterado pela administração.', metadata: { admin: true } });
    res.json(data);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao alterar destaque.' }); }
});
app.get('/api/admin/professionals/:id/cv', requireAuth, async (req, res) => {
  try {
    const { data: profile, error } = await supabase.from('professional_profiles').select('cv_url').eq('id', req.params.id).maybeSingle();
    if (error) throw error;
    await serveCurrentCv(profile, res);
  } catch (error) { console.error(error); res.status(500).end(); }
});
app.get('/api/admin/projects/:id/images/:index', requireAuth, async (req, res) => {
  try {
    const { data: project, error } = await supabase.from('professional_projects').select('images').eq('id', req.params.id).maybeSingle();
    if (error) throw error;
    const image = project?.images?.[Number(req.params.index)];
    if (!privatePath(image)) return res.status(404).end();
    await servePrivateUpload(image, res);
  } catch (error) { console.error(error); res.status(500).end(); }
});
app.get('/api/admin/professionals/:id/identity/:side', requireAuth, async (req, res) => {
  try {
    const field = req.params.side === 'front' ? 'id_front_path' : req.params.side === 'back' ? 'id_back_path' : null;
    if (!field) return res.status(400).json({ error: 'Lado inválido.' });
    const { data: profile, error } = await supabase.from('professional_profiles').select(field).eq('id', req.params.id).maybeSingle();
    if (error) throw error; const storagePath = profile?.[field];
    if (!storagePath) return res.status(404).json({ error: 'Documento não encontrado.' });
    const { data, error: signError } = await supabase.storage.from(VERIFICATION_BUCKET).createSignedUrl(storagePath, 600);
    if (signError) throw signError; res.json({ url: data.signedUrl });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao abrir documento.' }); }
});
app.patch('/api/admin/professionals/:id/verification', requireAuth, async (req, res) => {
  try {
    const status = String(req.body.status || ''), reason = String(req.body.reason || '').trim();
    if (!['approved','rejected','pending'].includes(status)) return res.status(400).json({ error: 'Estado de verificação inválido.' });
    if (status === 'rejected' && !reason) return res.status(400).json({ error: 'Informe o motivo da rejeição.' });
    const now = new Date(), retentionUntil = status !== 'pending' ? new Date(now.getTime() + IDENTITY_RETENTION_DAYS * 86400000).toISOString() : null;
    const update = { verification_status: status, verification_reason: status === 'rejected' ? reason : '', identity_verified_at: status === 'approved' ? now.toISOString() : null, identity_retention_until: retentionUntil, identity_documents_deleted_at: null, updated_at: now.toISOString(), ...(status === 'approved' ? {} : { verified: false }) };
    const { data, error } = await supabase.from('professional_profiles').update(update).eq('id', req.params.id).select('*').single();
    if (error) throw error;
    await safeAuditLog({ target_type: 'identity', target_id: req.params.id, action: status, reason, metadata: { retention_days: IDENTITY_RETENTION_DAYS } });
    await notifyProfessional(req.params.id, 'identity', status === 'approved' ? 'Identidade validada' : status === 'rejected' ? 'Documento precisa ser reenviado' : 'Identidade em análise', status === 'approved' ? 'A sua documentação de identificação foi aprovada. Continue a completar o perfil; a publicação pública do perfil depende ainda da aprovação administrativa do conteúdo profissional.' : status === 'rejected' ? `A validação do documento foi recusada. Motivo: ${reason}` : 'Os seus documentos estão em análise.', '/profissional/dashboard', { sendEmail: true });
    res.json(data);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao validar identidade.' }); }
});

app.patch('/api/admin/professionals/:id/verified', requireAuth, async (req, res) => {
  try {
    const verified = req.body.verified === true || req.body.verified === 'true';
    const { data: current, error: ce } = await supabase.from('professional_profiles').select('id,status,verification_status').eq('id', req.params.id).maybeSingle();
    if (ce) throw ce; if (!current) return res.status(404).json({ error: 'Profissional não encontrado.' });
    if (verified && (current.status !== 'approved' || current.verification_status !== 'approved')) return res.status(400).json({ error: 'Aprove o perfil e valide a identidade antes de atribuir o selo verificado.' });
    const { data, error } = await supabase.from('professional_profiles').update({ verified, updated_at: new Date().toISOString() }).eq('id', req.params.id).select('*').single();
    if (error) throw error;
    await safeAuditLog({ target_type: 'professional', target_id: req.params.id, action: verified ? 'verified_badge_on' : 'verified_badge_off', reason: 'Selo público alterado manualmente pela administração.', metadata: { admin: true } });
    res.json(data);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao alterar selo verificado.' }); }
});

// Edição e exclusão direta de profissionais pelo administrador.
app.put('/api/admin/professionals/:id', requireAuth, async (req, res) => {
  try {
    const { data: current, error: ce } = await supabase.from('professional_profiles').select('*').eq('id', req.params.id).maybeSingle();
    if (ce) throw ce; if (!current) return res.status(404).json({ error: 'Profissional não encontrado.' });
    const name = String(req.body.name ?? current.name).trim();
    if (name.length < 3) return res.status(400).json({ error: 'Informe um nome válido.' });
    const availability = ['available','limited','unavailable'].includes(String(req.body.availability)) ? String(req.body.availability) : (current.availability || 'available');
    const candidate = {
      ...current,
      name,
      specialty: String(req.body.specialty ?? current.specialty ?? '').trim(),
      headline: String(req.body.headline ?? current.headline ?? '').trim().slice(0,120),
      bio: String(req.body.bio ?? current.bio ?? '').trim(),
      address: String(req.body.address ?? current.address ?? '').trim(),
      location: String(req.body.location ?? current.location ?? '').trim(),
      province: String(req.body.province ?? current.province ?? '').trim().slice(0,120), district: String(req.body.district ?? current.district ?? '').trim().slice(0,120), neighborhood: String(req.body.neighborhood ?? current.neighborhood ?? '').trim().slice(0,160),
      phone: String(req.body.phone ?? current.phone ?? '').trim(),
      whatsapp: String(req.body.whatsapp ?? current.whatsapp ?? '').trim(),
      birth_date: String(req.body.birth_date ?? current.birth_date ?? '').trim() || null,
      id_number: String(req.body.id_number ?? current.id_number ?? '').trim().slice(0,120),
      service_area: String(req.body.service_area ?? current.service_area ?? '').trim(),
      skills: String(req.body.skills ?? current.skills ?? '').trim(),
      languages: String(req.body.languages ?? current.languages ?? '').trim(),
      certifications: String(req.body.certifications ?? current.certifications ?? '').trim(),
      education: req.body.education !== undefined ? normalizeEducation(req.body.education) : normalizeEducation(current.education || []),
      years_experience: Math.max(0, Math.min(80, Number(req.body.years_experience ?? current.years_experience ?? 0) || 0)),
      availability,
      profile_type: ['professional','team','founder','institutional'].includes(String(req.body.profile_type)) ? String(req.body.profile_type) : (current.profile_type || 'professional'),
      institutional_role: String(req.body.institutional_role ?? current.institutional_role ?? '').trim().slice(0,160),
      official_profile: ['on','true','1','yes'].includes(String(req.body.official_profile ?? current.official_profile ?? false).toLowerCase()),
      founder_message: String(req.body.founder_message ?? current.founder_message ?? '').trim().slice(0,3000)
    };
    const update = {
      name: candidate.name,
      slug: candidate.name !== current.name ? await uniqueProfessionalSlug(candidate.name, current.id) : current.slug,
      specialty: candidate.specialty,
      headline: candidate.headline,
      bio: candidate.bio,
      address: candidate.address,
      location: candidate.location,
      province: candidate.province, district: candidate.district, neighborhood: candidate.neighborhood,
      phone: candidate.phone,
      whatsapp: candidate.whatsapp,
      birth_date: candidate.birth_date,
      id_number: candidate.id_number,
      service_area: candidate.service_area,
      skills: candidate.skills,
      languages: candidate.languages,
      certifications: candidate.certifications,
      education: candidate.education,
      years_experience: candidate.years_experience,
      availability: candidate.availability,
      profile_type: candidate.profile_type,
      institutional_role: candidate.institutional_role,
      official_profile: candidate.official_profile,
      founder_message: candidate.founder_message,
      profile_completeness: profileCompleteness(candidate),
      updated_at: new Date().toISOString()
    };
    const { data, error } = await supabase.from('professional_profiles').update(update).eq('id', current.id).select('*').single();
    if (error) throw error;
    await safeAuditLog({ target_type: 'professional', target_id: current.id, action: 'admin_profile_edit', reason: 'Dados do perfil ajustados pela administração.', metadata: { admin: true } });
    await notifyProfessional(current.id, 'moderation', 'Perfil atualizado pela administração', 'A administração atualizou informações do seu perfil. Consulte a sua área profissional para confirmar os dados.', '/profissional/dashboard');
    res.json(data);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao editar profissional.' }); }
});

app.delete('/api/admin/professionals/:id', requireAuth, async (req, res) => {
  try {
    const { data: profile, error: pe } = await supabase.from('professional_profiles').select('*').eq('id', req.params.id).maybeSingle();
    if (pe) throw pe; if (!profile) return res.status(404).json({ error: 'Profissional não encontrado.' });
    const [{ data: services }, { data: projects }] = await Promise.all([
      supabase.from('professional_services').select('cover_image').eq('professional_id', profile.id),
      supabase.from('professional_projects').select('images').eq('professional_id', profile.id)
    ]);
    if (profile.id_front_path) await deletePrivateIdentityUpload(profile.id_front_path);
    if (profile.id_back_path) await deletePrivateIdentityUpload(profile.id_back_path);
    if (profile.photo) await deleteUpload(profile.photo);
    if (profile.cv_url) await deleteUpload(profile.cv_url);
    for (const s of services || []) if (s.cover_image) await deleteUpload(s.cover_image);
    for (const pr of projects || []) for (const url of pr.images || []) await deleteUpload(url);
    await safeAuditLog({ target_type: 'professional', target_id: profile.id, action: 'account_deleted', reason: String(req.body?.reason || 'Conta excluída pela administração.'), metadata: { admin: true, email: profile.email, name: profile.name } });
    const { error } = await supabase.from('professional_users').delete().eq('id', profile.user_id);
    if (error) throw error;
    if (req.session.professionalId === profile.id) delete req.session.professionalId;
    res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao excluir profissional.' }); }
});


app.get('/api/admin/email-center', requireAuth, async (req, res) => {
  try {
    const [{ data: professionals, error: pe }, { data: logs, error: le }] = await Promise.all([
      supabase.from('professional_profiles').select('id,name,email,status,verification_status').order('name', { ascending: true }),
      supabase.from('admin_email_logs').select('*').order('created_at', { ascending: false }).limit(50)
    ]);
    if (pe) throw pe;
    const emailConfig = emailConfigState();
    res.json({ configured: emailConfig.configured, from: emailConfig.from || '', testMode: emailConfig.testMode, warning: emailConfig.warning || '', professionals: professionals || [], logs: le ? [] : (logs || []) });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao carregar centro de comunicação.' }); }
});
app.post('/api/admin/emails/send', requireAuth, async (req, res) => {
  try {
    const emailConfig = emailConfigState();
    if (!emailConfig.configured) return res.status(503).json({ error: emailConfig.warning || 'O envio de e-mail ainda não está configurado.' });
    const audience = String(req.body.audience || 'individual');
    if (emailConfig.testMode && audience === 'all') return res.status(400).json({ error: 'O remetente onboarding@resend.dev só pode enviar para o e-mail da conta Resend. Verifique um domínio próprio e altere EMAIL_FROM antes de enviar a todos.' });
    const professionalId = String(req.body.professional_id || '');
    const subject = String(req.body.subject || '').trim().slice(0, 160);
    const message = String(req.body.message || '').trim().slice(0, 5000);
    if (subject.length < 3 || message.length < 5) return res.status(400).json({ error: 'Informe assunto e mensagem.' });
    let q = supabase.from('professional_profiles').select('id,name,email,status').not('email','is',null).neq('email','');
    if (audience === 'individual') {
      if (!professionalId) return res.status(400).json({ error: 'Selecione um profissional.' });
      q = q.eq('id', professionalId);
    } else if (audience !== 'all') return res.status(400).json({ error: 'Público inválido.' });
    const { data: recipients, error } = await q.order('name', { ascending: true }); if (error) throw error;
    if (!recipients?.length) return res.status(404).json({ error: 'Nenhum destinatário encontrado.' });
    let sent = 0, failed = 0, errors = [];
    for (let i = 0; i < recipients.length; i += 5) {
      const batch = recipients.slice(i, i + 5);
      const results = await Promise.all(batch.map(p => notifyProfessional(p.id, 'admin_message', subject, message, '/profissional/dashboard', { sendEmail: true })));
      for (const r of results) { if (r.emailSent) sent++; else { failed++; if (r.emailError && errors.length < 3) errors.push(r.emailError); } }
      if (i + 5 < recipients.length) await new Promise(resolve => setTimeout(resolve, 350));
    }
    try { await supabase.from('admin_email_logs').insert({ id: crypto.randomUUID(), audience, professional_id: audience === 'individual' ? professionalId : null, subject, recipient_count: recipients.length, sent_count: sent, failed_count: failed, created_at: new Date().toISOString() }); } catch {}
    await safeAuditLog({ target_type: 'communication', target_id: audience === 'individual' ? professionalId : 'all', action: 'email_sent', reason: subject, metadata: { recipient_count: recipients.length, sent, failed } });
    res.json({ ok: true, recipients: recipients.length, sent, failed, errors });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao enviar e-mails.' }); }
});

app.get('/api/admin/analytics', requireAuth, async (req, res) => {
  try {
    const [{ data: profiles, error: pe }, { data: events, error: ee }, { data: ratings, error: re }, { data: reports, error: rpe }] = await Promise.all([
      supabase.from('professional_profiles').select('id,name,slug,status,verified,warning_count').order('created_at', { ascending: false }),
      supabase.from('professional_events').select('professional_id,event_type,visitor_hash'),
      supabase.from('professional_ratings').select('professional_id,stars,status'),
      supabase.from('professional_reports').select('professional_id,status')
    ]); if (pe) throw pe; if (ee) throw ee; if (re) throw re; if (rpe) throw rpe;
    const result = (profiles || []).map(p => {
      const ev = (events || []).filter(x=>x.professional_id===p.id), rr=(ratings||[]).filter(x=>x.professional_id===p.id&&x.status==='published'), rp=(reports||[]).filter(x=>x.professional_id===p.id&&x.status==='open');
      return { ...p, views: new Set(ev.filter(x=>x.event_type==='view').map(x=>x.visitor_hash)).size, contacts: new Set(ev.filter(x=>x.event_type==='contact').map(x=>x.visitor_hash)).size, ratingCount: rr.length, ratingAvg: rr.length ? rr.reduce((a,x)=>a+Number(x.stars||0),0)/rr.length : 0, openReports: rp.length };
    });
    res.json(result);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao carregar desempenho.' }); }
});
app.get('/api/admin/reports', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('professional_reports').select('*, professional_profiles(name,slug,status,warning_count)').order('created_at', { ascending: false });
    if (error) throw error; res.json(data || []);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao carregar denúncias.' }); }
});
app.post('/api/admin/reports/:id/action', requireAuth, async (req, res) => {
  try {
    const action = String(req.body.action || ''), reason = String(req.body.reason || '').trim();
    if (!['warn','suspend','dismiss','delete'].includes(action)) return res.status(400).json({ error: 'Ação inválida.' });
    const { data: report, error } = await supabase.from('professional_reports').select('*').eq('id', req.params.id).single(); if (error) throw error;
    const { data: profile, error: pe } = await supabase.from('professional_profiles').select('*').eq('id', report.professional_id).single(); if (pe) throw pe;
    if (action === 'warn') {
      const message = reason || 'A administração recebeu uma denúncia e emitiu uma advertência. Reveja os seus dados e práticas profissionais.';
      await supabase.from('professional_profiles').update({ warning_count: Number(profile.warning_count || 0) + 1, last_warning: message, updated_at: new Date().toISOString() }).eq('id', profile.id);
      await supabase.from('professional_reports').update({ status: 'actioned', admin_action: 'warn', reviewed_at: new Date().toISOString() }).eq('id', report.id);
      await safeAuditLog({ target_type: 'professional', target_id: profile.id, action: 'warning', reason: message, metadata: { report_id: report.id } });
      await notifyProfessional(profile.id, 'warning', 'Advertência da administração', message, '/profissional/dashboard', { sendEmail: true });
    } else if (action === 'suspend') {
      const days = Math.min(365, Math.max(1, Number(req.body.suspensionDays || 7))), until = new Date(Date.now()+days*86400000).toISOString();
      const previous = profile.status === 'suspended' ? (profile.pre_suspension_status || 'pending') : profile.status;
      await supabase.from('professional_profiles').update({ status: 'suspended', pre_suspension_status: previous, suspended_until: until, suspension_reason: reason || `Suspensão temporária por ${days} dia(s).`, updated_at: new Date().toISOString() }).eq('id', profile.id);
      await supabase.from('professional_reports').update({ status: 'actioned', admin_action: `suspend_${days}d`, reviewed_at: new Date().toISOString() }).eq('id', report.id);
      await safeAuditLog({ target_type: 'professional', target_id: profile.id, action: `suspend_${days}d`, reason: reason || 'Suspensão após denúncia.', metadata: { report_id: report.id, suspended_until: until } });
      await notifyProfessional(profile.id, 'suspension', 'Conta suspensa temporariamente', reason || `A sua conta foi suspensa por ${days} dia(s).`, '/profissional/dashboard', { sendEmail: true });
    } else if (action === 'dismiss') {
      await supabase.from('professional_reports').update({ status: 'dismissed', admin_action: 'dismiss', reviewed_at: new Date().toISOString() }).eq('id', report.id);
      await safeAuditLog({ target_type: 'professional', target_id: profile.id, action: 'report_dismissed', reason: reason || 'Denúncia arquivada sem ação disciplinar.', metadata: { report_id: report.id } });
    } else if (action === 'delete') {
      if (profile.id_front_path) await deletePrivateIdentityUpload(profile.id_front_path);
      if (profile.id_back_path) await deletePrivateIdentityUpload(profile.id_back_path);
      await supabase.from('professional_reports').update({ status: 'actioned', admin_action: 'delete', reviewed_at: new Date().toISOString() }).eq('id', report.id);
      await safeAuditLog({ target_type: 'professional', target_id: profile.id, action: 'account_deleted', reason: reason || 'Conta excluída após análise de denúncia.', metadata: { report_id: report.id } });
      await supabase.from('professional_users').delete().eq('id', profile.user_id);
    }
    res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao aplicar ação.' }); }
});

app.get('/api/admin/password-reset-requests', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('password_reset_requests').select('*, professional_profiles(name,slug,user_id)').order('created_at', { ascending: false });
    if (error) throw error; res.json(data || []);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao carregar pedidos de recuperação.' }); }
});
app.post('/api/admin/password-reset-requests/:id/reset', requireAuth, async (req, res) => {
  try {
    const { data: request, error } = await supabase.from('password_reset_requests').select('*, professional_profiles(user_id,name)').eq('id', req.params.id).eq('status','pending').maybeSingle();
    if (error) throw error; if (!request) return res.status(404).json({ error: 'Pedido pendente não encontrado.' });
    const temporaryPassword = `${crypto.randomBytes(18).toString('base64url')}A7!`;
    const { error: ue } = await supabase.from('professional_users').update({ password_hash: hashPassword(temporaryPassword), password_change_required: true, updated_at: new Date().toISOString() }).eq('id', request.professional_profiles.user_id); if (ue) throw ue;
    await revokeSessions('professionalId', request.professional_id);
    await supabase.from('password_reset_requests').update({ status: 'resolved', resolved_at: new Date().toISOString(), used_at: new Date().toISOString(), token_hash: '' }).eq('id', request.id);
    res.json({ ok: true, temporaryPassword, name: request.professional_profiles.name });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao redefinir senha.' }); }
});
app.post('/api/admin/password-reset-requests/:id/reject', requireAuth, async (req, res) => {
  try { const { error } = await supabase.from('password_reset_requests').update({ status: 'rejected', resolved_at: new Date().toISOString() }).eq('id', req.params.id); if (error) throw error; res.json({ ok: true }); }
  catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao rejeitar pedido.' }); }
});


// ============================================================
// V7.0 — CONFIANÇA, DESCOBERTA, NOTIFICAÇÕES, SEO E SEGURANÇA
// ============================================================
app.get('/api/categories', async (_, res) => {
  try {
    const site=await readData(),rows=[],projectRows=[];
    for(let offset=0;;offset+=1000){const {data,error}=await supabase.from('professional_services').select('category').eq('status','approved').order('id').range(offset,offset+999);if(error)throw error;rows.push(...data);if(data.length<1000)break}
    for(let offset=0;;offset+=1000){const {data,error}=await supabase.from('professional_projects').select('id,category,professional_services(category),professional_profiles!inner(status)').eq('status','approved').eq('professional_profiles.status','approved').order('id').range(offset,offset+999);if(error)throw error;projectRows.push(...data);if(data.length<1000)break}
    const counts=new Map(); for(const r of rows||[]){const n=String(r.category||'').trim();if(n)counts.set(normalizeSearchText(n),(counts.get(normalizeSearchText(n))||0)+1)}
    const projectCounts=new Map();for(const r of projectRows||[]){const n=normalizeSearchText(r.category||r.professional_services?.category);if(n)projectCounts.set(n,(projectCounts.get(n)||0)+1)}
    for(const project of site.portfolio||[]){if(project.featured===false)continue;const n=normalizeSearchText(project.service);if(n)projectCounts.set(n,(projectCounts.get(n)||0)+1)}
    const managed=(site.categories||DEFAULT_CATEGORIES).filter(c=>c.active!==false).map(c=>({id:c.id,name:c.name,keywords:c.keywords||'',description:c.description||'',count:counts.get(normalizeSearchText(c.name))||0,projectCount:projectCounts.get(normalizeSearchText(c.name))||0,slug:slugify(c.name)}));
    res.json(managed.sort((a,b)=>a.name.localeCompare(b.name,'pt')));
  } catch (error) { console.error(error); res.status(500).json({ error:'Erro ao carregar categorias.' }); }
});
app.post('/api/admin/categories', requireAuth, async (req,res)=>{try{const data=await readData();data.categories||=[];const name=String(req.body.name||'').trim();if(name.length<2)return res.status(400).json({error:'Informe o nome da categoria.'});if(data.categories.some(c=>normalizeSearchText(c.name)===normalizeSearchText(name)))return res.status(409).json({error:'Esta categoria já existe.'});const item={id:uid('cat'),name,keywords:String(req.body.keywords||'').trim().slice(0,1500),description:String(req.body.description||'').trim().slice(0,600),active:req.body.active!==false&&String(req.body.active)!=='false'};data.categories.push(item);await writeData(data);res.json(item)}catch(error){console.error(error);res.status(500).json({error:'Erro ao criar categoria.'})}});
app.put('/api/admin/categories/:id', requireAuth, async (req,res)=>{
  try {
    const data=await readData(),i=(data.categories||[]).findIndex(c=>c.id===req.params.id);
    if(i<0)return res.status(404).json({error:'Categoria não encontrada.'});
    const oldName=data.categories[i].name,name=String(req.body.name??oldName).trim();
    if(name.length<2)return res.status(400).json({error:'Informe o nome da categoria.'});
    if(data.categories.some((c,index)=>index!==i&&normalizeSearchText(c.name)===normalizeSearchText(name)))
      return res.status(409).json({error:'Esta categoria já existe.'});
    const renamed=normalizeSearchText(oldName)!==normalizeSearchText(name);
    if(renamed&&USE_SUPABASE){
      const {error:projectError}=await supabase.from('professional_projects').update({category:name}).eq('category',oldName);
      if(projectError)throw projectError;
      const {error:serviceError}=await supabase.from('professional_services').update({category:name}).eq('category',oldName);
      if(serviceError)throw serviceError;
    }
    if(renamed)for(const service of data.services||[])if(normalizeSearchText(service.title)===normalizeSearchText(oldName))service.title=name;
    if(renamed)for(const project of data.portfolio||[])if(normalizeSearchText(project.service)===normalizeSearchText(oldName))project.service=name;
    data.categories[i]={...data.categories[i],name,keywords:String(req.body.keywords??data.categories[i].keywords??'').trim().slice(0,1500),description:String(req.body.description??data.categories[i].description??'').trim().slice(0,600),active:req.body.active===undefined?data.categories[i].active:!(req.body.active===false||String(req.body.active).toLowerCase()==='false')};
    await writeData(data);res.json(data.categories[i]);
  }catch(error){console.error(error);res.status(500).json({error:'Erro ao atualizar categoria.'})}
});
app.delete('/api/admin/categories/:id', requireAuth, async (req,res)=>{try{const data=await readData();const cat=(data.categories||[]).find(c=>c.id===req.params.id);if(!cat)return res.status(404).json({error:'Categoria não encontrada.'});const {count,error}=await supabase.from('professional_services').select('*',{count:'exact',head:true}).eq('category',cat.name);if(error)throw error;if(count>0)return res.status(409).json({error:'Esta categoria está em uso por serviços profissionais. Desative-a ou mova os serviços antes de remover.'});const {count:projectCount,error:projectError}=await supabase.from('professional_projects').select('*',{count:'exact',head:true}).eq('category',cat.name);if(projectError)throw projectError;if(projectCount>0)return res.status(409).json({error:'Esta categoria está em uso por projetos. Desative-a ou mova os projetos antes de remover.'});data.categories=data.categories.filter(c=>c.id!==req.params.id);await writeData(data);res.json({ok:true})}catch(error){console.error(error);res.status(500).json({error:'Erro ao remover categoria.'})}});
app.post('/api/admin/location-aliases', requireAuth, async (req,res)=>{try{const data=await readData();data.locationAliases||=[];const neighborhood=String(req.body.neighborhood||'').trim(),district=String(req.body.district||'').trim(),province=String(req.body.province||'').trim(),alias=String(req.body.alias||'').trim();if(!neighborhood||!district)return res.status(400).json({error:'Informe pelo menos o bairro/localidade e o distrito.'});const item={id:uid('loc'),neighborhood,alias,district,province};data.locationAliases.push(item);await writeData(data);res.json(item)}catch(error){console.error(error);res.status(500).json({error:'Erro ao adicionar localidade.'})}});
app.put('/api/admin/location-aliases/:id', requireAuth, async (req,res)=>{try{const data=await readData(),i=(data.locationAliases||[]).findIndex(x=>x.id===req.params.id);if(i<0)return res.status(404).json({error:'Localidade não encontrada.'});const next={...data.locationAliases[i],neighborhood:String(req.body.neighborhood ?? data.locationAliases[i].neighborhood ?? '').trim(),alias:String(req.body.alias ?? data.locationAliases[i].alias ?? '').trim(),district:String(req.body.district ?? data.locationAliases[i].district ?? '').trim(),province:String(req.body.province ?? data.locationAliases[i].province ?? '').trim()};if(!next.neighborhood||!next.district)return res.status(400).json({error:'Bairro/localidade e distrito são obrigatórios.'});data.locationAliases[i]=next;await writeData(data);res.json(next)}catch(error){console.error(error);res.status(500).json({error:'Erro ao atualizar localidade.'})}});
app.delete('/api/admin/location-aliases/:id', requireAuth, async (req,res)=>{try{const data=await readData();const before=(data.locationAliases||[]).length;data.locationAliases=(data.locationAliases||[]).filter(x=>x.id!==req.params.id);if(data.locationAliases.length===before)return res.status(404).json({error:'Localidade não encontrada.'});await writeData(data);res.json({ok:true})}catch(error){console.error(error);res.status(500).json({error:'Erro ao remover localidade.'})}});

function siteServiceMatchesCategory(siteService, category) {
  const title = normalizeSearchText(siteService?.title), name = normalizeSearchText(category);
  return Boolean(title && name && (title === name || name.startsWith(`${title} `)));
}
function findPublicServiceArea(site,id) {
  const configured=(site.services||[]).find(s=>String(s.id)===String(id));
  if(configured)return configured;
  const category=(site.categories||DEFAULT_CATEGORIES).find(c=>c.active!==false&&slugify(c.name)===String(id));
  if(!category)return null;
  const matchingService=(site.services||[]).find(s=>normalizeSearchText(s.title)===normalizeSearchText(category.name));
  if(matchingService)return matchingService;
  return {id:slugify(category.name),title:category.name,description:category.description||`Encontre profissionais de ${category.name} e conheça os projetos publicados nesta área.`,details:category.description||'',color:'#00c994',iconClass:'bi-briefcase'};
}
async function publishedProjectCountsBySiteService(site) {
  const areas = (site.services || []).filter(s => s.title && s.title !== 'Novo serviço');
  const counts = Object.fromEntries(areas.map(s => [s.id, 0]));
  for (const project of site.portfolio || []) {
    if (project.featured === false) continue;
    const area = areas.find(s => normalizeSearchText(s.title) === normalizeSearchText(project.service));
    if (area) counts[area.id]++;
  }
  // A paginação evita que o limite padrão de linhas do Supabase corte a contagem.
  for (let offset = 0; ; offset += 1000) {
    const { data, error } = await supabase.from('professional_projects')
      .select('id,category,professional_services(category),professional_profiles!inner(status)')
      .eq('status', 'approved')
      .eq('professional_profiles.status', 'approved').order('id').range(offset, offset + 999);
    if (error) throw error;
    for (const project of data || []) {
      const area = areas.find(s => siteServiceMatchesCategory(s, project.category || project.professional_services?.category));
      if (area) counts[area.id]++;
    }
    if ((data || []).length < 1000) break;
  }
  return counts;
}
app.get('/api/platform-summary', async (_, res) => {
  try {
    const [{ count: professionals }, { count: services }, { count: projects }, { data: ratings }] = await Promise.all([
      supabase.from('professional_profiles').select('*',{count:'exact',head:true}).eq('status','approved'),
      supabase.from('professional_services').select('*',{count:'exact',head:true}).eq('status','approved'),
      supabase.from('professional_projects').select('*',{count:'exact',head:true}).eq('status','approved'),
      supabase.from('professional_ratings').select('stars').eq('status','published')
    ]);
    const avg = ratings?.length ? ratings.reduce((a,x)=>a+Number(x.stars||0),0)/ratings.length : 0;
    let projectCounts = null, serviceAreas = services || 0, projectTotal = projects || 0;
    try {
      const site=await readData();
      projectCounts=await publishedProjectCountsBySiteService(site);
      projectTotal+=(site.portfolio||[]).filter(p=>p.featured!==false).length;
      const active=(site.categories||DEFAULT_CATEGORIES).filter(c=>c.active!==false);
      serviceAreas=active.length+(site.services||[]).filter(s=>s.title&&s.title!=='Novo serviço'&&!active.some(c=>normalizeSearchText(c.name)===normalizeSearchText(s.title))).length;
    }
    catch (error) { console.error('Erro ao contar projetos por serviço:', error); }
    res.json({ professionals:professionals||0, services:serviceAreas, projects:projectTotal, projectCounts, ratingAvg:avg, ratingCount:ratings?.length||0 });
  } catch (error) { console.error(error); res.json({ professionals:0,services:0,projects:0,projectCounts:null,ratingAvg:0,ratingCount:0 }); }
});

app.get('/api/featured-professionals', async (_, res) => {
  try {
    const { data: profiles, error } = await supabase.from('professional_profiles').select('id,name,slug,photo,specialty,headline,location,province,district,neighborhood,verified,verification_status,years_experience,availability,profile_completeness,profile_type,institutional_role,official_profile').eq('status','approved').eq('featured',true).order('updated_at',{ascending:false}).limit(8);
    if (error) throw error;
    const ids=(profiles||[]).map(x=>x.id);
    let ratings=[];
    if(ids.length){ const rr=await supabase.from('professional_ratings').select('professional_id,stars').in('professional_id',ids).eq('status','published'); if(rr.error)throw rr.error; ratings=rr.data||[]; }
    res.json((profiles||[]).map(p=>{const r=ratings.filter(x=>x.professional_id===p.id);return {...p,verified:Boolean(p.verified&&p.verification_status==='approved'),identityValidated:p.verification_status==='approved',verification_status:undefined,ratingAvg:r.length?r.reduce((a,x)=>a+Number(x.stars||0),0)/r.length:0,ratingCount:r.length};}));
  } catch (error) { console.error(error); res.json([]); }
});

app.get('/api/professionals/:slug/services/:serviceSlug', async (req,res)=>{
  try{
    const {data:profile,error:pe}=await supabase.from('professional_profiles').select('id,name,slug,photo,specialty,headline,location,province,district,neighborhood,whatsapp,phone,email,verified,verification_status,years_experience,service_area,availability,response_time_label,profile_type,institutional_role,official_profile,created_at').eq('slug',req.params.slug).eq('status','approved').maybeSingle();
    if(pe)throw pe;if(!profile)return res.status(404).json({error:'Profissional não encontrado.'});
    const {data:service,error:se}=await supabase.from('professional_services').select('*').eq('professional_id',profile.id).eq('slug',req.params.serviceSlug).eq('status','approved').maybeSingle();
    if(se)throw se;if(!service)return res.status(404).json({error:'Serviço não encontrado.'});
    const [{data:ratings,error:re},{data:projects,error:pre}]=await Promise.all([
      supabase.from('professional_ratings').select('id,stars,comment,professional_reply,replied_at,verified_interaction,created_at').eq('professional_id',profile.id).eq('service_id',service.id).eq('status','published').order('created_at',{ascending:false}),
      supabase.from('professional_projects').select('id,title,slug,description,images,project_url').eq('professional_id',profile.id).eq('service_id',service.id).eq('status','approved').order('created_at',{ascending:false})
    ]);if(re)throw re;if(pre)throw pre;
    await recordProfessionalEvent(req,profile.id,'service_view',{serviceId:service.id,scopeKey:service.id});
    const avg=ratings?.length?ratings.reduce((a,x)=>a+Number(x.stars||0),0)/ratings.length:0;
    const publicProfile={...profile,verified:Boolean(profile.verified&&profile.verification_status==='approved'),identityValidated:profile.verification_status==='approved'};delete publicProfile.verification_status;
    res.json({profile:publicProfile,service,projects:projects||[],rating:{average:avg,count:ratings?.length||0,reviews:ratings||[]}});
  }catch(error){console.error(error);res.status(500).json({error:'Erro ao carregar serviço.'});}
});

app.get('/api/professional/notifications', requireProfessional, async(req,res)=>{
  try{const {data,error}=await supabase.from('professional_notifications').select('*').eq('professional_id',req.session.professionalId).order('created_at',{ascending:false}).limit(100);if(error)throw error;res.json(data||[])}catch(error){console.error(error);res.status(500).json({error:'Erro ao carregar notificações.'})}
});
app.patch('/api/professional/notifications/:id/read', requireProfessional, async(req,res)=>{
  try{const {error}=await supabase.from('professional_notifications').update({read_at:new Date().toISOString()}).eq('id',req.params.id).eq('professional_id',req.session.professionalId);if(error)throw error;res.json({ok:true})}catch(error){console.error(error);res.status(500).json({error:'Erro ao marcar notificação.'})}
});
app.post('/api/professional/notifications/read-all', requireProfessional, async(req,res)=>{
  try{const {error}=await supabase.from('professional_notifications').update({read_at:new Date().toISOString()}).eq('professional_id',req.session.professionalId).is('read_at',null);if(error)throw error;res.json({ok:true})}catch(error){console.error(error);res.status(500).json({error:'Erro ao atualizar notificações.'})}
});
app.post('/api/professional/ratings/:id/reply', requireProfessional, async(req,res)=>{
  try{const reply=String(req.body.reply||'').trim().slice(0,1200);if(!reply)return res.status(400).json({error:'Escreva uma resposta.'});const {data,error}=await supabase.from('professional_ratings').update({professional_reply:reply,replied_at:new Date().toISOString(),updated_at:new Date().toISOString()}).eq('id',req.params.id).eq('professional_id',req.session.professionalId).eq('status','published').select('id').maybeSingle();if(error)throw error;if(!data)return res.status(404).json({error:'Avaliação não encontrada.'});res.json({ok:true})}catch(error){console.error(error);res.status(500).json({error:'Erro ao responder avaliação.'})}
});

app.get('/api/admin/ratings', requireAuth, async(_,res)=>{
  try{const {data,error}=await supabase.from('professional_ratings').select('*,professional_profiles(name,slug),professional_services(title)').order('created_at',{ascending:false});if(error)throw error;res.json(data||[])}catch(error){console.error(error);res.status(500).json({error:'Erro ao carregar avaliações.'})}
});
app.patch('/api/admin/ratings/:id/status', requireAuth, async(req,res)=>{
  try{const status=String(req.body.status||'');if(!['published','hidden'].includes(status))return res.status(400).json({error:'Estado inválido.'});const {data,error}=await supabase.from('professional_ratings').update({status,updated_at:new Date().toISOString()}).eq('id',req.params.id).select('professional_id').maybeSingle();if(error)throw error;if(!data)return res.status(404).json({error:'Avaliação não encontrada.'});await safeAuditLog({target_type:'rating',target_id:req.params.id,action:status,reason:String(req.body.reason||''),metadata:{admin:true}});res.json({ok:true})}catch(error){console.error(error);res.status(500).json({error:'Erro ao moderar avaliação.'})}
});
app.get('/api/admin/audit', requireAuth, async(_,res)=>{
  try{const {data,error}=await supabase.from('moderation_logs').select('*').order('created_at',{ascending:false}).limit(300);if(error)throw error;res.json(data||[])}catch(error){console.error(error);res.status(500).json({error:'Erro ao carregar auditoria.'})}
});
app.get('/api/admin/analytics/summary', requireAuth, async(_,res)=>{
  try{
    const since=new Date(Date.now()-30*86400000).toISOString();
    const [{count:pendingProfiles},{count:pendingServices},{count:pendingProjects},{count:openReports},{data:events},{data:services},{data:searches}]=await Promise.all([
      supabase.from('professional_profiles').select('*',{count:'exact',head:true}).eq('status','pending'),
      supabase.from('professional_services').select('*',{count:'exact',head:true}).eq('status','pending'),
      supabase.from('professional_projects').select('*',{count:'exact',head:true}).eq('status','pending'),
      supabase.from('professional_reports').select('*',{count:'exact',head:true}).eq('status','open'),
      supabase.from('professional_events').select('event_type,created_at').gte('created_at',since),
      supabase.from('professional_services').select('category').eq('status','approved'),
      supabase.from('search_analytics').select('query_text,category,location_query,result_count,created_at').gte('created_at',since).order('created_at',{ascending:false}).limit(1000)
    ]);
    const cats={};for(const x of services||[]){const c=String(x.category||'Outros').trim()||'Outros';cats[c]=(cats[c]||0)+1}
    const queryCounts={};for(const x of searches||[]){const q=String(x.query_text||x.category||x.location_query||'').trim();if(q)queryCounts[q]=(queryCounts[q]||0)+1}
    const topSearches=Object.entries(queryCounts).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([term,count])=>({term,count}));
    const noResultSearches=(searches||[]).filter(x=>Number(x.result_count||0)===0).slice(0,12);
    res.json({pendingProfiles:pendingProfiles||0,pendingServices:pendingServices||0,pendingProjects:pendingProjects||0,openReports:openReports||0,views30:(events||[]).filter(x=>x.event_type==='view').length,contacts30:(events||[]).filter(x=>x.event_type==='contact').length,searches30:(searches||[]).length,topSearches,noResultSearches,topCategories:Object.entries(cats).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([name,count])=>({name,count}))});
  }catch(error){console.error(error);res.status(500).json({error:'Erro ao carregar resumo.'})}
});

app.get('/api/admin/2fa/status', requireAuth, async(_,res)=>{try{const d=await readData();res.json({enabled:!!d._admin?.totpEnabled})}catch(e){res.status(500).json({error:'Erro ao verificar 2FA.'})}});
app.post('/api/admin/2fa/setup', requireAuth, async(req,res)=>{
  try{
    if (IS_PRODUCTION && !TOTP_ENCRYPTION_KEY_CONFIGURED) return res.status(503).json({error:'Configure TOTP_ENCRYPTION_KEY no Render antes de ativar a autenticação em dois fatores.'});
    const d=await readData();const secret=authenticator.generateSecret();d._admin||={};d._admin.totpPendingEncrypted=encryptSecret(secret);await writeData(d);const label=encodeURIComponent('Yuran Multicerviços Admin');const issuer=encodeURIComponent('Yuran Multicerviços');res.json({secret,otpauthUrl:`otpauth://totp/${label}?secret=${secret}&issuer=${issuer}`})}catch(error){console.error(error);res.status(500).json({error:'Erro ao preparar 2FA.'})}
});
app.post('/api/admin/2fa/enable', requireAuth, async(req,res)=>{
  try{const d=await readData();const secret=decryptSecret(d._admin?.totpPendingEncrypted||'');const token=String(req.body.token||'').replace(/\s/g,'');if(!verifyTotpToken(token,secret))return res.status(400).json({error:'Código inválido. Confirme o código atual do autenticador e a hora automática do telefone.'});d._admin.totpSecretEncrypted=encryptSecret(secret);d._admin.totpEnabled=true;delete d._admin.totpPendingEncrypted;await writeData(d);res.json({ok:true})}catch(error){console.error(error);res.status(500).json({error:'Erro ao ativar 2FA.'})}
});
app.post('/api/admin/2fa/disable', requireAuth, async(req,res)=>{
  try{if(!(await validAdminPassword(req.body.password)))return res.status(401).json({error:'Senha incorreta.'});const d=await readData();const secret=decryptSecret(d._admin?.totpSecretEncrypted||'');if(secret&&!verifyTotpToken(String(req.body.token||'').replace(/\s/g,''),secret))return res.status(401).json({error:'Código 2FA inválido.'});d._admin.totpEnabled=false;delete d._admin.totpSecretEncrypted;delete d._admin.totpPendingEncrypted;await writeData(d);res.json({ok:true})}catch(error){console.error(error);res.status(500).json({error:'Erro ao desativar 2FA.'})}
});
app.post('/api/admin/purge-expired-identities', requireAuth, async(_,res)=>{try{await purgeExpiredIdentityDocuments();res.json({ok:true})}catch(error){console.error(error);res.status(500).json({error:'Erro ao eliminar documentos expirados.'})}});

app.get('/sitemap.xml', async(req,res)=>{
  const base=baseUrl(req);
  const staticPaths=['/','/servicos','/profissionais','/categorias','/como-funciona','/ajuda','/planos','/politica-de-privacidade','/termos-de-uso'];
  const urls=staticPaths.map(route=>({loc:base+route}));
  // O sitemap principal tem de continuar disponível durante falhas ou lentidão da base de dados.
  // As páginas dinâmicas são acrescentadas quando as consultas terminam dentro do prazo.
  let deadline;
  try {
    const queries=USE_SUPABASE ? [
      supabase.from('professional_profiles').select('slug,updated_at').eq('status','approved'),
      supabase.from('professional_services').select('slug,updated_at,professional_profiles!inner(slug,status)').eq('status','approved').eq('professional_profiles.status','approved'),
      readData()
    ] : [readData()];
    const results=await Promise.race([
      Promise.allSettled(queries),
      new Promise(resolve=>{deadline=setTimeout(()=>resolve([]),4000)})
    ]);
    if(!results.length)console.warn('Sitemap: consultas excederam o prazo; a servir páginas principais.');
    const [profileResult,serviceResult,siteResult]=USE_SUPABASE ? results : [null,null,results[0]];
    const profiles=profileResult?.status==='fulfilled' && !profileResult.value.error ? profileResult.value.data||[] : [];
    const services=serviceResult?.status==='fulfilled' && !serviceResult.value.error ? serviceResult.value.data||[] : [];
    const site=siteResult?.status==='fulfilled' ? siteResult.value : null;
    if(profileResult?.status==='rejected'||profileResult?.value?.error||serviceResult?.status==='rejected'||serviceResult?.value?.error)
      console.warn('Sitemap: consulta dinâmica indisponível; a servir URLs disponíveis.');
    for(const item of site?.services||[])if(item?.id)urls.push({loc:`${base}/servico/${encodeURIComponent(item.id)}`});
    for(const item of profiles)if(item?.slug)urls.push({loc:`${base}/profissional/${encodeURIComponent(item.slug)}`,lastmod:item.updated_at});
    for(const item of services)if(item?.slug&&item.professional_profiles?.slug)
      urls.push({loc:`${base}/profissional/${encodeURIComponent(item.professional_profiles.slug)}/servico/${encodeURIComponent(item.slug)}`,lastmod:item.updated_at});
  } catch(error) {
    console.error('Sitemap: falha ao adicionar páginas dinâmicas:',error);
  } finally {
    clearTimeout(deadline);
  }
  const xmlEscape=value=>String(value).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const xml=`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls.map(item=>{
    const timestamp=item.lastmod&&new Date(item.lastmod);
    const lastmod=timestamp&&!Number.isNaN(timestamp.getTime())?`<lastmod>${timestamp.toISOString()}</lastmod>`:'';
    return `<url><loc>${xmlEscape(item.loc)}</loc>${lastmod}</url>`;
  }).join('')}</urlset>`;
  res.set('Cache-Control','public, max-age=300').type('application/xml').send(xml);
});
app.get('/robots.txt',(req,res)=>res.type('text/plain').send(`User-agent: *\nAllow: /\nDisallow: /admin/\nDisallow: /api/\nDisallow: /profissional/dashboard\nDisallow: /profissional/google-callback\nSitemap: ${baseUrl(req)}/sitemap.xml\n`));
app.get('/llms.txt',async(req,res)=>{
  try{const site=await readData();const cats=(site.categories||[]).filter(x=>x.active!==false).map(x=>x.name).join(', ');res.type('text/plain; charset=utf-8').send(`# ${site.settings?.siteName||'Yuran Multicerviços'}\n\n> Plataforma para descobrir profissionais e serviços em Moçambique.\n\n## Páginas principais\n- ${baseUrl(req)}/profissionais — diretório público de profissionais aprovados\n- ${baseUrl(req)}/categorias — categorias de serviços\n- ${baseUrl(req)}/como-funciona — funcionamento, moderação e confiança\n- ${baseUrl(req)}/ajuda — ajuda e orientações\n\n## Categorias\n${cats||'Consulte /categorias para a lista atual.'}\n\n## Regras\nPerfis e serviços públicos passam por moderação. Áreas administrativas, dashboards, APIs privadas e documentos de identidade não são conteúdo público.`)}catch(error){console.error(error);res.status(500).send('')}
});

app.get('/categorias',(req,res)=>sendSeoHtml(req,res,'categories.html',{title:'Categorias de serviços | Yuran Multicerviços',description:'Explore categorias de serviços e encontre profissionais por área de atuação na Yuran Multicerviços.'}));
app.get('/como-funciona',(req,res)=>sendSeoHtml(req,res,'how-it-works.html',{title:'Como funciona | Yuran Multicerviços',description:'Saiba como pesquisar profissionais, publicar serviços e como funcionam a verificação, moderação e segurança na Yuran Multicerviços.'}));
app.get('/ajuda',(req,res)=>sendSeoHtml(req,res,'help.html',{title:'Ajuda | Yuran Multicerviços',description:'Central de ajuda da Yuran Multicerviços para visitantes e profissionais.'}));
app.get('/politica-de-privacidade',(req,res)=>sendSeoHtml(req,res,'privacy.html',{title:'Política de Privacidade | Yuran Multicerviços',description:'Saiba como a Yuran Multicerviços trata dados pessoais, documentos de identidade e informações de utilização.'}));
app.get('/termos-de-uso',(req,res)=>sendSeoHtml(req,res,'terms.html',{title:'Termos de Uso | Yuran Multicerviços',description:'Termos de uso, regras de publicação, moderação e responsabilidades na Yuran Multicerviços.'}));
app.get('/profissional/:slug/servico/:serviceSlug',async(req,res)=>{
  try{
    const {data:p,error:pe}=await supabase.from('professional_profiles').select('id,name,slug,photo,specialty,location,province,district,neighborhood').eq('slug',req.params.slug).eq('status','approved').maybeSingle();
    if(pe)throw pe;if(!p)return res.status(404).send('Profissional não encontrado.');
    const {data:service,error:se}=await supabase.from('professional_services').select('title,slug,category,description,keywords,service_area,price_mode,price_amount,cover_image').eq('professional_id',p.id).eq('slug',req.params.serviceSlug).eq('status','approved').maybeSingle();
    if(se)throw se;if(!service)return res.status(404).send('Serviço não encontrado.');
    const canonical=`${baseUrl(req)}/profissional/${encodeURIComponent(p.slug)}/servico/${encodeURIComponent(service.slug)}`;
    const description=cleanSeoText(service.description||`${service.title} por ${p.name}. ${service.service_area||p.location||''}`,175);
    const schema={'@context':'https://schema.org','@type':'Service',name:service.title,description,url:canonical,areaServed:service.service_area||p.district||p.province||p.location||undefined,provider:{'@type':'Person',name:p.name,url:`${baseUrl(req)}/profissional/${encodeURIComponent(p.slug)}`}};
    return sendSeoHtml(req,res,'professional-service.html',{title:`${service.title} — ${p.name} | Yuran Multicerviços`,description,canonical,image:service.cover_image||p.photo,schema});
  }catch(error){console.error(error);res.status(500).send('Não foi possível carregar o serviço.')}
});

if (USE_SUPABASE) {
  setInterval(()=>require('./scripts/migrate-private-files.cjs').drainQueue().catch(e=>console.error('Limpeza de mídia pública:',e)),60*1000).unref();
  setInterval(()=>purgeExpiredIdentityDocuments().catch(()=>{}),6*60*60*1000).unref();
  setInterval(()=>releaseExpiredSuspensions().catch(()=>{}),60*60*1000).unref();
  setInterval(()=>supabase.from('app_sessions').delete().lt('expire',new Date().toISOString()).then(()=>{}).catch(()=>{}),6*60*60*1000).unref();
  setInterval(()=>supabase.from('security_rate_limits').delete().lt('reset_at',new Date(Date.now()-86400000).toISOString()).then(()=>{}).catch(()=>{}),6*60*60*1000).unref();
}

app.get('/health', (_, res) => res.json({ ok: true }));
app.use((error, _req, res, _next) => {
  if (error instanceof multer.MulterError) return res.status(400).json({ error: error.code === 'LIMIT_FILE_SIZE' ? 'O ficheiro excede o tamanho permitido.' : 'O envio contém demasiados ficheiros ou campos.' });
  console.error('Erro no processamento do pedido:', error);
  res.status(500).json({ error: 'Não foi possível processar o pedido.' });
});
async function startServer() {
  if (IS_PRODUCTION && (!SESSION_SECRET_CONFIGURED || SESSION_SECRET.length < 32))
    throw new Error('Configure SESSION_SECRET independente, aleatória e com pelo menos 32 caracteres antes do deploy.');
  if (USE_SUPABASE) {
    const { data: bucket, error: bucketError } = await supabase.storage.getBucket(VERIFICATION_BUCKET);
    if (bucketError || !bucket || bucket.public !== false) throw new Error('Bucket de documentos privados inexistente ou público. Verifique a migração v7.9.0.');
    const { error: limiterError } = await supabase.rpc('security_rate_check', { p_key: crypto.randomBytes(32).toString('hex'), p_limit: 1, p_window_seconds: 1 });
    if (limiterError) throw new Error('Migração de limitação de tráfego v7.9.0 ausente.');
    const { error: metricsError } = await supabase.rpc('professional_event_metrics', { p_professional_id: crypto.randomUUID() });
    if (metricsError) throw new Error('Migração de métricas v7.9.0 ausente.');
    const { data: legacyFiles, error: legacyError } = await supabase.rpc('security_private_media_pending');
    if (legacyError) throw new Error('Migração de ficheiros privados v7.9.0 ausente.');
    if (Number(legacyFiles?.public_cvs || 0) || Number(legacyFiles?.public_cv_objects || 0) || Number(legacyFiles?.pending_public_images || 0) || Number(legacyFiles?.queued_cleanup || 0)) {
      console.log('A migrar currículos e imagens pendentes para armazenamento privado antes de iniciar o site.');
      await require('./scripts/migrate-private-files.cjs').main({ apply: true });
      const { data: remaining, error: checkError } = await supabase.rpc('security_private_media_pending');
      if (checkError || Number(remaining?.public_cvs || 0) || Number(remaining?.public_cv_objects || 0) || Number(remaining?.pending_public_images || 0) || Number(remaining?.queued_cleanup || 0))
        throw new Error('Migração de ficheiros privados incompleta; consulte os logs.');
    }
  }
  app.listen(PORT, () => { console.log(`Site disponível na porta ${PORT}`); });
}
if (require.main === module) startServer().catch(error => { console.error('Início bloqueado por configuração insegura:', error); process.exitCode = 1; });
module.exports = { app, startServer };
