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

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'mudar-esta-senha';
const ADMIN_RECOVERY_KEY = process.env.ADMIN_RECOVERY_KEY || '';
const SESSION_SECRET = process.env.SESSION_SECRET || 'troque-esta-chave-em-producao';
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_KEY || '';
const STORAGE_BUCKET = process.env.SUPABASE_STORAGE_BUCKET || 'uploads';
const VERIFICATION_BUCKET = process.env.SUPABASE_VERIFICATION_BUCKET || 'verification-documents';
const PUBLIC_BASE_URL = String(process.env.PUBLIC_BASE_URL || '').replace(/\/$/, '');
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const EMAIL_FROM = process.env.EMAIL_FROM || '';
const IDENTITY_RETENTION_DAYS = Math.min(365, Math.max(1, Number(process.env.IDENTITY_RETENTION_DAYS || 30)));
const IS_PRODUCTION = process.env.NODE_ENV === 'production' || process.env.RENDER === 'true';
const USE_SUPABASE = Boolean(SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY);
const ALLOW_LOCAL_STORAGE = process.env.ALLOW_LOCAL_STORAGE === 'true';

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
const CV_DIR = path.join(__dirname, 'public', 'uploads', 'cvs');
[IMAGE_DIR, CV_DIR].forEach(dir => fs.mkdirSync(dir, { recursive: true }));

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
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
      imgSrc: ["'self'", 'data:', 'blob:', 'https:'],
      fontSrc: ["'self'", 'data:', 'https://cdn.jsdelivr.net'],
      connectSrc: cspConnect,
      frameSrc: ["'self'", 'https:'],
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

const sessionStore = USE_SUPABASE ? new SupabaseSessionStore(supabase) : undefined;
app.use(session({
  store: sessionStore,
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: { httpOnly: true, sameSite: 'lax', secure: IS_PRODUCTION, maxAge: 1000 * 60 * 60 * 8 }
}));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Muitas tentativas. Aguarde alguns minutos e tente novamente.' } });
const registerLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Limite temporário de cadastros atingido neste dispositivo. Tente mais tarde.' } });
const feedbackLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 30, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Muitas ações em pouco tempo. Tente novamente mais tarde.' } });

function sameOriginGuard(req, res, next) {
  const origin = req.get('origin');
  if (!origin) return next();
  try {
    const expected = `${req.protocol}://${req.get('host')}`;
    if (new URL(origin).origin !== new URL(expected).origin) return res.status(403).json({ error: 'Origem da solicitação não autorizada.' });
  } catch { return res.status(403).json({ error: 'Origem inválida.' }); }
  next();
}
app.use('/api/admin', sameOriginGuard);
app.use('/api/professional', sameOriginGuard);
app.use('/api/professionals', sameOriginGuard);
app.use('/api/admin/login', authLimiter);
app.use('/api/admin/login-2fa', authLimiter);
app.use('/api/professional/login', authLimiter);
app.use('/api/professional/google-login', authLimiter);
app.use('/api/professional/recovery-request', authLimiter);
app.use('/api/professional/reset-password', authLimiter);
app.use('/api/professional/register', registerLimiter);

app.use(express.static(path.join(__dirname, 'public'), { maxAge: 0, etag: true, setHeaders(res, filePath) { if (/\.(?:html|js|css)$/i.test(filePath) || /sw\.js$/i.test(filePath)) res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate'); } }));
app.use('/admin', express.static(path.join(__dirname, 'admin'), { maxAge: 0, etag: true, setHeaders(res, filePath) { if (/\.(?:html|js|css)$/i.test(filePath)) res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate'); } }));

function readLocalData() { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
function writeLocalData(data) { fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8'); }
function uid(prefix = 'item') { return `${prefix}-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`; }
function requireAuth(req, res, next) { if (!req.session.admin) return res.status(401).json({ error: 'Não autenticado.' }); next(); }
function regenerateSession(req) { return new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve())); }
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
  return data._admin?.passwordHash ? verifyPassword(password, data._admin.passwordHash) : String(password) === ADMIN_PASSWORD;
}

function secretKey() { return crypto.createHash('sha256').update(String(SESSION_SECRET)).digest(); }
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
function baseUrl(req) { return PUBLIC_BASE_URL || `${req.protocol}://${req.get('host')}`; }
function isValidImageBuffer(file) {
  const b = file?.buffer; if (!b || b.length < 12) return false;
  const jpg = b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff;
  const png = b.slice(0,8).equals(Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]));
  const webp = b.slice(0,4).toString() === 'RIFF' && b.slice(8,12).toString() === 'WEBP';
  return jpg || png || webp;
}
function isValidPdfBuffer(file) { return !!file?.buffer?.slice(0,5).equals(Buffer.from('%PDF-')); }
function profileCompleteness(p = {}) {
  let score = 0;
  if (String(p.name||'').trim()) score += 5;
  if (String(p.specialty||'').trim()) score += 10;
  if (String(p.bio||'').trim().length >= 80) score += 15;
  if (String(p.location||'').trim()) score += 10;
  if (String(p.photo||'').trim()) score += 15;
  if (digits(p.phone).length >= 8) score += 5;
  if (digits(p.whatsapp).length >= 8) score += 5;
  if (String(p.service_area||'').trim()) score += 10;
  if (String(p.skills||'').trim()) score += 10;
  if (Number(p.years_experience||0) > 0) score += 5;
  if (String(p.cv_url||'').trim()) score += 10;
  return Math.min(100, score);
}
function profileQualityMissing(p = {}) {
  const missing = [];
  if (!String(p.specialty||'').trim()) missing.push('especialidade');
  if (String(p.bio||'').trim().length < 80) missing.push('apresentação profissional com pelo menos 80 caracteres');
  if (!String(p.location||'').trim()) missing.push('localização');
  if (!String(p.photo||'').trim()) missing.push('foto profissional');
  if (!String(p.service_area||'').trim()) missing.push('área de atendimento');
  return missing;
}
async function sendTransactionalEmail(to, subject, text) {
  if (!RESEND_API_KEY || !EMAIL_FROM || !to) return false;
  try {
    const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ from: EMAIL_FROM, to: [to], subject, text }) });
    return r.ok;
  } catch (e) { console.error('E-mail não enviado:', e.message); return false; }
}
async function notifyProfessional(professionalId, type, title, message, link = '') {
  try {
    const { data: profile } = await supabase.from('professional_profiles').select('email,name').eq('id', professionalId).maybeSingle();
    const id = crypto.randomUUID();
    const { error } = await supabase.from('professional_notifications').insert({ id, professional_id: professionalId, type, title, message, link, created_at: new Date().toISOString() });
    if (error) throw error;
    const sent = await sendTransactionalEmail(profile?.email, title, `${message}${link && PUBLIC_BASE_URL ? `

${PUBLIC_BASE_URL}${link}` : ''}`);
    if (sent) await supabase.from('professional_notifications').update({ email_sent: true }).eq('id', id);
    return { notificationId: id, emailSent: sent, email: profile?.email || '' };
  } catch (e) { console.error('Notificação não registada:', e.message); return { notificationId: '', emailSent: false, email: '' }; }
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
  content.settings.heroLogo ||= content.settings.logo || '';
  content.settings.address ||= content.settings.location || '';
  content.settings.favicon ||= '';
  content.settings.heroBackgroundImage ||= '';
  content.settings.heroOverlay = content.settings.heroOverlay ?? '0.24';
  content.settings.seoTitle ||= `${content.settings.siteName || 'Yuran Multicerviços'} | Profissionais e serviços`;
  content.settings.seoDescription ||= 'Encontre profissionais, serviços e trabalhos numa plataforma moderada, transparente e profissional.';
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
  limits: { fileSize: 8 * 1024 * 1024, files: 16 },
  fileFilter: (_, file, cb) => cb(null, file.mimetype.startsWith('image/'))
});
const cvUpload = multer({
  storage: multer.memoryStorage(), limits: { fileSize: 12 * 1024 * 1024 },
  fileFilter: (_, file, cb) => cb(null, file.mimetype === 'application/pdf')
});
const identityUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 2 },
  fileFilter: (_, file, cb) => cb(null, file.mimetype.startsWith('image/') || file.mimetype === 'application/pdf')
});
function safeName(name) { return name.replace(/[^a-zA-Z0-9._-]/g, '-'); }

async function saveUpload(file, folder) {
  if (!file) return '';
  if (folder === 'images' && !isValidImageBuffer(file)) throw new Error('Imagem inválida. Use JPG, PNG ou WebP.');
  if (folder === 'cvs' && !isValidPdfBuffer(file)) throw new Error('PDF inválido.');
  const filename = `${Date.now()}-${crypto.randomBytes(4).toString('hex')}-${safeName(file.originalname)}`;
  if (USE_SUPABASE) {
    const storagePath = `${folder}/${filename}`;
    const { error } = await supabase.storage.from(STORAGE_BUCKET).upload(storagePath, file.buffer, { contentType: file.mimetype, upsert: false });
    if (error) throw error;
    return supabase.storage.from(STORAGE_BUCKET).getPublicUrl(storagePath).data.publicUrl;
  }
  const dir = folder === 'cvs' ? CV_DIR : IMAGE_DIR;
  fs.writeFileSync(path.join(dir, filename), file.buffer);
  return `/uploads/${folder}/${filename}`;
}

async function deleteUpload(url) {
  if (!url) return;
  if (USE_SUPABASE) {
    const marker = `/storage/v1/object/public/${STORAGE_BUCKET}/`;
    const index = url.indexOf(marker);
    if (index >= 0) await supabase.storage.from(STORAGE_BUCKET).remove([decodeURIComponent(url.slice(index + marker.length))]);
    return;
  }
  if (url.startsWith('/uploads/')) {
    const localPath = path.join(__dirname, 'public', url.replace(/^\//, ''));
    if (fs.existsSync(localPath)) fs.unlinkSync(localPath);
  }
}

async function savePrivateIdentityUpload(file, profileId, side) {
  if (!file || !USE_SUPABASE) throw new Error('Documentos de identificação requerem Supabase.');
  if (!(isValidImageBuffer(file) || isValidPdfBuffer(file))) throw new Error('Documento inválido. Use JPG, PNG, WebP ou PDF.');
  const ext = path.extname(file.originalname || '').replace(/[^.a-zA-Z0-9]/g, '') || (file.mimetype === 'application/pdf' ? '.pdf' : '.jpg');
  const storagePath = `professionals/${profileId}/${side}-${Date.now()}-${crypto.randomBytes(5).toString('hex')}${ext}`;
  const { error } = await supabase.storage.from(VERIFICATION_BUCKET).upload(storagePath, file.buffer, { contentType: file.mimetype, upsert: false });
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

app.get('/servico/:id', (_, res) => res.sendFile(path.join(__dirname, 'public', 'service.html')));

app.post('/api/admin/login', async (req, res) => {
  try {
    if (!(await validAdminPassword(req.body.password))) return res.status(401).json({ error: 'Senha incorreta.' });
    const data = await readData();
    if (data._admin?.totpEnabled && data._admin?.totpSecretEncrypted) {
      await regenerateSession(req);
      req.session.admin2faPending = true;
      req.session.admin2faStartedAt = Date.now();
      return res.json({ ok: true, requires2fa: true });
    }
    await regenerateSession(req);
    req.session.admin = true;
    return res.json({ ok: true, requires2fa: false });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Não foi possível validar a senha.' }); }
});
app.post('/api/admin/login-2fa', async (req, res) => {
  try {
    if (!req.session.admin2faPending || Date.now() - Number(req.session.admin2faStartedAt || 0) > 10 * 60 * 1000) return res.status(401).json({ error: 'Sessão de autenticação expirada. Entre novamente.' });
    const data = await readData();
    const secret = decryptSecret(data._admin?.totpSecretEncrypted || '');
    const token = String(req.body.token || '').replace(/\s/g,'');
    if (!secret || !authenticator.check(token, secret)) return res.status(401).json({ error: 'Código de autenticação inválido.' });
    await regenerateSession(req);
    req.session.admin = true;
    res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Não foi possível validar o código.' }); }
});
app.post('/api/admin/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!(await validAdminPassword(currentPassword))) return res.status(401).json({ error: 'A senha atual está incorreta.' });
    if (String(newPassword || '').length < 8) return res.status(400).json({ error: 'A nova senha deve ter pelo menos 8 caracteres.' });
    const data = await readData();
    data._admin ||= {}; data._admin.passwordHash = hashPassword(newPassword); data._admin.passwordUpdatedAt = new Date().toISOString();
    await writeData(data);
    res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao alterar a senha.' }); }
});
app.post('/api/admin/recover-password', async (req, res) => {
  try {
    if (!ADMIN_RECOVERY_KEY) return res.status(503).json({ error: 'Recuperação ainda não configurada. Defina ADMIN_RECOVERY_KEY no Render.' });
    const { recoveryKey, newPassword } = req.body || {};
    if (!safeSecretEqual(recoveryKey, ADMIN_RECOVERY_KEY)) return res.status(401).json({ error: 'Código de recuperação inválido.' });
    if (String(newPassword || '').length < 8) return res.status(400).json({ error: 'A nova senha deve ter pelo menos 8 caracteres.' });
    const data = await readData();
    data._admin ||= {}; data._admin.passwordHash = hashPassword(newPassword); data._admin.passwordUpdatedAt = new Date().toISOString();
    await writeData(data);
    res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao recuperar a senha.' }); }
});
app.post('/api/admin/logout', requireAuth, (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/admin/session', (req, res) => res.json({ authenticated: !!req.session.admin }));

app.put('/api/admin/settings', requireAuth, async (req, res) => {
  try {
    const data = await readData();
    data.settings = { ...data.settings, ...req.body };
    await writeData(data); res.json(data.settings);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao guardar configurações.' }); }
});

app.post('/api/admin/settings/assets', requireAuth, imageUpload.fields([{ name: 'headerLogo', maxCount: 1 }, { name: 'heroLogo', maxCount: 1 }, { name: 'logo', maxCount: 1 }, { name: 'favicon', maxCount: 1 }, { name: 'heroBackground', maxCount: 1 }]), async (req, res) => {
  try {
    const data = await readData();
    data.settings ||= {};
    if (req.files?.headerLogo?.[0]) {
      data.settings.headerLogo = await saveUpload(req.files.headerLogo[0], 'images');
    }
    if (req.files?.heroLogo?.[0]) {
      data.settings.heroLogo = await saveUpload(req.files.heroLogo[0], 'images');
    }
    // Compatibilidade com formulários antigos: um logo legado preenche as duas áreas.
    if (req.files?.logo?.[0]) {
      const legacy = await saveUpload(req.files.logo[0], 'images');
      data.settings.logo = legacy; data.settings.headerLogo = legacy; data.settings.heroLogo = legacy;
    }
    if (req.files?.favicon?.[0]) {
      if (data.settings.favicon) await deleteUpload(data.settings.favicon);
      data.settings.favicon = await saveUpload(req.files.favicon[0], 'images');
    }
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
function requireProfessional(req, res, next) {
  if (!req.session.professionalId) return res.status(401).json({ error: 'Faça login como profissional.' });
  next();
}
function professionalSessionRow(p = {}) {
  const { user_id, id_front_path, id_back_path, pre_suspension_status, ...safe } = p;
  safe.verified = Boolean(safe.verified && safe.status === 'approved' && safe.verification_status === 'approved');
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
  await releaseExpiredSuspensions();
  const { data, error } = await supabase.from('professional_profiles').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return data;
}
function canPublish(profile) {
  return profile && profile.verification_status === 'approved' && !['suspended','rejected'].includes(profile.status);
}
async function recordProfessionalEvent(req, professionalId, eventType, { serviceId = null, channel = '', scopeKey = 'general' } = {}) {
  try {
    const item = { id: crypto.randomUUID(), professional_id: professionalId, service_id: serviceId || null, event_type: eventType, channel, scope_key: scopeKey || 'general', visitor_hash: visitorHash(req), event_day: new Date().toISOString().slice(0,10), created_at: new Date().toISOString() };
    const { error } = await supabase.from('professional_events').insert(item);
    if (error && error.code !== '23505') throw error;
  } catch (error) { console.error('Métrica não registada:', error.message); }
}

app.post('/api/professional/register', identityUpload.fields([{ name: 'idFront', maxCount: 1 }, { name: 'idBack', maxCount: 1 }]), async (req, res) => {
  let frontPath = '', backPath = '';
  try {
    if (!USE_SUPABASE) return res.status(503).json({ error: 'O cadastro de profissionais requer Supabase.' });
    const name = String(req.body.name || '').trim();
    const address = String(req.body.address || '').trim();
    const location = String(req.body.location || '').trim();
    const phone = String(req.body.phone || '').trim();
    const whatsapp = String(req.body.whatsapp || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const confirmPassword = String(req.body.confirmPassword || '');
    const legalAccepted = ['on','true','1','yes'].includes(String(req.body.legalAccepted || '').toLowerCase());
    const front = req.files?.idFront?.[0], back = req.files?.idBack?.[0];
    const googleIdentity = req.body.googleRegistration === '1' ? req.session.googleIdentity : null;
    if (name.length < 3) return res.status(400).json({ error: 'Informe o nome completo.' });
    if (!address) return res.status(400).json({ error: 'Informe o endereço.' });
    if (digits(phone).length < 8) return res.status(400).json({ error: 'Informe um número de celular válido.' });
    if (digits(whatsapp).length < 8) return res.status(400).json({ error: 'Informe um número de WhatsApp válido.' });
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Informe um e-mail válido.' });
    if (password.length < 8) return res.status(400).json({ error: 'A senha deve ter pelo menos 8 caracteres.' });
    if (password !== confirmPassword) return res.status(400).json({ error: 'As duas senhas não coincidem.' });
    if (!front || !back) return res.status(400).json({ error: 'Carregue a frente e o verso do documento de identificação.' });
    if (!legalAccepted) return res.status(400).json({ error: 'É necessário aceitar os Termos de Uso e a Política de Privacidade.' });
    if (googleIdentity && googleIdentity.email !== email) return res.status(400).json({ error: 'O e-mail deve ser o mesmo da conta Google.' });
    const { data: exists, error: existsError } = await supabase.from('professional_users').select('id').eq('email', email).maybeSingle();
    if (existsError) throw existsError;
    if (exists) return res.status(409).json({ error: 'Já existe uma conta com este e-mail.' });
    const userId = crypto.randomUUID(), profileId = crypto.randomUUID(), slug = await uniqueProfessionalSlug(name), now = new Date().toISOString();
    frontPath = await savePrivateIdentityUpload(front, profileId, 'front');
    backPath = await savePrivateIdentityUpload(back, profileId, 'back');
    const { error: userError } = await supabase.from('professional_users').insert({ id: userId, email, password_hash: hashPassword(password), google_sub: googleIdentity?.sub || null, auth_provider: googleIdentity ? 'google+password' : 'password', created_at: now, updated_at: now });
    if (userError) throw userError;
    const seed = { name, specialty: '', bio: '', location, phone, whatsapp, photo: '', service_area: '', skills: '', years_experience: 0, cv_url: '' };
    const { error: profileError } = await supabase.from('professional_profiles').insert({ id: profileId, user_id: userId, name, slug, email, address, location, phone, whatsapp, status: 'pending', verified: false, verification_status: 'pending', id_front_path: frontPath, id_back_path: backPath, identity_submitted_at: now, terms_accepted_at: now, privacy_accepted_at: now, profile_completeness: profileCompleteness(seed), last_active_at: now, created_at: now, updated_at: now });
    if (profileError) { await supabase.from('professional_users').delete().eq('id', userId); throw profileError; }
    await regenerateSession(req);
    req.session.professionalId = profileId;
    await notifyProfessional(profileId, 'account', 'Cadastro recebido — perfil e documentação em análise', 'Recebemos o seu cadastro e os documentos de identificação. O seu perfil e a documentação estão agora em análise. Pode completar o perfil enquanto aguarda a validação.', '/profissional/dashboard');
    res.json({ ok: true, profile: { id: profileId, name, slug, email, status: 'pending', verification_status: 'pending' } });
  } catch (error) {
    console.error(error);
    if (frontPath) await deletePrivateIdentityUpload(frontPath);
    if (backPath) await deletePrivateIdentityUpload(backPath);
    res.status(500).json({ error: error.message || 'Não foi possível criar a conta.' });
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
    req.session.professionalId = profile.id;
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
    if (authError || !authData?.user?.email) return res.status(401).json({ error: 'Não foi possível validar a conta Google.' });
    const googleUser = authData.user, email = googleUser.email.toLowerCase();
    let { data: account, error } = await supabase.from('professional_users').select('*').eq('google_sub', googleUser.id).maybeSingle();
    if (error) throw error;
    if (!account) {
      const byEmail = await supabase.from('professional_users').select('*').eq('email', email).maybeSingle();
      if (byEmail.error) throw byEmail.error;
      account = byEmail.data;
      if (account) await supabase.from('professional_users').update({ google_sub: googleUser.id, auth_provider: 'google+password', updated_at: new Date().toISOString() }).eq('id', account.id);
    }
    if (account) {
      const { data: profile, error: pError } = await supabase.from('professional_profiles').select('*').eq('user_id', account.id).maybeSingle();
      if (pError) throw pError;
      if (!profile) return res.status(404).json({ error: 'Perfil profissional não encontrado.' });
      await regenerateSession(req);
      req.session.professionalId = profile.id;
      await supabase.from('professional_profiles').update({ last_active_at: new Date().toISOString() }).eq('id', profile.id);
      return res.json({ ok: true, needsRegistration: false });
    }
    const googleIdentity = { sub: googleUser.id, email, name: googleUser.user_metadata?.full_name || googleUser.user_metadata?.name || '' };
    await regenerateSession(req);
    req.session.googleIdentity = googleIdentity;
    res.json({ ok: true, needsRegistration: true, googleProfile: { email, name: googleIdentity.name } });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao entrar com Google.' }); }
});
app.get('/api/professional/google-pending', (req, res) => res.json({ googleProfile: req.session.googleIdentity ? { email: req.session.googleIdentity.email, name: req.session.googleIdentity.name } : null }));

app.post('/api/professional/logout', requireProfessional, (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/professional/session', async (req, res) => {
  try {
    if (!req.session.professionalId) return res.json({ authenticated: false });
    const profile = await getProfessionalSessionProfile(req.session.professionalId);
    if (!profile) return res.json({ authenticated: false });
    res.json({ authenticated: true, profile: professionalSessionRow(profile) });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao carregar sessão.' }); }
});
app.post('/api/professional/change-password', requireProfessional, async (req, res) => {
  try {
    const currentPassword = String(req.body.currentPassword || ''), newPassword = String(req.body.newPassword || ''), confirmPassword = String(req.body.confirmPassword || '');
    if (newPassword.length < 8) return res.status(400).json({ error: 'A nova senha deve ter pelo menos 8 caracteres.' });
    if (newPassword !== confirmPassword) return res.status(400).json({ error: 'As duas novas senhas não coincidem.' });
    const profile = await getProfessionalSessionProfile(req.session.professionalId);
    const { data: user, error } = await supabase.from('professional_users').select('*').eq('id', profile.user_id).single();
    if (error) throw error;
    if (!verifyPassword(currentPassword, user.password_hash)) return res.status(401).json({ error: 'A senha atual está incorreta.' });
    const { error: updateError } = await supabase.from('professional_users').update({ password_hash: hashPassword(newPassword), updated_at: new Date().toISOString() }).eq('id', user.id);
    if (updateError) throw updateError;
    res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao alterar a senha.' }); }
});
app.post('/api/professional/recovery-request', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase(), whatsapp = digits(req.body.whatsapp || '');
    const generic = { ok: true, message: 'Se os dados coincidirem com uma conta, receberá as instruções de recuperação pelo canal disponível.' };
    if (!email || whatsapp.length < 8) return res.json(generic);
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
      const link=`${baseUrl(req)}/profissional?reset=${encodeURIComponent(token)}`;
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
    const {error:ue}=await supabase.from('professional_users').update({password_hash:hashPassword(newPassword),updated_at:now}).eq('id',userId);if(ue)throw ue;
    await supabase.from('password_reset_requests').update({status:'resolved',resolved_at:now,used_at:now,token_hash:''}).eq('id',request.id);
    await notifyProfessional(request.professional_id,'security','Senha alterada','A senha da sua conta foi redefinida através do processo de recuperação. Se não reconhece esta ação, contacte a administração.','/profissional/dashboard');
    res.json({ok:true});
  }catch(error){console.error(error);res.status(500).json({error:'Não foi possível redefinir a senha.'})}
});

app.get('/api/professional/dashboard', requireProfessional, async (req, res) => {
  try {
    const profile = await getProfessionalSessionProfile(req.session.professionalId);
    const [{ data: services, error: se }, { data: projects, error: pe }, { data: events }, { data: ratings }, { data: notifications }, { data: reviews }] = await Promise.all([
      supabase.from('professional_services').select('*').eq('professional_id', profile.id).order('created_at', { ascending: false }),
      supabase.from('professional_projects').select('*').eq('professional_id', profile.id).order('created_at', { ascending: false }),
      supabase.from('professional_events').select('event_type,visitor_hash,created_at').eq('professional_id', profile.id),
      supabase.from('professional_ratings').select('stars,status').eq('professional_id', profile.id).eq('status', 'published'),
      supabase.from('professional_notifications').select('*').eq('professional_id', profile.id).order('created_at', { ascending: false }).limit(50),
      supabase.from('professional_ratings').select('id,stars,comment,scope_key,professional_reply,replied_at,created_at,professional_services(title)').eq('professional_id', profile.id).eq('status','published').order('created_at',{ascending:false}).limit(30)
    ]);
    if (se) throw se; if (pe) throw pe;
    const ratingAvg = ratings?.length ? ratings.reduce((a,x)=>a+Number(x.stars||0),0)/ratings.length : 0;
    const uniqueViews = new Set((events||[]).filter(x=>x.event_type==='view').map(x=>x.visitor_hash)).size;
    const uniqueContacts = new Set((events||[]).filter(x=>x.event_type==='contact').map(x=>x.visitor_hash)).size;
    const completion = profileCompleteness(profile);
    if (completion !== Number(profile.profile_completeness||0)) await supabase.from('professional_profiles').update({ profile_completeness: completion }).eq('id', profile.id);
    res.json({ profile: professionalSessionRow({ ...profile, profile_completeness: completion }), services: services || [], projects: projects || [], notifications: notifications || [], reviews: reviews || [], metrics: { views: uniqueViews, contacts: uniqueContacts, ratingAvg, ratingCount: ratings?.length || 0, unreadNotifications: (notifications||[]).filter(n=>!n.read_at).length } });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao carregar o painel.' }); }
});

app.put('/api/professional/profile', requireProfessional, imageUpload.fields([{ name: 'photo', maxCount: 1 }]), async (req, res) => {
  try {
    const current = await getProfessionalSessionProfile(req.session.professionalId);
    if (!current) return res.status(404).json({ error: 'Perfil não encontrado.' });
    const phone = String(req.body.phone || '').trim(), whatsapp = String(req.body.whatsapp || '').trim(), address = String(req.body.address || '').trim();
    if (digits(phone).length < 8 || digits(whatsapp).length < 8 || !address) return res.status(400).json({ error: 'Endereço, celular e WhatsApp são obrigatórios.' });
    let photo = current.photo || '';
    if (req.files?.photo?.[0]) { if (photo) await deleteUpload(photo); photo = await saveUpload(req.files.photo[0], 'images'); }
    const name = String(req.body.name || current.name).trim();
    const candidate = {
      ...current, name, specialty: String(req.body.specialty || '').trim(), headline: String(req.body.headline || '').trim().slice(0,120), bio: String(req.body.bio || '').trim(), address,
      location: String(req.body.location || '').trim(), phone, whatsapp, website: normalizeUrl(req.body.website || ''), linkedin: normalizeUrl(req.body.linkedin || ''), instagram: normalizeUrl(req.body.instagram || ''), photo,
      years_experience: Math.max(0, Math.min(80, Number(req.body.years_experience || 0))), service_area: String(req.body.service_area || '').trim(), availability: ['available','limited','unavailable'].includes(String(req.body.availability)) ? String(req.body.availability) : 'available',
      languages: String(req.body.languages || '').trim().slice(0,500), skills: String(req.body.skills || '').trim().slice(0,1000), certifications: String(req.body.certifications || '').trim().slice(0,1500), education: normalizeEducation(req.body.education), response_time_label: String(req.body.response_time_label || '').trim().slice(0,100)
    };
    const update = { ...candidate, slug: name !== current.name ? await uniqueProfessionalSlug(name, current.id) : current.slug, status: current.status === 'approved' ? 'pending' : current.status, profile_completeness: profileCompleteness(candidate), last_active_at: new Date().toISOString(), updated_at: new Date().toISOString() };
    delete update.user_id; delete update.id_front_path; delete update.id_back_path; delete update.created_at; delete update.id; delete update.verification_status; delete update.verified; delete update.warning_count; delete update.last_warning; delete update.suspended_until; delete update.suspension_reason; delete update.pre_suspension_status; delete update.identity_submitted_at; delete update.identity_verified_at; delete update.identity_retention_until; delete update.identity_documents_deleted_at; delete update.terms_accepted_at; delete update.privacy_accepted_at; delete update.rejection_reason; delete update.email; delete update.cv_url; delete update.featured;
    const { data, error } = await supabase.from('professional_profiles').update(update).eq('id', current.id).select('*').single();
    if (error) throw error;
    if (current.status === 'approved') await notifyProfessional(current.id, 'moderation', 'Alterações enviadas para revisão', 'As alterações do seu perfil foram guardadas e precisam de nova aprovação antes de o perfil voltar a ficar público.', '/profissional/dashboard');
    res.json(professionalSessionRow(data));
  } catch (error) { console.error(error); res.status(500).json({ error: error.message || 'Erro ao guardar o perfil.' }); }
});

app.post('/api/professional/profile/cv', requireProfessional, cvUpload.single('cv'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Envie um PDF.' });
    const current = await getProfessionalSessionProfile(req.session.professionalId);
    if (current.cv_url) await deleteUpload(current.cv_url);
    const cv_url = await saveUpload(req.file, 'cvs');
    const candidate = { ...current, cv_url };
    const { data, error } = await supabase.from('professional_profiles').update({ cv_url, status: current.status === 'approved' ? 'pending' : current.status, profile_completeness: profileCompleteness(candidate), last_active_at: new Date().toISOString(), updated_at: new Date().toISOString() }).eq('id', current.id).select('*').single();
    if (error) throw error; res.json(professionalSessionRow(data));
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao guardar CV.' }); }
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
    const { data, error } = await supabase.from('professional_profiles').update({ id_front_path: frontPath, id_back_path: backPath, verification_status: 'pending', verification_reason: '', verified: false, identity_submitted_at: new Date().toISOString(), updated_at: new Date().toISOString() }).eq('id', current.id).select('*').single();
    if (error) throw error; res.json(professionalSessionRow(data));
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao reenviar documentos.' }); }
});

app.post('/api/professional/services', requireProfessional, imageUpload.single('coverImage'), async (req, res) => {
  try {
    const profile = await getProfessionalSessionProfile(req.session.professionalId);
    if (!canPublish(profile)) return res.status(403).json({ error: profile.verification_status !== 'approved' ? 'Aguarde a autenticação dos seus documentos antes de publicar.' : 'Esta conta não pode publicar neste momento.' });
    if (profileCompleteness(profile) < 60) return res.status(403).json({ error: 'Complete pelo menos 60% do seu perfil antes de enviar serviços.' });
    const title = String(req.body.title || '').trim();
    if (!title) return res.status(400).json({ error: 'Informe o título do serviço.' });
    const cover_image = req.file ? await saveUpload(req.file, 'images') : '';
    const item = { id: crypto.randomUUID(), professional_id: profile.id, title, slug: `${slugify(title)}-${crypto.randomBytes(2).toString('hex')}`, category: String(req.body.category || '').trim(), description: String(req.body.description || '').trim(), price: String(req.body.price || '').trim(), service_area: String(req.body.service_area || profile.service_area || '').trim(), availability: ['available','limited','unavailable'].includes(String(req.body.availability)) ? String(req.body.availability) : 'available', delivery_time: String(req.body.delivery_time || '').trim().slice(0,100), cover_image, status: 'pending', rejection_reason: '', featured: false, created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
    const { data, error } = await supabase.from('professional_services').insert(item).select('*').single();
    if (error) throw error;
    await notifyProfessional(profile.id, 'moderation', 'Serviço enviado para análise', `O serviço “${title}” foi recebido e está aguardando revisão da administração.`, '/profissional/dashboard');
    res.json(data);
  } catch (error) { console.error(error); res.status(500).json({ error: error.message || 'Erro ao enviar serviço.' }); }
});
app.put('/api/professional/services/:id', requireProfessional, imageUpload.single('coverImage'), async (req, res) => {
  try {
    const profile = await getProfessionalSessionProfile(req.session.professionalId);
    if (!canPublish(profile)) return res.status(403).json({ error: 'Esta conta não pode editar serviços neste momento.' });
    const { data: current, error: ce } = await supabase.from('professional_services').select('*').eq('id', req.params.id).eq('professional_id', profile.id).maybeSingle();
    if (ce) throw ce; if (!current) return res.status(404).json({ error: 'Serviço não encontrado.' });
    let cover_image = current.cover_image || '';
    if (req.file) { if (cover_image) await deleteUpload(cover_image); cover_image = await saveUpload(req.file, 'images'); }
    const title = String(req.body.title || current.title).trim();
    const update = { title, category: String(req.body.category ?? current.category).trim(), description: String(req.body.description ?? current.description).trim(), price: String(req.body.price ?? current.price).trim(), service_area: String(req.body.service_area ?? current.service_area ?? '').trim(), availability: ['available','limited','unavailable'].includes(String(req.body.availability)) ? String(req.body.availability) : (current.availability || 'available'), delivery_time: String(req.body.delivery_time ?? current.delivery_time ?? '').trim().slice(0,100), cover_image, status: 'pending', rejection_reason: '', featured: false, updated_at: new Date().toISOString() };
    const { data, error } = await supabase.from('professional_services').update(update).eq('id', current.id).select('*').single(); if (error) throw error;
    await notifyProfessional(profile.id, 'moderation', 'Alteração de serviço enviada', `As alterações em “${title}” estão aguardando nova revisão.`, '/profissional/dashboard');
    res.json(data);
  } catch (error) { console.error(error); res.status(500).json({ error: error.message || 'Erro ao atualizar serviço.' }); }
});

app.delete('/api/professional/services/:id', requireProfessional, async (req, res) => {
  try { const { data: item } = await supabase.from('professional_services').select('cover_image').eq('id', req.params.id).eq('professional_id', req.session.professionalId).maybeSingle(); if (item?.cover_image) await deleteUpload(item.cover_image); const { error } = await supabase.from('professional_services').delete().eq('id', req.params.id).eq('professional_id', req.session.professionalId); if (error) throw error; res.json({ ok: true }); }
  catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao remover serviço.' }); }
});
app.post('/api/professional/projects', requireProfessional, imageUpload.array('images', 8), async (req, res) => {
  try {
    const profile = await getProfessionalSessionProfile(req.session.professionalId);
    if (!canPublish(profile)) return res.status(403).json({ error: profile.verification_status !== 'approved' ? 'Aguarde a autenticação dos seus documentos antes de publicar.' : 'Esta conta não pode publicar neste momento.' });
    if (profileCompleteness(profile) < 60) return res.status(403).json({ error: 'Complete pelo menos 60% do seu perfil antes de enviar projetos.' });
    const title = String(req.body.title || '').trim();
    if (!title) return res.status(400).json({ error: 'Informe o título do projeto.' });
    let serviceId = String(req.body.service_id || '').trim() || null;
    if (serviceId) { const { data: svc } = await supabase.from('professional_services').select('id').eq('id', serviceId).eq('professional_id', profile.id).maybeSingle(); if (!svc) serviceId = null; }
    const images = []; for (const f of req.files || []) images.push(await saveUpload(f, 'images'));
    const item = { id: crypto.randomUUID(), professional_id: profile.id, service_id: serviceId, title, slug: `${slugify(title)}-${crypto.randomBytes(2).toString('hex')}`, description: String(req.body.description || '').trim(), project_url: normalizeUrl(req.body.project_url || ''), images, status: 'pending', rejection_reason: '', featured: false, created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
    const { data, error } = await supabase.from('professional_projects').insert(item).select('*').single();
    if (error) throw error;
    await notifyProfessional(profile.id, 'moderation', 'Projeto enviado para análise', `O projeto “${title}” foi recebido e está aguardando revisão.`, '/profissional/dashboard');
    res.json(data);
  } catch (error) { console.error(error); res.status(500).json({ error: error.message || 'Erro ao enviar projeto.' }); }
});
app.put('/api/professional/projects/:id', requireProfessional, imageUpload.array('images', 8), async (req, res) => {
  try {
    const profile = await getProfessionalSessionProfile(req.session.professionalId);
    if (!canPublish(profile)) return res.status(403).json({ error: 'Esta conta não pode editar projetos neste momento.' });
    const { data: current, error: ce } = await supabase.from('professional_projects').select('*').eq('id', req.params.id).eq('professional_id', profile.id).maybeSingle(); if (ce) throw ce; if (!current) return res.status(404).json({ error: 'Projeto não encontrado.' });
    let serviceId = String(req.body.service_id || '').trim() || null;
    if (serviceId) { const { data: svc } = await supabase.from('professional_services').select('id').eq('id', serviceId).eq('professional_id', profile.id).maybeSingle(); if (!svc) serviceId = null; }
    const images = [...(current.images || [])]; for (const f of req.files || []) images.push(await saveUpload(f, 'images'));
    const update = { service_id: serviceId, title: String(req.body.title || current.title).trim(), description: String(req.body.description ?? current.description).trim(), project_url: normalizeUrl(req.body.project_url ?? current.project_url ?? ''), images: images.slice(0,12), status: 'pending', rejection_reason: '', featured: false, updated_at: new Date().toISOString() };
    const { data, error } = await supabase.from('professional_projects').update(update).eq('id', current.id).select('*').single(); if (error) throw error;
    await notifyProfessional(profile.id, 'moderation', 'Alteração de projeto enviada', `As alterações em “${update.title}” estão aguardando nova revisão.`, '/profissional/dashboard');
    res.json(data);
  } catch (error) { console.error(error); res.status(500).json({ error: error.message || 'Erro ao atualizar projeto.' }); }
});

app.delete('/api/professional/projects/:id', requireProfessional, async (req, res) => {
  try {
    const { data: item } = await supabase.from('professional_projects').select('images').eq('id', req.params.id).eq('professional_id', req.session.professionalId).maybeSingle();
    for (const url of item?.images || []) await deleteUpload(url);
    const { error } = await supabase.from('professional_projects').delete().eq('id', req.params.id).eq('professional_id', req.session.professionalId); if (error) throw error; res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao remover projeto.' }); }
});

// Público: perfis aprovados. O selo `verified` é um distintivo manual da administração.
app.get('/api/professionals', async (req, res) => {
  try {
    await releaseExpiredSuspensions();
    const [{ data: profiles, error: pe }, { data: services, error: se }, { data: ratings, error: re }] = await Promise.all([
      supabase.from('professional_profiles').select('id,name,slug,photo,specialty,headline,bio,location,verified,featured,years_experience,service_area,availability,languages,skills,response_time_label,profile_completeness,verification_status,created_at,last_active_at').eq('status', 'approved').order('featured',{ascending:false}).order('created_at', { ascending: false }),
      supabase.from('professional_services').select('id,professional_id,title,category,availability,service_area').eq('status', 'approved').order('created_at', { ascending: false }),
      supabase.from('professional_ratings').select('professional_id,stars,status').eq('status','published')
    ]);
    if (pe) throw pe; if (se) throw se; if (re) throw re;
    const term = String(req.query.q || '').trim().toLowerCase();
    const category = String(req.query.category || '').trim().toLowerCase();
    const location = String(req.query.location || '').trim().toLowerCase();
    const availability = String(req.query.availability || '').trim();
    const verified = String(req.query.verified || '') === 'true';
    const minRating = Math.max(0, Math.min(5, Number(req.query.minRating || 0)));
    let result = (profiles || []).map(p => {
      const ps = (services || []).filter(s => s.professional_id === p.id).map(({professional_id,...rest})=>rest);
      const rr = (ratings || []).filter(r=>r.professional_id===p.id);
      const avg = rr.length ? rr.reduce((a,x)=>a+Number(x.stars||0),0)/rr.length : 0;
      return { ...p, verified: Boolean(p.verified && p.verification_status === 'approved'), identityValidated: p.verification_status === 'approved', verification_status: undefined, services: ps, ratingAvg: avg, ratingCount: rr.length };
    });
    if (term) result = result.filter(p => [p.name,p.specialty,p.headline,p.location,p.bio,p.service_area,p.skills,...p.services.flatMap(s=>[s.title,s.category,s.service_area])].some(v => String(v||'').toLowerCase().includes(term)));
    if (category) result = result.filter(p => p.services.some(s=>String(s.category||'').toLowerCase()===category || String(s.title||'').toLowerCase().includes(category)) || String(p.specialty||'').toLowerCase().includes(category));
    if (location) result = result.filter(p => [p.location,p.service_area,...p.services.map(s=>s.service_area)].some(v=>String(v||'').toLowerCase().includes(location)));
    if (availability) result = result.filter(p => p.availability === availability);
    if (verified) result = result.filter(p => p.verified);
    if (minRating) result = result.filter(p => p.ratingAvg >= minRating);
    res.json(result);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao carregar profissionais.' }); }
});

app.get('/api/professionals/:slug', async (req, res) => {
  try {
    await releaseExpiredSuspensions();
    const { data: profile, error } = await supabase.from('professional_profiles').select('id,name,slug,photo,specialty,headline,bio,location,phone,whatsapp,email,website,linkedin,instagram,cv_url,verified,verification_status,featured,years_experience,service_area,availability,languages,skills,certifications,education,response_time_label,profile_completeness,created_at,last_active_at').eq('slug', req.params.slug).eq('status', 'approved').maybeSingle();
    if (error) throw error; if (!profile) return res.status(404).json({ error: 'Profissional não encontrado.' });
    const [{ data: services, error: se }, { data: projects, error: pe }, { data: ratings, error: re }, { data: events }] = await Promise.all([
      supabase.from('professional_services').select('id,title,slug,category,description,price,service_area,availability,delivery_time,cover_image').eq('professional_id', profile.id).eq('status', 'approved').order('featured',{ascending:false}).order('created_at', { ascending: false }),
      supabase.from('professional_projects').select('id,title,slug,description,project_url,images,service_id').eq('professional_id', profile.id).eq('status', 'approved').order('featured',{ascending:false}).order('created_at', { ascending: false }),
      supabase.from('professional_ratings').select('id,stars,comment,scope_key,professional_reply,replied_at,verified_interaction,created_at,professional_services(title)').eq('professional_id', profile.id).eq('status', 'published').order('created_at', { ascending: false }),
      supabase.from('professional_events').select('event_type,visitor_hash').eq('professional_id',profile.id)
    ]);
    if (se) throw se; if (pe) throw pe; if (re) throw re;
    await recordProfessionalEvent(req, profile.id, 'view');
    const avg = ratings?.length ? ratings.reduce((a,x)=>a+Number(x.stars||0),0)/ratings.length : 0;
    const views = new Set((events||[]).filter(x=>x.event_type==='view').map(x=>x.visitor_hash)).size;
    const contacts = new Set((events||[]).filter(x=>x.event_type==='contact').map(x=>x.visitor_hash)).size;
    const publicProfile = { ...profile, verified: Boolean(profile.verified && profile.verification_status === 'approved'), identityValidated: profile.verification_status === 'approved' }; delete publicProfile.verification_status;
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
    if (existing) await supabase.from('professional_ratings').update({ stars, comment, service_id: serviceId, status: 'published', verified_interaction: true, updated_at: now }).eq('id', existing.id);
    else await supabase.from('professional_ratings').insert({ id: crypto.randomUUID(), professional_id: profile.id, service_id: serviceId, scope_key: scopeKey, stars, comment, visitor_hash: vh, status: 'published', verified_interaction: true, created_at: now, updated_at: now });
    await notifyProfessional(profile.id, 'rating', 'Nova avaliação recebida', `O seu perfil recebeu uma avaliação de ${stars} estrela${stars===1?'':'s'}.`, '/profissional/dashboard');
    res.json({ ok: true });
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
    const { data, error } = await supabase.from('professional_projects').select('id,title,description,project_url,images,professional_profiles!inner(name,slug,specialty,status,verified)').eq('status', 'approved').eq('featured', true).eq('professional_profiles.status', 'approved').order('updated_at', { ascending: false }).limit(12);
    if (error) throw error;
    res.json((data || []).map(x => ({ id: x.id, title: x.title, description: x.description, link: x.project_url, images: x.images || [], image: x.images?.[0] || '', service: x.professional_profiles?.specialty || 'Profissional', professionalName: x.professional_profiles?.name || '', professionalSlug: x.professional_profiles?.slug || '' })));
  } catch (error) { console.error(error); res.json([]); }
});

app.get('/profissionais', (_, res) => res.sendFile(path.join(__dirname, 'public', 'professionals.html')));
app.get('/profissional', (_, res) => res.sendFile(path.join(__dirname, 'public', 'professional-login.html')));
app.get('/profissional/google-callback', (_, res) => res.sendFile(path.join(__dirname, 'public', 'professional-google-callback.html')));
app.get('/profissional/dashboard', (_, res) => res.sendFile(path.join(__dirname, 'professional', 'dashboard.html')));
app.get('/profissional/:slug', (_, res) => res.sendFile(path.join(__dirname, 'public', 'professional-profile.html')));
app.use('/professional-assets', express.static(path.join(__dirname, 'professional'), { maxAge: 0, etag: true, setHeaders(res, filePath) { if (/\.(?:html|js|css)$/i.test(filePath)) res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate'); } }));

// Moderação administrativa.
app.get('/api/admin/moderation', requireAuth, async (req, res) => {
  try {
    await releaseExpiredSuspensions();
    const [{ data: professionals, error: pe }, { data: services, error: se }, { data: projects, error: pre }] = await Promise.all([
      supabase.from('professional_profiles').select('*').order('created_at', { ascending: false }),
      supabase.from('professional_services').select('*, professional_profiles(name,slug)').order('created_at', { ascending: false }),
      supabase.from('professional_projects').select('*, professional_profiles(name,slug)').order('created_at', { ascending: false })
    ]); if (pe) throw pe; if (se) throw se; if (pre) throw pre;
    res.json({ professionals: professionals || [], services: services || [], projects: projects || [] });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao carregar moderação.' }); }
});
app.patch('/api/admin/moderation/:type/:id', requireAuth, async (req, res) => {
  try {
    const map = { professionals: 'professional_profiles', services: 'professional_services', projects: 'professional_projects' }, table = map[req.params.type];
    if (!table) return res.status(400).json({ error: 'Tipo inválido.' });
    const allowed = ['pending','approved','rejected','suspended'], status = String(req.body.status || '');
    if (!allowed.includes(status)) return res.status(400).json({ error: 'Estado inválido.' });
    let targetProfile = null;
    if (table === 'professional_profiles' && status === 'approved') {
      const { data: profile } = await supabase.from('professional_profiles').select('*').eq('id', req.params.id).maybeSingle();
      targetProfile = profile;
      if (profile?.verification_status !== 'approved') return res.status(400).json({ error: 'Valide primeiro o documento de identificação.' });
      const missing = profileQualityMissing(profile || {});
      if (missing.length) return res.status(400).json({ error: `Perfil incompleto para publicação: ${missing.join(', ')}.` });
    }
    const update = { status, rejection_reason: status === 'rejected' ? String(req.body.rejection_reason || '').trim() : '', updated_at: new Date().toISOString() };
    if (table === 'professional_profiles' && status !== 'suspended') Object.assign(update, { suspended_until: null, suspension_reason: '', pre_suspension_status: '' });
    const { data, error } = await supabase.from(table).update(update).eq('id', req.params.id).select('*').single(); if (error) throw error;
    await safeAuditLog({ target_type: req.params.type, target_id: req.params.id, action: status, reason: String(req.body.rejection_reason || ''), metadata: { admin: true } });
    let professionalId = table === 'professional_profiles' ? data.id : data.professional_id;
    const typeLabel = table === 'professional_profiles' ? 'perfil' : table === 'professional_services' ? 'serviço' : 'projeto';
    const message = status === 'approved' ? (table === 'professional_profiles' ? 'A sua documentação já foi validada e o seu perfil profissional foi aprovado. O perfil pode agora ficar disponível ao público, de acordo com as regras da plataforma.' : `O seu ${typeLabel} foi aprovado.`) : status === 'rejected' ? `O seu ${typeLabel} foi rejeitado. Motivo: ${String(req.body.rejection_reason || 'Consulte o painel.')}` : status === 'suspended' ? `O seu ${typeLabel} foi suspenso pela administração.` : `O seu ${typeLabel} voltou para análise.`;
    await notifyProfessional(professionalId, 'moderation', `${typeLabel[0].toUpperCase()+typeLabel.slice(1)}: ${status === 'approved' ? 'aprovado' : status === 'rejected' ? 'rejeitado' : status === 'suspended' ? 'suspenso' : 'em análise'}`, message, '/profissional/dashboard');
    res.json(data);
  } catch (error) { console.error(error); res.status(500).json({ error: error.message || 'Erro ao moderar item.' }); }
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
    await notifyProfessional(req.params.id, 'identity', status === 'approved' ? 'Identidade validada' : status === 'rejected' ? 'Documento precisa ser reenviado' : 'Identidade em análise', status === 'approved' ? 'A sua documentação de identificação foi aprovada. Continue a completar o perfil; a publicação pública do perfil depende ainda da aprovação administrativa do conteúdo profissional.' : status === 'rejected' ? `A validação do documento foi recusada. Motivo: ${reason}` : 'Os seus documentos estão em análise.', '/profissional/dashboard');
    res.json(data);
  } catch (error) { console.error(error); res.status(500).json({ error: error.message || 'Erro ao validar identidade.' }); }
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
  } catch (error) { console.error(error); res.status(500).json({ error: error.message || 'Erro ao alterar selo verificado.' }); }
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
      location: String(req.body.location ?? current.location ?? '').trim(),
      phone: String(req.body.phone ?? current.phone ?? '').trim(),
      whatsapp: String(req.body.whatsapp ?? current.whatsapp ?? '').trim(),
      service_area: String(req.body.service_area ?? current.service_area ?? '').trim(),
      skills: String(req.body.skills ?? current.skills ?? '').trim(),
      languages: String(req.body.languages ?? current.languages ?? '').trim(),
      certifications: String(req.body.certifications ?? current.certifications ?? '').trim(),
      education: req.body.education !== undefined ? normalizeEducation(req.body.education) : normalizeEducation(current.education || []),
      years_experience: Math.max(0, Math.min(80, Number(req.body.years_experience ?? current.years_experience ?? 0) || 0)),
      availability
    };
    const update = {
      name: candidate.name,
      slug: candidate.name !== current.name ? await uniqueProfessionalSlug(candidate.name, current.id) : current.slug,
      specialty: candidate.specialty,
      headline: candidate.headline,
      bio: candidate.bio,
      location: candidate.location,
      phone: candidate.phone,
      whatsapp: candidate.whatsapp,
      service_area: candidate.service_area,
      skills: candidate.skills,
      languages: candidate.languages,
      certifications: candidate.certifications,
      education: candidate.education,
      years_experience: candidate.years_experience,
      availability: candidate.availability,
      profile_completeness: profileCompleteness(candidate),
      updated_at: new Date().toISOString()
    };
    const { data, error } = await supabase.from('professional_profiles').update(update).eq('id', current.id).select('*').single();
    if (error) throw error;
    await safeAuditLog({ target_type: 'professional', target_id: current.id, action: 'admin_profile_edit', reason: 'Dados do perfil ajustados pela administração.', metadata: { admin: true } });
    await notifyProfessional(current.id, 'moderation', 'Perfil atualizado pela administração', 'A administração atualizou informações do seu perfil. Consulte a sua área profissional para confirmar os dados.', '/profissional/dashboard');
    res.json(data);
  } catch (error) { console.error(error); res.status(500).json({ error: error.message || 'Erro ao editar profissional.' }); }
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
  } catch (error) { console.error(error); res.status(500).json({ error: error.message || 'Erro ao excluir profissional.' }); }
});


app.get('/api/admin/email-center', requireAuth, async (req, res) => {
  try {
    const [{ data: professionals, error: pe }, { data: logs, error: le }] = await Promise.all([
      supabase.from('professional_profiles').select('id,name,email,status,verification_status').order('name', { ascending: true }),
      supabase.from('admin_email_logs').select('*').order('created_at', { ascending: false }).limit(50)
    ]);
    if (pe) throw pe;
    res.json({ configured: Boolean(RESEND_API_KEY && EMAIL_FROM), from: EMAIL_FROM || '', professionals: professionals || [], logs: le ? [] : (logs || []) });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao carregar centro de comunicação.' }); }
});
app.post('/api/admin/emails/send', requireAuth, async (req, res) => {
  try {
    if (!RESEND_API_KEY || !EMAIL_FROM) return res.status(503).json({ error: 'O envio de e-mail ainda não está configurado. Adicione RESEND_API_KEY e EMAIL_FROM no Render.' });
    const audience = String(req.body.audience || 'individual');
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
    let sent = 0, failed = 0;
    for (let i = 0; i < recipients.length; i += 5) {
      const batch = recipients.slice(i, i + 5);
      const results = await Promise.all(batch.map(p => notifyProfessional(p.id, 'admin_message', subject, message, '/profissional/dashboard')));
      for (const r of results) r.emailSent ? sent++ : failed++;
      if (i + 5 < recipients.length) await new Promise(resolve => setTimeout(resolve, 350));
    }
    try { await supabase.from('admin_email_logs').insert({ id: crypto.randomUUID(), audience, professional_id: audience === 'individual' ? professionalId : null, subject, recipient_count: recipients.length, sent_count: sent, failed_count: failed, created_at: new Date().toISOString() }); } catch {}
    await safeAuditLog({ target_type: 'communication', target_id: audience === 'individual' ? professionalId : 'all', action: 'email_sent', reason: subject, metadata: { recipient_count: recipients.length, sent, failed } });
    res.json({ ok: true, recipients: recipients.length, sent, failed });
  } catch (error) { console.error(error); res.status(500).json({ error: error.message || 'Erro ao enviar e-mails.' }); }
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
      await notifyProfessional(profile.id, 'warning', 'Advertência da administração', message, '/profissional/dashboard');
    } else if (action === 'suspend') {
      const days = Math.min(365, Math.max(1, Number(req.body.suspensionDays || 7))), until = new Date(Date.now()+days*86400000).toISOString();
      const previous = profile.status === 'suspended' ? (profile.pre_suspension_status || 'pending') : profile.status;
      await supabase.from('professional_profiles').update({ status: 'suspended', pre_suspension_status: previous, suspended_until: until, suspension_reason: reason || `Suspensão temporária por ${days} dia(s).`, updated_at: new Date().toISOString() }).eq('id', profile.id);
      await supabase.from('professional_reports').update({ status: 'actioned', admin_action: `suspend_${days}d`, reviewed_at: new Date().toISOString() }).eq('id', report.id);
      await safeAuditLog({ target_type: 'professional', target_id: profile.id, action: `suspend_${days}d`, reason: reason || 'Suspensão após denúncia.', metadata: { report_id: report.id, suspended_until: until } });
      await notifyProfessional(profile.id, 'suspension', 'Conta suspensa temporariamente', reason || `A sua conta foi suspensa por ${days} dia(s).`, '/profissional/dashboard');
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
    const temporaryPassword = `${crypto.randomBytes(4).toString('hex')}A7!`;
    const { error: ue } = await supabase.from('professional_users').update({ password_hash: hashPassword(temporaryPassword), updated_at: new Date().toISOString() }).eq('id', request.professional_profiles.user_id); if (ue) throw ue;
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
    const [{ data: rows, error }, site] = await Promise.all([
      supabase.from('professional_services').select('category').eq('status','approved'),
      readData()
    ]);
    if (error) throw error;
    const counts = new Map();
    for (const r of rows || []) { const c=String(r.category||'').trim(); if(c) counts.set(c,(counts.get(c)||0)+1); }
    for (const x of site.services || []) { const c=String(x.title||'').trim(); if(c && !counts.has(c)) counts.set(c,0); }
    res.json([...counts.entries()].map(([name,count])=>({name,count,slug:slugify(name)})).sort((a,b)=>b.count-a.count||a.name.localeCompare(b.name,'pt')));
  } catch (error) { console.error(error); res.status(500).json({ error:'Erro ao carregar categorias.' }); }
});

app.get('/api/platform-summary', async (_, res) => {
  try {
    const [{ count: professionals }, { count: services }, { count: projects }, { data: ratings }] = await Promise.all([
      supabase.from('professional_profiles').select('*',{count:'exact',head:true}).eq('status','approved'),
      supabase.from('professional_services').select('*',{count:'exact',head:true}).eq('status','approved'),
      supabase.from('professional_projects').select('*',{count:'exact',head:true}).eq('status','approved'),
      supabase.from('professional_ratings').select('stars').eq('status','published')
    ]);
    const avg = ratings?.length ? ratings.reduce((a,x)=>a+Number(x.stars||0),0)/ratings.length : 0;
    res.json({ professionals:professionals||0, services:services||0, projects:projects||0, ratingAvg:avg, ratingCount:ratings?.length||0 });
  } catch (error) { console.error(error); res.json({ professionals:0,services:0,projects:0,ratingAvg:0,ratingCount:0 }); }
});

app.get('/api/featured-professionals', async (_, res) => {
  try {
    const { data: profiles, error } = await supabase.from('professional_profiles').select('id,name,slug,photo,specialty,headline,location,verified,verification_status,years_experience,availability,profile_completeness').eq('status','approved').eq('featured',true).order('updated_at',{ascending:false}).limit(8);
    if (error) throw error;
    const ids=(profiles||[]).map(x=>x.id);
    let ratings=[];
    if(ids.length){ const rr=await supabase.from('professional_ratings').select('professional_id,stars').in('professional_id',ids).eq('status','published'); if(rr.error)throw rr.error; ratings=rr.data||[]; }
    res.json((profiles||[]).map(p=>{const r=ratings.filter(x=>x.professional_id===p.id);return {...p,verified:Boolean(p.verified&&p.verification_status==='approved'),identityValidated:p.verification_status==='approved',verification_status:undefined,ratingAvg:r.length?r.reduce((a,x)=>a+Number(x.stars||0),0)/r.length:0,ratingCount:r.length};}));
  } catch (error) { console.error(error); res.json([]); }
});

app.get('/api/professionals/:slug/services/:serviceSlug', async (req,res)=>{
  try{
    const {data:profile,error:pe}=await supabase.from('professional_profiles').select('id,name,slug,photo,specialty,headline,location,whatsapp,phone,email,verified,verification_status,years_experience,service_area,availability,response_time_label,created_at').eq('slug',req.params.slug).eq('status','approved').maybeSingle();
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
    const [{count:pendingProfiles},{count:pendingServices},{count:pendingProjects},{count:openReports},{data:events},{data:services}]=await Promise.all([
      supabase.from('professional_profiles').select('*',{count:'exact',head:true}).eq('status','pending'),
      supabase.from('professional_services').select('*',{count:'exact',head:true}).eq('status','pending'),
      supabase.from('professional_projects').select('*',{count:'exact',head:true}).eq('status','pending'),
      supabase.from('professional_reports').select('*',{count:'exact',head:true}).eq('status','open'),
      supabase.from('professional_events').select('event_type,created_at').gte('created_at',since),
      supabase.from('professional_services').select('category').eq('status','approved')
    ]);
    const cats={};for(const x of services||[]){const c=String(x.category||'Outros').trim()||'Outros';cats[c]=(cats[c]||0)+1}
    res.json({pendingProfiles:pendingProfiles||0,pendingServices:pendingServices||0,pendingProjects:pendingProjects||0,openReports:openReports||0,views30:(events||[]).filter(x=>x.event_type==='view').length,contacts30:(events||[]).filter(x=>x.event_type==='contact').length,topCategories:Object.entries(cats).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([name,count])=>({name,count}))});
  }catch(error){console.error(error);res.status(500).json({error:'Erro ao carregar resumo.'})}
});

app.get('/api/admin/2fa/status', requireAuth, async(_,res)=>{try{const d=await readData();res.json({enabled:!!d._admin?.totpEnabled})}catch(e){res.status(500).json({error:'Erro ao verificar 2FA.'})}});
app.post('/api/admin/2fa/setup', requireAuth, async(req,res)=>{
  try{const d=await readData();const secret=authenticator.generateSecret();d._admin||={};d._admin.totpPendingEncrypted=encryptSecret(secret);await writeData(d);const label=encodeURIComponent('Yuran Multicerviços Admin');const issuer=encodeURIComponent('Yuran Multicerviços');res.json({secret,otpauthUrl:`otpauth://totp/${label}?secret=${secret}&issuer=${issuer}`})}catch(error){console.error(error);res.status(500).json({error:'Erro ao preparar 2FA.'})}
});
app.post('/api/admin/2fa/enable', requireAuth, async(req,res)=>{
  try{const d=await readData();const secret=decryptSecret(d._admin?.totpPendingEncrypted||'');const token=String(req.body.token||'').replace(/\s/g,'');if(!secret||!authenticator.check(token,secret))return res.status(400).json({error:'Código inválido. Confirme o código do autenticador.'});d._admin.totpSecretEncrypted=encryptSecret(secret);d._admin.totpEnabled=true;delete d._admin.totpPendingEncrypted;await writeData(d);res.json({ok:true})}catch(error){console.error(error);res.status(500).json({error:'Erro ao ativar 2FA.'})}
});
app.post('/api/admin/2fa/disable', requireAuth, async(req,res)=>{
  try{if(!(await validAdminPassword(req.body.password)))return res.status(401).json({error:'Senha incorreta.'});const d=await readData();const secret=decryptSecret(d._admin?.totpSecretEncrypted||'');if(secret&&!authenticator.check(String(req.body.token||'').replace(/\s/g,''),secret))return res.status(401).json({error:'Código 2FA inválido.'});d._admin.totpEnabled=false;delete d._admin.totpSecretEncrypted;delete d._admin.totpPendingEncrypted;await writeData(d);res.json({ok:true})}catch(error){console.error(error);res.status(500).json({error:'Erro ao desativar 2FA.'})}
});
app.post('/api/admin/purge-expired-identities', requireAuth, async(_,res)=>{try{await purgeExpiredIdentityDocuments();res.json({ok:true})}catch(error){console.error(error);res.status(500).json({error:'Erro ao eliminar documentos expirados.'})}});

app.get('/sitemap.xml', async(req,res)=>{
  try{const base=baseUrl(req);const [{data:profiles},{data:services}]=await Promise.all([supabase.from('professional_profiles').select('slug,updated_at').eq('status','approved'),supabase.from('professional_services').select('slug,updated_at,professional_profiles!inner(slug,status)').eq('status','approved').eq('professional_profiles.status','approved')]);const staticPaths=['/','/profissionais','/categorias','/como-funciona','/ajuda','/politica-de-privacidade','/termos-de-uso'];const urls=[...staticPaths.map(x=>({loc:base+x})),...(profiles||[]).map(x=>({loc:`${base}/profissional/${encodeURIComponent(x.slug)}`,lastmod:x.updated_at})),...(services||[]).map(x=>({loc:`${base}/profissional/${encodeURIComponent(x.professional_profiles.slug)}/servico/${encodeURIComponent(x.slug)}`,lastmod:x.updated_at}))];const xml=`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls.map(x=>`<url><loc>${x.loc.replace(/&/g,'&amp;')}</loc>${x.lastmod?`<lastmod>${new Date(x.lastmod).toISOString()}</lastmod>`:''}</url>`).join('')}</urlset>`;res.type('application/xml').send(xml)}catch(error){console.error(error);res.status(500).send('')}
});
app.get('/robots.txt',(req,res)=>res.type('text/plain').send(`User-agent: *\nAllow: /\nDisallow: /admin/\nDisallow: /profissional/dashboard\nSitemap: ${baseUrl(req)}/sitemap.xml\n`));

app.get('/categorias',(_,res)=>res.sendFile(path.join(__dirname,'public','categories.html')));
app.get('/como-funciona',(_,res)=>res.sendFile(path.join(__dirname,'public','how-it-works.html')));
app.get('/ajuda',(_,res)=>res.sendFile(path.join(__dirname,'public','help.html')));
app.get('/politica-de-privacidade',(_,res)=>res.sendFile(path.join(__dirname,'public','privacy.html')));
app.get('/termos-de-uso',(_,res)=>res.sendFile(path.join(__dirname,'public','terms.html')));
app.get('/profissional/:slug/servico/:serviceSlug',(_,res)=>res.sendFile(path.join(__dirname,'public','professional-service.html')));

if (USE_SUPABASE) {
  setInterval(()=>purgeExpiredIdentityDocuments().catch(()=>{}),6*60*60*1000).unref();
  setInterval(()=>supabase.from('app_sessions').delete().lt('expire',new Date().toISOString()).then(()=>{}).catch(()=>{}),6*60*60*1000).unref();
}

app.get('/health', (_, res) => res.json({ ok: true, storage: USE_SUPABASE ? 'supabase' : 'local', persistent: USE_SUPABASE, supabaseConfigured: USE_SUPABASE }));
app.listen(PORT, () => { console.log(`Site disponível na porta ${PORT}`); console.log(`Armazenamento: ${USE_SUPABASE ? 'Supabase (persistente)' : 'local (desenvolvimento)'}`); });
