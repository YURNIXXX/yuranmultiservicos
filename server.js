const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'mudar-esta-senha';
const ADMIN_RECOVERY_KEY = process.env.ADMIN_RECOVERY_KEY || '';
const SESSION_SECRET = process.env.SESSION_SECRET || 'troque-esta-chave-em-producao';
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const STORAGE_BUCKET = process.env.SUPABASE_STORAGE_BUCKET || 'uploads';
const USE_SUPABASE = Boolean(SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY);
const supabase = USE_SUPABASE ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } }) : null;

const DATA_FILE = path.join(__dirname, 'data', 'site.json');
const IMAGE_DIR = path.join(__dirname, 'public', 'uploads', 'images');
const CV_DIR = path.join(__dirname, 'public', 'uploads', 'cvs');
[IMAGE_DIR, CV_DIR].forEach(dir => fs.mkdirSync(dir, { recursive: true }));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 8 }
}));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/admin', express.static(path.join(__dirname, 'admin')));

function readLocalData() { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
function writeLocalData(data) { fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8'); }
function uid(prefix = 'item') { return `${prefix}-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`; }
function requireAuth(req, res, next) { if (!req.session.admin) return res.status(401).json({ error: 'Não autenticado.' }); next(); }
function slugify(value = '') { return String(value).normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || uid('servico'); }
function normalizeUrl(value = '') {
  const v = String(value).trim();
  if (!v || v === '#') return v || '#';
  if (/^(https?:)?\/\//i.test(v)) return v.startsWith('//') ? `https:${v}` : v;
  return `https://${v.replace(/^\/+/, '')}`;
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

function normalizeContent(content) {
  content.settings ||= {};
  if (!content.settings.siteName || content.settings.siteName === 'Nexa MultiServiços') content.settings.siteName = 'Yuran Multicerviços';
  content.settings.primaryColor ||= '#151a16';
  content.settings.heroColor ||= '#00C9A7';
  content.settings.navHoverColor ||= '#00C9A7';
  content.settings.logo ||= '';
  content.settings.favicon ||= '';
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
  content.portfolio = (content.portfolio || []).map(p => ({ ...p, images: p.images?.length ? p.images : (p.image ? [p.image] : []) }));
  content.partners ||= []; content.links = (content.links || []).map(l => ({ ...l, iconClass: l.iconClass || 'bi-link-45deg' })); content.team ||= [];
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
function safeName(name) { return name.replace(/[^a-zA-Z0-9._-]/g, '-'); }

async function saveUpload(file, folder) {
  if (!file) return '';
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

app.get('/api/site', async (_, res) => {
  try { const data = await readData(); const { _admin, ...publicData } = data; res.json(publicData); }
  catch (error) { console.error(error); res.status(500).json({ error: 'Não foi possível carregar os dados.' }); }
});

app.get('/servico/:id', (_, res) => res.sendFile(path.join(__dirname, 'public', 'service.html')));

app.post('/api/admin/login', async (req, res) => {
  try {
    if (await validAdminPassword(req.body.password)) { req.session.admin = true; return res.json({ ok: true }); }
    res.status(401).json({ error: 'Senha incorreta.' });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Não foi possível validar a senha.' }); }
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

app.post('/api/admin/settings/assets', requireAuth, imageUpload.fields([{ name: 'logo', maxCount: 1 }, { name: 'favicon', maxCount: 1 }]), async (req, res) => {
  try {
    const data = await readData();
    data.settings ||= {};
    if (req.files?.logo?.[0]) {
      if (data.settings.logo) await deleteUpload(data.settings.logo);
      data.settings.logo = await saveUpload(req.files.logo[0], 'images');
    }
    if (req.files?.favicon?.[0]) {
      if (data.settings.favicon) await deleteUpload(data.settings.favicon);
      data.settings.favicon = await saveUpload(req.files.favicon[0], 'images');
    }
    await writeData(data); res.json(data.settings);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao guardar identidade visual.' }); }
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
      featured: true
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
app.post('/api/admin/partners', requireAuth, imageUpload.single('logo'), async (req, res) => {
  try {
    const data = await readData();
    const item = { id: uid('partner'), name: req.body.name || 'Parceiro', logo: req.file ? await saveUpload(req.file, 'images') : '', url: normalizeUrl(req.body.url) };
    data.partners.push(item); await writeData(data); res.json(item);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao adicionar parceiro.' }); }
});
app.delete('/api/admin/partners/:id', requireAuth, async (req, res) => {
  try {
    const data = await readData(); const item = data.partners.find(i => i.id === req.params.id);
    if (item?.logo) await deleteUpload(item.logo);
    data.partners = data.partners.filter(i => i.id !== req.params.id); await writeData(data); res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao remover parceiro.' }); }
});

// PORTFÓLIO: múltiplas imagens por projeto.
app.post('/api/admin/portfolio', requireAuth, imageUpload.array('images', 12), async (req, res) => {
  try {
    const data = await readData();
    const images = [];
    for (const file of req.files || []) images.push(await saveUpload(file, 'images'));
    const item = { id: uid('portfolio'), title: req.body.title || 'Projeto', service: req.body.service || '', description: req.body.description || '', link: normalizeUrl(req.body.link || ''), images, image: images[0] || '' };
    data.portfolio.unshift(item); await writeData(data); res.json(item);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao publicar projeto.' }); }
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
app.post('/api/admin/team/:id/cv', requireAuth, cvUpload.single('cv'), async (req, res) => {
  try {
    const data = await readData(); const index = data.team.findIndex(i => i.id === req.params.id);
    if (index < 0) return res.status(404).json({ error: 'Profissional não encontrado.' });
    if (!req.file) return res.status(400).json({ error: 'Envie um PDF.' });
    if (data.team[index].cv) await deleteUpload(data.team[index].cv);
    data.team[index].cv = await saveUpload(req.file, 'cvs'); await writeData(data); res.json(data.team[index]);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao guardar CV.' }); }
});
app.delete('/api/admin/team/:id', requireAuth, async (req, res) => {
  try {
    const data = await readData(); const item = data.team.find(i => i.id === req.params.id);
    if (item?.photo) await deleteUpload(item.photo); if (item?.cv) await deleteUpload(item.cv);
    data.team = data.team.filter(i => i.id !== req.params.id); await writeData(data); res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao remover profissional.' }); }
});

app.get('/health', (_, res) => res.json({ ok: true, storage: USE_SUPABASE ? 'supabase' : 'local' }));
app.listen(PORT, () => { console.log(`Site disponível na porta ${PORT}`); console.log(`Armazenamento: ${USE_SUPABASE ? 'Supabase (persistente)' : 'local (desenvolvimento)'}`); });
