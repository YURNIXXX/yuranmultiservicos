// ============================================================
// SERVIDOR DO SITE MULTI-SERVIÇOS
//
// Produção no Render:
// - Render executa o Node/Express.
// - Supabase guarda os dados do site (PostgreSQL).
// - Supabase Storage guarda imagens e CVs.
//
// Se as variáveis SUPABASE_URL e SUPABASE_SERVICE_ROLE_KEY não
// existirem, o projeto continua funcionando localmente usando
// os arquivos da pasta /data e /public/uploads.
// ============================================================

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

function readLocalData() {
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}
function writeLocalData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
}
function uid(prefix = 'item') {
  return `${prefix}-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
}
function requireAuth(req, res, next) {
  if (!req.session.admin) return res.status(401).json({ error: 'Não autenticado.' });
  next();
}

// ============================================================
// BANCO DE DADOS
// ============================================================
async function readData() {
  if (!USE_SUPABASE) return readLocalData();

  const { data, error } = await supabase
    .from('site_content')
    .select('content')
    .eq('id', 'main')
    .maybeSingle();

  if (error) throw error;

  // Na primeira execução, importa o conteúdo inicial do JSON.
  if (!data) {
    const initial = readLocalData();
    const { error: insertError } = await supabase.from('site_content').insert({ id: 'main', content: initial });
    if (insertError) throw insertError;
    return initial;
  }
  return data.content;
}

async function writeData(content) {
  if (!USE_SUPABASE) {
    writeLocalData(content);
    return;
  }
  const { error } = await supabase
    .from('site_content')
    .upsert({ id: 'main', content, updated_at: new Date().toISOString() });
  if (error) throw error;
}

// ============================================================
// ARMAZENAMENTO DE ARQUIVOS
// ============================================================
const imageUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (_, file, cb) => cb(null, file.mimetype.startsWith('image/'))
});
const cvUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 12 * 1024 * 1024 },
  fileFilter: (_, file, cb) => cb(null, file.mimetype === 'application/pdf')
});

function safeName(name) {
  return name.replace(/[^a-zA-Z0-9._-]/g, '-');
}

async function saveUpload(file, folder) {
  if (!file) return '';
  const filename = `${Date.now()}-${crypto.randomBytes(4).toString('hex')}-${safeName(file.originalname)}`;

  if (USE_SUPABASE) {
    const storagePath = `${folder}/${filename}`;
    const { error } = await supabase.storage.from(STORAGE_BUCKET).upload(storagePath, file.buffer, {
      contentType: file.mimetype,
      upsert: false
    });
    if (error) throw error;
    const { data } = supabase.storage.from(STORAGE_BUCKET).getPublicUrl(storagePath);
    return data.publicUrl;
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
    if (index >= 0) {
      const objectPath = decodeURIComponent(url.slice(index + marker.length));
      await supabase.storage.from(STORAGE_BUCKET).remove([objectPath]);
    }
    return;
  }
  if (url.startsWith('/uploads/')) {
    const localPath = path.join(__dirname, 'public', url.replace(/^\//, ''));
    if (fs.existsSync(localPath)) fs.unlinkSync(localPath);
  }
}

// ============================================================
// API PÚBLICA
// ============================================================
app.get('/api/site', async (req, res) => {
  try { res.json(await readData()); }
  catch (error) { console.error(error); res.status(500).json({ error: 'Não foi possível carregar os dados.' }); }
});

// ============================================================
// AUTENTICAÇÃO
// ============================================================
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    req.session.admin = true;
    return res.json({ ok: true });
  }
  res.status(401).json({ error: 'Senha incorreta.' });
});
app.post('/api/admin/logout', requireAuth, (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/admin/session', (req, res) => res.json({ authenticated: !!req.session.admin }));

// ============================================================
// CONFIGURAÇÕES
// ============================================================
app.put('/api/admin/settings', requireAuth, async (req, res) => {
  try {
    const data = await readData();
    data.settings = { ...data.settings, ...req.body };
    await writeData(data);
    res.json(data.settings);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao guardar configurações.' }); }
});

// ============================================================
// COLEÇÕES SIMPLES
// ============================================================
const allowedCollections = ['services', 'partners', 'links'];
allowedCollections.forEach(collection => {
  app.post(`/api/admin/${collection}`, requireAuth, async (req, res) => {
    try {
      const data = await readData();
      const item = { id: uid(collection.slice(0, -1)), ...req.body };
      data[collection].push(item);
      await writeData(data);
      res.json(item);
    } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao adicionar item.' }); }
  });

  app.put(`/api/admin/${collection}/:id`, requireAuth, async (req, res) => {
    try {
      const data = await readData();
      const index = data[collection].findIndex(i => i.id === req.params.id);
      if (index < 0) return res.status(404).json({ error: 'Item não encontrado.' });
      data[collection][index] = { ...data[collection][index], ...req.body, id: req.params.id };
      await writeData(data);
      res.json(data[collection][index]);
    } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao atualizar item.' }); }
  });

  app.delete(`/api/admin/${collection}/:id`, requireAuth, async (req, res) => {
    try {
      const data = await readData();
      data[collection] = data[collection].filter(i => i.id !== req.params.id);
      await writeData(data);
      res.json({ ok: true });
    } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao remover item.' }); }
  });
});

// ============================================================
// PORTFÓLIO
// ============================================================
app.post('/api/admin/portfolio', requireAuth, imageUpload.single('image'), async (req, res) => {
  try {
    const data = await readData();
    const image = req.file ? await saveUpload(req.file, 'images') : '';
    const item = {
      id: uid('portfolio'),
      title: req.body.title || 'Projeto',
      service: req.body.service || '',
      description: req.body.description || '',
      link: req.body.link || '',
      image
    };
    data.portfolio.unshift(item);
    await writeData(data);
    res.json(item);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao publicar projeto.' }); }
});

app.delete('/api/admin/portfolio/:id', requireAuth, async (req, res) => {
  try {
    const data = await readData();
    const item = data.portfolio.find(i => i.id === req.params.id);
    if (item?.image) await deleteUpload(item.image);
    data.portfolio = data.portfolio.filter(i => i.id !== req.params.id);
    await writeData(data);
    res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao remover projeto.' }); }
});

// ============================================================
// EQUIPA + CV
// ============================================================
app.post('/api/admin/team', requireAuth, imageUpload.single('photo'), async (req, res) => {
  try {
    const data = await readData();
    const photo = req.file ? await saveUpload(req.file, 'images') : '';
    const item = {
      id: uid('team'), name: req.body.name || 'Profissional', role: req.body.role || '',
      bio: req.body.bio || '', photo, cv: ''
    };
    data.team.push(item);
    await writeData(data);
    res.json(item);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao adicionar profissional.' }); }
});

app.put('/api/admin/team/:id', requireAuth, imageUpload.single('photo'), async (req, res) => {
  try {
    const data = await readData();
    const index = data.team.findIndex(i => i.id === req.params.id);
    if (index < 0) return res.status(404).json({ error: 'Profissional não encontrado.' });
    let photo = data.team[index].photo;
    if (req.file) {
      if (photo) await deleteUpload(photo);
      photo = await saveUpload(req.file, 'images');
    }
    data.team[index] = {
      ...data.team[index], name: req.body.name ?? data.team[index].name,
      role: req.body.role ?? data.team[index].role, bio: req.body.bio ?? data.team[index].bio, photo
    };
    await writeData(data);
    res.json(data.team[index]);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao atualizar profissional.' }); }
});

app.post('/api/admin/team/:id/cv', requireAuth, cvUpload.single('cv'), async (req, res) => {
  try {
    const data = await readData();
    const index = data.team.findIndex(i => i.id === req.params.id);
    if (index < 0) return res.status(404).json({ error: 'Profissional não encontrado.' });
    if (!req.file) return res.status(400).json({ error: 'Envie um PDF.' });
    if (data.team[index].cv) await deleteUpload(data.team[index].cv);
    data.team[index].cv = await saveUpload(req.file, 'cvs');
    await writeData(data);
    res.json(data.team[index]);
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao guardar CV.' }); }
});

app.delete('/api/admin/team/:id', requireAuth, async (req, res) => {
  try {
    const data = await readData();
    const item = data.team.find(i => i.id === req.params.id);
    if (item?.photo) await deleteUpload(item.photo);
    if (item?.cv) await deleteUpload(item.cv);
    data.team = data.team.filter(i => i.id !== req.params.id);
    await writeData(data);
    res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Erro ao remover profissional.' }); }
});

// Health check para o Render.
app.get('/health', (req, res) => res.json({ ok: true, storage: USE_SUPABASE ? 'supabase' : 'local' }));

app.listen(PORT, () => {
  console.log(`Site disponível na porta ${PORT}`);
  console.log(`Armazenamento: ${USE_SUPABASE ? 'Supabase (persistente)' : 'local (desenvolvimento)'}`);
});
