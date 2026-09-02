// ============================================================
// JAVASCRIPT PRINCIPAL DO SITE
// Carrega conteúdo da API e constrói o site dinamicamente.
// ============================================================

let siteData = null;

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

async function loadSite() {
  const res = await fetch('/api/site');
  siteData = await res.json();
  renderSettings();
  renderServices();
  renderPortfolio();
  renderTeam();
  renderPartners();
  renderLinks();
  setupReveal();
}

function renderSettings() {
  const s = siteData.settings;
  $('#brandName').textContent = s.siteName;
  $('#footerName').textContent = s.siteName;
  $('#heroTitle').textContent = s.heroTitle;
  $('#heroText').textContent = s.heroText;
  $('#aboutText').textContent = s.about;
  $('#contactList').innerHTML = `
    <div><strong>Telefone</strong><br>${s.phone}</div>
    <div><strong>E-mail</strong><br>${s.email}</div>
    <div><strong>Localização</strong><br>${s.location}</div>`;
  $('#socialLinks').innerHTML = [
    ['Instagram', s.instagram], ['Facebook', s.facebook], ['LinkedIn', s.linkedin]
  ].filter(([,url]) => url).map(([name,url]) => `<a href="${url}" target="_blank" rel="noopener">${name} ↗</a>`).join('');
}

function renderServices() {
  const grid = $('#servicesGrid');
  grid.innerHTML = siteData.services.map(service => `
    <article class="service-card reveal" data-service="${service.id}">
      <button class="service-action" aria-label="Solicitar ${service.title}" data-service-request="${service.title}">↗</button>
      <div class="service-accent" style="background:${service.color}"></div>
      <div class="service-icon">${service.icon || '•'}</div>
      <h3>${service.title}</h3>
      <p>${service.description}</p>
    </article>`).join('');

  const options = siteData.services.map(s => `<option value="${s.title}">${s.title}</option>`).join('');
  $('#contactService').insertAdjacentHTML('beforeend', options);
  $('#quickService').insertAdjacentHTML('beforeend', options);

  $$('[data-service-request]').forEach(btn => btn.addEventListener('click', () => openRequest(btn.dataset.serviceRequest)));
}

function renderPortfolio(filter = 'Todos') {
  const filters = ['Todos', ...new Set(siteData.services.map(s => s.title))];
  $('#portfolioFilters').innerHTML = filters.map(name => `<button class="filter-btn ${filter === name ? 'active' : ''}" data-filter="${name}">${name}</button>`).join('');
  $$('.filter-btn').forEach(btn => btn.onclick = () => renderPortfolio(btn.dataset.filter));

  const items = filter === 'Todos' ? siteData.portfolio : siteData.portfolio.filter(p => p.service === filter);
  $('#portfolioGrid').innerHTML = items.length ? items.map(item => `
    <article class="portfolio-card reveal">
      ${item.image ? `<img class="portfolio-media" src="${item.image}" alt="${item.title}">` : `<div class="portfolio-media"></div>`}
      <div class="portfolio-info">
        <span class="eyebrow">${item.service || 'PROJETO'}</span>
        <h3>${item.title}</h3><p>${item.description || ''}</p>
        ${item.link ? `<a href="${item.link}" target="_blank" rel="noopener"><strong>Ver projeto ↗</strong></a>` : ''}
      </div>
    </article>`).join('') : `<div class="empty-state">Ainda não há trabalhos publicados nesta categoria. Adicione-os no painel administrativo.</div>`;
  setupReveal();
}

function renderTeam() {
  $('#teamGrid').innerHTML = siteData.team.map(member => `
    <article class="team-card reveal">
      ${member.photo ? `<img class="team-photo" src="${member.photo}" alt="${member.name}">` : `<div class="team-photo team-placeholder">◉</div>`}
      <div class="team-body">
        <h3>${member.name}</h3><div class="team-role">${member.role}</div><p>${member.bio}</p>
        ${member.cv ? `<button class="btn ghost" data-cv="${member.cv}" data-name="${member.name}">Ver currículo</button>` : `<button class="btn ghost" disabled>CV ainda não publicado</button>`}
      </div>
    </article>`).join('');

  $$('[data-cv]').forEach(btn => btn.onclick = () => {
    $('#cvTitle').textContent = `CV — ${btn.dataset.name}`;
    $('#cvFrame').src = btn.dataset.cv;
    $('#cvModal').showModal();
  });
}

function renderPartners() {
  const items = siteData.partners.map(p => `<a class="partner-chip" href="${p.url || '#'}" ${p.url && p.url !== '#' ? 'target="_blank" rel="noopener"' : ''}>${p.logo ? `<img src="${p.logo}" alt="${p.name}">` : p.name}</a>`).join('');
  $('#partnersTrack').innerHTML = items + items; // Duplica para criar loop contínuo.
}

function renderLinks() {
  $('#linksGrid').innerHTML = siteData.links.map(l => `<a class="link-card reveal" href="${l.url}" target="_blank" rel="noopener"><span>${l.title}</span><span>↗</span></a>`).join('');
}

function setupReveal() {
  const io = new IntersectionObserver(entries => entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('visible'); }), { threshold: .08 });
  $$('.reveal').forEach(el => io.observe(el));
}

// ---------- Tema claro / escuro ----------
const savedTheme = localStorage.getItem('theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
document.documentElement.dataset.theme = savedTheme;
$('#themeToggle').onclick = () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  localStorage.setItem('theme', next);
};

// ---------- Menu mobile ----------
$('#menuToggle').onclick = () => $('#nav').classList.toggle('open');
$$('#nav a').forEach(a => a.onclick = () => $('#nav').classList.remove('open'));

// ---------- Formulários para WhatsApp ----------
function openWhatsApp(values) {
  const s = siteData.settings;
  const text = `Olá! Gostaria de solicitar um serviço.%0A%0A*Nome:* ${encodeURIComponent(values.nome)}%0A*Telefone:* ${encodeURIComponent(values.telefone)}%0A*Serviço:* ${encodeURIComponent(values.servico)}%0A*Detalhes:* ${encodeURIComponent(values.mensagem || '')}`;
  window.open(`https://wa.me/${String(s.whatsapp).replace(/\D/g,'')}?text=${text}`, '_blank', 'noopener');
}

function openRequest(service = '') {
  $('#quickService').value = service;
  $('#requestModal').showModal();
}
$$('[data-open-request]').forEach(btn => btn.onclick = () => openRequest());
$('#modalClose').onclick = () => $('#requestModal').close();
$('#cvClose').onclick = () => { $('#cvModal').close(); $('#cvFrame').src = ''; };

$('#contactForm').onsubmit = e => { e.preventDefault(); openWhatsApp(Object.fromEntries(new FormData(e.currentTarget))); };
$('#quickForm').onsubmit = e => { e.preventDefault(); openWhatsApp(Object.fromEntries(new FormData(e.currentTarget))); };

$('#year').textContent = new Date().getFullYear();
loadSite();
