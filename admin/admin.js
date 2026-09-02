```javascript
// ============================================================
// PAINEL ADMINISTRATIVO
// Permite alterar conteúdo do site visualmente, sem abrir JSON.
// ============================================================

let data;

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

async function api(url, options = {}) {
  const r = await fetch(url, options);

  if (!r.ok) {
    throw new Error(
      (await r.json().catch(() => ({}))).error ||
      'Erro na operação'
    );
  }

  return r.json();
}

// ============================================================
// INICIALIZAÇÃO
// ============================================================

async function init() {
  try {
    const s = await api('/api/admin/session');

    if (s.authenticated) {
      await showApp();
    }
  } catch (err) {
    console.error('Erro ao verificar sessão:', err);
  }
}

// ============================================================
// LOGIN
// ============================================================

$('#loginForm').onsubmit = async e => {
  e.preventDefault();

  const error = $('#loginError');
  error.textContent = '';

  try {
    await api('/api/admin/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(
        Object.fromEntries(
          new FormData(e.currentTarget)
        )
      )
    });

    // Aguarda o carregamento completo do painel
    await showApp();

  } catch (err) {
    console.error('Erro no login/painel:', err);

    error.textContent =
      err.message || 'Erro ao entrar no painel.';
  }
};

// ============================================================
// ABRIR PAINEL
// ============================================================

async function showApp() {
  try {
    $('#loginView').hidden = true;
    $('#appView').hidden = false;

    data = await api('/api/site');

    renderAll();

  } catch (err) {
    console.error('Erro ao carregar painel:', err);

    // Se houver erro depois do login,
    // volta para a tela de login e mostra a mensagem.
    $('#loginView').hidden = false;
    $('#appView').hidden = true;

    $('#loginError').textContent =
      'Login efetuado, mas houve um erro ao carregar o painel: ' +
      (err.message || 'erro desconhecido');
  }
}

// ============================================================
// LOGOUT
// ============================================================

$('#logout').onclick = async () => {
  try {
    await api('/api/admin/logout', {
      method: 'POST'
    });

    location.reload();

  } catch (err) {
    console.error('Erro ao sair:', err);
  }
};

// ============================================================
// NAVEGAÇÃO DO PAINEL
// ============================================================

$$('#adminNav button').forEach(btn => {
  btn.onclick = () => {
    $$('#adminNav button').forEach(
      b => b.classList.remove('active')
    );

    btn.classList.add('active');

    $$('.tab').forEach(
      t => t.classList.remove('active')
    );

    $(`#tab-${btn.dataset.tab}`).classList.add('active');
  };
});

// ============================================================
// RENDERIZAÇÃO GERAL
// ============================================================

function renderAll() {
  renderSettings();
  renderServices();
  renderPortfolio();
  renderTeam();
  renderPartners();
  renderLinks();
}

// ============================================================
// CONFIGURAÇÕES
// ============================================================

function renderSettings() {
  const s = data.settings;

  const fields = [
    ['siteName', 'Nome do site'],
    ['tagline', 'Slogan'],
    ['heroTitle', 'Título principal'],
    ['heroText', 'Texto principal'],
    ['whatsapp', 'WhatsApp (ex.: 25884...)'],
    ['phone', 'Telefone'],
    ['email', 'E-mail'],
    ['location', 'Localização'],
    ['instagram', 'Instagram'],
    ['facebook', 'Facebook'],
    ['linkedin', 'LinkedIn']
  ];

  $('#settingsForm').innerHTML =
    fields.map(([k, l]) => `
      <label>
        ${l}
        <input
          name="${k}"
          value="${esc(s[k] || '')}"
        >
      </label>
    `).join('') +
    `
      <label class="span-2">
        Sobre nós
        <textarea
          rows="7"
          name="about"
        >${esc(s.about || '')}</textarea>
      </label>

      <button class="span-2">
        Guardar alterações
      </button>
    `;

  $('#settingsForm').onsubmit = async e => {
    e.preventDefault();

    try {
      data.settings = await api(
        '/api/admin/settings',
        {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(
            Object.fromEntries(
              new FormData(e.currentTarget)
            )
          )
        }
      );

      alert('Informações guardadas.');

    } catch (err) {
      alert(err.message);
    }
  };
}

// ============================================================
// SERVIÇOS
// ============================================================

function renderServices() {
  $('#servicesAdmin').innerHTML = `
    <form
      class="panel upload-form"
      id="serviceForm"
    >
      <input
        name="title"
        placeholder="Nome do serviço"
        required
      >

      <input
        name="icon"
        placeholder="Ícone / emoji"
      >

      <input
        name="color"
        type="color"
        value="#6f8875"
      >

      <input
        name="description"
        placeholder="Descrição"
        required
      >

      <button class="full">
        Adicionar serviço
      </button>
    </form>

    <div class="admin-grid">
      ${data.services.map(s => `
        <article class="admin-card">

          <div
            style="
              height:8px;
              border-radius:99px;
              background:${s.color}
            "
          ></div>

          <h3>${esc(s.title)}</h3>

          <p>${esc(s.description)}</p>

          <div class="actions">
            <button
              class="danger"
              onclick="removeItem(
                'services',
                '${s.id}'
              )"
            >
              Remover
            </button>
          </div>

        </article>
      `).join('')}
    </div>
  `;

  $('#serviceForm').onsubmit = async e => {
    e.preventDefault();

    try {
      const v = Object.fromEntries(
        new FormData(e.currentTarget)
      );

      const item = await api(
        '/api/admin/services',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(v)
        }
      );

      data.services.push(item);

      renderServices();
      renderPortfolio();

    } catch (err) {
      alert(err.message);
    }
  };
}

// ============================================================
// PORTFÓLIO
// ============================================================

function renderPortfolio() {
  const options = data.services
    .map(
      s => `<option>${esc(s.title)}</option>`
    )
    .join('');

  $('#portfolioAdmin').innerHTML = `
    <form
      class="panel upload-form"
      id="portfolioForm"
      enctype="multipart/form-data"
    >

      <input
        name="title"
        placeholder="Título do projeto"
        required
      >

      <select
        name="service"
        required
      >
        <option value="">
          Serviço
        </option>

        ${options}
      </select>

      <input
        class="full"
        type="file"
        name="image"
        accept="image/*"
        required
      >

      <textarea
        name="description"
        placeholder="Descrição"
      ></textarea>

      <input
        name="link"
        placeholder="Link externo (opcional)"
      >

      <button class="full">
        Publicar trabalho
      </button>

    </form>

    <div class="admin-grid">
      ${data.portfolio.map(p => `
        <article class="admin-card">

          ${
            p.image
              ? `<img src="${p.image}">`
              : ''
          }

          <small>
            ${esc(p.service)}
          </small>

          <h3>
            ${esc(p.title)}
          </h3>

          <p>
            ${esc(p.description || '')}
          </p>

          <button
            class="danger"
            onclick="removePortfolio('${p.id}')"
          >
            Remover
          </button>

        </article>
      `).join('')}
    </div>
  `;

  $('#portfolioForm').onsubmit = async e => {
    e.preventDefault();

    try {
      const item = await api(
        '/api/admin/portfolio',
        {
          method: 'POST',
          body: new FormData(e.currentTarget)
        }
      );

      data.portfolio.unshift(item);

      renderPortfolio();

    } catch (err) {
      alert(err.message);
    }
  };
}

// ============================================================
// EQUIPA
// ============================================================

function renderTeam() {
  $('#teamAdmin').innerHTML = `
    <form
      class="panel upload-form"
      id="teamForm"
    >

      <input
        name="name"
        placeholder="Nome"
        required
      >

      <input
        name="role"
        placeholder="Função / especialidade"
        required
      >

      <input
        class="full"
        type="file"
        name="photo"
        accept="image/*"
      >

      <textarea
        name="bio"
        placeholder="Breve biografia"
      ></textarea>

      <button class="full">
        Adicionar profissional
      </button>

    </form>

    <div class="admin-grid">

      ${data.team.map(m => `
        <article class="admin-card">

          ${
            m.photo
              ? `<img src="${m.photo}">`
              : ''
          }

          <h3>
            ${esc(m.name)}
          </h3>

          <small>
            ${esc(m.role)}
          </small>

          <p>
            ${esc(m.bio)}
          </p>

          <form
            class="team-cv"
            onsubmit="uploadCv(
              event,
              '${m.id}'
            )"
          >

            <input
              type="file"
              name="cv"
              accept="application/pdf"
              required
            >

            <button>
              ${
                m.cv
                  ? 'Trocar CV'
                  : 'Adicionar CV'
              }
            </button>

          </form>

          ${
            m.cv
              ? `
                <a
                  class="mini"
                  href="${m.cv}"
                  target="_blank"
                >
                  Abrir CV atual ↗
                </a>
              `
              : ''
          }

          <div class="actions">

            <button
              class="danger"
              onclick="removeItem(
                'team',
                '${m.id}'
              )"
            >
              Remover
            </button>

          </div>

        </article>
      `).join('')}

    </div>
  `;

  $('#teamForm').onsubmit = async e => {
    e.preventDefault();

    try {
      const item = await api(
        '/api/admin/team',
        {
          method: 'POST',
          body: new FormData(e.currentTarget)
        }
      );

      data.team.push(item);

      renderTeam();

    } catch (err) {
      alert(err.message);
    }
  };
}

// ============================================================
// CV
// ============================================================

window.uploadCv = async (e, id) => {
  e.preventDefault();

  try {
    const updated = await api(
      `/api/admin/team/${id}/cv`,
      {
        method: 'POST',
        body: new FormData(e.currentTarget)
      }
    );

    const index = data.team.findIndex(
      x => x.id === id
    );

    data.team[index] = updated;

    renderTeam();

  } catch (err) {
    alert(err.message);
  }
};

// ============================================================
// REMOVER PORTFÓLIO
// ============================================================

window.removePortfolio = async id => {
  if (!confirm('Remover este projeto?')) {
    return;
  }

  try {
    await api(
      `/api/admin/portfolio/${id}`,
      {
        method: 'DELETE'
      }
    );

    data.portfolio =
      data.portfolio.filter(
        x => x.id !== id
      );

    renderPortfolio();

  } catch (err) {
    alert(err.message);
  }
};

// ============================================================
// REMOVER ITEM
// ============================================================

window.removeItem = async (
  collection,
  id
) => {

  if (!confirm('Remover este item?')) {
    return;
  }

  try {
    await api(
      `/api/admin/${collection}/${id}`,
      {
        method: 'DELETE'
      }
    );

    data[collection] =
      data[collection].filter(
        x => x.id !== id
      );

    renderAll();

  } catch (err) {
    alert(err.message);
  }
};

// ============================================================
// PARCEIROS
// ============================================================

function renderPartners() {

  $('#partnersAdmin').innerHTML = `
    <form
      class="panel upload-form"
      id="partnerForm"
    >

      <input
        name="name"
        placeholder="Nome do parceiro"
        required
      >

      <input
        name="logo"
        placeholder="URL do logotipo (opcional)"
      >

      <input
        class="full"
        name="url"
        placeholder="Site / link do parceiro"
      >

      <button class="full">
        Adicionar parceiro
      </button>

    </form>

    <div class="admin-grid">

      ${data.partners.map(p => `
        <article class="admin-card">

          <h3>
            ${esc(p.name)}
          </h3>

          <p>
            ${esc(p.url || '')}
          </p>

          <button
            class="danger"
            onclick="removeItem(
              'partners',
              '${p.id}'
            )"
          >
            Remover
          </button>

        </article>
      `).join('')}

    </div>
  `;

  $('#partnerForm').onsubmit = async e => {
    e.preventDefault();

    try {
      const item = await api(
        '/api/admin/partners',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(
            Object.fromEntries(
              new FormData(e.currentTarget)
            )
          )
        }
      );

      data.partners.push(item);

      renderPartners();

    } catch (err) {
      alert(err.message);
    }
  };
}

// ============================================================
// LINKS
// ============================================================

function renderLinks() {

  $('#linksAdmin').innerHTML = `
    <form
      class="panel upload-form"
      id="linkForm"
    >

      <input
        name="title"
        placeholder="Título"
        required
      >

      <input
        name="url"
        placeholder="https://..."
        required
      >

      <button class="full">
        Adicionar link
      </button>

    </form>

    <div class="admin-grid">

      ${data.links.map(l => `
        <article class="admin-card">

          <h3>
            ${esc(l.title)}
          </h3>

          <p>
            ${esc(l.url)}
          </p>

          <button
            class="danger"
            onclick="removeItem(
              'links',
              '${l.id}'
            )"
          >
            Remover
          </button>

        </article>
      `).join('')}

    </div>
  `;

  $('#linkForm').onsubmit = async e => {
    e.preventDefault();

    try {
      const item = await api(
        '/api/admin/links',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(
            Object.fromEntries(
              new FormData(e.currentTarget)
            )
          )
        }
      );

      data.links.push(item);

      renderLinks();

    } catch (err) {
      alert(err.message);
    }
  };
}

// ============================================================
// ESCAPE HTML
// ============================================================

function esc(s = '') {
  return String(s).replace(
    /[&<>'"]/g,
    c => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[c])
  );
}

// ============================================================
// INICIAR
// ============================================================

init();
```
