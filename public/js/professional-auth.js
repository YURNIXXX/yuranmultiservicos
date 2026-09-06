const $=s=>document.querySelector(s);async function api(u,o={}){const r=await fetch(u,o);const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||'Erro');return j}
function bindPasswordToggles(){document.querySelectorAll('[data-password-toggle]').forEach(btn=>{btn.onclick=()=>{const input=btn.parentElement.querySelector('input');if(!input)return;const show=input.type==='password';input.type=show?'text':'password';btn.innerHTML=`<i class="bi ${show?'bi-eye-slash':'bi-eye'}"></i>`;btn.setAttribute('aria-label',show?'Ocultar senha':'Mostrar senha')}})}
function switchTab(tab){document.querySelectorAll('[data-auth-tab]').forEach(x=>x.classList.toggle('active',x.dataset.authTab===tab));$('#loginForm').classList.toggle('hidden',tab!=='login');$('#registerForm').classList.toggle('hidden',tab!=='register');$('#recoveryForm').classList.add('hidden');$('#resetPasswordForm')?.classList.add('hidden')}
document.querySelectorAll('[data-auth-tab]').forEach(b=>b.onclick=()=>switchTab(b.dataset.authTab));
$('#showRecovery').onclick=()=>{$('#loginForm').classList.add('hidden');$('#registerForm').classList.add('hidden');$('#recoveryForm').classList.remove('hidden');document.querySelectorAll('[data-auth-tab]').forEach(x=>x.classList.remove('active'))};$('#backLogin').onclick=()=>switchTab('login');
$('#loginForm').onsubmit=async e=>{e.preventDefault();const m=$('#loginMsg');m.textContent='A entrar...';try{await api('/api/professional/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.fromEntries(new FormData(e.currentTarget)))});location.href='/profissional/dashboard'}catch(x){m.textContent=x.message}};
$('#registerForm').onsubmit=async e=>{e.preventDefault();const m=$('#registerMsg');m.textContent='A criar conta e enviar documentos...';try{await api('/api/professional/register',{method:'POST',body:new FormData(e.currentTarget)});location.href='/profissional/dashboard'}catch(x){m.textContent=x.message}};
$('#recoveryForm').onsubmit = async e => {
  e.preventDefault();

  const form = e.currentTarget;
  const m = $('#recoveryMsg');

  m.textContent = 'A enviar pedido...';

  try {
    const j = await api('/api/professional/recovery-request', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(
        Object.fromEntries(new FormData(form))
      )
    });

    m.textContent =
      j.message ||
      'Pedido enviado com sucesso. Aguarde a análise da administração.';

    form.reset();

  } catch (x) {
    m.textContent =
      'Não foi possível concluir o pedido neste momento. Tente novamente.';
  }
};
async function setupGoogle(){try{const c=await api('/api/public-config');if(!c.googleOAuthAvailable){$('#googleLogin').disabled=true;$('#googleLogin').title='Configure SUPABASE_ANON_KEY e Google no Supabase para ativar.';return}const sb=window.supabase.createClient(c.supabaseUrl,c.supabaseAnonKey);$('#googleLogin').onclick=async()=>{const {error}=await sb.auth.signInWithOAuth({provider:'google',options:{redirectTo:location.origin+'/profissional/google-callback'}});if(error)$('#loginMsg').textContent=error.message}}catch(e){$('#googleLogin').disabled=true}}
async function completeGoogle(){if(!new URLSearchParams(location.search).has('google'))return false;try{const x=await api('/api/professional/google-pending');if(!x.googleProfile)return false;switchTab('register');$('#googleRegistration').value='1';const f=$('#registerForm');f.elements.name.value=x.googleProfile.name||'';f.elements.email.value=x.googleProfile.email||'';f.elements.email.readOnly=true;$('#registerMsg').textContent='Conta Google validada. Complete os dados e envie o documento de identificação.';return true}catch{return false}}
bindPasswordToggles();
Promise.all([setupGoogle(),completeGoogle()]).finally(()=>fetch('/api/professional/session').then(r=>r.json()).then(x=>{if(x.authenticated&&!new URLSearchParams(location.search).has('google'))location.href='/profissional/dashboard'}).catch(()=>{}));

const resetToken=new URLSearchParams(location.search).get('reset');
if(resetToken&&$('#resetPasswordForm')){
  $('#loginForm').classList.add('hidden');$('#registerForm').classList.add('hidden');$('#recoveryForm').classList.add('hidden');$('#resetPasswordForm').classList.remove('hidden');document.querySelectorAll('[data-auth-tab]').forEach(x=>x.classList.remove('active'));$('#resetToken').value=resetToken;
  $('#resetPasswordForm').onsubmit=async e=>{e.preventDefault();const form=e.currentTarget,m=$('#resetPasswordMsg'),v=Object.fromEntries(new FormData(form));if(v.newPassword!==v.confirmPassword){m.textContent='As duas senhas não coincidem.';return}m.textContent='A guardar...';try{await api('/api/professional/reset-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(v)});m.textContent='Senha alterada com sucesso. Já pode entrar.';history.replaceState({},'',location.pathname);setTimeout(()=>switchTab('login'),900)}catch(x){m.textContent=x.message}}
}
