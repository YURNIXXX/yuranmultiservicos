(()=>{
  const $=(s,r=document)=>r.querySelector(s), $$=(s,r=document)=>[...r.querySelectorAll(s)];
  const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const safeUrl=v=>String(v||'').replace(/"/g,'%22');
  const cachedLogo=localStorage.getItem('yuran-header-logo')||'';const initialLogo=$('#sharedBrandLogo'),initialMark=$('#sharedBrandMark');if(initialMark)initialMark.hidden=true;if(initialLogo&&cachedLogo){initialLogo.src=cachedLogo;initialLogo.hidden=false;}
  async function applyBrand(){
    try{
      const r=await fetch('/api/site',{cache:'no-store',headers:{'Cache-Control':'no-cache'}}); if(!r.ok)throw new Error('Falha ao carregar identidade visual'); const d=await r.json(); const s=d.settings||{};
      document.documentElement.style.setProperty('--primary-custom',s.primaryColor||'#151a16');
      document.documentElement.style.setProperty('--nav-hover',s.navHoverColor||'#00C9A7');
      const logo=$('#sharedBrandLogo'), mark=$('#sharedBrandMark'), cachedLogo=localStorage.getItem('yuran-header-logo')||'', headerLogo=s.headerLogo||s.logo||cachedLogo;
      if(logo&&mark){if(headerLogo){logo.src=headerLogo;logo.hidden=false;mark.hidden=true;try{localStorage.setItem('yuran-header-logo',headerLogo)}catch{}}else{logo.hidden=true;mark.hidden=true}}
      let fav=$('#sharedFavicon'); if(!fav){fav=document.createElement('link');fav.rel='icon';fav.id='sharedFavicon';document.head.appendChild(fav)} if(s.favicon)fav.href=s.favicon;
      const siteName=s.siteName||'Yuran Multicerviços',footerName=$('#sharedFooterName'),copyName=$('#sharedCopyrightName'),tagline=$('#sharedFooterTagline'); if(footerName)footerName.textContent=siteName;if(copyName)copyName.textContent=siteName;if(tagline)tagline.textContent=s.tagline||'Conectamos necessidades a profissionais preparados para entregar resultados.';
      const contacts=$('#sharedFooterContacts');if(contacts){const items=[],address=s.address||s.location||'';if(s.phone)items.push(`<a href="tel:${esc(String(s.phone).replace(/[^+\d]/g,''))}"><i class="bi bi-telephone"></i><span>${esc(s.phone)}</span></a>`);if(s.email)items.push(`<a href="mailto:${esc(s.email)}"><i class="bi bi-envelope"></i><span>${esc(s.email)}</span></a>`);if(s.whatsapp){const wa=String(s.whatsapp).replace(/\D/g,'');items.push(`<a href="https://wa.me/${esc(wa)}" target="_blank" rel="noopener"><i class="bi bi-whatsapp"></i><span>WhatsApp</span></a>`)}if(address)items.push(`<span><i class="bi bi-geo-alt"></i><span>${esc(address)}</span></span>`);contacts.innerHTML=items.join('')}
      const footerSocial=$('#sharedSocialLinks');
      if(footerSocial){const map={Instagram:'bi-instagram',Facebook:'bi-facebook',LinkedIn:'bi-linkedin',YouTube:'bi-youtube',TikTok:'bi-tiktok',X:'bi-twitter-x',WhatsApp:'bi-whatsapp',Telegram:'bi-telegram',Pinterest:'bi-pinterest',GitHub:'bi-github',Behance:'bi-behance',Dribbble:'bi-dribbble',Website:'bi-globe2'};footerSocial.innerHTML=(d.socials||[]).filter(x=>x.url&&x.url!=='#').map(x=>`<a class="social-icon-link" href="${safeUrl(x.url)}" target="_blank" rel="noopener" aria-label="${esc(x.platform||'Rede social')}"><i class="bi ${esc(x.iconClass||map[x.platform]||'bi-link-45deg')}"></i></a>`).join('')}
      const legal=$('.footer-links');if(legal&&!legal.querySelector('a[href="/politica-de-privacidade"]'))legal.innerHTML=`<a href="/como-funciona">Como funciona</a><a href="/ajuda">Ajuda</a><a href="/politica-de-privacidade">Privacidade</a><a href="/termos-de-uso">Termos</a><a href="/profissional">Área profissional</a>`;
    }catch(e){console.error(e)}
  }
  const saved=localStorage.getItem('theme')||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');document.documentElement.dataset.theme=saved;
  const theme=$('#themeToggle'); if(theme)theme.onclick=()=>{const n=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=n;localStorage.setItem('theme',n)};
  const menu=$('#menuToggle'),nav=$('#nav');if(menu&&nav)menu.onclick=()=>nav.classList.toggle('open');$$('#nav a').forEach(a=>a.onclick=()=>nav?.classList.remove('open'));
  const year=$('#sharedYear');if(year)year.textContent=new Date().getFullYear();
  if(!document.querySelector('link[rel="manifest"]')){const m=document.createElement('link');m.rel='manifest';m.href='/manifest.webmanifest';document.head.appendChild(m)}
  if('serviceWorker'in navigator)window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js',{updateViaCache:'none'}).then(r=>r.update()).catch(()=>{}));
  applyBrand();
})();
