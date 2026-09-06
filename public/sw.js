const CACHE='yuran-static-v7.2';
const SHELL=['/','/profissionais','/categorias','/como-funciona','/ajuda','/css/style.css','/css/platform.css','/js/platform-shared.js'];
self.addEventListener('install',event=>{event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(SHELL).catch(()=>{})));self.skipWaiting()});
self.addEventListener('activate',event=>{event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))));self.clients.claim()});
self.addEventListener('fetch',event=>{
  const req=event.request;if(req.method!=='GET')return;
  const url=new URL(req.url);
  if(url.origin!==self.location.origin||url.pathname.startsWith('/api/')||url.pathname.startsWith('/admin')||url.pathname.startsWith('/profissional/dashboard'))return;
  if(req.mode==='navigate'){
    event.respondWith(fetch(req,{cache:'no-store'}).then(res=>{if(res.ok){const clone=res.clone();caches.open(CACHE).then(c=>c.put(req,clone))}return res}).catch(()=>caches.match(req).then(r=>r||caches.match('/'))));return;
  }
  if(/\.(?:css|js)$/i.test(url.pathname)){
    event.respondWith(fetch(req,{cache:'no-store'}).then(res=>{if(res.ok){const clone=res.clone();caches.open(CACHE).then(c=>c.put(req,clone))}return res}).catch(()=>caches.match(req)));return;
  }
  if(/\.(?:png|jpe?g|webp|svg|ico|woff2?)$/i.test(url.pathname)){
    event.respondWith(caches.match(req).then(cached=>cached||fetch(req).then(res=>{if(res.ok){const clone=res.clone();caches.open(CACHE).then(c=>c.put(req,clone))}return res})));return;
  }
});
