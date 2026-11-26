# Segurança — Yuran Multicerviços V7.7

## Novidades

### Verificação de e-mail
- código de 6 dígitos gerado com `crypto.randomInt`;
- apenas hash HMAC do código é guardado no banco;
- validade de 10 minutos;
- limitação de reenvio e rate limit;
- número de tentativas controlado;
- conta Google é considerada verificada depois de validação OAuth/Supabase.

### Identidade
- frente e verso continuam em bucket privado;
- uploads continuam sujeitos à validação de assinatura binária;
- número do documento não substitui os ficheiros de identidade;
- perfil não entra em validação sem e-mail confirmado e, quando necessário, frente + verso.

### Sessões
A sessão profissional permanece longa conforme requisito do produto, mas:
- palavra-passe pode ser alterada;
- logout destrói a sessão;
- Admin continua com sessão mais curta;
- `SESSION_SECRET` deve permanecer estável no Render.

### SEO e privacidade
- `robots.txt` bloqueia Admin, API, dashboard e callback;
- páginas privadas possuem `noindex,nofollow`;
- documentos de identidade nunca entram no sitemap, llms.txt ou metadados públicos.

## Segredos

Nunca versionar:
- `SESSION_SECRET`
- `TOTP_ENCRYPTION_KEY`
- `ADMIN_RECOVERY_KEY`
- `ADMIN_PASSWORD`
- `SUPABASE_SERVICE_ROLE_KEY`
- `RESEND_API_KEY`

`GOOGLE_SITE_VERIFICATION` não é uma credencial sensível, mas deve ser configurado conscientemente para a propriedade correta.
