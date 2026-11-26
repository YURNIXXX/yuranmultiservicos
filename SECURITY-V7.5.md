# Segurança — V7.5

## 2FA

A V7.5 mantém `TOTP_ENCRYPTION_KEY` separada de `SESSION_SECRET`. A verificação TOTP aceita uma janela de um passo antes/depois (±30 s) para tolerar pequena dessincronização de relógio.

Se o segredo 2FA armazenado não puder ser decifrado com a chave atual, o login retorna um erro específico. O administrador pode usar **Problemas com o 2FA?** e redefinir somente o 2FA fornecendo simultaneamente:

- senha administrativa válida;
- `ADMIN_RECOVERY_KEY` válida.

Após a recuperação, o 2FA fica desativado e deve ser configurado novamente dentro do painel.

## Segredos

Nunca versionar:

- `SESSION_SECRET`
- `TOTP_ENCRYPTION_KEY`
- `ADMIN_RECOVERY_KEY`
- `SUPABASE_SERVICE_ROLE_KEY`
- `RESEND_API_KEY`

Se qualquer segredo já esteve num repositório público, trate-o como exposto e faça rotação no serviço correspondente.

## PWA do Admin

O Service Worker administrativo não usa uma tela antiga de login/dashboard como fallback de navegação. Se o backend não responder, o utilizador recebe `admin/offline.html`, evitando a impressão de que uma sessão cacheada continua operacional.

## Checklist antes de produção

- Confirmar RLS e buckets privados no Supabase.
- Testar IDOR entre duas contas profissionais.
- Confirmar que documentos de identidade só são acessíveis por URL assinada e temporária.
- Testar rate limiting em login, 2FA, recuperação, cadastro, avaliações e denúncias.
- Testar uploads com extensões falsas e payloads não suportados.
- Confirmar CSP/Helmet e cookies `HttpOnly`, `Secure`, `SameSite` em produção.
- Confirmar SPF/DKIM/DMARC quando o domínio de e-mail estiver validado.
