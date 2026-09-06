# Yuran Multicerviços — Plataforma V7.2

Plataforma de descoberta e apresentação de profissionais, serviços e projetos, com moderação, verificação administrativa, reputação, métricas, comunicação e contacto direto.

## Destaques da V7.2

- Página inicial resiliente a refresh, cache antigo e falhas temporárias de API.
- Cabeçalho com logotipo carregado pelo administrador, sem fallback genérico "Y".
- Perfil profissional com idiomas estruturados e até 3 formações académicas.
- Formação académica apresentada publicamente no perfil.
- Botão **Completar perfil** corrigido.
- Melhorias de espaçamento e navegação mobile.
- Modais administrativos próprios em vez de `prompt/confirm` do navegador.
- Nova área **Admin > Comunicação** para e-mail individual ou geral.
- Notificações internas e e-mails automáticos para eventos importantes da conta, quando Resend estiver configurado.
- Cache PWA V7.2 e recursos principais em `network-first`.

## Instalação

1. Execute `supabase-v7.2.sql` uma única vez no Supabase.
2. Faça o deploy do código no GitHub/Render.
3. Leia `INSTALACAO-V7.2.txt` para configuração de e-mail e testes.

## Segurança

Nunca publique no GitHub:

- `SUPABASE_SERVICE_ROLE_KEY`
- `ADMIN_RECOVERY_KEY`
- `SESSION_SECRET`
- `RESEND_API_KEY`

Esses valores devem existir somente nas variáveis de ambiente do Render.
