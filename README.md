# Yuran Multicerviços v7.9.0

**Instalação atual:** leia [INSTALACAO-V7.9.0.md](INSTALACAO-V7.9.0.md) antes de fazer deploy. A migração SQL v7.9.0 e uma `SESSION_SECRET` própria são obrigatórias. As notas abaixo são o histórico da versão v7.7.4; o `/health` atual responde apenas `{"ok":true}`.

## Histórico v7.7.4 — UI mobile e seletores

Versão de teste focada em **confiança da conta, identidade, desempenho da área profissional, UX visual e SEO técnico**.

## Correções V7.7.4

- O cadastro apresenta a falha real de envio de confirmação no painel.
- Um envio recusado não deixa o código bloqueado para reenvio.
- O painel distingue e-mail por confirmar, código enviado e e-mail confirmado.
- O Admin indica as limitações do remetente de teste Resend e impede envios em massa nesse modo.
- O código de seis dígitos chega apenas ao e-mail do profissional; não é exposto nas notificações internas.


- Cabeçalho mobile com colunas fixas para logotipo e botões; menu aberto ancorado ao cabeçalho.
- Botão do menu informa o estado aberto/fechado e fecha com Escape ou clique fora.

- Menu mobile e cabeçalho fixos à largura do ecrã; correção dos indicadores marcados.
- Seletores com pesquisa e identidade Yuran.
- Indicativos internacionais para celular e WhatsApp; dados persistidos em formato +indicativo+número.
- Não há migração SQL nova para a V7.7.4.

## Principais mudanças

- Verificação real do e-mail por código de 6 dígitos para contas criadas com e-mail/senha.
- Contas Google entram como e-mail verificado pelo provedor OAuth.
- O perfil só pode ser enviado à validação administrativa depois de o e-mail estar confirmado.
- Verificação de identidade reforçada: número do documento + frente + verso, com mensagem mais clara no painel.
- Acesso a `/profissional` verifica primeiro a sessão existente, evitando o flash/delay do formulário de login para utilizadores já autenticados.
- Dashboard profissional otimizado: a limpeza global de suspensões saiu do caminho crítico e foi movida para rotina periódica.
- Skeleton de carregamento enquanto os dados essenciais chegam.
- Modais do perfil com botões Yuran; ao concluir a gravação, o fluxo retorna para **Visão geral**.
- Checkboxes alinhados e consistentes no site, Área Profissional e Admin.
- Área de pesquisa corrigida para impedir sobreposição entre filtro “selo verificado” e contador de resultados.
- Logo do Admin com renderização mais limpa, opção de fundo transparente e recomendação de PNG/WebP transparente.
- Google Search Console preparado por token configurável no Admin ou `GOOGLE_SITE_VERIFICATION`.
- SEO server-side com canonical, Open Graph, Twitter Cards, Schema.org/JSON-LD e metadados dinâmicos de profissionais e serviços.
- `sitemap.xml`, `robots.txt` e novo `llms.txt`.
- Páginas privadas (login profissional, callback, dashboard e Admin) protegidas contra indexação.
- Auditoria estrutural: `npm run seo:audit`.
- Guia para teste real no PageSpeed/Lighthouse: `PAGESPEED-V7.7.md`.

## Migração obrigatória

Se ainda não tiver aplicado a migração V7.7 no ambiente, execute no Supabase SQL Editor:

`supabase-v7.7.sql`

A migração adiciona apenas os campos necessários à confirmação de e-mail. Não apaga profissionais, serviços, projetos ou avaliações.

## Deploy

1. confirme que `supabase-v7.7.sql` já foi aplicado (execute apenas se ainda estiver pendente);
2. publique os ficheiros V7.7.4;
3. aguarde o Render ficar `Live`;
4. abra `/health` e confirme `"version":"7.7.4"`;
5. teste o roteiro de `QA-V7.7.txt`.

## Search Console

A base V7.7 prepara a verificação por meta tag. Cole **apenas o token** em:

`Admin → Visão geral → Google Search Console — token de verificação`

ou configure no Render:

`GOOGLE_SITE_VERIFICATION`

Depois, no Google Search Console, adicione a propriedade e envie:

`https://SEU-DOMINIO/sitemap.xml`

## Segurança

Não coloque no GitHub os valores de `SESSION_SECRET`, `TOTP_ENCRYPTION_KEY`, `ADMIN_RECOVERY_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, `RESEND_API_KEY`, `ADMIN_PASSWORD` ou outras credenciais. Consulte `SECURITY-V7.7.md`.
