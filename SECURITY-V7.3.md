# Segurança — V7.3

Esta versão reforça a base atual sem prometer invulnerabilidade. O objetivo é reduzir superfície de ataque, impedir acesso direto indevido e melhorar recuperação/auditoria.

## Implementado
- sessões HttpOnly/Secure/SameSite em produção;
- sessão persistente no Supabase;
- segredo de sessão sem fallback fixo previsível;
- rate limit de autenticação/cadastro/feedback;
- proteção de origem e Sec-Fetch-Site;
- Helmet/CSP;
- validação MIME + assinatura real de JPG/PNG/WebP/PDF;
- extensão e MIME derivados do conteúdo real do upload, sem confiar no nome enviado pelo navegador;
- documentos de identidade privados com URL assinada temporária;
- retenção e eliminação documental;
- filtros por professional_id nas rotas de edição/remoção do profissional;
- status/verified/featured não podem ser definidos pelo profissional;
- RLS em tabelas sensíveis e revogação de acesso direto anon/authenticated;
- logs de moderação;
- 2FA administrativo disponível.

## Antes do lançamento oficial
- ativar 2FA do administrador;
- confirmar SESSION_SECRET permanente no Render;
- concluir domínio próprio e e-mail com SPF/DKIM/DMARC;
- rever histórico do GitHub e rotacionar qualquer segredo que tenha sido publicado;
- definir rotina de backup/exportação;
- executar teste de autorização com duas contas profissionais distintas;
- executar revisão de dependências Node antes de cada release importante.
