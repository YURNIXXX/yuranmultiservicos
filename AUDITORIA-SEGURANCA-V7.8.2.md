# Auditoria dos pontos da imagem — Yuran Multicerviços V7.8.2

Esta revisão foi feita no código, sem acesso às configurações ativas do Render/Supabase e sem teste de intrusão na instalação publicada. “Protegido no código” significa que há uma medida visível, não que se provou ausência de falhas.

| Nº | Ponto da imagem | Resultado no código e ação |
|---:|---|---|
| 1 | `.env` exposta | Não há `.env` no pacote; credenciais vêm do ambiente do Render. `/api/public-config` entrega a chave **anon** do Supabase, que é pública por desenho; a chave **service role** fica no servidor. Confirme no Render e no histórico Git que nunca publicou chaves privadas. |
| 2 | Validação frontend | Formulários usam campos obrigatórios e restrições básicas. Os formulários de autenticação passam a desativar o botão enquanto enviam. A interface não é a barreira de segurança. |
| 3 | Validação backend | Cadastro, verificação, moderação e categorias validam dados; uploads têm tamanho, tipo e assinatura. Continua a ser necessário testar entradas inesperadas em produção; nem todos os campos livres têm limite uniforme. |
| 4 | SQL injection | Consultas usam o construtor do Supabase com filtros por valor; tabelas escolhidas dinamicamente são obtidas de mapas fixos. Não foi identificada concatenação de SQL com dados do visitante. |
| 5 | Autenticação fraca | Senhas de utilizadores são verificadas com scrypt; 2FA do admin existe. **Corrigido:** o endpoint Google agora exige identidade Google e e-mail confirmado, em vez de aceitar qualquer token válido do Supabase. Ative 2FA no painel. |
| 6 | IDOR | Endpoints do profissional usam sessão e filtros de proprietário; os do admin exigem sessão de administrador. O endpoint público devolve apenas perfis aprovados. Não houve teste dinâmico exaustivo de todos os identificadores. |
| 7 | Senhas direto no banco | Senhas de profissionais e senha administrativa alterada são guardadas como hash scrypt com salt. A senha inicial `ADMIN_PASSWORD` é um segredo de ambiente, nunca deve entrar no repositório. |
| 8 | Força bruta | Login, recuperação e 2FA usam limite de 20 pedidos por 15 minutos por IP. Este contador fica na memória de cada instância e reinicia num novo deploy; uma defesa distribuída exigiria armazenamento partilhado. |
| 9 | Bloquear durante envio | Login do admin já bloqueava o botão. Os formulários de login, registo e recuperação profissionais agora bloqueiam envios repetidos durante a operação. |
| 10 | CSRF | Cookies `SameSite=Lax` e verificação de `Origin`/`Sec-Fetch-Site`. **Reforçado:** alterações sem ambos os sinais de origem são rejeitadas. Não se usa token CSRF separado. |
| 11 | Upload sem validação | Uploads têm limite de tamanho, MIME permitido, assinatura binária, nome aleatório e verificação no servidor. Documentos de identidade vão para bucket privado. A inspeção de conteúdo de PDF/imagem não substitui antivírus ou processamento especializado. |
| 12 | Revelando info | `/api/site` remove `_admin`. **Corrigido:** erros internos e resposta pública de falha do Resend deixam de expor mensagens técnicas ou o endereço da conta Resend. A página do admin ainda apresenta detalhes de entrega ao administrador autenticado. |
| 13 | BD vulnerável | `supabase-v7.8.2-seguranca.sql` ativa RLS e remove privilégios `anon/authenticated` nas tabelas sensíveis existentes e torna privado o bucket padrão de identidade. É preciso **executar este SQL** para aplicar a proteção ao projeto Supabase real. |
| 14 | Tokens mal otimizados | Sessão admin dura 8 horas; a profissional passa de dez anos para 30 dias sem atividade. O callback Google limpa o token da URL e encerra a sessão Supabase local após criar a sessão HTTP; links de recuperação duram 30 minutos. A rotação global de sessões após trocar senha ainda não está implementada. |
| 15 | Rate limit | Ver ponto 8; há também limites próprios para registo, verificação de e-mail e avaliações. |
| 16 | Sensíveis expostos | Documentos têm URL assinada de 10 minutos apenas pelo admin. O script SQL reforça o bucket privado; o token OAuth é removido do navegador após troca. Contactos do perfil aprovado são públicos por finalidade da plataforma. |
| 17 | SSRF | A única chamada HTTP feita pelo backend é para a URL fixa da API Resend; URLs introduzidas por utilizadores não são buscadas pelo servidor. Links de recuperação deixam de confiar no cabeçalho `Host` e exigem `PUBLIC_BASE_URL` HTTPS em produção. |
| 18 | Cookies inseguros | Cookies HTTP only, `SameSite=Lax`, `Secure` em produção e separados por caminho para admin/profissional. Verifique HTTPS e `SESSION_SECRET` permanente no Render. |
| 19 | Em branco | A imagem não contém um décimo nono ponto. |

## Instalação

1. Se ainda não o fez, execute `supabase-v7.8.1.sql` no SQL Editor do Supabase. Depois execute `supabase-v7.8.2-seguranca.sql`. Confirme que o bucket configurado como `SUPABASE_VERIFICATION_BUCKET` é privado; o SQL protege o nome padrão `verification-documents`.
2. No Render, confirme `PUBLIC_BASE_URL=https://yuranmts.onrender.com` (ou o domínio HTTPS oficial), `SESSION_SECRET` permanente e as chaves privadas apenas em **Environment**. Não cole valores de segredos em capturas ou no código.
3. Publique todos os ficheiros desta versão. Teste login do admin e do profissional, atualização da página, login Google, recuperação de senha, envio de imagem/PDF e acesso ao documento de identidade apenas no admin.
4. Corra `npm run security:check` antes de publicar. O teste é local e simulado; não prova a configuração efetiva no Supabase/Render.

**Limites:** Não foram executados `npm audit`, análise de dependências online, pentest, nem ensaios na base de dados e no serviço publicados. O código usa dependências com versões sem fixação exata e scripts/estilos de CDN; a política CSP ainda admite JavaScript inline por compatibilidade com o site existente. É necessário rever esses pontos numa etapa própria se o objetivo for uma garantia de segurança mais forte.
