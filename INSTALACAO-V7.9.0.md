# Yuran Multicerviços v7.9.0 — instalação de segurança

Esta versão precisa da migração SQL **antes** da atualização do servidor. Não coloque chaves ou senhas no código ou no repositório.

## Sequência de atualização

1. Faça backup da base de dados e dos buckets `uploads` e `verification-documents` no Supabase.
2. Confirme que as migrações anteriores até v7.8.2 foram aplicadas. Execute `supabase-v7.9.0-seguranca.sql` no SQL Editor do Supabase. O script torna o bucket `verification-documents` privado, restringe as tabelas e cria as funções de limites e métricas. Se usa `SUPABASE_VERIFICATION_BUCKET` com outro nome, ajuste o nome do bucket e a política no SQL antes de executar. Se o bucket público `SUPABASE_STORAGE_BUCKET` não é `uploads`, ajuste também `bucket_id = 'uploads'` na função `security_private_media_pending`.
3. No Render, configure `SESSION_SECRET` com uma sequência aleatória permanente de pelo menos 32 caracteres, **independente** das chaves do Supabase. Mantenha `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` e `NODE_ENV=production`. Não altere `SESSION_SECRET` em cada deploy. Confirme que o bucket `SUPABASE_STORAGE_BUCKET` continua destinado a imagens públicas aprovadas.
4. Faça deploy dos ficheiros v7.9.0. O servidor verifica o bucket privado e as funções SQL antes de abrir a porta. Se houver currículos ou imagens de projetos pendentes no bucket público, copia-os para o bucket privado, atualiza as referências e remove os objetos públicos. Enquanto isso, o site aguarda o fim da migração. Consulte os logs do Render; uma falha interrompe o arranque.
5. Confirme `/health` com `{"ok":true}`. Entre novamente no Admin e no painel profissional; as sessões antigas são invalidadas nesta atualização. No Admin, consulte **Segurança** para a origem efetiva da senha e as proteções de instalação. Teste a criação/edição de um projeto, moderação, visualização das imagens e currículo somente autenticado.

Pode fazer inventário manual com `npm run security:migrate` e repetir a migração com `npm run security:migrate -- --apply` num ambiente que tenha as variáveis do Supabase. Suspenda edições de projetos durante a migração. **Não publique a versão se o arranque reclamar de objetos públicos ou de configuração ausente.** As remoções pendentes ficam registadas na tabela `security_media_cleanup` para nova tentativa. Se uma remoção continuar a falhar, o log apresenta o caminho: remova-o diretamente no Storage, confirme que a cópia privada está acessível e volte a executar a migração para limpar o registo.

## Senha administrativa

Quando existe uma senha hash gravada na configuração do site, essa é a senha efetiva. Alterar somente `ADMIN_PASSWORD` no Render não substitui o hash da base de dados. Use a função **Segurança → Alterar senha** estando autenticado, ou o fluxo de recuperação configurado. Confirme também que o e-mail de recuperação e `ADMIN_RECOVERY_KEY` estão corretos. A nova senha derruba sessões antigas. Ative a autenticação de dois fatores no Admin.

## O que muda

- Currículos e imagens de projetos por aprovar têm acesso autenticado, sem URL pública no perfil.
- Imagens editadas de um projeto aprovado são movidas para armazenamento privado durante a nova moderação. Só voltam ao bucket público quando o Admin aprova o projeto.
- A alteração/recuperação de senha revoga sessões anteriores; senhas temporárias têm mais entropia e exigem troca no primeiro acesso antes de modificar a conta.
- Uma avaliação baseada num clique de contacto fica pendente até à moderação; os antigos selos de “interação verificada” são removidos pelo SQL.
- A política de scripts bloqueia código inline e usa um nonce para dados estruturados gerados pelo servidor.
- A pesquisa usa páginas e cache curto; métricas usam agregação na base de dados; limites de tentativas são partilhados pelas instâncias.
- `/health` mostra apenas a disponibilidade. O estado detalhado está no Admin autenticado.

## Limites e operação

Esta atualização é uma defesa em camadas, não uma garantia contra invasões, abuso automatizado ou conteúdo gerado por IA. O armazenamento público e caches/CDNs podem reter cópias de ficheiros que já foram publicados; a migração remove os objetos originais e novas referências. Faça revisão de logs, dependências, permissões de fornecedores e contas administrativas. Mantenha o serviço atrás de HTTPS e atualize as dependências com um processo de testes antes de publicar.

Os testes estáticos estão em `npm run security:check`. O deploy real exige as credenciais e recursos do seu Supabase e Render; não são incluídos no pacote.
