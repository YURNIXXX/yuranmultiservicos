# Yuran Multicerviços V7.8 — instalação

1. Abra o SQL Editor do projeto Supabase e execute integralmente `supabase-v7.8.sql` **antes** da publicação do código. A migração acrescenta a categoria aos projetos e transfere a categoria dos projetos antigos quando existe um serviço ligado. Não apaga serviços ou projetos.
2. Substitua o conteúdo da aplicação pelos ficheiros desta pasta, mantendo as variáveis de ambiente já configuradas no Render. Na raiz do projeto, instale as dependências com `npm install` e inicie com `npm start`, ou faça o seu deploy habitual.
3. No telemóvel, atualize a página; caso veja a versão antiga, feche e reabra a aba para o navegador atualizar a cache da aplicação.

## Alterações

- O menu móvel centraliza as ligações e mantém os botões originais do cabeçalho.
- A página inicial apresenta todas as áreas ativas em **Serviços**, com descrições e número de projetos publicados. As categorias deixam de ocupar uma secção própria e continuam no filtro da pesquisa.
- O painel profissional apresenta projetos com categoria própria; a aba e as operações de publicação de serviços profissionais foram desativadas. Os serviços antigos continuam na base de dados, nos perfis públicos e nas avaliações.
- Portfólios apresentam texto ao lado de imagens em grelha no computador, e em coluna no telemóvel. As imagens abrem uma galeria com anterior, seguinte e fechar; as setas do teclado também funcionam.
- As descrições padrão das áreas estão no ficheiro `public/js/app.js`; a administração pode ajustar cada descrição no separador **Categorias**.

## Verificações após publicar

- Abra `/#servicos`: confirme descrições e contagens dos serviços.
- Entre numa conta profissional aprovada, abra **Projetos**, escolha uma categoria e envie imagens; confirme a moderação na administração.
- Após aprovar o projeto, confira as imagens no perfil público, na página inicial se estiver em destaque, e o contador correspondente.
