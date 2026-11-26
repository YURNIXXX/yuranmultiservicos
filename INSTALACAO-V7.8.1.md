# Yuran Multicerviços V7.8.1

## Ordem de instalação

1. No **SQL Editor do Supabase**, execute `supabase-v7.8.1.sql`. Este único ficheiro também incorpora a migração de categorias da V7.8; se já a executou, pode voltar a executar o SQL sem apagar os seus projetos.
2. Substitua os ficheiros do projeto pelo conteúdo do ZIP e faça o deploy habitual no Render. Mantenha as variáveis de ambiente atuais.
3. Em **Render → Environment**, configure `SESSION_SECRET` com um valor longo, aleatório e permanente. Gere um valor com `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"` no seu computador e guarde-o apenas como variável de ambiente. O servidor dispõe de uma chave estável derivada da chave privada do Supabase se `SESSION_SECRET` ainda faltar, mas uma chave exclusiva é a configuração adequada.
4. Entre em `/admin/` e confira que o painel permanece aberto após atualizar a página. Em `/health`, `security.sessionSecretConfigured` deve aparecer `true` após definir a variável. Caso não, confira que o Render guardou a variável no serviço correto e reinicie o deploy.

## Alterações desta versão

- Login administrativo confirma gravação e leitura da sessão antes de responder; a página verifica se o navegador devolveu o cookie antes de abrir o painel.
- Se o cookie faltar ou a sessão falhar, o login mostra uma explicação no ecrã. Uma senha atual incorreta ao alterar a senha já não é interpretada como sessão expirada.
- Todos os cartões de serviço da página inicial abrem uma página de serviço, incluindo os que provêm de categorias novas. A pesquisa nessa página filtra a categoria respetiva.
- O perfil público deixa de mostrar o bloco de serviços antigos, reúne o título e a lista de certificações no mesmo cartão e tem largura móvel controlada.
- O botão principal da página inicial apresenta ícone de pesquisa e texto atualizado; os cartões de projetos, seletores e galerias foram ajustados para ecrãs pequenos.

## Verificação local

`node scripts/check-v7.8.1.cjs`

Este teste cobre sintaxe, gravação e leitura simulada de sessão, páginas de serviço e estrutura do perfil. A verificação de acesso real com Supabase e Render deve ser feita após o deploy.
