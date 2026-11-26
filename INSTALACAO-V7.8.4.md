# Yuran Multicerviços V7.8.4

## Aplicação

Substitua os ficheiros do projeto pelo conteúdo deste ZIP e faça novo deploy no Render. Esta versão inclui as correções da V7.8.3 e **não precisa de SQL novo**.

## Serviços no painel

Em **Administração → Conteúdo → Serviços**, os serviços já personalizados continuam nos cartões iniciais. A seguir, em **Áreas que também são serviços**, aparecem todas as áreas ativas da pesquisa que ainda não tinham cartão editável. Abra **Editar serviço** para definir descrição, ícone, cor e banner. Ao guardar, a área passa para a lista inicial como serviço configurado. Os projetos e os serviços dos profissionais não são apagados por esta operação.

Para renomear uma área, utilize **Categorias**: a atualização mantém associados o serviço institucional, os projetos e as categorias dos serviços profissionais. O campo de nome no cartão do serviço é bloqueado para evitar desligar essa associação.

## Seleção em mobile e tablet

Os checkboxes têm área de toque e dimensões adequadas. O seletor personalizado abre dentro da largura útil do ecrã, permite quebra de texto e apresenta cada opção como um alvo de toque maior.

## Verificação local

`npm run security:check` passou. Inclui um cenário com uma área sem cartão, um serviço já personalizado e uma área inativa. Confirme o comportamento visual em telemóvel e tablet após o deploy; o navegador de produção e a base de dados não estavam ligados a este ambiente.
