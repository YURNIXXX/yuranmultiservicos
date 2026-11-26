# Yuran Multicerviços 7.9.5

## Alterações

- A página inicial apresenta até seis serviços. Quando existem mais, o botão “Ver todos os serviços” abre `/servicos`, com o catálogo completo e ligações para a página individual de cada serviço.
- Removida a ligação “Ver imagem completa” que abria o ficheiro original em outra janela. A galeria continua com navegação entre imagens e botão de fechar.
- Seletores personalizados acompanham zoom, deslocamento lateral e abertura do teclado. A janela é posicionada antes de focar a opção, e a posição da página é preservada ao abrir e fechar; a lista de opções pode ser percorrida dentro dela.
- Imagens de projetos na galeria e nos cartões passam a caber na área disponível sem corte em ecrãs estreitos. A galeria acompanha o zoom e o deslocamento do ecrã para manter os controlos visíveis.
- A nova página foi incluída no sitemap e na lista de páginas da aplicação offline.

## Instalação

Substitua os ficheiros da aplicação pela versão deste pacote e faça o deploy normal. A página `/servicos` é uma rota do servidor Node; o alojamento deve encaminhar esta rota para `server.js`.

## Verificação

`npm run security:check` concluiu sem falhas. A inspeção visual em navegador não pôde ser executada neste ambiente por falta do binário do Chromium; verifique os seletores e imagens num telemóvel após o deploy.
