# Yuran Multicerviços — sistema visual v9

Ficheiro de decisões. O código está em `public/css/design.css` (carrega depois de `style.css` e `platform.css`).
Qualquer página nova deve usar os tokens abaixo, nunca valores soltos.

## Ideia
Um mercado de serviços local, não um site de startup. Prioridades: procurar depressa, ver quem é o profissional, confiar.
Por isso a home começa por uma **pesquisa**, e as listas (serviços, planos, passos) são **linhas e réguas**, não grelhas de cartões iguais.

## Cor
| Token | Valor | Papel |
|---|---|---|
| `--bg` | #f6f7f5 | fundo da página |
| `--surface` | #ffffff | campos, cartões de profissional |
| `--surface-2` | #ecefec | faixas alternadas, placeholders |
| `--text` | #14211e | texto e régua principal |
| `--muted` | #4f5f59 | texto secundário (6:1 sobre o fundo) |
| `--border` | #d4dbd7 | divisórias finas |
| `--primary-custom` | definido no admin | botão principal (por omissão tinta #151a16) |
| `--hero-color` | #00c9a7, definido no admin | **um** bloco de cor da marca na home e destaque do plano |
| `--brand-deep` | #00705f | links, selos, marcas de verificação (5,6:1 sobre branco) |
| `--accent` | #e8791a | só estrelas de avaliação |
Modo escuro: mesmos papéis, valores em `html[data-theme=dark]`.
O verde neon `#00D88B` e o gradiente turquesa foram retirados.

## Tipografia
Schibsted Grotesk (variável, 400–900), alojada em `/fonts` (a CSP só permite `'self'`).
h1 clamp(2.1rem, 4.4vw, 3.4rem) / 1.08 / -0.022em / 700 · h2 clamp(1.55rem, 2.6vw, 2.2rem) / 1.15 · h3 1.125rem / 650 · corpo 16px / 1.6.
Etiquetas em frase normal, sem caixa alta nem espaçamento entre letras.

## Forma e profundidade
Raio: `--r` 6px (controlos, imagens), `--r-lg` 10px (cartões e painéis), pílula só para etiquetas de estado.
Sem sombras. A hierarquia vem de réguas de 1px, tamanho e contraste.
Sem vidro/blur, sem animação de entrada, sem faixa de parceiros em movimento.

## Layout
Largura útil 1180px (`--wrap`), margem lateral `--pad`. Cabeçalho em barra simples e colado ao topo.
Hero assimétrico: texto + pesquisa à esquerda, bloco de cor da marca a sangrar à direita com os números reais da plataforma.

## Componentes
- Botão principal: tinta, raio 6px. Secundário: contorno. Foco visível 2px.
- Serviços: linha com ícone 48px, título, descrição, contagem e seta; a linha inteira é o link.
- Profissional: cartão com foto, local, disponibilidade (ponto + texto), nome com selo, avaliação.
- Planos: tabela de colunas unidas por divisórias; o plano destacado tem fundo da cor da marca a 12%.
- Rodapé: faixa escura fixa, igual nos dois temas.

## Ícones e imagem
Bootstrap Icons (já usado). Fotografia dos profissionais e dos projetos; nada decorativo gerado.

## O que NÃO fazer
Gradiente roxo/azul ou turquesa de página inteira · texto em gradiente · cartões todos iguais com raio grande e sombra · números gigantes de fundo ·
etiquetas em caixa alta espaçada acima de cada título · animações de entrada em tudo · métricas inventadas.
