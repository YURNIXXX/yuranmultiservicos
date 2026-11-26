# PageSpeed / Lighthouse — Yuran Multicerviços V7.7

A V7.7 prepara a plataforma para auditoria de desempenho, mas **não inventa uma pontuação PageSpeed**: o teste real deve ser executado contra o site publicado no Render/domínio final.

## URLs mínimas a testar

1. `/`
2. `/profissionais`
3. um `/profissional/<slug>` aprovado
4. um `/profissional/<slug>/servico/<slug>` aprovado
5. `/profissional` para avaliar a experiência de autenticação

Teste **Mobile** e **Desktop** no PageSpeed Insights ou Chrome Lighthouse.

## Metas recomendadas

- Performance: >= 90 quando a infraestrutura permitir
- Accessibility: >= 90
- Best Practices: >= 90
- SEO: >= 95
- LCP: <= 2,5 s
- INP: <= 200 ms
- CLS: <= 0,1

## V7.7 já trata

- sessão profissional verificada antes de renderizar a tela de login;
- remoção da limpeza global de suspensões do caminho crítico do dashboard;
- carregamento visual com skeleton em vez de conteúdo incompleto;
- sitemap, robots, llms.txt, canonical e metadados dinâmicos;
- cache control explícito nas páginas SEO;
- imagens públicas continuam com lazy loading onde já suportado.

## Depois do deploy

Registe os resultados reais em Mobile/Desktop e corrija primeiro:
1. imagens grandes / LCP;
2. JavaScript bloqueante;
3. fontes e CSS;
4. mudanças de layout / CLS;
5. chamadas de API lentas.
