# V7.9.7 — sitemap e Search Console

- A rota `/sitemap.xml` continua a responder com as páginas públicas principais quando as consultas ao Supabase falham ou demoram mais de quatro segundos.
- Perfis, serviços e serviços antigos são incluídos quando os dados estão disponíveis.
- Datas inválidas deixam de impedir a geração do XML.
- O XML tem `Content-Type: application/xml` e cache de cinco minutos.
- O teste `scripts/check-v7.9.7-sitemap.cjs` cobre respostas completas, erros e demora da base de dados.

## Verificação após publicar

1. Abrir `https://yuranmts.onrender.com/sitemap.xml` e confirmar que mostra XML com `<urlset>` e URLs do domínio público.
2. Abrir `https://yuranmts.onrender.com/robots.txt` e conferir a linha `Sitemap:`.
3. No Search Console, inspecionar a URL do sitemap, executar **Testar URL publicado** e conferir se a obtenção da página teve sucesso.
4. Voltar a enviar `/sitemap.xml` no relatório de Sitemaps. A atualização do estado depende da próxima leitura do Google.

O erro mostrado em 04/10/2026 refere-se à leitura de 29/09/2026. Sem os registos HTTP dessa leitura, não é possível afirmar qual falha ocorreu naquela tentativa.
