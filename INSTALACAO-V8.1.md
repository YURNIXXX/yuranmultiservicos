# V8.1 — Página de Planos + Gestão da Assinatura

## Instalação
1. Aplicar primeiro `supabase-v8.0-monetizacao.sql` no Supabase, caso ainda não tenha sido aplicado.
2. Substituir o projeto pelo conteúdo desta V8.1 e fazer deploy no Render.
3. Confirmar `/planos` e `/api/plans`.
4. Entrar numa conta profissional e confirmar a aba `Plano`.

## O que esta versão acrescenta
- Página pública `/planos`.
- Alternância Mensal/Anual.
- Gestão visual da assinatura no painel profissional.
- Indicadores de utilização e limites.
- Período de tolerância apresentado quando aplicável.

## Importante
Esta versão ainda não cobra pagamentos. Os botões de upgrade encaminham para o fluxo preparado para a futura integração do provedor de pagamento.
