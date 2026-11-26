# Yuran Multicerviços V8.0 — Monetização

## 1. Banco de dados
Execute uma única vez `supabase-v8.0-monetizacao.sql` no Supabase SQL Editor antes do deploy.

A migração cria planos, assinaturas, pagamentos, histórico e limites de projetos/serviços personalizados. Não apaga conteúdo existente.

## 2. Planos
- Gratuito: 0 MT — 5 projetos
- PRO: 200 MT/mês ou 2.000 MT/ano — 20 projetos
- PRO+: 500 MT/mês ou 5.000 MT/ano — 50 projetos
- Empresarial: 1.500 MT/mês ou 15.000 MT/ano — 100 projetos
- Empresarial + 5 Serviços: 2.000 MT/mês ou 20.000 MT/ano — 100 projetos + 5 serviços personalizados

## 3. Expiração
Existe período de tolerância de 7 dias. Depois dele, a conta passa para as regras do Gratuito. Projetos e serviços excedentes são arquivados por limite do plano, nunca apagados.

## 4. Serviços personalizados
Disponíveis apenas no Empresarial + 5 Serviços. São publicados imediatamente e podem ser posteriormente ocultados/removidos pela administração.

## 5. Destaques
Continuam como compra separada, entre 50 e 150 MT.

## 6. Pagamentos
A V8.0 prepara a estrutura de assinaturas e pagamentos, mas não integra ainda um provedor de pagamento. A integração deve ser feita depois de validar o motor de planos.
