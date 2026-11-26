# Segurança — V7.6

Esta versão preserva as proteções já introduzidas nas versões anteriores e acrescenta ajustes relacionados ao novo fluxo.

## Credenciais administrativas

A V7.6 remove o fallback de senha administrativa embutida no código. `ADMIN_PASSWORD` deve estar configurada no ambiente quando necessária, ou a instalação deve usar a credencial administrativa armazenada de forma hash pelo fluxo existente.

Nunca versionar segredos como `SESSION_SECRET`, `TOTP_ENCRYPTION_KEY`, `ADMIN_RECOVERY_KEY`, `SUPABASE_SERVICE_ROLE_KEY` e `RESEND_API_KEY`.

## Sessões

A Área Profissional usa sessão persistente de longa duração para atender ao requisito de permanecer autenticada até logout explícito. Isso aumenta a importância de:

- usar dispositivos protegidos;
- encerrar a sessão em dispositivos partilhados;
- invalidar sessões quando houver suspeita de comprometimento;
- manter cookies `HttpOnly`, `Secure` e `SameSite` em produção.

O Admin mantém política de sessão mais curta e 2FA.

## Alterações de perfis aprovados

Alterações feitas por um profissional já aprovado são armazenadas como alterações pendentes. A versão pública aprovada anterior permanece ativa até decisão administrativa. Isso evita retirar perfis legítimos do ar por uma edição simples e impede publicação direta de alterações ainda não revistas.

## Pesquisa

`search_analytics` guarda termos de pesquisa, filtros de categoria/localização, número de resultados e data. Não deve receber dados secretos, documentos ou credenciais. A tabela tem RLS ativo e permissões diretas de `anon`/`authenticated` revogadas.

## Dados pessoais e localização

Endereço privado, data de nascimento, número de identificação e documentos de identidade não devem ser expostos nas APIs públicas. Província, distrito e bairro usados no perfil público devem refletir apenas a localização que a plataforma decidiu publicar.

## Uploads

Mantêm-se as verificações de assinatura/tipo de ficheiro e nomes controlados pelo servidor. Documentos de identidade continuam privados.

## Teste recomendado antes de produção

Além do `QA-V7.6.txt`, testar intencionalmente:

- profissional A tentando editar dados do profissional B;
- alteração manual de IDs em rotas;
- envio de `status=approved` pelo profissional;
- acesso público a documentos privados;
- uploads disfarçados de imagem/PDF;
- XSS em bio, serviço, certificações e palavras-chave;
- repetição de login/recuperação/2FA;
- exposição de segredos no bundle público e no repositório.

Nenhum sistema conectado à Internet pode ser declarado impossível de comprometer; a segurança depende também da configuração real do Render, Supabase, domínio, DNS e credenciais.
