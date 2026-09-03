# Yuran Multicerviços — versão Render + Supabase

Esta versão foi preparada para rodar no **Render Free** sem depender do disco local para os dados do site.

## Arquitetura

- **Render Free:** executa Node.js + Express.
- **Supabase Free:** guarda o conteúdo do site em PostgreSQL e imagens/CVs no Storage.
- **Painel `/admin/`:** continua permitindo editar o site sem mexer no código.

O Render pode executar aplicações Express como Web Service no plano gratuito; serviços gratuitos entram em suspensão após 15 minutos sem atividade e voltam quando recebem uma nova requisição. Consulte a documentação atual do Render antes de publicar em produção.

## 1. Criar o Supabase

1. Crie um projeto gratuito no Supabase.
2. Abra **SQL Editor**.
3. Cole e execute o conteúdo de `supabase-schema.sql`.
4. Vá a **Project Settings > API**.
5. Copie:
   - Project URL → `SUPABASE_URL`
   - `service_role` key → `SUPABASE_SERVICE_ROLE_KEY`

**IMPORTANTE:** nunca coloque a `service_role` key no JavaScript do navegador, GitHub público ou README. Ela deve ficar apenas nas variáveis de ambiente do servidor.

## 2. Colocar no GitHub

Crie um repositório e envie todos os arquivos desta pasta para a raiz do repositório.

Exemplo:

```bash
git init
git add .
git commit -m "Versão inicial do portfólio"
git branch -M main
git remote add origin SEU_REPOSITORIO_GITHUB
git push -u origin main
```

## 3. Criar o Web Service no Render

No Render:

1. **New → Web Service**.
2. Conecte o GitHub.
3. Selecione o repositório.
4. Runtime: **Node**.
5. Build Command: `npm install`.
6. Start Command: `npm start`.
7. Plan: **Free**.
8. Health Check Path: `/health`.
9. Adicione as variáveis:

```text
ADMIN_PASSWORD=uma-senha-forte
ADMIN_RECOVERY_KEY=uma-chave-de-recuperacao-longa-e-secreta
SESSION_SECRET=uma-chave-aleatoria-forte
SUPABASE_URL=https://SEU-PROJETO.supabase.co
SUPABASE_SERVICE_ROLE_KEY=SUA_SERVICE_ROLE_KEY
SUPABASE_STORAGE_BUCKET=uploads
```

O arquivo `render.yaml` já contém essa configuração para facilitar o deploy.

## 4. Primeiro acesso

Depois do deploy:

```text
https://SEU-SERVICO.onrender.com/
https://SEU-SERVICO.onrender.com/admin/
```

Use a senha definida em `ADMIN_PASSWORD`.

## 5. O que ficou persistente

Quando o Supabase estiver configurado, ficam persistentes:

- textos e configurações;
- serviços;
- projetos do portfólio;
- fotos da equipa;
- CVs em PDF;
- parceiros;
- links/redes sociais.

Assim, um reinício do Web Service no Render não apaga o conteúdo.

## 6. Limites do plano gratuito

O Render Free pode suspender o serviço após 15 minutos de inatividade.

O Supabase Free atualmente inclui 500 MB de banco de dados e 1 GB de Storage, além dos limites de tráfego do plano. Para um portfólio inicial, isso é suficiente se as imagens forem otimizadas.

## 7. Segurança

Antes de divulgar o site:

- altere `ADMIN_PASSWORD`;
- configure `ADMIN_RECOVERY_KEY` e guarde essa chave fora do GitHub;
- use uma `SESSION_SECRET` forte;
- nunca publique a `SUPABASE_SERVICE_ROLE_KEY`;
- não coloque `.env` no GitHub;
- mantenha os PDFs e imagens dentro dos limites configurados no servidor.

## Fallback local

Se `SUPABASE_URL` e `SUPABASE_SERVICE_ROLE_KEY` não estiverem definidos, o sistema usa `data/site.json` e `public/uploads/` localmente. Isso facilita testes no computador.

## Comandos locais

```bash
npm install
npm start
```

Site: `http://localhost:3000`

Painel: `http://localhost:3000/admin/`

Health check: `http://localhost:3000/health`

## Alteração e recuperação da senha

Depois de entrar no painel, abra **Segurança** para alterar a senha. A nova senha fica guardada de forma criptográfica no conteúdo privado do Supabase e não é enviada pela API pública do site.

Se esquecer a senha, use **Esqueci a senha** na página de login e informe a chave definida em `ADMIN_RECOVERY_KEY` no Render. Não publique nem envie essa chave ao GitHub.
