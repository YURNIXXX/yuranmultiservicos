# Yuran Multicerviços V7.8.3 — correções do relatório

## Instalação

1. Substitua os ficheiros da aplicação pelo conteúdo deste ZIP e faça o deploy no Render. Esta atualização não tem migração SQL nova; mantenha as tabelas da V7.8.1 e os ajustes de segurança da V7.8.2.
2. Em **Render → serviço yuranmultiservicos → Environment**, confirme que `SESSION_SECRET` tem um valor permanente. Não o mude a cada deploy, pois isso invalida as sessões abertas.
3. Nesse mesmo serviço, confirme **também** `ADMIN_RECOVERY_KEY`. É uma variável diferente de `SESSION_SECRET` e de `ADMIN_PASSWORD`. Se não conhece o valor antigo, defina uma chave nova longa e aleatória, guarde-a num gestor de senhas e faça o deploy. Pode gerar uma chave no seu próprio computador com `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`. Não cole a chave em mensagens nem a inclua no código.
4. Entre em `/admin/` com a senha atual. Se já existir uma senha administrativa alterada pelo painel, essa senha guardada na base de dados prevalece sobre `ADMIN_PASSWORD` no Render. Para recuperar, abra **Recuperar senha** e introduza o valor **exato** de `ADMIN_RECOVERY_KEY` e uma senha nova. Depois entre com a senha nova.
5. Aceda a um projeto, percorra as imagens e use **Ver imagem completa ↗** para abrir o ficheiro original com zoom no navegador.

## Alterações

- O servidor passa a enviar explicitamente o cookie administrativo depois de guardar e verificar a sessão. Mantém `HttpOnly`, `SameSite=Lax`, `Secure` em produção e o caminho `/api/admin`.
- O erro de recuperação identifica qual variável deve ser usada quando a chave informada não coincide.
- A galeria mostra a imagem inteira dentro do espaço disponível, conserva os controlos de navegação e fornece acesso ao original para imagens compridas ou de grande resolução.

## Verificação

`npm run security:check` valida a assinatura do cookie, as opções de segurança e a presença dos controlos da galeria, além das verificações anteriores. Não houve teste de login com a base de dados nem com o navegador de produção neste ambiente; confirme os passos 4 e 5 após o deploy.
