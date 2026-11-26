-- V7.3.1 — RESET SEGURO DO 2FA ADMINISTRATIVO
-- Execute uma única vez apenas para recuperar o acesso após a mudança da chave de encriptação.
-- Não altera a senha do administrador e não apaga outros dados do site.

update public.site_content
set content = jsonb_set(
      (content #- '{_admin,totpSecretEncrypted}') #- '{_admin,totpPendingEncrypted}',
      '{_admin,totpEnabled}',
      'false'::jsonb,
      true
    ),
    updated_at = now()
where id = 'main';
