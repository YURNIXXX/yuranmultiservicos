-- Yuran Multicerviços V6.3
-- A coluna `verified` já existe desde a V6.2.
-- Na V6.2 ela era ativada automaticamente ao validar o documento.
-- A partir da V6.3, o selo público é exclusivamente manual no painel administrativo.

update public.professional_profiles
set verified = false,
    updated_at = now()
where verified = true;
