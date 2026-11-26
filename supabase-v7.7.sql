-- Yuran Multicerviços V7.7 — verificação de e-mail e base de confiança
-- Execute uma vez no Supabase SQL Editor antes do deploy V7.7.

alter table if exists public.professional_users
  add column if not exists email_verified_at timestamptz,
  add column if not exists email_verification_code_hash text not null default '',
  add column if not exists email_verification_expires_at timestamptz,
  add column if not exists email_verification_sent_at timestamptz,
  add column if not exists email_verification_attempts integer not null default 0;

-- Contas Google existentes já tiveram posse do e-mail validada pelo provedor.
update public.professional_users
set email_verified_at = coalesce(email_verified_at, updated_at, created_at, now()),
    email_verification_code_hash = '',
    email_verification_expires_at = null,
    email_verification_attempts = 0
where email_verified_at is null
  and google_sub is not null
  and length(trim(google_sub)) > 0;

create index if not exists idx_professional_users_email_verified
  on public.professional_users (email_verified_at);

comment on column public.professional_users.email_verified_at is
  'Data/hora em que a posse do e-mail foi confirmada pela Yuran ou pelo provedor OAuth.';
