-- ============================================================
-- YURAN MULTICERVIÇOS V7.4 — ONBOARDING EM ETAPAS
-- Execute UMA VEZ no Supabase > SQL Editor antes do deploy V7.4.
-- Não apaga contas nem conteúdos existentes.
-- ============================================================

alter table public.professional_profiles
  add column if not exists birth_date date,
  add column if not exists id_number text default '',
  add column if not exists validation_submitted_at timestamptz;

-- A conta pode existir antes de o perfil ser enviado à moderação.
alter table public.professional_profiles
  drop constraint if exists professional_profiles_status_check;

alter table public.professional_profiles
  add constraint professional_profiles_status_check
  check (status in ('draft','pending','approved','rejected','suspended'));

create index if not exists idx_professional_profiles_validation
  on public.professional_profiles(status, verification_status, created_at desc);

-- Mantém os perfis antigos intactos. Apenas normaliza valores nulos dos novos campos.
update public.professional_profiles
set id_number = ''
where id_number is null;
