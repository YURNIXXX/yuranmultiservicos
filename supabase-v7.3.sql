-- ============================================================
-- YURAN MULTICERVIÇOS V7.3 — ESTABILIDADE, PERFIS OFICIAIS E SEGURANÇA
-- Execute UMA VEZ no Supabase > SQL Editor antes do deploy V7.3.
-- Não apaga dados existentes.
-- ============================================================

-- Perfis institucionais / fundador. Estes campos só são alterados pelo backend administrativo.
alter table public.professional_profiles
  add column if not exists profile_type text not null default 'professional',
  add column if not exists institutional_role text default '',
  add column if not exists official_profile boolean not null default false,
  add column if not exists founder_message text default '';

do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'professional_profiles_profile_type_check'
  ) then
    alter table public.professional_profiles
      add constraint professional_profiles_profile_type_check
      check (profile_type in ('professional','team','founder','institutional'));
  end if;
end $$;

create index if not exists idx_professional_profiles_type
  on public.professional_profiles(profile_type, status);

-- Hardening: todas as tabelas sensíveis são acessadas apenas pelo backend com SERVICE ROLE.
alter table public.site_content enable row level security;
alter table public.professional_users enable row level security;
alter table public.professional_profiles enable row level security;
alter table public.professional_services enable row level security;
alter table public.professional_projects enable row level security;
alter table public.moderation_logs enable row level security;
alter table public.professional_events enable row level security;
alter table public.professional_ratings enable row level security;
alter table public.professional_reports enable row level security;
alter table public.password_reset_requests enable row level security;
alter table public.professional_notifications enable row level security;
alter table public.app_sessions enable row level security;
alter table public.admin_email_logs enable row level security;

-- Defesa adicional: clientes anon/authenticated não recebem acesso direto às tabelas sensíveis.
-- O backend usa a SERVICE ROLE e continua a funcionar normalmente.
revoke all on table public.site_content from anon, authenticated;
revoke all on table public.professional_users from anon, authenticated;
revoke all on table public.professional_profiles from anon, authenticated;
revoke all on table public.professional_services from anon, authenticated;
revoke all on table public.professional_projects from anon, authenticated;
revoke all on table public.moderation_logs from anon, authenticated;
revoke all on table public.professional_events from anon, authenticated;
revoke all on table public.professional_ratings from anon, authenticated;
revoke all on table public.professional_reports from anon, authenticated;
revoke all on table public.password_reset_requests from anon, authenticated;
revoke all on table public.professional_notifications from anon, authenticated;
revoke all on table public.app_sessions from anon, authenticated;
revoke all on table public.admin_email_logs from anon, authenticated;

-- O bucket de documentos deve permanecer privado e aceitar apenas tipos seguros.
update storage.buckets
set public = false,
    file_size_limit = 10485760,
    allowed_mime_types = array['image/jpeg','image/png','image/webp','application/pdf']::text[]
where id = 'verification-documents';
