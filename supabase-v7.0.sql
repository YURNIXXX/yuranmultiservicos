-- ============================================================
-- YURAN MULTICERVIÇOS V7.0 — PROFISSIONALIZAÇÃO DA PLATAFORMA
-- Execute UMA VEZ no Supabase > SQL Editor, ANTES do deploy V7.0.
-- Não apaga os dados existentes.
-- ============================================================

create extension if not exists pgcrypto;

-- Perfil profissional mais completo e indicadores de confiança.
alter table public.professional_profiles add column if not exists featured boolean not null default false;
alter table public.professional_profiles add column if not exists headline text default '';
alter table public.professional_profiles add column if not exists years_experience integer not null default 0;
alter table public.professional_profiles add column if not exists service_area text default '';
alter table public.professional_profiles add column if not exists availability text not null default 'available';
alter table public.professional_profiles add column if not exists languages text default '';
alter table public.professional_profiles add column if not exists skills text default '';
alter table public.professional_profiles add column if not exists certifications text default '';
alter table public.professional_profiles add column if not exists response_time_label text default '';
alter table public.professional_profiles add column if not exists profile_completeness integer not null default 0;
alter table public.professional_profiles add column if not exists last_active_at timestamptz default now();
alter table public.professional_profiles add column if not exists terms_accepted_at timestamptz;
alter table public.professional_profiles add column if not exists privacy_accepted_at timestamptz;
alter table public.professional_profiles add column if not exists identity_retention_until timestamptz;
alter table public.professional_profiles add column if not exists identity_documents_deleted_at timestamptz;

-- Serviços profissionais com informação mais útil para o cliente.
alter table public.professional_services add column if not exists service_area text default '';
alter table public.professional_services add column if not exists availability text not null default 'available';
alter table public.professional_services add column if not exists delivery_time text default '';
alter table public.professional_services add column if not exists cover_image text default '';

-- Projetos ligados a um serviço, quando aplicável.
alter table public.professional_projects add column if not exists service_id uuid references public.professional_services(id) on delete set null;
create index if not exists idx_professional_projects_service on public.professional_projects(service_id);

-- Avaliações com resposta pública do profissional e marca de interação real.
alter table public.professional_ratings add column if not exists professional_reply text default '';
alter table public.professional_ratings add column if not exists replied_at timestamptz;
alter table public.professional_ratings add column if not exists verified_interaction boolean not null default false;

-- Protocolo para denúncias.
alter table public.professional_reports add column if not exists protocol text;
create unique index if not exists uq_professional_reports_protocol on public.professional_reports(protocol) where protocol is not null;

-- Centro de notificações do profissional.
create table if not exists public.professional_notifications (
  id uuid primary key,
  professional_id uuid not null references public.professional_profiles(id) on delete cascade,
  type text not null default 'info',
  title text not null,
  message text not null default '',
  link text default '',
  read_at timestamptz,
  email_sent boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists idx_professional_notifications_owner on public.professional_notifications(professional_id, created_at desc);
create index if not exists idx_professional_notifications_unread on public.professional_notifications(professional_id, read_at) where read_at is null;

-- Sessões persistentes: evita logout em restart/redeploy do Render.
create table if not exists public.app_sessions (
  sid text primary key,
  sess jsonb not null,
  expire timestamptz not null,
  updated_at timestamptz not null default now()
);
create index if not exists idx_app_sessions_expire on public.app_sessions(expire);

-- Recuperação de senha por link seguro (quando e-mail transacional estiver configurado).
alter table public.password_reset_requests add column if not exists token_hash text default '';
alter table public.password_reset_requests add column if not exists expires_at timestamptz;
alter table public.password_reset_requests add column if not exists used_at timestamptz;
create index if not exists idx_password_reset_token on public.password_reset_requests(token_hash) where token_hash <> '';

-- Logs administrativos mais completos.
alter table public.moderation_logs add column if not exists metadata jsonb not null default '{}'::jsonb;

-- Índices de pesquisa / descoberta.
create index if not exists idx_professional_profiles_featured on public.professional_profiles(featured, status);
create index if not exists idx_professional_profiles_availability on public.professional_profiles(availability, status);
create index if not exists idx_professional_services_category on public.professional_services(category, status);

-- RLS: o backend usa SERVICE ROLE; acesso direto anónimo continua bloqueado.
alter table public.professional_notifications enable row level security;
alter table public.app_sessions enable row level security;

-- Preenche uma percentagem inicial aproximada para perfis já existentes.
update public.professional_profiles
set profile_completeness = least(100,
    (case when coalesce(name,'') <> '' then 5 else 0 end) +
    (case when coalesce(specialty,'') <> '' then 10 else 0 end) +
    (case when length(coalesce(bio,'')) >= 80 then 15 else 0 end) +
    (case when coalesce(location,'') <> '' then 10 else 0 end) +
    (case when coalesce(photo,'') <> '' then 15 else 0 end) +
    (case when coalesce(phone,'') <> '' then 5 else 0 end) +
    (case when coalesce(whatsapp,'') <> '' then 5 else 0 end) +
    (case when coalesce(service_area,'') <> '' then 10 else 0 end) +
    (case when coalesce(skills,'') <> '' then 10 else 0 end) +
    (case when coalesce(years_experience,0) > 0 then 5 else 0 end) +
    (case when coalesce(cv_url,'') <> '' then 10 else 0 end)
);
