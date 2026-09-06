-- ============================================================
-- YURAN MULTICERVIÇOS V6.2 — ATUALIZAÇÃO SOBRE A V6.1
-- Execute UMA VEZ no Supabase > SQL Editor.
-- Não apaga os dados existentes.
-- ============================================================

create extension if not exists pgcrypto;

-- Login Google + rastreio do método de autenticação.
alter table public.professional_users add column if not exists google_sub text;
alter table public.professional_users add column if not exists auth_provider text not null default 'password';
create unique index if not exists uq_professional_users_google_sub on public.professional_users(google_sub) where google_sub is not null;

-- Dados obrigatórios, verificação de identidade e medidas disciplinares.
alter table public.professional_profiles add column if not exists address text default '';
alter table public.professional_profiles add column if not exists verification_status text not null default 'pending';
alter table public.professional_profiles add column if not exists verification_reason text default '';
alter table public.professional_profiles add column if not exists id_front_path text default '';
alter table public.professional_profiles add column if not exists id_back_path text default '';
alter table public.professional_profiles add column if not exists identity_submitted_at timestamptz;
alter table public.professional_profiles add column if not exists identity_verified_at timestamptz;
alter table public.professional_profiles add column if not exists warning_count integer not null default 0;
alter table public.professional_profiles add column if not exists last_warning text default '';
alter table public.professional_profiles add column if not exists suspended_until timestamptz;
alter table public.professional_profiles add column if not exists suspension_reason text default '';
alter table public.professional_profiles add column if not exists pre_suspension_status text default '';

-- Conteúdos escolhidos pelo administrador para destaque.
alter table public.professional_services add column if not exists featured boolean not null default false;
alter table public.professional_projects add column if not exists featured boolean not null default false;

-- Métricas de visualizações e cliques de contacto.
create table if not exists public.professional_events (
  id uuid primary key,
  professional_id uuid not null references public.professional_profiles(id) on delete cascade,
  service_id uuid references public.professional_services(id) on delete set null,
  event_type text not null,
  channel text default '',
  scope_key text not null default 'general',
  visitor_hash text not null,
  event_day date not null default current_date,
  created_at timestamptz not null default now(),
  unique (professional_id, event_type, scope_key, visitor_hash, event_day)
);
create index if not exists idx_professional_events_professional on public.professional_events(professional_id, event_type);

-- Avaliações: atendimento geral ou serviço específico.
create table if not exists public.professional_ratings (
  id uuid primary key,
  professional_id uuid not null references public.professional_profiles(id) on delete cascade,
  service_id uuid references public.professional_services(id) on delete set null,
  scope_key text not null default 'general',
  stars integer not null check (stars between 1 and 5),
  comment text default '',
  visitor_hash text not null,
  status text not null default 'published',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (professional_id, scope_key, visitor_hash)
);
create index if not exists idx_professional_ratings_professional on public.professional_ratings(professional_id, status);

-- Denúncias contra profissionais.
create table if not exists public.professional_reports (
  id uuid primary key,
  professional_id uuid not null references public.professional_profiles(id) on delete cascade,
  reason text not null,
  details text default '',
  reporter_contact text default '',
  visitor_hash text default '',
  status text not null default 'open',
  admin_action text default '',
  created_at timestamptz not null default now(),
  reviewed_at timestamptz
);
create index if not exists idx_professional_reports_status on public.professional_reports(status, created_at desc);
create index if not exists idx_professional_reports_professional on public.professional_reports(professional_id);

-- Recuperação de senha mediada pela administração enquanto não há provedor SMTP próprio.
create table if not exists public.password_reset_requests (
  id uuid primary key,
  professional_id uuid not null references public.professional_profiles(id) on delete cascade,
  email text not null,
  whatsapp text not null,
  status text not null default 'pending',
  created_at timestamptz not null default now(),
  resolved_at timestamptz
);
create index if not exists idx_password_reset_requests_status on public.password_reset_requests(status, created_at desc);

-- Bucket PRIVADO para documentos de identificação.
-- Os documentos NÃO recebem URL pública. O painel admin usa links assinados de 10 minutos.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'verification-documents',
  'verification-documents',
  false,
  10485760,
  array['image/jpeg','image/png','image/webp','application/pdf']::text[]
)
on conflict (id) do update set
  public = false,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

-- A aplicação usa SERVICE ROLE no backend; acesso direto anônimo fica bloqueado.
alter table public.professional_events enable row level security;
alter table public.professional_ratings enable row level security;
alter table public.professional_reports enable row level security;
alter table public.password_reset_requests enable row level security;
