-- YURAN MULTICERVIÇOS V6.1 — executar uma vez no SQL Editor do Supabase.
create extension if not exists pgcrypto;

create table if not exists public.professional_users (
  id uuid primary key,
  email text not null unique,
  password_hash text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.professional_profiles (
  id uuid primary key,
  user_id uuid not null unique references public.professional_users(id) on delete cascade,
  name text not null,
  slug text not null unique,
  email text,
  photo text default '',
  specialty text default '',
  bio text default '',
  location text default '',
  phone text default '',
  whatsapp text default '',
  website text default '',
  linkedin text default '',
  instagram text default '',
  cv_url text default '',
  status text not null default 'pending' check (status in ('pending','approved','rejected','suspended')),
  rejection_reason text default '',
  verified boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.professional_services (
  id uuid primary key,
  professional_id uuid not null references public.professional_profiles(id) on delete cascade,
  title text not null,
  slug text not null,
  category text default '',
  description text default '',
  price text default '',
  status text not null default 'pending' check (status in ('pending','approved','rejected','suspended')),
  rejection_reason text default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.professional_projects (
  id uuid primary key,
  professional_id uuid not null references public.professional_profiles(id) on delete cascade,
  title text not null,
  slug text not null,
  description text default '',
  project_url text default '',
  images jsonb not null default '[]'::jsonb,
  status text not null default 'pending' check (status in ('pending','approved','rejected','suspended')),
  rejection_reason text default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.moderation_logs (
  id uuid primary key,
  target_type text not null,
  target_id uuid not null,
  action text not null,
  reason text default '',
  created_at timestamptz not null default now()
);

create index if not exists idx_professional_profiles_status on public.professional_profiles(status);
create index if not exists idx_professional_services_professional on public.professional_services(professional_id, status);
create index if not exists idx_professional_projects_professional on public.professional_projects(professional_id, status);

-- O backend usa SERVICE ROLE. Bloqueamos acesso direto anônimo às tabelas sensíveis.
alter table public.professional_users enable row level security;
alter table public.professional_profiles enable row level security;
alter table public.professional_services enable row level security;
alter table public.professional_projects enable row level security;
alter table public.moderation_logs enable row level security;
