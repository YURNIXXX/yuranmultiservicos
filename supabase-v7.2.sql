-- ============================================================
-- YURAN MULTICERVIÇOS V7.2 — EDUCAÇÃO, COMUNICAÇÃO E ESTABILIDADE
-- Execute UMA VEZ no Supabase > SQL Editor antes do deploy V7.2.
-- Não apaga dados existentes.
-- ============================================================

alter table public.professional_profiles
  add column if not exists education jsonb not null default '[]'::jsonb;

create table if not exists public.admin_email_logs (
  id uuid primary key,
  audience text not null default 'individual',
  professional_id uuid references public.professional_profiles(id) on delete set null,
  subject text not null,
  recipient_count integer not null default 0,
  sent_count integer not null default 0,
  failed_count integer not null default 0,
  created_at timestamptz not null default now()
);

create index if not exists idx_admin_email_logs_created_at
  on public.admin_email_logs(created_at desc);

alter table public.admin_email_logs enable row level security;

-- Normaliza registos antigos, caso a coluna tenha sido criada manualmente.
update public.professional_profiles
set education = '[]'::jsonb
where education is null;
