-- YURAN MULTICERVIÇOS V8.0 — MONETIZAÇÃO E PLANOS
-- Executar UMA VEZ no Supabase SQL Editor antes do deploy.
-- Não apaga projetos, serviços ou perfis existentes.

create extension if not exists pgcrypto;

create table if not exists public.subscription_plans (
  id uuid primary key default gen_random_uuid(),
  code text not null unique check (code in ('free','pro','pro_plus','business','business_plus')),
  name text not null,
  description text not null default '',
  monthly_price numeric(12,2) not null default 0 check (monthly_price >= 0),
  annual_price numeric(12,2) not null default 0 check (annual_price >= 0),
  currency text not null default 'MZN',
  project_limit integer not null default 5 check (project_limit >= 0),
  custom_service_limit integer not null default 0 check (custom_service_limit >= 0),
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

insert into public.subscription_plans (code,name,description,monthly_price,annual_price,project_limit,custom_service_limit)
values
 ('free','Gratuito','Comece a apresentar o seu trabalho.',0,0,5,0),
 ('pro','PRO','Para profissionais ativos.',200,2000,20,0),
 ('pro_plus','PRO+','Para profissionais avançados.',500,5000,50,0),
 ('business','Empresarial','Para empresas que querem apresentar os seus serviços e projetos.',1500,15000,100,0),
 ('business_plus','Empresarial + 5 Serviços','Plano empresarial com até 5 serviços personalizados.',2000,20000,100,5)
on conflict (code) do update set
  name=excluded.name,
  description=excluded.description,
  monthly_price=excluded.monthly_price,
  annual_price=excluded.annual_price,
  project_limit=excluded.project_limit,
  custom_service_limit=excluded.custom_service_limit,
  currency=excluded.currency,
  updated_at=now();

create table if not exists public.professional_subscriptions (
  id uuid primary key default gen_random_uuid(),
  professional_id uuid not null references public.professional_profiles(id) on delete cascade,
  plan_id uuid not null references public.subscription_plans(id),
  billing_cycle text not null default 'monthly' check (billing_cycle in ('monthly','annual')),
  status text not null default 'active' check (status in ('active','expiring','grace_period','expired','cancelled','pending')),
  started_at timestamptz not null default now(),
  current_period_start timestamptz not null default now(),
  current_period_end timestamptz not null,
  grace_period_end timestamptz,
  cancelled_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create unique index if not exists uq_professional_active_subscription on public.professional_subscriptions(professional_id) where status in ('active','expiring','grace_period','pending');
create index if not exists idx_professional_subscriptions_owner on public.professional_subscriptions(professional_id, current_period_end desc);

create table if not exists public.subscription_payments (
  id uuid primary key default gen_random_uuid(),
  subscription_id uuid references public.professional_subscriptions(id) on delete set null,
  professional_id uuid not null references public.professional_profiles(id) on delete cascade,
  plan_id uuid not null references public.subscription_plans(id),
  amount numeric(12,2) not null check (amount >= 0),
  currency text not null default 'MZN',
  billing_cycle text not null check (billing_cycle in ('monthly','annual')),
  payment_method text not null default '',
  provider text not null default '',
  provider_transaction_id text not null default '',
  status text not null default 'pending' check (status in ('pending','paid','failed','refunded','cancelled')),
  paid_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists idx_subscription_payments_owner on public.subscription_payments(professional_id, created_at desc);

create table if not exists public.subscription_history (
  id uuid primary key default gen_random_uuid(),
  professional_id uuid not null references public.professional_profiles(id) on delete cascade,
  subscription_id uuid references public.professional_subscriptions(id) on delete set null,
  from_plan text not null default '',
  to_plan text not null default '',
  action text not null,
  reason text not null default '',
  created_at timestamptz not null default now()
);
create index if not exists idx_subscription_history_owner on public.subscription_history(professional_id, created_at desc);

alter table public.professional_projects add column if not exists plan_visibility text not null default 'active' check (plan_visibility in ('active','archived_plan_limit'));
alter table public.professional_services add column if not exists is_custom boolean not null default false;
alter table public.professional_services add column if not exists plan_visibility text not null default 'active' check (plan_visibility in ('active','archived_plan_limit'));
alter table public.professional_services add column if not exists custom_description text not null default '';

create index if not exists idx_professional_projects_plan_visibility on public.professional_projects(professional_id, plan_visibility);
create index if not exists idx_professional_services_custom on public.professional_services(professional_id, is_custom, plan_visibility);

alter table public.subscription_plans enable row level security;
alter table public.professional_subscriptions enable row level security;
alter table public.subscription_payments enable row level security;
alter table public.subscription_history enable row level security;
revoke all on table public.subscription_plans, public.professional_subscriptions, public.subscription_payments, public.subscription_history from anon, authenticated;

-- Todos os dados são lidos/escritos pelo backend com SERVICE ROLE.
