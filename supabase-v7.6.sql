-- Yuran Multicerviços V7.6
-- Execute uma única vez no Supabase SQL Editor antes de publicar o código V7.6.
-- Migração aditiva: não apaga perfis, serviços, avaliações nem projetos existentes.

begin;

alter table public.professional_profiles
  add column if not exists province text not null default '',
  add column if not exists district text not null default '',
  add column if not exists neighborhood text not null default '',
  add column if not exists pending_profile_changes jsonb not null default '{}'::jsonb,
  add column if not exists profile_changes_status text not null default 'none',
  add column if not exists profile_change_rejection_reason text not null default '';

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'professional_profiles_profile_changes_status_check'
      and conrelid = 'public.professional_profiles'::regclass
  ) then
    alter table public.professional_profiles
      add constraint professional_profiles_profile_changes_status_check
      check (profile_changes_status in ('none','pending','rejected'));
  end if;
end $$;

alter table public.professional_services
  add column if not exists keywords text not null default '',
  add column if not exists price_mode text not null default 'consult',
  add column if not exists price_amount numeric(12,2);


do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'professional_services_price_mode_check'
      and conrelid = 'public.professional_services'::regclass
  ) then
    alter table public.professional_services
      add constraint professional_services_price_mode_check
      check (price_mode in ('consult','price'));
  end if;
end $$;

create table if not exists public.search_analytics (
  id uuid primary key,
  query_text text not null default '',
  category text not null default '',
  location_query text not null default '',
  result_count integer not null default 0,
  created_at timestamptz not null default now()
);

create index if not exists idx_search_analytics_created_at
  on public.search_analytics (created_at desc);
create index if not exists idx_professional_profiles_location_structured
  on public.professional_profiles (province, district, neighborhood);
create index if not exists idx_professional_services_category
  on public.professional_services (category);

alter table public.search_analytics enable row level security;
revoke all on table public.search_analytics from anon, authenticated;

commit;
