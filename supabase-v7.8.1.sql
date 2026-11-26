-- Execute uma vez no SQL Editor do Supabase antes de publicar a versão 7.8.1.
-- Conserva os serviços, projetos e dados já existentes.

create table if not exists public.app_sessions (
  sid text primary key,
  sess jsonb not null,
  expire timestamptz not null,
  updated_at timestamptz not null default now()
);
create index if not exists idx_app_sessions_expire on public.app_sessions(expire);
alter table public.app_sessions enable row level security;
revoke all on table public.app_sessions from anon, authenticated;
grant all on table public.app_sessions to service_role;

alter table public.professional_projects add column if not exists category text;
update public.professional_projects as project
set category = service.category
from public.professional_services as service
where project.service_id = service.id
  and (project.category is null or btrim(project.category) = '');
create index if not exists idx_professional_projects_category_status
  on public.professional_projects (category, status);
