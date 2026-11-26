-- Executar uma vez no SQL Editor do Supabase antes de publicar o código V7.8.
-- Os serviços e as ligações de projetos existentes são preservados.
alter table public.professional_projects
  add column if not exists category text;

update public.professional_projects as project
set category = service.category
from public.professional_services as service
where project.service_id = service.id
  and (project.category is null or btrim(project.category) = '');

create index if not exists idx_professional_projects_category_status
  on public.professional_projects (category, status);
