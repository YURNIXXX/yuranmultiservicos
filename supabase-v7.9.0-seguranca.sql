-- Executar UMA VEZ no SQL Editor do Supabase ANTES do deploy v7.9.0.
-- Não contém senhas nem elimina projetos. O bucket de documentos é privado.

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('verification-documents', 'verification-documents', false, 12582912,
        array['image/jpeg','image/png','image/webp','application/pdf']::text[])
on conflict (id) do update set public = false, file_size_limit = 12582912,
    allowed_mime_types = excluded.allowed_mime_types;
drop policy if exists "yuran_no_public_private_docs" on storage.objects;
create policy "yuran_no_public_private_docs" on storage.objects as restrictive
for select to anon, authenticated using (bucket_id <> 'verification-documents');

-- Aplicar também a migração supabase-v7.8.2-seguranca.sql se ainda não o fez.
-- Se SUPABASE_VERIFICATION_BUCKET tiver outro nome, torne ESSE bucket privado.
alter table public.professional_users add column if not exists password_change_required boolean not null default false;
do $$
declare table_name text;
begin
  foreach table_name in array array[
    'site_content','professional_users','professional_profiles','professional_services',
    'professional_projects','professional_events','professional_ratings','professional_reports',
    'professional_notifications','password_reset_requests','moderation_logs','app_sessions',
    'admin_email_logs','search_analytics'
  ] loop
    if to_regclass(format('public.%I', table_name)) is not null then
      execute format('alter table public.%I enable row level security', table_name);
      execute format('revoke all on table public.%I from anon, authenticated', table_name);
    end if;
  end loop;
end $$;

create table if not exists public.security_rate_limits (
  key_hash text primary key,
  hits integer not null,
  reset_at timestamptz not null
);
create index if not exists idx_security_rate_limits_reset on public.security_rate_limits(reset_at);
alter table public.security_rate_limits enable row level security;
revoke all on table public.security_rate_limits from anon, authenticated;
grant all on table public.security_rate_limits to service_role;

-- Registo durável das remoções públicas entre a atualização da referência e
-- a remoção do objeto no Storage. Um reinício retoma estas pendências.
create table if not exists public.security_media_cleanup (
  public_path text primary key,
  public_url text not null,
  kind text not null check (kind in ('cv', 'project')),
  created_at timestamptz not null default now()
);
alter table public.security_media_cleanup enable row level security;
revoke all on table public.security_media_cleanup from anon, authenticated;
grant all on table public.security_media_cleanup to service_role;

create or replace function public.security_rate_check(p_key text, p_limit integer, p_window_seconds integer)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare result public.security_rate_limits%rowtype;
begin
  if length(p_key) <> 64 or p_limit < 1 or p_limit > 1000 or p_window_seconds < 1 or p_window_seconds > 86400 then
    raise exception 'Parâmetros de segurança inválidos';
  end if;
  insert into public.security_rate_limits as existing (key_hash, hits, reset_at)
  values (p_key, 1, now() + make_interval(secs => p_window_seconds))
  on conflict (key_hash) do update set
    hits = case when existing.reset_at <= now() then 1 else existing.hits + 1 end,
    reset_at = case when existing.reset_at <= now() then now() + make_interval(secs => p_window_seconds) else existing.reset_at end
  returning * into result;
  return jsonb_build_object('allowed', result.hits <= p_limit,
    'retry_after', greatest(1, ceil(extract(epoch from result.reset_at - now()))::integer));
end;
$$;
revoke all on function public.security_rate_check(text, integer, integer) from public, anon, authenticated;
grant execute on function public.security_rate_check(text, integer, integer) to service_role;

create or replace function public.professional_event_metrics(p_professional_id uuid)
returns jsonb language sql stable security definer set search_path = public, pg_temp as $$
  select jsonb_build_object(
    'views', count(distinct visitor_hash) filter (where event_type = 'view'),
    'contacts', count(distinct visitor_hash) filter (where event_type = 'contact'))
  from public.professional_events where professional_id = p_professional_id;
$$;
revoke all on function public.professional_event_metrics(uuid) from public, anon, authenticated;
grant execute on function public.professional_event_metrics(uuid) to service_role;
create index if not exists idx_professional_events_metrics
  on public.professional_events(professional_id, event_type, visitor_hash);

create or replace function public.security_private_media_pending()
returns jsonb language sql stable security definer set search_path = public, pg_temp as $$
  select jsonb_build_object(
    'public_cvs', (select count(*) from public.professional_profiles
      where cv_url like '%/storage/v1/object/public/%/cvs/%'),
    'public_cv_objects', (select count(*) from storage.objects
      where bucket_id = 'uploads' and name like 'cvs/%'),
    'pending_public_images', (select count(*) from public.professional_projects p
      cross join lateral jsonb_array_elements_text(coalesce(p.images, '[]'::jsonb)) as image(value)
      where p.status <> 'approved' and image.value like '%/storage/v1/object/public/%/images/%'),
    'queued_cleanup', (select count(*) from public.security_media_cleanup));
$$;
revoke all on function public.security_private_media_pending() from public, anon, authenticated;
grant execute on function public.security_private_media_pending() to service_role;

-- O clique no botão de contacto não prova uma interação real.
update public.professional_ratings set verified_interaction = false where verified_interaction = true;

-- Limpeza de contadores expirados (executar em manutenção periódica).
delete from public.security_rate_limits where reset_at < now() - interval '1 day';
