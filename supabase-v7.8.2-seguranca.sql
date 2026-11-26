-- Execute no SQL Editor do Supabase antes da versão 7.8.2.
-- Mantém dados e assegura que a chave pública não acede às tabelas privadas.
do $$
declare table_name text;
begin
  foreach table_name in array array[
    'site_content', 'professional_users', 'professional_profiles',
    'professional_services', 'professional_projects', 'moderation_logs',
    'professional_events', 'professional_ratings', 'professional_reports',
    'password_reset_requests', 'professional_notifications', 'app_sessions',
    'admin_email_logs', 'search_analytics'
  ] loop
    if to_regclass(format('public.%I', table_name)) is not null then
      execute format('alter table public.%I enable row level security', table_name);
      execute format('revoke all on table public.%I from anon, authenticated', table_name);
    end if;
  end loop;
end $$;

-- Documentos de identidade têm de ficar num bucket privado.
update storage.buckets
set public = false,
    file_size_limit = 10485760,
    allowed_mime_types = array['image/jpeg','image/png','image/webp','application/pdf']::text[]
where id = 'verification-documents';

-- Inspecione em Storage se o bucket privado configurado em
-- SUPABASE_VERIFICATION_BUCKET tiver outro nome.
