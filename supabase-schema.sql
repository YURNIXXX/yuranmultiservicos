-- ============================================================
-- SUPABASE: banco + armazenamento do site
-- Execute este SQL no SQL Editor do seu projeto Supabase.
-- ============================================================

create table if not exists public.site_content (
  id text primary key,
  content jsonb not null,
  updated_at timestamptz not null default now()
);

-- Bucket público para imagens e CVs.
insert into storage.buckets (id, name, public)
values ('uploads', 'uploads', true)
on conflict (id) do update set public = true;

-- O servidor usa a SERVICE ROLE KEY para gravar os arquivos.
-- As políticas abaixo permitem que os arquivos públicos sejam
-- visualizados pelo site sem autenticação.
create policy if not exists "uploads public read"
on storage.objects for select
using (bucket_id = 'uploads');
