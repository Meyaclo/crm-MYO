-- =====================================================================
-- CRM Meyaclo — Sécurité de la base (à coller dans Supabase → SQL Editor → Run)
-- Le script peut être relancé sans risque.
-- =====================================================================

-- ---------- ÉTAPE 0 : DIAGNOSTIC (lancez ces 2 requêtes seules d'abord, pour voir l'état actuel) ----------
-- select relname, relrowsecurity as rls_active from pg_class where relname = 'records' and relnamespace = 'public'::regnamespace;
-- select policyname, roles, cmd, qual, with_check from pg_policies where schemaname = 'public' and tablename = 'records';
-- Si rls_active = false, ou si une règle cite le rôle "anon" ou "public" : la base est lisible par n'importe qui.

begin;

-- ---------- 1. Table records : accès réservé aux membres connectés ----------
alter table public.records enable row level security;

do $$ declare p record; begin
  for p in select policyname from pg_policies where schemaname = 'public' and tablename = 'records' loop
    execute format('drop policy %I on public.records', p.policyname);
  end loop;
end $$;

create policy "equipe_lecture"     on public.records for select to authenticated using (true);
create policy "equipe_ajout"       on public.records for insert to authenticated with check (true);
create policy "equipe_modification" on public.records for update to authenticated using (true) with check (true);
create policy "equipe_suppression" on public.records for delete to authenticated using (true);

revoke all on public.records from anon;

-- ---------- 2. Administrateur ----------
-- Table invisible depuis le navigateur (RLS active, aucune règle).
create table if not exists public.admins (email text primary key);
alter table public.admins enable row level security;
revoke all on public.admins from anon, authenticated;

-- ⚠️ Mettez ici l'e-mail avec lequel VOUS vous connectez au CRM
insert into public.admins (email) values ('vad.meyaclo@gmail.com') on conflict do nothing;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.admins where lower(email) = lower(auth.jwt() ->> 'email'));
$$;
revoke all on function public.is_admin() from public, anon;
grant execute on function public.is_admin() to authenticated;

-- ---------- 3. Effacement total réservé à l'administrateur (utilisé par « Restaurer une sauvegarde ») ----------
create or replace function public.admin_wipe_records() returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then
    raise exception 'Restauration réservée à l''administrateur';
  end if;
  delete from public.records where true;
end $$;
revoke all on function public.admin_wipe_records() from public, anon;
grant execute on function public.admin_wipe_records() to authenticated;

-- ---------- 4. Corbeille : toute fiche supprimée (par n'importe qui) est conservée ----------
create table if not exists public.records_trash (like public.records);
alter table public.records_trash add column if not exists deleted_at timestamptz default now();
alter table public.records_trash add column if not exists deleted_by text;
alter table public.records_trash enable row level security;
revoke all on public.records_trash from anon, authenticated;

create or replace function public.trash_record() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.records_trash select (old).*, now(), auth.jwt() ->> 'email';
  return old;
end $$;

drop trigger if exists trg_records_trash on public.records;
create trigger trg_records_trash before delete on public.records
  for each row execute function public.trash_record();

commit;

-- ---------- Pour retrouver une fiche supprimée (à lancer au besoin) ----------
-- select deleted_at, deleted_by, kind, data->>'name' as nom, data->>'title' as objet
--   from public.records_trash order by deleted_at desc limit 50;
-- Remettre une fiche :  insert into public.records (id, kind, data)
--   select id, kind, data from public.records_trash where id = 'ID_DE_LA_FICHE' order by deleted_at desc limit 1
--   on conflict (id) do update set data = excluded.data;
