-- Table des autorisations Google durables (une par membre). Lisible uniquement par la fonction serveur.
create table if not exists public.google_tokens (
  user_id uuid primary key references auth.users(id) on delete cascade,
  email text,
  refresh_token text not null,
  updated_at timestamptz default now()
);
alter table public.google_tokens enable row level security;
-- Volontairement aucune règle (policy) : personne ne peut lire cette table depuis le navigateur.
