create table public.profiles (
  id uuid primary key,
  user_id uuid not null,
  email text,
  password text
);

create policy "read" on public.profiles for select using (true);
