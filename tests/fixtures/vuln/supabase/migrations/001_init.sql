create table public.profiles (
  id uuid primary key,
  user_id uuid not null,
  email text,
  password text,
  cpf text,
  date_of_birth date
);

create policy "read" on public.profiles for select using (true);
