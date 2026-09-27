-- Existing public tables are retained; browser access to admin data is removed.
-- The Vercel /admin API uses its server-only Supabase secret after validating
-- the signed, HttpOnly administrator session.

create table if not exists public.reservations (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  name text not null,
  phone text not null,
  route text,
  dest text,
  plate text,
  car text,
  people text,
  golf text,
  note text,
  in_date date,
  in_time text,
  out_date date,
  out_time text,
  status text not null default '접수대기'
);

create table if not exists public.stats (
  date date primary key,
  uniq integer not null default 0,
  pv integer not null default 0,
  updated_at timestamptz not null default now(),
  mobile_pv integer not null default 0,
  pc_pv integer not null default 0
);

create table if not exists public.referrer_stats (
  date date not null,
  source text not null,
  pv integer not null default 0,
  updated_at timestamptz not null default now(),
  primary key (date, source)
);

create or replace function public.mask_name_(p_name text)
returns text language sql immutable
as $function$
  select case
    when p_name is null or length(p_name) <= 1 then p_name
    when length(p_name) = 2 then left(p_name, 1) || '*'
    else left(p_name, 1) || repeat('*', length(p_name) - 2) || right(p_name, 1)
  end;
$function$;

create or replace function public.mask_phone_(p_phone text)
returns text language sql immutable
as $function$
  select case
    when p_phone is null then null
    when length(digits) < 4 then '****'
    else left(digits, length(digits) - 4) || '****'
  end
  from (select regexp_replace(p_phone, '\D', '', 'g') as digits) as normalized;
$function$;

create or replace function public.mask_plate_(p_plate text)
returns text language sql immutable
as $function$
  select case
    when p_plate is null or length(p_plate) <= 2 then p_plate
    else left(p_plate, length(p_plate) - 2) || '**'
  end;
$function$;

create or replace function public.public_preview()
returns table("createdAt" bigint, name text, phone text, plate text, status text)
language sql stable security definer
set search_path = pg_catalog, public
as $function$
  select (extract(epoch from r.created_at) * 1000)::bigint,
         public.mask_name_(r.name), public.mask_phone_(r.phone),
         public.mask_plate_(r.plate), r.status
  from public.reservations as r
  order by r.created_at desc
  limit 10;
$function$;

alter table public.reservations enable row level security;
alter table public.stats enable row level security;
alter table public.referrer_stats enable row level security;

drop policy if exists "authenticated can select reservations" on public.reservations;
drop policy if exists "authenticated can update reservations" on public.reservations;
drop policy if exists "authenticated can select stats" on public.stats;
drop policy if exists "authenticated can select referrer_stats" on public.referrer_stats;

revoke all on table public.reservations from anon, authenticated;
revoke all on table public.stats from anon, authenticated;
revoke all on table public.referrer_stats from anon, authenticated;

create or replace function public.create_reservation(p_data jsonb)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public
as $function$
declare
  new_id uuid;
begin
  if p_data is null
    or nullif(trim(p_data->>'name'), '') is null
    or nullif(trim(p_data->>'phone'), '') is null
    or nullif(trim(p_data->>'dest'), '') is null
    or nullif(trim(p_data->>'plate'), '') is null
    or nullif(trim(p_data->>'car'), '') is null
    or nullif(trim(p_data->>'inDate'), '') is null
    or nullif(trim(p_data->>'outDate'), '') is null then
    raise exception '필수 예약 정보를 확인해주세요.' using errcode = '22023';
  end if;

  insert into public.reservations
    (name, phone, route, dest, plate, car, people, golf, note, in_date, in_time, out_date, out_time, status)
  values (
    left(trim(p_data->>'name'), 80),
    left(trim(p_data->>'phone'), 40),
    left(coalesce(p_data->>'route', ''), 40),
    left(trim(p_data->>'dest'), 200),
    left(trim(p_data->>'plate'), 40),
    left(trim(p_data->>'car'), 100),
    left(coalesce(p_data->>'people', ''), 10),
    left(coalesce(p_data->>'golf', '0'), 10),
    left(coalesce(p_data->>'note', ''), 1000),
    nullif(p_data->>'inDate', '')::date,
    left(coalesce(p_data->>'inTime', ''), 10),
    nullif(p_data->>'outDate', '')::date,
    left(coalesce(p_data->>'outTime', ''), 10),
    '접수대기'
  )
  returning id into new_id;
  return new_id;
end;
$function$;

create or replace function public.lookup_reservation(p_name text, p_last4 text)
returns table(
  id uuid,
  "createdAt" bigint,
  name text,
  phone text,
  route text,
  dest text,
  plate text,
  car text,
  people text,
  golf text,
  note text,
  "inDate" date,
  "inTime" text,
  "outDate" date,
  "outTime" text,
  status text
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $function$
  select r.id,
         (extract(epoch from r.created_at) * 1000)::bigint,
         r.name, r.phone, r.route, r.dest, r.plate, r.car, r.people, r.golf, r.note,
         r.in_date, r.in_time, r.out_date, r.out_time, r.status
  from public.reservations as r
  where nullif(trim(p_name), '') is not null
    and length(regexp_replace(coalesce(p_last4, ''), '\D', '', 'g')) = 4
    and trim(r.name) = trim(p_name)
    and right(regexp_replace(r.phone, '\D', '', 'g'), 4) = regexp_replace(p_last4, '\D', '', 'g')
  order by r.created_at desc
  limit 20;
$function$;

create or replace function public.track_visit(
  p_is_new_uniq boolean,
  p_is_mobile boolean default false,
  p_source text default '기타'
)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public
as $function$
declare
  today date := current_date;
  src text := left(coalesce(nullif(trim(p_source), ''), '기타'), 80);
begin
  insert into public.stats(date, uniq, pv, mobile_pv, pc_pv, updated_at)
  values (today, case when coalesce(p_is_new_uniq, false) then 1 else 0 end, 1,
          case when coalesce(p_is_mobile, false) then 1 else 0 end,
          case when coalesce(p_is_mobile, false) then 0 else 1 end, now())
  on conflict (date) do update
    set pv = public.stats.pv + 1,
        uniq = public.stats.uniq + case when coalesce(p_is_new_uniq, false) then 1 else 0 end,
        mobile_pv = public.stats.mobile_pv + case when coalesce(p_is_mobile, false) then 1 else 0 end,
        pc_pv = public.stats.pc_pv + case when coalesce(p_is_mobile, false) then 0 else 1 end,
        updated_at = now();

  insert into public.referrer_stats(date, source, pv, updated_at)
  values (today, src, 1, now())
  on conflict (date, source) do update
    set pv = public.referrer_stats.pv + 1, updated_at = now();
end;
$function$;

revoke all on function public.create_reservation(jsonb) from public;
revoke all on function public.lookup_reservation(text, text) from public;
revoke all on function public.public_preview() from public;
revoke all on function public.track_visit(boolean, boolean, text) from public;

grant execute on function public.create_reservation(jsonb) to anon, authenticated;
grant execute on function public.lookup_reservation(text, text) to anon, authenticated;
grant execute on function public.public_preview() to anon, authenticated;
grant execute on function public.track_visit(boolean, boolean, text) to anon, authenticated;
