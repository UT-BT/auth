create table "public"."registered_hwids" (
    "id" uuid not null default uuid_generate_v4(),
    "user_id" uuid not null,
    "hwid" text not null,
    "created_at" timestamp with time zone default now(),
    "updated_at" timestamp with time zone default now()
);


alter table "public"."registered_hwids" enable row level security;

CREATE UNIQUE INDEX registered_hwids_pkey ON public.registered_hwids USING btree (id);

CREATE UNIQUE INDEX unique_user_hwid ON public.registered_hwids USING btree (user_id);

alter table "public"."registered_hwids" add constraint "registered_hwids_pkey" PRIMARY KEY using index "registered_hwids_pkey";

alter table "public"."registered_hwids" add constraint "registered_hwids_user_id_fkey" FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE not valid;

alter table "public"."registered_hwids" validate constraint "registered_hwids_user_id_fkey";

alter table "public"."registered_hwids" add constraint "unique_user_hwid" UNIQUE using index "unique_user_hwid";

set check_function_bodies = off;

CREATE OR REPLACE FUNCTION public.update_updated_at_column()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
begin
    new.updated_at = now();
    return new;
end;
$function$
;

drop policy if exists "Users can read their own HWID" on "public"."registered_hwids";

create policy "Users can read their own HWID"
on "public"."registered_hwids"
as permissive
for select
to authenticated
using ((auth.uid() = user_id));

create policy "Service can manage HWIDs"
on "public"."registered_hwids"
as permissive
for all
to service_role
using (true);


CREATE TRIGGER update_registered_hwids_updated_at BEFORE UPDATE ON public.registered_hwids FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
