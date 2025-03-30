DROP POLICY IF EXISTS "Users can read their own HWID" ON public.registered_hwids;
DROP POLICY IF EXISTS "Service can manage HWIDs" ON public.registered_hwids;

DROP TRIGGER IF EXISTS update_registered_hwids_updated_at ON public.registered_hwids;

ALTER TABLE public.registered_hwids SET SCHEMA auth;

CREATE POLICY "Users can read their own HWID"
ON auth.registered_hwids
AS PERMISSIVE
FOR SELECT
TO authenticated
USING ((auth.uid() = user_id));

CREATE POLICY "Service can manage HWIDs"
ON auth.registered_hwids
AS PERMISSIVE
FOR ALL
TO service_role
USING (true);

CREATE TRIGGER update_registered_hwids_updated_at
BEFORE UPDATE ON auth.registered_hwids
FOR EACH ROW
EXECUTE FUNCTION public.update_updated_at_column();

ALTER TABLE auth.registered_hwids ENABLE ROW LEVEL SECURITY;
