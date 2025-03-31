CREATE OR REPLACE FUNCTION auth.update_user_role_metadata()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
  role_types jsonb;
BEGIN
  SELECT jsonb_agg(r.role_type)
  INTO role_types
  FROM auth.roles r
  JOIN auth.user_roles ur ON r.id = ur.role_id
  WHERE ur.user_id = COALESCE(NEW.user_id, OLD.user_id);

  UPDATE auth.users
  SET raw_app_meta_data = 
    CASE 
      WHEN raw_app_meta_data IS NULL THEN 
        jsonb_build_object(
          'roles', COALESCE(role_types, '[]'::jsonb),
          'roles_updated_at', extract(epoch from now())::bigint
        )
      ELSE
        raw_app_meta_data || jsonb_build_object(
          'roles', COALESCE(role_types, '[]'::jsonb),
          'roles_updated_at', extract(epoch from now())::bigint
        )
    END
  WHERE id = COALESCE(NEW.user_id, OLD.user_id);
  
  RETURN NEW;
END;
$$;

CREATE TRIGGER update_jwt_with_roles
AFTER INSERT OR UPDATE OR DELETE ON auth.user_roles
FOR EACH ROW EXECUTE FUNCTION auth.update_user_role_metadata();

CREATE OR REPLACE FUNCTION auth.initialize_user_role_metadata()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  INSERT INTO auth.user_roles (user_id, role_id)
  SELECT NEW.id, id FROM auth.roles WHERE role_type = 'player' LIMIT 1;
  
  RETURN NEW;
END;
$$;

CREATE TRIGGER initialize_new_user_roles
AFTER INSERT ON auth.users
FOR EACH ROW EXECUTE FUNCTION auth.initialize_user_role_metadata();