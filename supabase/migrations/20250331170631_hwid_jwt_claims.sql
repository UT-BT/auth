UPDATE auth.users u
SET raw_app_meta_data = CASE 
    WHEN raw_app_meta_data IS NULL THEN 
        jsonb_build_object(
            'hwid', (SELECT hwid FROM auth.registered_hwids WHERE user_id = u.id),
            'hwid_updated_at', extract(epoch from now())::bigint
        )
    ELSE
        raw_app_meta_data || jsonb_build_object(
            'hwid', (SELECT hwid FROM auth.registered_hwids WHERE user_id = u.id),
            'hwid_updated_at', extract(epoch from now())::bigint
        )
    END
FROM auth.registered_hwids rh
WHERE u.id = rh.user_id;

CREATE OR REPLACE FUNCTION auth.update_user_hwid_metadata()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        UPDATE auth.users
        SET raw_app_meta_data = 
            CASE 
                WHEN raw_app_meta_data IS NULL THEN 
                    jsonb_build_object(
                        'hwid', NULL,
                        'hwid_updated_at', extract(epoch from now())::bigint
                    )
                ELSE
                    raw_app_meta_data || jsonb_build_object(
                        'hwid', NULL,
                        'hwid_updated_at', extract(epoch from now())::bigint
                    )
            END
        WHERE id = OLD.user_id;
        
        RETURN OLD;
    ELSE
        UPDATE auth.users
        SET raw_app_meta_data = 
            CASE 
                WHEN raw_app_meta_data IS NULL THEN 
                    jsonb_build_object(
                        'hwid', NEW.hwid,
                        'hwid_updated_at', extract(epoch from now())::bigint
                    )
                ELSE
                    raw_app_meta_data || jsonb_build_object(
                        'hwid', NEW.hwid,
                        'hwid_updated_at', extract(epoch from now())::bigint
                    )
            END
        WHERE id = NEW.user_id;
        
        RETURN NEW;
    END IF;
END;
$$;

DROP TRIGGER IF EXISTS update_jwt_with_hwid ON auth.registered_hwids;

CREATE TRIGGER update_jwt_with_hwid
AFTER INSERT OR UPDATE OR DELETE ON auth.registered_hwids
FOR EACH ROW EXECUTE FUNCTION auth.update_user_hwid_metadata();