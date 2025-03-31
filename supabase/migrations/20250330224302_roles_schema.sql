CREATE TYPE auth.role_type AS ENUM (
    'admin',
    'moderator',
    'map_maker',
    'streamer',
    'player'
);

CREATE TABLE auth.roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    description TEXT,
    role_type auth.role_type NOT NULL,
    discord_role_id TEXT UNIQUE,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE auth.user_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES auth.roles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(user_id, role_id)
);

CREATE INDEX idx_user_roles_user_id ON auth.user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON auth.user_roles(role_id);

CREATE TRIGGER update_roles_updated_at
BEFORE UPDATE ON auth.roles
FOR EACH ROW
EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_user_roles_updated_at
BEFORE UPDATE ON auth.user_roles
FOR EACH ROW
EXECUTE FUNCTION public.update_updated_at_column();

ALTER TABLE auth.roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth.user_roles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Anyone can read roles" 
ON auth.roles
AS PERMISSIVE
FOR SELECT
TO authenticated
USING (true);

CREATE POLICY "Service can manage roles"
ON auth.roles
AS PERMISSIVE
FOR ALL
TO service_role
USING (true);

CREATE POLICY "Users can read their own roles"
ON auth.user_roles
AS PERMISSIVE
FOR SELECT
TO authenticated
USING ((auth.uid() = user_id));

CREATE POLICY "Service can manage user roles"
ON auth.user_roles
AS PERMISSIVE
FOR ALL
TO service_role
USING (true);

INSERT INTO auth.roles (name, description, role_type, discord_role_id) VALUES
('Admin', 'UTBT Administrators', 'admin', NULL),
('Moderator', 'UTBT Moderators', 'moderator', NULL),
('Map Maker', 'UTBT Map Makers', 'map_maker', NULL),
('Streamer', 'UTBT Streamers', 'streamer', NULL),
('Player', 'UTBT Players', 'player', NULL); 