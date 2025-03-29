package types

// User represents a user in the system
type User struct {
	ID             string // Supabase auth user ID (UUID)
	DiscordUserID  string // Discord user ID
	Username       string
	AvatarURL      string
	RegisteredHWID string // The user's registered hardware ID, if any
	GameToken      string // The game token string ("utbt:{provider_refresh_token}"), if available
}
