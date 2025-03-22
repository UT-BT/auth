package types

// User represents a user in the system
type User struct {
	ID            string // Supabase auth user ID (UUID)
	DiscordUserID string // Discord user ID
	Username      string
	AvatarURL     string
}
