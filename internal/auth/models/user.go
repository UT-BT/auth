package models

// User represents a user in the system
type User struct {
	ID             string   `json:"id"`
	DiscordUserID  string   `json:"discord_user_id"`
	Username       string   `json:"username"`
	AvatarURL      string   `json:"avatar_url,omitempty"`
	RegisteredHWID string   `json:"registered_hwid,omitempty"`
	GameToken      string   `json:"game_token,omitempty"`
	Roles          []string `json:"roles,omitempty"`
}
