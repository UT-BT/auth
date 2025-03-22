package supabase

import (
	"time"

	"github.com/google/uuid"
)

// RegisteredHWID represents a hardware ID registration in the database
type RegisteredHWID struct {
	ID        uuid.UUID  `json:"id"`
	UserID    string     `json:"user_id"`
	HWID      string     `json:"hwid"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

// RegisteredHWIDInput represents the input for creating/updating a HWID registration
type RegisteredHWIDInput struct {
	UserID string `json:"user_id"`
	HWID   string `json:"hwid"`
}
