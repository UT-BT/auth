package supabase

import (
	"fmt"

	"github.com/UT-BT/auth/internal/types"
	"github.com/rs/zerolog/log"
)

// Service provides high-level operations for Supabase data
type Service interface {
	RegisterHWID(user *types.User, hwid string) (*RegisteredHWID, error)
	GetUserHWIDs(userID string) ([]RegisteredHWID, error)
}

type service struct {
	repo Repository
}

// NewService creates a new Supabase service instance
func NewService(repo Repository) Service {
	return &service{
		repo: repo,
	}
}

func (s *service) RegisterHWID(user *types.User, hwid string) (*RegisteredHWID, error) {
	log.Debug().
		Str("user_id", user.ID).
		Str("discord_user_id", user.DiscordUserID).
		Str("hwid", hwid).
		Msg("Registering HWID for user")

	input := &RegisteredHWIDInput{
		UserID: user.ID,
		HWID:   hwid,
	}

	result, err := s.repo.UpsertRegisteredHWID(input)
	if err != nil {
		log.Error().
			Err(err).
			Str("user_id", user.ID).
			Str("discord_user_id", user.DiscordUserID).
			Str("hwid", hwid).
			Msg("Failed to register HWID")
		return nil, fmt.Errorf("failed to register HWID: %w", err)
	}

	log.Info().
		Str("user_id", user.ID).
		Str("discord_user_id", user.DiscordUserID).
		Str("hwid", hwid).
		Msg("Successfully registered HWID")

	return result, nil
}
