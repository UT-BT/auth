package services

import (
	"fmt"

	"github.com/UT-BT/auth/internal/auth/models"
	"github.com/UT-BT/auth/internal/auth/repository"
	"github.com/rs/zerolog/log"
)

// HWIDService provides high-level operations for HWID management
type HWIDService interface {
	RegisterHWID(user *models.User, hwid string) (*models.RegisteredHWID, bool, error)
	GetRegisteredHWID(userID string) (*models.RegisteredHWID, error)
}

type hwidService struct {
	repo repository.HWIDRepository
}

// NewHWIDService creates a new HWID service instance
func NewHWIDService(repo repository.HWIDRepository) HWIDService {
	return &hwidService{
		repo: repo,
	}
}

func (s *hwidService) RegisterHWID(user *models.User, hwid string) (*models.RegisteredHWID, bool, error) {
	log.Debug().
		Str("user_id", user.ID).
		Str("discord_user_id", user.DiscordUserID).
		Str("hwid", hwid).
		Msg("Registering HWID for user")

	input := &models.RegisteredHWIDInput{
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
		return nil, false, fmt.Errorf("failed to register HWID: %w", err)
	}

	needsRefresh := user.RegisteredHWID != hwid

	log.Info().
		Str("user_id", user.ID).
		Str("discord_user_id", user.DiscordUserID).
		Str("hwid", hwid).
		Bool("needs_refresh", needsRefresh).
		Msg("Successfully registered HWID")

	return result, needsRefresh, nil
}

func (s *hwidService) GetRegisteredHWID(userID string) (*models.RegisteredHWID, error) {
	log.Debug().Str("user_id", userID).Msg("Getting registered HWID for user")
	hwid, err := s.repo.GetRegisteredHWID(userID)
	if err != nil {
		log.Error().Err(err).Str("user_id", userID).Msg("Failed to get registered HWID")
		return nil, fmt.Errorf("failed to get registered HWID: %w", err)
	}

	if hwid == nil {
		log.Debug().Str("user_id", userID).Msg("No registered HWID found for user")
		return nil, nil
	}

	log.Debug().Str("user_id", userID).Str("hwid", hwid.HWID).Msg("Successfully retrieved registered HWID")
	return hwid, nil
}
