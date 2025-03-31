package repository

import (
	"context"
	"fmt"

	"github.com/UT-BT/auth/internal/auth/models"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
)

// HWIDRepository defines the interface for handling hardware ID operations
type HWIDRepository interface {
	UpsertRegisteredHWID(input *models.RegisteredHWIDInput) (*models.RegisteredHWID, error)
	GetRegisteredHWID(userID string) (*models.RegisteredHWID, error)
}

type hwidRepository struct {
	db *DBPool
}

// NewHWIDRepository creates a new HWID repository instance
func NewHWIDRepository(db *DBPool) HWIDRepository {
	return &hwidRepository{
		db: db,
	}
}

func (r *hwidRepository) UpsertRegisteredHWID(input *models.RegisteredHWIDInput) (*models.RegisteredHWID, error) {
	ctx := context.Background()

	query := `
		INSERT INTO auth.registered_hwids (user_id, hwid)
		VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE
		SET hwid = EXCLUDED.hwid,
			updated_at = NOW()
		RETURNING id, user_id, hwid, created_at, updated_at`

	row := r.db.GetPool().QueryRow(ctx, query, input.UserID, input.HWID)

	var result models.RegisteredHWID
	err := row.Scan(
		&result.ID,
		&result.UserID,
		&result.HWID,
		&result.CreatedAt,
		&result.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to upsert HWID: %w", err)
	}

	log.Debug().
		Str("user_id", result.UserID).
		Str("hwid", result.HWID).
		Msg("Successfully upserted HWID")

	return &result, nil
}

func (r *hwidRepository) GetRegisteredHWID(userID string) (*models.RegisteredHWID, error) {
	ctx := context.Background()

	query := `
		SELECT id, user_id, hwid, created_at, updated_at
		FROM auth.registered_hwids
		WHERE user_id = $1`

	row := r.db.GetPool().QueryRow(ctx, query, userID)

	var result models.RegisteredHWID
	err := row.Scan(
		&result.ID,
		&result.UserID,
		&result.HWID,
		&result.CreatedAt,
		&result.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get HWID: %w", err)
	}

	log.Debug().
		Str("user_id", result.UserID).
		Str("hwid", result.HWID).
		Msg("Successfully retrieved HWID")

	return &result, nil
}
