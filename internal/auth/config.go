package auth

import (
	"fmt"

	"github.com/UT-BT/auth/internal/config"
	"github.com/supabase-community/auth-go"
)

type Client struct {
	auth auth.Client
	cfg  *config.Config
}

func NewClient(cfg *config.Config) *Client {
	client := auth.New(
		cfg.SupabaseInstance,
		cfg.SupabaseServiceKey,
	)

	if cfg.Environment == "development" {
		client = client.WithCustomAuthURL(fmt.Sprintf("%s/auth/v1", cfg.SupabaseURL))
	}

	return &Client{
		auth: client,
		cfg:  cfg,
	}
}
