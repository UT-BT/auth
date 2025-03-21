package auth

import (
	"errors"
	"net/http"
	"strings"

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

	return &Client{
		auth: client,
		cfg:  cfg,
	}
}

func ExtractTokenFromHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("no authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("invalid authorization header format")
	}

	return parts[1], nil
}
