package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/supabase-community/auth-go/types"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

func (c *Client) RefreshToken(refreshToken string) (*TokenResponse, error) {
	log.Debug().Str("refresh_token", refreshToken).Msg("Attempting to refresh token")
	token, err := c.auth.Token(types.TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: refreshToken,
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to refresh token")
		return nil, err
	}

	log.Debug().Int("expires_in", token.ExpiresIn).Msg("Token refreshed successfully")
	return &TokenResponse{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresIn:    token.ExpiresIn,
		TokenType:    token.TokenType,
	}, nil
}

func (c *Client) GetUserFromToken(token string) (*types.UserResponse, error) {
	log.Debug().Str("token", token).Msg("Attempting to get user from token")
	if len(token) < 10 {
		log.Warn().Msg("Invalid token format: token too short")
		return nil, errors.New("invalid token format: token too short")
	}

	if !strings.HasPrefix(token, "ey") {
		log.Warn().Msg("Invalid token format: not a JWT")
		return nil, errors.New("invalid token format: not a JWT")
	}

	client := c.auth.WithToken(token)

	user, err := client.GetUser()
	if err != nil {
		if strings.Contains(err.Error(), "401") {
			log.Warn().Err(err).Msg("Invalid or expired token")
			return nil, fmt.Errorf("invalid or expired token: %w", err)
		}
		log.Error().Err(err).Msg("Failed to get user from token")
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if user == nil {
		log.Warn().Msg("No user found for token")
		return nil, errors.New("no user found for token")
	}

	log.Debug().Str("user_id", user.ID.String()).Msg("Successfully retrieved user from token")
	return user, nil
}

func (c *Client) SignOut(token string) error {
	log.Debug().Str("token", token).Msg("Attempting to sign out user")
	client := c.auth.WithToken(token)
	if err := client.Logout(); err != nil {
		log.Error().Err(err).Msg("Failed to sign out user")
		return err
	}
	log.Debug().Str("token", token).Msg("User signed out successfully")
	return nil
}

func (c *Client) ExtractTokenFromHeader(r *http.Request) (string, error) {
	log.Debug().Str("auth_header", r.Header.Get("Authorization")).Msg("Extracting token from header")
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		log.Warn().Msg("No authorization header found")
		return "", errors.New("no authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		log.Warn().Msg("Invalid authorization header format")
		return "", errors.New("invalid authorization header format")
	}

	token := parts[1]
	if len(token) < 10 {
		log.Warn().Msg("Invalid token: too short")
		return "", errors.New("invalid token: too short")
	}

	log.Debug().Str("token", token).Msg("Successfully extracted token from header")
	return token, nil
}

func (c *Client) GetDiscordLoginURL() string {
	url := fmt.Sprintf("%s/auth/v1/authorize?provider=discord&redirect_to=%s/callback",
		c.cfg.SupabaseURL,
		c.cfg.AppURL,
	)
	log.Debug().Str("url", url).Msg("Generated Discord login URL")
	return url
}

func (c *Client) IsLocalEnvironment() bool {
	isLocal := c.cfg.Environment == "development" || c.cfg.Environment == "local"
	log.Debug().Bool("is_local", isLocal).Str("environment", c.cfg.Environment).Msg("Checking environment")
	return isLocal
}
