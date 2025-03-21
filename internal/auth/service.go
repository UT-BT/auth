package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/supabase-community/auth-go/types"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

func (c *Client) RefreshToken(refreshToken string) (*TokenResponse, error) {
	token, err := c.auth.Token(types.TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: refreshToken,
	})
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresIn:    token.ExpiresIn,
		TokenType:    token.TokenType,
	}, nil
}

func (c *Client) GetUserFromToken(token string) (*types.UserResponse, error) {
	if len(token) < 10 {
		return nil, errors.New("invalid token format: token too short")
	}

	if !strings.HasPrefix(token, "ey") {
		return nil, errors.New("invalid token format: not a JWT")
	}

	client := c.auth.WithToken(token)

	user, err := client.GetUser()
	if err != nil {
		if strings.Contains(err.Error(), "401") {
			return nil, fmt.Errorf("invalid or expired token: %w", err)
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if user == nil {
		return nil, errors.New("no user found for token")
	}

	return user, nil
}

func (c *Client) SignOut(token string) error {
	client := c.auth.WithToken(token)
	return client.Logout()
}

func (c *Client) ExtractTokenFromHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("no authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("invalid authorization header format")
	}

	token := parts[1]
	if len(token) < 10 {
		return "", errors.New("invalid token: too short")
	}

	return token, nil
}

func (c *Client) GetDiscordLoginURL() string {
	return fmt.Sprintf("%s/auth/v1/authorize?provider=discord&redirect_to=%s/callback",
		c.cfg.SupabaseURL,
		c.cfg.AppURL,
	)
}

func (c *Client) IsLocalEnvironment() bool {
	return c.cfg.Environment == "development" || c.cfg.Environment == "local"
}
