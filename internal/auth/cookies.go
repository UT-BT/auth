package auth

import (
	"net/http"
	"time"

	"github.com/UT-BT/auth/internal/config"
)

const (
	accessTokenCookie          = "access_token"
	refreshTokenCookie         = "refresh_token"
	providerTokenCookie        = "provider_token"
	providerRefreshTokenCookie = "provider_refresh_token"
)

// CookieManager handles all cookie-related operations
type CookieManager struct {
	config *config.Config
}

// NewCookieManager creates a new CookieManager instance
func NewCookieManager(cfg *config.Config) *CookieManager {
	return &CookieManager{
		config: cfg,
	}
}

// SetAuthCookies sets all authentication-related cookies
func (cm *CookieManager) SetAuthCookies(w http.ResponseWriter, token *TokenResponse) {
	cm.setSecureCookie(w, accessTokenCookie, token.AccessToken, time.Hour)
	cm.setSecureCookie(w, refreshTokenCookie, token.RefreshToken, 30*24*time.Hour)
}

// SetProviderCookies sets provider-specific cookies
func (cm *CookieManager) SetProviderCookies(w http.ResponseWriter, providerToken, providerRefreshToken string) {
	cm.setSecureCookie(w, providerTokenCookie, providerToken, time.Hour)
	cm.setSecureCookie(w, providerRefreshTokenCookie, providerRefreshToken, 30*24*time.Hour)
}

// ClearAllAuthCookies removes all authentication-related cookies
func (cm *CookieManager) ClearAllAuthCookies(w http.ResponseWriter) {
	cookies := []string{
		accessTokenCookie,
		refreshTokenCookie,
		providerTokenCookie,
		providerRefreshTokenCookie,
	}

	for _, name := range cookies {
		cm.clearCookie(w, name)
	}
}

// GetAccessToken retrieves the access token from cookies
func (cm *CookieManager) GetAccessToken(r *http.Request) (string, error) {
	cookie, err := r.Cookie(accessTokenCookie)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

// GetRefreshToken retrieves the refresh token from cookies
func (cm *CookieManager) GetRefreshToken(r *http.Request) (string, error) {
	cookie, err := r.Cookie(refreshTokenCookie)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

func (cm *CookieManager) setSecureCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Domain:   cm.config.CookieDomain,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: true,
		Secure:   !cm.config.IsLocal(),
		SameSite: http.SameSiteLaxMode,
	})
}

func (cm *CookieManager) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Domain:   cm.config.CookieDomain,
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !cm.config.IsLocal(),
		SameSite: http.SameSiteLaxMode,
	})
}
