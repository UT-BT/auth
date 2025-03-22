package auth

import (
	"net/http"
	"time"

	"github.com/UT-BT/auth/internal/config"
	"github.com/rs/zerolog/log"
)

const (
	accessTokenCookie          = "access_token"
	refreshTokenCookie         = "refresh_token"
	providerTokenCookie        = "provider_token"
	providerRefreshTokenCookie = "provider_refresh_token"
	pendingHWIDCookie          = "pending_hwid"
)

// CookieManager handles all cookie-related operations
type CookieManager struct {
	config *config.Config
}

// NewCookieManager creates a new CookieManager instance
func NewCookieManager(cfg *config.Config) *CookieManager {
	log.Debug().Msg("Initializing cookie manager")
	return &CookieManager{
		config: cfg,
	}
}

// SetAuthCookies sets all authentication-related cookies
func (cm *CookieManager) SetAuthCookies(w http.ResponseWriter, token *TokenResponse) {
	log.Debug().Str("access_token", token.AccessToken).Str("refresh_token", token.RefreshToken).Msg("Setting authentication cookies")
	cm.setSecureCookie(w, accessTokenCookie, token.AccessToken, time.Hour)
	cm.setSecureCookie(w, refreshTokenCookie, token.RefreshToken, 30*24*time.Hour)
	log.Debug().Str("access_token", token.AccessToken).Str("refresh_token", token.RefreshToken).Msg("Authentication cookies set successfully")
}

// SetProviderCookies sets provider-specific cookies
func (cm *CookieManager) SetProviderCookies(w http.ResponseWriter, providerToken, providerRefreshToken string) {
	// Max age is 30 days in Time Duration
	maxAge := 30 * 24 * time.Hour
	log.Debug().Str("provider_token", providerToken).Str("provider_refresh_token", providerRefreshToken).Dur("max_age", maxAge).Msg("Setting provider cookies")
	cm.setSecureCookie(w, providerTokenCookie, providerToken, maxAge)
	cm.setSecureCookie(w, providerRefreshTokenCookie, providerRefreshToken, maxAge)
	log.Debug().Str("provider_token", providerToken).Str("provider_refresh_token", providerRefreshToken).Dur("max_age", maxAge).Msg("Provider cookies set successfully")
}

// SetPendingHWID sets the pending HWID cookie
func (cm *CookieManager) SetPendingHWID(w http.ResponseWriter, hwid string) {
	log.Debug().Str("hwid", hwid).Msg("Setting pending HWID")
	cm.setSecureCookie(w, pendingHWIDCookie, hwid, 30*24*time.Hour)
	log.Debug().Str("hwid", hwid).Msg("Pending HWID set successfully")
}

// ClearAllAuthCookies removes all authentication-related cookies
func (cm *CookieManager) ClearAllAuthCookies(w http.ResponseWriter) {
	log.Debug().Msg("Clearing all authentication cookies")
	cookies := []string{
		accessTokenCookie,
		refreshTokenCookie,
		providerTokenCookie,
		providerRefreshTokenCookie,
	}

	for _, name := range cookies {
		cm.clearCookie(w, name)
	}
	log.Debug().Msg("All authentication cookies cleared")
}

// ClearPendingHWID removes the pending HWID cookie
func (cm *CookieManager) ClearPendingHWID(w http.ResponseWriter) {
	log.Debug().Msg("Clearing pending HWID")
	cm.clearCookie(w, pendingHWIDCookie)
	log.Debug().Msg("Pending HWID cleared")
}

// GetAccessToken retrieves the access token from cookies
func (cm *CookieManager) GetAccessToken(r *http.Request) (string, error) {
	log.Debug().Msg("Retrieving access token from cookies")
	cookie, err := r.Cookie(accessTokenCookie)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to get access token cookie")
		return "", err
	}
	log.Debug().Str("access_token", cookie.Value).Msg("Successfully retrieved access token from cookies")
	return cookie.Value, nil
}

// GetRefreshToken retrieves the refresh token from cookies
func (cm *CookieManager) GetRefreshToken(r *http.Request) (string, error) {
	log.Debug().Msg("Retrieving refresh token from cookies")
	cookie, err := r.Cookie(refreshTokenCookie)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to get refresh token cookie")
		return "", err
	}
	log.Debug().Str("refresh_token", cookie.Value).Msg("Successfully retrieved refresh token from cookies")
	return cookie.Value, nil
}

// GetPendingHWID retrieves the pending HWID from cookies
func (cm *CookieManager) GetPendingHWID(r *http.Request) (string, error) {
	log.Debug().Msg("Retrieving pending HWID from cookies")
	cookie, err := r.Cookie(pendingHWIDCookie)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to get pending HWID cookie")
		return "", err
	}
	log.Debug().Str("pending_hwid", cookie.Value).Msg("Successfully retrieved pending HWID from cookies")
	return cookie.Value, nil
}

func (cm *CookieManager) setSecureCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	log.Debug().Str("cookie_name", name).Dur("max_age", maxAge).Msg("Setting secure cookie")
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
	log.Debug().Str("cookie_name", name).Msg("Secure cookie set successfully")
}

func (cm *CookieManager) clearCookie(w http.ResponseWriter, name string) {
	log.Debug().Str("cookie_name", name).Msg("Clearing cookie")
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
	log.Debug().Str("cookie_name", name).Msg("Cookie cleared successfully")
}
