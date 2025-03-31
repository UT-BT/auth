package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/UT-BT/auth/internal/auth"
	"github.com/UT-BT/auth/internal/auth/models"
	"github.com/UT-BT/auth/internal/auth/services"
	"github.com/UT-BT/auth/internal/config"
	"github.com/UT-BT/auth/internal/templates"
	"github.com/golang-jwt/jwt/v5"
	supabasetypes "github.com/supabase-community/auth-go/types"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
)

// AuthHandler handles authentication-related HTTP requests
type AuthHandler struct {
	authClient    *auth.Client
	cookieManager *auth.CookieManager
	hwidService   services.HWIDService
	cfg           *config.Config
}

func NewAuthHandler(authClient *auth.Client, cookieManager *auth.CookieManager, hwidService services.HWIDService, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		authClient:    authClient,
		cookieManager: cookieManager,
		hwidService:   hwidService,
		cfg:           cfg,
	}
}

func (h *AuthHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Web routes (HTML)
	r.Get("/", h.indexPage)
	r.Get("/logout", h.logoutPage)
	r.Get("/discord", h.discordLogin)
	r.Get("/callback", h.discordCallback)

	// API routes (JSON)
	r.Route("/api", func(r chi.Router) {
		r.Post("/refresh", h.refreshToken)
		r.Get("/verify", h.verifyToken)
		r.Post("/logout", h.logout)
		r.Post("/store-auth", h.storeAuth)
		r.Post("/refresh-if-needed", h.refreshTokenIfNeeded)
	})

	return r
}

func (h *AuthHandler) indexPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("error") != "" {
		templates.Error().Render(r.Context(), w)
		return
	}

	user, err := h.getUserFromCookies(w, r)
	// User not logged in
	if err != nil {
		hwid := r.URL.Query().Get("hwid")
		if hwid != "" {
			h.cookieManager.SetPendingHWID(w, hwid)
		}

		templates.Index(nil).Render(r.Context(), w)
		return
	}

	hwid := r.URL.Query().Get("hwid")
	if hwid != "" {
		h.hwidService.RegisterHWID(user, hwid)
		h.cookieManager.ClearPendingHWID(w)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	pendingHWID, _ := h.cookieManager.GetPendingHWID(r)
	if pendingHWID != "" {
		h.hwidService.RegisterHWID(user, pendingHWID)
		h.cookieManager.ClearPendingHWID(w)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	templates.Index(user).Render(r.Context(), w)
}

func (h *AuthHandler) logoutPage(w http.ResponseWriter, r *http.Request) {
	h.cookieManager.ClearAllAuthCookies(w)
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func extractDiscordUsername(identity *supabasetypes.Identity) string {
	var discordUsername string

	if customClaims, ok := identity.IdentityData["custom_claims"].(map[string]interface{}); ok {
		if globalName, exists := customClaims["global_name"].(string); exists && globalName != "" {
			discordUsername = globalName
		}
	}

	if discordUsername == "" {
		if name, ok := identity.IdentityData["name"].(string); ok && name != "" {
			if strings.HasSuffix(name, "#0") {
				discordUsername = name[:len(name)-2]
			} else {
				discordUsername = name
			}
		}
	}

	if discordUsername == "" {
		if fullName, ok := identity.IdentityData["full_name"].(string); ok && fullName != "" {
			discordUsername = fullName
		}
	}

	if discordUsername == "" {
		discordUsername = "Unknown Discord User"
	}

	return discordUsername
}

func (h *AuthHandler) getUserFromCookies(w http.ResponseWriter, r *http.Request) (*models.User, error) {
	accessToken, err := h.cookieManager.GetAccessToken(r)
	if err != nil {
		refreshToken, refreshErr := h.cookieManager.GetRefreshToken(r)
		if refreshErr != nil {
			return nil, refreshErr
		}

		newToken, refreshErr := h.authClient.RefreshToken(refreshToken)
		if refreshErr != nil {
			h.cookieManager.ClearAllAuthCookies(w)
			return nil, refreshErr
		}

		h.cookieManager.SetAuthCookies(w, newToken)
		accessToken = newToken.AccessToken
	}

	roles := []string{} // Default

	type CustomClaims struct {
		AppMetadata struct {
			Roles          []string `json:"roles"`
			RolesUpdatedAt int64    `json:"roles_updated_at"`
		} `json:"app_metadata"`
		jwt.RegisteredClaims
	}

	token, err := jwt.ParseWithClaims(accessToken, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(h.cfg.SupabaseJWTSecret), nil
	})

	if err == nil && token.Valid {
		if claims, ok := token.Claims.(*CustomClaims); ok {
			log.Debug().Interface("claims", claims).Msg("Successfully parsed JWT claims")

			supabaseUser, err := h.authClient.GetUserFromToken(accessToken)
			if err != nil {
				log.Error().Err(err).Msg("Failed to get user data for role timestamp check")
				return nil, err
			}

			currentTimestamp := int64(0)
			if supabaseUser.AppMetadata != nil {
				if timestamp, ok := supabaseUser.AppMetadata["roles_updated_at"].(float64); ok {
					currentTimestamp = int64(timestamp)
				}
			}

			if currentTimestamp > claims.AppMetadata.RolesUpdatedAt {
				log.Info().
					Str("user_id", supabaseUser.ID.String()).
					Int64("token_timestamp", claims.AppMetadata.RolesUpdatedAt).
					Int64("current_timestamp", currentTimestamp).
					Msg("Roles have been updated, refreshing token")

				refreshToken, refreshErr := h.cookieManager.GetRefreshToken(r)
				if refreshErr != nil {
					log.Error().Err(refreshErr).Msg("Failed to get refresh token for role update")
					h.cookieManager.ClearAllAuthCookies(w)
					return nil, errors.New("roles have been updated, please re-authenticate")
				}

				newToken, refreshErr := h.authClient.RefreshToken(refreshToken)
				if refreshErr != nil {
					log.Error().Err(refreshErr).Msg("Failed to refresh token for role update")
					h.cookieManager.ClearAllAuthCookies(w)
					return nil, errors.New("roles have been updated, please re-authenticate")
				}

				h.cookieManager.SetAuthCookies(w, newToken)
				accessToken = newToken.AccessToken

				supabaseUser, err = h.authClient.GetUserFromToken(accessToken)
				if err != nil {
					log.Error().Err(err).Msg("Failed to get updated user data after token refresh")
					return nil, err
				}
			}

			if len(claims.AppMetadata.Roles) > 0 {
				roles = claims.AppMetadata.Roles
			} else {
				log.Warn().Msg("JWT claims did not contain 'roles' in app_metadata, defaulting roles")
			}
		} else {
			log.Error().Msg("Failed to assert JWT claims to CustomClaims type, defaulting roles")
		}
	} else {
		log.Warn().Err(err).Msg("Failed to parse JWT or token is invalid, defaulting roles. GetUserFromToken will verify.")
	}

	supabaseUser, err := h.authClient.GetUserFromToken(accessToken)
	if err != nil {
		h.cookieManager.ClearAllAuthCookies(w)
		return nil, err
	}

	discordIdentityIndex := -1
	for i, identity := range supabaseUser.Identities {
		if identity.Provider == "discord" {
			discordIdentityIndex = i
			break
		}
	}

	if discordIdentityIndex == -1 {
		return nil, errors.New("no discord identity found")
	}

	identity := supabaseUser.Identities[discordIdentityIndex]
	discordUsername := extractDiscordUsername(&identity)

	avatarURL := ""
	if supabaseUser.UserMetadata != nil {
		if avatar, ok := supabaseUser.UserMetadata["avatar_url"].(string); ok {
			avatarURL = avatar
		}
	}

	registeredHWIDRecord, err := h.hwidService.GetRegisteredHWID(supabaseUser.ID.String())
	if err != nil {
		log.Warn().Err(err).Str("user_id", supabaseUser.ID.String()).Msg("Error fetching registered HWID")
	}
	hwid := ""
	if registeredHWIDRecord != nil {
		hwid = registeredHWIDRecord.HWID
	}

	providerRefreshToken, err := h.cookieManager.GetProviderRefreshToken(r)
	gameToken := ""
	if err == nil && providerRefreshToken != "" {
		gameToken = fmt.Sprintf("utbt:%s", providerRefreshToken)
	} else if err != http.ErrNoCookie {
		log.Warn().Err(err).Str("user_id", supabaseUser.ID.String()).Msg("Error fetching provider refresh token cookie")
	}

	return &models.User{
		ID:             supabaseUser.ID.String(),
		DiscordUserID:  identity.ID,
		Username:       discordUsername,
		AvatarURL:      avatarURL,
		RegisteredHWID: hwid,
		GameToken:      gameToken,
		Roles:          roles,
	}, nil
}

func (h *AuthHandler) refreshToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	token, err := h.authClient.RefreshToken(req.RefreshToken)
	if err != nil {
		http.Error(w, "Failed to refresh token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(token)
}

func (h *AuthHandler) verifyToken(w http.ResponseWriter, r *http.Request) {
	token, err := h.authClient.ExtractTokenFromHeader(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	user, err := h.authClient.GetUserFromToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	avatarURL := ""
	if user.UserMetadata != nil {
		if avatar, ok := user.UserMetadata["avatar_url"].(string); ok {
			avatarURL = avatar
		}
	}

	response := map[string]interface{}{
		"id":         user.ID.String(),
		"email":      user.Email,
		"avatar_url": avatarURL,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *AuthHandler) logout(w http.ResponseWriter, r *http.Request) {
	token, err := h.authClient.ExtractTokenFromHeader(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if err := h.authClient.SignOut(token); err != nil {
		http.Error(w, "Failed to logout", http.StatusInternalServerError)
		return
	}

	h.cookieManager.ClearAllAuthCookies(w)
	w.WriteHeader(http.StatusOK)
}

func (h *AuthHandler) discordLogin(w http.ResponseWriter, r *http.Request) {
	redirectURL := h.authClient.GetDiscordLoginURL()
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func (h *AuthHandler) discordCallback(w http.ResponseWriter, r *http.Request) {
	templates.Callback().Render(r.Context(), w)
}

type StoreAuthRequest struct {
	RefreshToken         string `json:"refresh_token"`
	ProviderToken        string `json:"provider_token"`
	ProviderRefreshToken string `json:"provider_refresh_token"`
}

func (h *AuthHandler) storeAuth(w http.ResponseWriter, r *http.Request) {
	var req StoreAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	token, err := h.authClient.ExtractTokenFromHeader(r)
	if err != nil {
		http.Error(w, "Missing or invalid access token", http.StatusUnauthorized)
		return
	}

	_, err = h.authClient.GetUserFromToken(token)
	if err != nil {
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	domain := ".utbt.net"
	if h.authClient.IsLocalEnvironment() {
		domain = "localhost"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    token,
		Domain:   domain,
		Path:     "/",
		MaxAge:   900, // 15 minutes
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    req.RefreshToken,
		Domain:   domain,
		Path:     "/",
		MaxAge:   30 * 24 * 60 * 60, // 30 days
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	if req.ProviderToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "provider_token",
			Value:    req.ProviderToken,
			Domain:   domain,
			Path:     "/",
			MaxAge:   3600, // 1 hour
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
	}

	if req.ProviderRefreshToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "provider_refresh_token",
			Value:    req.ProviderRefreshToken,
			Domain:   domain,
			Path:     "/",
			MaxAge:   30 * 24 * 60 * 60, // 30 days
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
	}

	w.WriteHeader(http.StatusOK)
}

type RefreshResponse struct {
	TokenRefreshed bool   `json:"token_refreshed"`
	AccessToken    string `json:"access_token,omitempty"`
	Error          string `json:"error,omitempty"`
}

func (h *AuthHandler) refreshTokenIfNeeded(w http.ResponseWriter, r *http.Request) {
	accessToken, err := h.authClient.ExtractTokenFromHeader(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	type CustomClaims struct {
		AppMetadata struct {
			Roles          []string `json:"roles"`
			RolesUpdatedAt int64    `json:"roles_updated_at"`
		} `json:"app_metadata"`
		jwt.RegisteredClaims
	}

	token, err := jwt.ParseWithClaims(accessToken, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(h.cfg.SupabaseJWTSecret), nil
	})

	if err != nil || !token.Valid {
		json.NewEncoder(w).Encode(RefreshResponse{
			TokenRefreshed: false,
			Error:          "Invalid token",
		})
		return
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		json.NewEncoder(w).Encode(RefreshResponse{
			TokenRefreshed: false,
			Error:          "Invalid token claims",
		})
		return
	}

	supabaseUser, err := h.authClient.GetUserFromToken(accessToken)
	if err != nil {
		json.NewEncoder(w).Encode(RefreshResponse{
			TokenRefreshed: false,
			Error:          "Failed to get user data",
		})
		return
	}

	currentTimestamp := int64(0)
	if supabaseUser.AppMetadata != nil {
		if timestamp, ok := supabaseUser.AppMetadata["roles_updated_at"].(float64); ok {
			currentTimestamp = int64(timestamp)
		}
	}

	if currentTimestamp <= claims.AppMetadata.RolesUpdatedAt {
		json.NewEncoder(w).Encode(RefreshResponse{
			TokenRefreshed: false,
		})
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(RefreshResponse{
			TokenRefreshed: false,
			Error:          "Invalid request body",
		})
		return
	}

	newToken, err := h.authClient.RefreshToken(req.RefreshToken)
	if err != nil {
		json.NewEncoder(w).Encode(RefreshResponse{
			TokenRefreshed: false,
			Error:          "Failed to refresh token",
		})
		return
	}

	json.NewEncoder(w).Encode(RefreshResponse{
		TokenRefreshed: true,
		AccessToken:    newToken.AccessToken,
	})
}
