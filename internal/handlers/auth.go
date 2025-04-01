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
		r.Get("/hwid", h.getHWID)
		r.Get("/game-token", h.getGameToken)
	})

	return r
}

func (h *AuthHandler) indexPage(w http.ResponseWriter, r *http.Request) {
	if value := r.URL.Query().Get("error"); value != "" {
		templates.Error(value).Render(r.Context(), w)
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
		err := h.hwidService.ValidateHWID(hwid)
		if err != nil {
			log.Error().Err(err).Msg("Failed to validate HWID")
			templates.Error("invalid_hwid").Render(r.Context(), w)
			return
		}

		_, needsRefresh, err := h.hwidService.RegisterHWID(user, hwid)
		if err != nil {
			log.Error().Err(err).Msg("Failed to register HWID")
			templates.Error("internal_server_error").Render(r.Context(), w)
			return
		}

		h.cookieManager.ClearPendingHWID(w)

		if needsRefresh {
			refreshToken, err := h.cookieManager.GetRefreshToken(r)
			if err != nil {
				log.Error().Err(err).Msg("Failed to get refresh token for HWID update")
				templates.Error("internal_server_error").Render(r.Context(), w)
				return
			}

			newToken, err := h.authClient.RefreshToken(refreshToken)
			if err != nil {
				log.Error().Err(err).Msg("Failed to refresh token for HWID update")
				templates.Error("internal_server_error").Render(r.Context(), w)
				return
			}

			h.cookieManager.SetAuthCookies(w, newToken)
		}

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	pendingHWID, _ := h.cookieManager.GetPendingHWID(r)
	if pendingHWID != "" {
		err := h.hwidService.ValidateHWID(pendingHWID)
		if err != nil {
			log.Error().Err(err).Msg("Failed to validate pending HWID")
			templates.Error("invalid_hwid").Render(r.Context(), w)
			return
		}

		_, needsRefresh, err := h.hwidService.RegisterHWID(user, pendingHWID)
		if err != nil {
			log.Error().Err(err).Msg("Failed to register pending HWID")
			templates.Error("internal_server_error").Render(r.Context(), w)
			return
		}

		h.cookieManager.ClearPendingHWID(w)

		if needsRefresh {
			refreshToken, err := h.cookieManager.GetRefreshToken(r)
			if err != nil {
				log.Error().Err(err).Msg("Failed to get refresh token for HWID update")
				templates.Error("internal_server_error").Render(r.Context(), w)
				return
			}

			newToken, err := h.authClient.RefreshToken(refreshToken)
			if err != nil {
				log.Error().Err(err).Msg("Failed to refresh token for HWID update")
				templates.Error("internal_server_error").Render(r.Context(), w)
				return
			}

			h.cookieManager.SetAuthCookies(w, newToken)
		}

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
			HWID           string   `json:"hwid"`
			HWIDUpdatedAt  int64    `json:"hwid_updated_at"`
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
				log.Error().Err(err).Msg("Failed to get user data for metadata timestamp check")
				return nil, err
			}

			currentRolesTimestamp := int64(0)
			currentHWIDTimestamp := int64(0)
			if supabaseUser.AppMetadata != nil {
				if timestamp, ok := supabaseUser.AppMetadata["roles_updated_at"].(float64); ok {
					currentRolesTimestamp = int64(timestamp)
				}
				if timestamp, ok := supabaseUser.AppMetadata["hwid_updated_at"].(float64); ok {
					currentHWIDTimestamp = int64(timestamp)
				}
			}

			if currentRolesTimestamp > claims.AppMetadata.RolesUpdatedAt ||
				currentHWIDTimestamp > claims.AppMetadata.HWIDUpdatedAt {
				log.Info().
					Str("user_id", supabaseUser.ID.String()).
					Int64("token_roles_timestamp", claims.AppMetadata.RolesUpdatedAt).
					Int64("current_roles_timestamp", currentRolesTimestamp).
					Int64("token_hwid_timestamp", claims.AppMetadata.HWIDUpdatedAt).
					Int64("current_hwid_timestamp", currentHWIDTimestamp).
					Msg("User metadata has been updated, refreshing token")

				refreshToken, refreshErr := h.cookieManager.GetRefreshToken(r)
				if refreshErr != nil {
					log.Error().Err(refreshErr).Msg("Failed to get refresh token for metadata update")
					h.cookieManager.ClearAllAuthCookies(w)
					return nil, errors.New("user metadata has been updated, please re-authenticate")
				}

				newToken, refreshErr := h.authClient.RefreshToken(refreshToken)
				if refreshErr != nil {
					log.Error().Err(refreshErr).Msg("Failed to refresh token for metadata update")
					h.cookieManager.ClearAllAuthCookies(w)
					return nil, errors.New("user metadata has been updated, please re-authenticate")
				}

				h.cookieManager.SetAuthCookies(w, newToken)
				accessToken = newToken.AccessToken

				supabaseUser, err = h.authClient.GetUserFromToken(accessToken)
				if err != nil {
					log.Error().Err(err).Msg("Failed to get updated user data after token refresh")
					return nil, err
				}

				token, err = jwt.ParseWithClaims(accessToken, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
					}
					return []byte(h.cfg.SupabaseJWTSecret), nil
				})

				if err != nil || !token.Valid {
					log.Error().Err(err).Msg("Failed to parse refreshed token")
					return nil, errors.New("failed to parse refreshed token")
				}

				claims, ok = token.Claims.(*CustomClaims)
				if !ok {
					log.Error().Msg("Failed to parse claims from refreshed token")
					return nil, errors.New("failed to parse claims from refreshed token")
				}
			}

			if len(claims.AppMetadata.Roles) > 0 {
				roles = claims.AppMetadata.Roles
			} else {
				log.Warn().Msg("JWT claims did not contain 'roles' in app_metadata, defaulting roles")
			}

			hwid := claims.AppMetadata.HWID
			if hwid == "" {
				log.Debug().Msg("No HWID found in JWT claims")
			} else {
				log.Debug().Str("hwid", hwid).Msg("Found HWID in JWT claims")
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
	hwid := ""

	if supabaseUser.AppMetadata != nil {
		if storedHWID, ok := supabaseUser.AppMetadata["hwid"].(string); ok {
			hwid = storedHWID
			log.Debug().Str("hwid", hwid).Msg("Found HWID in user metadata")
		}
	}
	avatarURL := ""
	if supabaseUser.UserMetadata != nil {
		if avatar, ok := supabaseUser.UserMetadata["avatar_url"].(string); ok {
			avatarURL = avatar
		}
	}

	if hwid == "" && supabaseUser.AppMetadata != nil {
		if storedHWID, ok := supabaseUser.AppMetadata["hwid"].(string); ok {
			hwid = storedHWID
			log.Debug().Str("hwid", hwid).Msg("Found HWID in user metadata")
		}
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
			HWID           string   `json:"hwid"`
			HWIDUpdatedAt  int64    `json:"hwid_updated_at"`
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

func (h *AuthHandler) getHWID(w http.ResponseWriter, r *http.Request) {
	const hwidDisplayText = "• • • • • • • • • • • •"

	user, err := h.getUserFromCookies(w, r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if user.RegisteredHWID == "" {
		w.Write([]byte(hwidDisplayText))
		return
	}

	w.Write([]byte(user.RegisteredHWID))
}

func (h *AuthHandler) getGameToken(w http.ResponseWriter, r *http.Request) {
	user, err := h.getUserFromCookies(w, r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if user.GameToken == "" {
		http.Error(w, "No game token found", http.StatusNotFound)
		return
	}

	triggerData := fmt.Sprintf(`{"showModal": {"token": "%s"}}`, user.GameToken)
	w.Header().Set("HX-Trigger", triggerData)
	w.WriteHeader(http.StatusOK)
}
