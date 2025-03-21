package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/UT-BT/auth/internal/auth"
	"github.com/UT-BT/auth/internal/templates"

	"github.com/go-chi/chi/v5"
)

type AuthHandler struct {
	authClient *auth.Client
}

func NewAuthHandler(authClient *auth.Client) *AuthHandler {
	return &AuthHandler{
		authClient: authClient,
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
	})

	return r
}

func (h *AuthHandler) indexPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("error") != "" {
		templates.Error().Render(r.Context(), w)
		return
	}

	user, err := h.getUserFromCookies(w, r)
	if err != nil {
		h.clearAuthCookies(w, r)
		templates.Index(nil).Render(r.Context(), w)
		return
	}

	templates.Index(user).Render(r.Context(), w)
}

func (h *AuthHandler) logoutPage(w http.ResponseWriter, r *http.Request) {
	h.clearAuthCookies(w, r)
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (h *AuthHandler) getUserFromCookies(w http.ResponseWriter, r *http.Request) (*templates.User, error) {
	accessToken, err := r.Cookie("access_token")
	if err != nil {
		refreshToken, err := r.Cookie("refresh_token")
		if err != nil {
			return nil, err
		}

		token, err := h.authClient.RefreshToken(refreshToken.Value)
		if err != nil {
			return nil, err
		}

		domain := ".utbt.net"
		if h.authClient.IsLocalEnvironment() {
			domain = "localhost"
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "access_token",
			Value:    token.AccessToken,
			Domain:   domain,
			Path:     "/",
			MaxAge:   token.ExpiresIn,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})

		accessToken = &http.Cookie{
			Name:  "access_token",
			Value: token.AccessToken,
		}
	}

	user, err := h.authClient.GetUserFromToken(accessToken.Value)
	if err != nil {
		return nil, err
	}

	discordIdentityIndex := -1
	for i, identity := range user.Identities {
		if identity.Provider == "discord" {
			discordIdentityIndex = i
			break // Exit loop once found
		}
	}

	if discordIdentityIndex == -1 {
		return nil, errors.New("no discord identity found")
	}

	identity := user.Identities[discordIdentityIndex]

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

	avatarURL := ""
	if user.UserMetadata != nil {
		if avatar, ok := user.UserMetadata["avatar_url"].(string); ok {
			avatarURL = avatar
		}
	}

	return &templates.User{
		ID:        identity.ID,
		Username:  discordUsername,
		AvatarURL: avatarURL,
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

	h.clearAuthCookies(w, r)
	w.WriteHeader(http.StatusOK)
}

func (h *AuthHandler) discordLogin(w http.ResponseWriter, r *http.Request) {
	redirectURL := h.authClient.GetDiscordLoginURL()
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func (h *AuthHandler) discordCallback(w http.ResponseWriter, r *http.Request) {
	templates.Callback().Render(r.Context(), w)
}

func (h *AuthHandler) setAuthCookies(w http.ResponseWriter, token *auth.TokenResponse) {
	domain := ".utbt.net"
	if h.authClient.IsLocalEnvironment() {
		domain = "localhost"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    token.AccessToken,
		Domain:   domain,
		Path:     "/",
		MaxAge:   3600, // 1 hour
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    token.RefreshToken,
		Domain:   domain,
		Path:     "/",
		MaxAge:   30 * 24 * 60 * 60, // 30 days
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *AuthHandler) clearAuthCookies(w http.ResponseWriter, r *http.Request) {
	domain := ".utbt.net"
	if h.authClient.IsLocalEnvironment() {
		domain = "localhost"
	}

	cookies := []string{
		"access_token",
		"refresh_token",
		"provider_token",
		"provider_refresh_token",
	}

	for _, name := range cookies {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Domain:   domain,
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
	}
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
		MaxAge:   3600, // 1 hour
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
