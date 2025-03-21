package middleware

import (
	"context"
	"net/http"

	"github.com/UT-BT/auth/internal/auth"
	"github.com/UT-BT/auth/internal/errors"
)

type contextKey string

const (
	UserContextKey contextKey = "user"
	RoleContextKey contextKey = "role"
)

// AuthMiddleware handles authentication-related middleware
type AuthMiddleware struct {
	authClient    *auth.Client
	cookieManager *auth.CookieManager
	roleManager   *auth.RoleManager
}

// NewAuthMiddleware creates a new AuthMiddleware instance
func NewAuthMiddleware(authClient *auth.Client, cookieManager *auth.CookieManager, roleManager *auth.RoleManager) *AuthMiddleware {
	return &AuthMiddleware{
		authClient:    authClient,
		cookieManager: cookieManager,
		roleManager:   roleManager,
	}
}

// RequireAuth middleware checks if the request has a valid authentication token
func (m *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token string
		var err error

		token, err = m.authClient.ExtractTokenFromHeader(r)
		if err != nil {
			token, err = m.cookieManager.GetAccessToken(r)
			if err != nil {
				refreshToken, err := m.cookieManager.GetRefreshToken(r)
				if err != nil {
					errors.HandleAuthError(w, errors.Unauthorized())
					return
				}

				tokenResponse, err := m.authClient.RefreshToken(refreshToken)
				if err != nil {
					errors.HandleAuthError(w, errors.TokenExpired())
					return
				}

				m.cookieManager.SetAuthCookies(w, tokenResponse)
				token = tokenResponse.AccessToken
			}
		}

		user, err := m.authClient.GetUserFromToken(token)
		if err != nil {
			errors.HandleAuthError(w, errors.InvalidToken())
			return
		}

		role := m.roleManager.GetUserRole(user)

		ctx := context.WithValue(r.Context(), UserContextKey, user)
		ctx = context.WithValue(ctx, RoleContextKey, role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole middleware checks if the user has the required role
func (m *AuthMiddleware) RequireRole(requiredRole auth.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, ok := r.Context().Value(RoleContextKey).(auth.Role)
			if !ok {
				errors.HandleAuthError(w, errors.Unauthorized())
				return
			}

			if !m.roleManager.HasRequiredRole(role, requiredRole) {
				errors.HandleAuthError(w, errors.Forbidden())
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission middleware checks if the user has the required permission
func (m *AuthMiddleware) RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, ok := r.Context().Value(RoleContextKey).(auth.Role)
			if !ok {
				errors.HandleAuthError(w, errors.Unauthorized())
				return
			}

			if !m.roleManager.HasPermission(role, permission) {
				errors.HandleAuthError(w, errors.Forbidden())
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireMicroserviceAuth middleware validates microservice authentication tokens
func (m *AuthMiddleware) RequireMicroserviceAuth(allowedServices []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := m.authClient.ExtractTokenFromHeader(r)
			if err != nil {
				errors.HandleAuthError(w, errors.Unauthorized())
				return
			}

			user, err := m.authClient.GetUserFromToken(token)
			if err != nil {
				errors.HandleAuthError(w, errors.InvalidToken())
				return
			}

			serviceName, ok := user.AppMetadata["service"].(string)
			if !ok || !isAllowedService(serviceName, allowedServices) {
				errors.HandleAuthError(w, errors.Forbidden())
				return
			}

			ctx := context.WithValue(r.Context(), "service", serviceName)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func isAllowedService(service string, allowedServices []string) bool {
	for _, allowed := range allowedServices {
		if service == allowed {
			return true
		}
	}
	return false
}
