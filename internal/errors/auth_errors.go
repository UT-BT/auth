package errors

import (
	"errors"
	"net/http"
)

// Common error types
var (
	ErrNoAuthHeader = errors.New("no authorization header")
	ErrInvalidToken = errors.New("invalid token")
	ErrTokenExpired = errors.New("token expired")
	ErrUserNotFound = errors.New("user not found")
	ErrInvalidRole  = errors.New("invalid role")
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
)

// ErrorResponse represents a standardized error response
type ErrorResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// AuthError wraps authentication-related errors with context
type AuthError struct {
	Err     error
	Status  int
	Code    string
	Message string
}

func (e *AuthError) Error() string {
	return e.Message
}

// NewAuthError creates a new AuthError with the given parameters
func NewAuthError(err error, status int, code string) *AuthError {
	return &AuthError{
		Err:     err,
		Status:  status,
		Code:    code,
		Message: err.Error(),
	}
}

// Common auth errors
func InvalidToken() *AuthError {
	return NewAuthError(ErrInvalidToken, http.StatusUnauthorized, "invalid_token")
}

func TokenExpired() *AuthError {
	return NewAuthError(ErrTokenExpired, http.StatusUnauthorized, "token_expired")
}

func Unauthorized() *AuthError {
	return NewAuthError(ErrUnauthorized, http.StatusUnauthorized, "unauthorized")
}

func Forbidden() *AuthError {
	return NewAuthError(ErrForbidden, http.StatusForbidden, "forbidden")
}

func UserNotFound() *AuthError {
	return NewAuthError(ErrUserNotFound, http.StatusNotFound, "user_not_found")
}

// HandleAuthError writes the error response to the http.ResponseWriter
func HandleAuthError(w http.ResponseWriter, err error) {
	var authErr *AuthError
	if errors.As(err, &authErr) {
		http.Error(w, authErr.Message, authErr.Status)
		return
	}

	http.Error(w, "Internal server error", http.StatusInternalServerError)
}
