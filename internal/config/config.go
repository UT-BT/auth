package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config holds all configuration for the application
type Config struct {
	Port        string
	Environment string
	AppURL      string

	SupabaseURL        string
	SupabaseInstance   string
	SupabaseServiceKey string

	SuperUserDiscordID string
	AdminRoleID        string
	ModeratorRoleID    string
	CookieDomain       string

	LogDir string
}

// Load creates a new Config from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		Port:        getEnvOrDefault("PORT", "8080"),
		Environment: getEnvOrDefault("ENV", "development"),
		AppURL:      os.Getenv("APP_URL"),

		SupabaseURL:        os.Getenv("SUPABASE_URL"),
		SupabaseInstance:   os.Getenv("SUPABASE_INSTANCE"),
		SupabaseServiceKey: os.Getenv("SUPABASE_SERVICE_ROLE_KEY"),

		SuperUserDiscordID: os.Getenv("SUPER_USER_DISCORD_ID"),
		AdminRoleID:        os.Getenv("ADMIN_ROLE_ID"),
		ModeratorRoleID:    os.Getenv("MODERATOR_ROLE_ID"),
		CookieDomain:       getCookieDomain(getEnvOrDefault("ENV", "development")),

		LogDir: getEnvOrDefault("LOG_DIR", filepath.Join(".", "logs")),
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// Validate ensures all required configuration is present
func (c *Config) Validate() error {
	var missingVars []string

	if c.SupabaseURL == "" {
		missingVars = append(missingVars, "SUPABASE_URL")
	}
	if c.SupabaseInstance == "" {
		missingVars = append(missingVars, "SUPABASE_INSTANCE")
	}
	if c.SupabaseServiceKey == "" {
		missingVars = append(missingVars, "SUPABASE_SERVICE_ROLE_KEY")
	}
	if c.AppURL == "" {
		missingVars = append(missingVars, "APP_URL")
	}
	if c.SuperUserDiscordID == "" {
		missingVars = append(missingVars, "SUPER_USER_DISCORD_ID")
	}

	if len(missingVars) > 0 {
		return fmt.Errorf("missing required environment variables: %s", strings.Join(missingVars, ", "))
	}

	return nil
}

// IsProduction returns true if the environment is production
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// IsLocal returns true if the environment is local or development
func (c *Config) IsLocal() bool {
	return c.Environment == "development" || c.Environment == "local"
}

// Helper functions
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getCookieDomain(env string) string {
	if env == "development" || env == "local" {
		return "localhost"
	}
	return ".utbt.net"
}
