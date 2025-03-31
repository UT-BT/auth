package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
)

// Config holds all configuration for the application
type Config struct {
	Port        string
	Environment string
	AppURL      string

	SupabaseURL        string
	SupabaseInstance   string
	SupabaseServiceKey string
	SupabaseJWTSecret  string

	CookieDomain string
	LogDir       string

	DatabaseURL string
}

// Load creates a new Config from environment variables
func Load() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		fmt.Printf("Warning: .env file not found: %v\n", err)
	}

	cfg := &Config{
		Port:        getEnvOrDefault("PORT", "8080"),
		Environment: getEnvOrDefault("ENV", "development"),
		AppURL:      os.Getenv("APP_URL"),

		SupabaseURL:        os.Getenv("SUPABASE_URL"),
		SupabaseInstance:   os.Getenv("SUPABASE_INSTANCE"),
		SupabaseServiceKey: os.Getenv("SUPABASE_SERVICE_KEY"),
		SupabaseJWTSecret:  os.Getenv("SUPABASE_JWT_SECRET"),

		CookieDomain: getCookieDomain(getEnvOrDefault("ENV", "development")),
		LogDir:       getEnvOrDefault("LOG_DIR", filepath.Join(".", "logs")),

		DatabaseURL: os.Getenv("DATABASE_URL"),
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
		missingVars = append(missingVars, "SUPABASE_SERVICE_KEY")
	}
	if c.SupabaseJWTSecret == "" {
		missingVars = append(missingVars, "SUPABASE_JWT_SECRET")
	}
	if c.AppURL == "" {
		missingVars = append(missingVars, "APP_URL")
	}
	if c.Port == "" {
		missingVars = append(missingVars, "PORT")
	}
	if c.DatabaseURL == "" {
		missingVars = append(missingVars, "DATABASE_URL")
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
