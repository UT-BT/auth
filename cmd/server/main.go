package main

import (
	"net/http"
	"os"

	"github.com/UT-BT/auth/internal/auth"
	"github.com/UT-BT/auth/internal/config"
	"github.com/UT-BT/auth/internal/handlers"
	"github.com/UT-BT/auth/internal/logger"
	"github.com/UT-BT/auth/internal/middleware"
	"github.com/UT-BT/auth/internal/supabase"
	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
)

var version string

func main() {
	if err := godotenv.Load(); err != nil {
		log.Warn().Err(err).Msg("Warning: Error loading .env file")
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("Error loading config")
	}

	if err := logger.Initialize(logger.Config{
		Environment: cfg.Environment,
		LogDir:      cfg.LogDir,
	}); err != nil {
		log.Fatal().Err(err).Msg("Error initializing logger")
	}

	log.Info().Str("version", version).Msgf("UTBT Auth Server")
	log.Info().
		Str("port", cfg.Port).
		Msg("Starting server")

	authClient := auth.NewClient(cfg)
	log.Debug().Msg("Auth client initialized")

	r := chi.NewRouter()

	// Add request ID middleware
	r.Use(chiMiddleware.RequestID)
	r.Use(chiMiddleware.Recoverer)
	r.Use(chiMiddleware.RealIP)

	// Add our custom logger middleware
	r.Use(middleware.Logger)

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*.utbt.net", "http://localhost:*", "http://127.0.0.1:*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	log.Debug().Msg("CORS middleware configured")

	fileServer := http.FileServer(http.Dir("static"))
	r.Handle("/static/*", http.StripPrefix("/static/", fileServer))
	r.Handle("/favicon.ico", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/favicon.ico")
	}))
	log.Debug().Msg("Static file server configured")

	cookieManager := auth.NewCookieManager(cfg)
	supabaseRepository := supabase.NewRepository(cfg.SupabaseURL, cfg.SupabaseServiceKey)
	supabaseService := supabase.NewService(supabaseRepository)
	authHandler := handlers.NewAuthHandler(authClient, cookieManager, supabaseService)
	r.Mount("/", authHandler.Routes())
	log.Debug().Msg("Routes mounted")

	log.Info().Msgf("Server listening on port %s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, r); err != nil {
		log.Fatal().Err(err).Msg("Error starting server")
		os.Exit(1)
	}
}
