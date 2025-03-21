package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/natefinch/lumberjack.v2"
)

var Logger zerolog.Logger

// Config holds logger configuration
type Config struct {
	Environment string
	LogDir      string
}

// Initialize sets up the logger with the given configuration
func Initialize(cfg Config) error {
	if err := os.MkdirAll(cfg.LogDir, 0o755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	fileLogger := &lumberjack.Logger{
		Filename:   filepath.Join(cfg.LogDir, "app.log"),
		MaxSize:    10, // megabytes
		MaxBackups: 5,
		MaxAge:     28, // days
		Compress:   true,
	}

	var writers []io.Writer

	if cfg.Environment == "development" {
		consoleWriter := zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}
		writers = append(writers, consoleWriter)
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		writers = append(writers, os.Stdout)
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	writers = append(writers, fileLogger)
	mw := io.MultiWriter(writers...)

	Logger = zerolog.New(mw).With().
		Timestamp().
		Str("env", cfg.Environment).
		Caller().
		Logger()

	log.Logger = Logger

	return nil
}
