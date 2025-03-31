package repository

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

// DBPool manages the PostgreSQL connection pool
type DBPool struct {
	pool *pgxpool.Pool
}

// NewDBPool creates a new database connection pool
func NewDBPool(connectionString string) (*DBPool, error) {
	config, err := pgxpool.ParseConfig(connectionString)
	if err != nil {
		return nil, fmt.Errorf("error parsing connection string: %w", err)
	}

	config.MaxConns = 10
	config.MinConns = 2

	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, fmt.Errorf("error creating connection pool: %w", err)
	}

	if err := pool.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("error connecting to the database: %w", err)
	}

	log.Info().Msg("Successfully connected to PostgreSQL database")
	return &DBPool{pool: pool}, nil
}

// Close closes the database connection pool
func (db *DBPool) Close() {
	if db.pool != nil {
		db.pool.Close()
	}
}

// GetPool returns the underlying connection pool
func (db *DBPool) GetPool() *pgxpool.Pool {
	return db.pool
}
