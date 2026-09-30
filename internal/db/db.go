package db

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func ResolveURL(explicit string) string {
	if s := strings.TrimSpace(explicit); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv("DATABASE_URL")); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv("DEFENDSEC_DATABASE_URL")); s != "" {
		return s
	}
	return ""
}

func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	// 20 by default: inventory processing at fleet scale is round-trip
	// bound (roadmap 5.5 load test). DEFENDSEC_DB_MAX_CONNS overrides it;
	// keep it under Postgres's max_connections less other clients.
	cfg.MaxConns = 20
	if v := strings.TrimSpace(os.Getenv("DEFENDSEC_DB_MAX_CONNS")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 2 || n > 500 {
			return nil, fmt.Errorf("DEFENDSEC_DB_MAX_CONNS must be a number from 2 to 500, got %q", v)
		}
		cfg.MaxConns = int32(n)
	}
	cfg.MinConns = 1
	cfg.MaxConnLifetime = time.Hour
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return pool, nil
}

func Migrate(ctx context.Context, pool *pgxpool.Pool, sql string) error {
	_, err := pool.Exec(ctx, sql)
	return err
}
