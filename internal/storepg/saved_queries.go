package storepg

import (
	"context"
	"time"
)

type SavedQuery struct {
	ID        string
	Name      string
	Query     string
	CreatedAt string
}

func (s *Store) ListSavedQueries(ctx context.Context) ([]SavedQuery, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, query, created_at FROM saved_queries ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SavedQuery
	for rows.Next() {
		var rec SavedQuery
		var created time.Time
		if err := rows.Scan(&rec.ID, &rec.Name, &rec.Query, &created); err != nil {
			return nil, err
		}
		rec.CreatedAt = created.UTC().Format(time.RFC3339)
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *Store) InsertSavedQuery(ctx context.Context, id, name, query string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO saved_queries (id, name, query) VALUES ($1,$2,$3)
	`, id, name, query)
	return err
}
