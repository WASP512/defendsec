package storepg

import (
	"context"
	"fmt"
)

type PruneResult struct {
	AlertsDeleted      int64
	LiveQueryDeleted   int64
}

func (s *Store) PruneOld(ctx context.Context, alertRetentionDays, liveQueryRetentionDays int) (PruneResult, error) {
	var out PruneResult
	if alertRetentionDays > 0 {
		tag, err := s.pool.Exec(ctx, fmt.Sprintf(`
			DELETE FROM alerts
			WHERE status = 'resolved'
			  AND updated_at < now() - interval '%d days'
		`, alertRetentionDays))
		if err != nil {
			return out, fmt.Errorf("prune alerts: %w", err)
		}
		out.AlertsDeleted = tag.RowsAffected()
	}
	if liveQueryRetentionDays > 0 {
		tag, err := s.pool.Exec(ctx, fmt.Sprintf(`
			DELETE FROM live_query_results
			WHERE created_at < now() - interval '%d days'
		`, liveQueryRetentionDays))
		if err != nil {
			return out, fmt.Errorf("prune live_query_results: %w", err)
		}
		out.LiveQueryDeleted = tag.RowsAffected()
	}
	return out, nil
}
