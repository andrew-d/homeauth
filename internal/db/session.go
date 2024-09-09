package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type Session struct {
	ID     string
	Expiry time.Time
	UserID int
	Data   map[string]any
}

func (tx *Tx) GetSessionByID(ctx context.Context, id string) (*Session, error) {
	var (
		s        Session
		expiryMs int64
		data     []byte
	)
	err := tx.QueryRowContext(ctx, `
		SELECT id, expiry, user_id, data
		FROM sessions
		WHERE id = $1
	`, id).Scan(&s.ID, &expiryMs, &s.UserID, &data)
	if err != nil {
		return nil, fmt.Errorf("querying session: %w", err)
	}

	s.Expiry = time.UnixMilli(expiryMs)
	if err := json.Unmarshal(data, &s.Data); err != nil {
		return nil, fmt.Errorf("unmarshalling session data: %w", err)
	}
	return &s, nil
}

func (tx *Tx) PutSession(ctx context.Context, s *Session) error {
	data, err := json.Marshal(s.Data)
	if err != nil {
		return fmt.Errorf("marshalling session data: %w", err)
	}

	// NOTE: intentionally not updating the user_id since we should never
	// need to do that, and it might result in security bugs if we did.
	//
	// Use the WHERE clause to ensure that we only update a session if the
	// user matches, otherwise this becomes a no-op.
	_, err = tx.ExecContext(ctx, `
		INSERT INTO sessions (id, expiry, user_id, data)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (id) DO UPDATE
		SET expiry = $2, data = $4
		WHERE user_id = $3
	`, s.ID, s.Expiry.UnixMilli(), s.UserID, string(data))
	if err != nil {
		return fmt.Errorf("inserting session: %w", err)
	}
	return nil
}
