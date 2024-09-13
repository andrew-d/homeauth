package db

import (
	"context"

	"github.com/andrew-d/homeauth/internal/norm"
)

// User is the type of a user in the database.
type User struct {
	ID           int // TODO: key by email instead?
	Email        string
	PasswordHash string
}

// GetUser retrieves a user from the database by user ID.
func (tx *Tx) GetUser(ctx context.Context, id int) (*User, error) {
	row := tx.QueryRowContext(ctx, "SELECT id, email, password_hash FROM users WHERE id = ?", id)
	user := &User{}
	if err := row.Scan(&user.ID, &user.Email, &user.PasswordHash); err != nil {
		return nil, err
	}
	return user, nil
}

// GetUserByEmail retrieves a user from the database by email.
func (tx *Tx) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	row := tx.QueryRowContext(ctx, "SELECT id, email, password_hash FROM users WHERE email = ?", norm.Email(email))
	user := &User{}
	if err := row.Scan(&user.ID, &user.Email, &user.PasswordHash); err != nil {
		return nil, err
	}
	return user, nil
}

// PutUser adds a user to the database.
func (tx *Tx) PutUser(ctx context.Context, user *User) error {
	_, err := tx.ExecContext(ctx,
		"INSERT INTO users (email, password_hash) VALUES ($1)",
		norm.Email(user.Email),
		user.PasswordHash,
	)
	// TODO: return/set ID?
	if err != nil {
		return err
	}
	return nil
}
