package db

import (
	"context"

	"github.com/andrew-d/homeauth/internal/norm"
)

// User is the type of a user in the database.
type User struct {
	Email        string
	PasswordHash string
}

// GetUser retrieves a user from the database.
func (tx *Tx) GetUser(ctx context.Context, email string) (*User, error) {
	row := tx.QueryRowContext(ctx, "SELECT email, password_hash FROM users WHERE email = ?", norm.Email(email))
	user := &User{}
	if err := row.Scan(&user.Email, &user.PasswordHash); err != nil {
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
	if err != nil {
		return err
	}
	return nil
}
