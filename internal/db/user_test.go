package db

import (
	"context"
	"reflect"
	"testing"
)

func TestUser(t *testing.T) {
	db := newTestDB(t)

	ctx := context.Background()
	tx := db.MustTx(ctx)
	defer tx.Rollback()
	if err := tx.PutUser(ctx, &User{Email: "andrew@du.nham.ca"}); err != nil {
		t.Fatalf("PutUser: %v", err)
	}

	u, err := tx.GetUser(ctx, "andrew@du.nham.ca")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}

	want := &User{Email: "andrew@du.nham.ca"}
	if !reflect.DeepEqual(u, want) {
		t.Errorf("got user %v, want %v", u, want)
	}
}
