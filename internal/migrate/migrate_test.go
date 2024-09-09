package migrate

import "testing"

const notIndented = `CREATE TABLE foo (
    id INTEGER PRIMARY KEY,
    name TEXT
);`

const notIndentedWithTabs = `CREATE TABLE foo (
	id INTEGER PRIMARY KEY,
	name TEXT
);`

const indented = `
	CREATE TABLE foo (
		id INTEGER PRIMARY KEY,
		name TEXT
	);`

const indentedExceptFirst = `CREATE TABLE foo (
		id INTEGER PRIMARY KEY,
		name TEXT
	);`

func TestCleanCreateTableSQL(t *testing.T) {
	testCases := []struct {
		name     string
		sql      string
		expected string
	}{
		{
			name:     "single_line",
			sql:      `CREATE TABLE foo (id INTEGER PRIMARY KEY, name TEXT);`,
			expected: `CREATE TABLE foo (id INTEGER PRIMARY KEY, name TEXT);`,
		},
		{
			name:     "not_indented",
			sql:      notIndented,
			expected: notIndented,
		},
		{
			name:     "not_indented_with_tabs",
			sql:      notIndentedWithTabs,
			expected: notIndented,
		},
		{
			name:     "indented",
			sql:      indented,
			expected: notIndented,
		},
		{
			name:     "indented_except_first",
			sql:      indentedExceptFirst,
			expected: notIndented,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			actual := cleanCreateTableSQL(tt.sql)
			if actual != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, actual)
			}
		})
	}
}
