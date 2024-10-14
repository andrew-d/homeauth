package testproc

import (
	"slices"
	"testing"
)

func TestLineWriter(t *testing.T) {
	tests := []struct {
		name   string
		writes []string
		want   []string
	}{
		{
			name:   "single_line_with_newline",
			writes: []string{"hello, world\n"},
			want:   []string{"hello, world"},
		},
		{
			name:   "single_line_without_newline",
			writes: []string{"hello, world"},
			want:   []string{"hello, world"},
		},
		{
			name:   "multiple_lines",
			writes: []string{"line1\nline2\nline3\n"},
			want:   []string{"line1", "line2", "line3"},
		},
		{
			name:   "partial_then_full",
			writes: []string{"line1 ", "line2\nline3"},
			want:   []string{"line1 line2", "line3"},
		},
		{
			name:   "blank lines",
			writes: []string{"\n", "foo\n"},
			want:   []string{"", "foo"},
		},
		{
			name:   "empty",
			writes: []string{""},
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockFunc{}
			lw := newLineWriter(mock.Handle)

			for i, write := range tt.writes {
				n, err := lw.Write([]byte(write))
				if err != nil {
					t.Fatalf("Write(%q) [i=%d] got unexpected error: %v", write, i, err)
				}
				if n > len(write) {
					t.Fatalf("Write(%q) [i=%d] wrote more than the input: %d > %d", write, i, n, len(write))
				}
			}

			// Close to flush any remaining data.
			if err := lw.Close(); err != nil {
				t.Fatalf("Close got unexpected error: %v", err)
			}

			if !slices.Equal(mock.got, tt.want) {
				t.Errorf("got lines %+v, want %+v", mock.got, tt.want)
			}
		})
	}
}

type mockFunc struct {
	got []string
}

func (m *mockFunc) Handle(line string) error {
	m.got = append(m.got, line)
	return nil
}
