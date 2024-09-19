package norm

import "testing"

func TestEmail(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "simple",
			in:   "andrew@du.nham.ca",
			want: "andrew@du.nham.ca",
		},
		{
			name: "case",
			in:   "AnDrEw@Du.NhAm.CA",
			want: "andrew@du.nham.ca",
		},
		{
			name: "spaces",
			in:   "andrew@du.nham.ca ",
			want: "andrew@du.nham.ca",
		},
		{
			name: "gmail",
			in:   "andrew.dunham+foo@gmail.com",
			want: "andrewdunham@gmail.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Email(tt.in); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
