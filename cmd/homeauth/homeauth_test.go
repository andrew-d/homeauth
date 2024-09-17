package main

import (
	"net/url"
	"testing"
)

func TestValidateRedirectURI(t *testing.T) {
	tests := []struct {
		name string
		uri  string
		want string
	}{
		{
			name: "valid",
			uri:  "http://example.com",
		},
		{
			name: "not_absolute",
			uri:  "/foo",
			want: "redirect_uri must be an absolute URI",
		},
		{
			name: "not_http",
			uri:  "ftp://example.com",
			want: "redirect_uri must be http or https",
		},
		{
			name: "no_host",
			uri:  "http:///foo",
			want: "redirect_uri must include a host",
		},
		{
			name: "has_fragment",
			uri:  "http://example.com/#foo",
			want: "redirect_uri must not include a fragment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uu, err := url.Parse(tt.uri)
			if err != nil {
				t.Fatalf("failed to parse URI: %v", err)
			}

			got := validateRedirectURI(uu)
			if tt.want == "" && got != nil {
				t.Errorf("validateRedirectURI() = %v, want nil", got)
			} else if tt.want != "" && got == nil {
				t.Errorf("validateRedirectURI() = nil, want %v", tt.want)
			} else if tt.want != "" && got.Error() != tt.want {
				t.Errorf("validateRedirectURI() = %q, want %q", got, tt.want)
			}
		})
	}
}
