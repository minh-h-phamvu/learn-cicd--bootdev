package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	testcases := []struct {
		name    string
		headers http.Header
		want    string
		wanterr error
	}{
		{
			"No Authorization header",
			http.Header{"Miss": []string{}},
			"", ErrNoAuthHeaderIncluded,
		},
		{
			"Malformed Authorization header",
			http.Header{"Authorization": []string{"malform"}},
			"", ErrMalformedHeader,
		},
		{
			"Empty value ApiKey Authorization header",
			http.Header{"Authorization": []string{"ApiKey"}},
			"", ErrMalformedHeader,
		},
		{
			"Valid Authorization header",
			http.Header{"Authorization": []string{"ApiKey random-UUID-key"}},
			"random-UUID-key", nil,
		},
		{
			"Too-much-fields Authorization header",
			http.Header{"Authorization": []string{"ApiKey random-UUID-key nonsense", "0xdeadbeaf"}},
			"random-UUID-key", nil,
		},
	}
	for _, tc := range testcases {
		got, err := GetAPIKey(tc.headers)
		t.Logf("Testcase name: %s  headers: %v", tc.name, tc.headers)
		if err != tc.wanterr {
			t.Errorf("Error is not match: got: %q, want: %q", err, tc.wanterr)
		}
		if got != tc.want {
			t.Errorf("return value mismatch: got: %q, want: %q", got, tc.want)
		}
	}
}
