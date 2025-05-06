package auth 

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Define test cases
	tests := []struct {
		name          string
		authHeader    string
		expectedKey   string
		expectedError error
	}{
		{
			name:          "Valid API Key",
			authHeader:    "ApiKey valid-api-key",
			expectedKey:   "valid-api-key",
			expectedError: nil,
		},
		{
			name:          "No Authorization Header",
			authHeader:    "",
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "Malformed Authorization Header",
			authHeader:    "InvalidHeader",
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "Wrong Authorization Scheme",
			authHeader:    "Bearer some-token",
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock HTTP request
			req := &http.Request{Header: http.Header{}}

			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			// req := &http.Request{Header: headers}

			// Call the GetAPIKey function
			apiKey, err := GetAPIKey(req.Header)

			// Assert the returned API key matches the expected value
			if apiKey != tt.expectedKey {
				t.Errorf("expected API key %q, got %q", tt.expectedKey, apiKey)
			}

			// Assert the returned error matches the expected error
			if (err != nil && tt.expectedError == nil) || (err == nil && tt.expectedError != nil) || (err != nil && err.Error() != tt.expectedError.Error()) {
				t.Errorf("expected error %v, got %v", tt.expectedError, err)
			}
		})
	}
}
