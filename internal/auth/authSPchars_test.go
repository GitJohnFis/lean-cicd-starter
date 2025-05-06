package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKeyWithSpecialCharacters(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		expectedKey   string
		expectedError error
	}{
		{
			name:          "API Key with Special Characters",
			authHeader:    "ApiKey ab@#$%^&*()_+={}[]|\\'\"<>,.?/~`-123",
			expectedKey:   "ab@#$%^&*()_+={}[]|\\'\"<>,.?/~`-123",
			expectedError: nil,
		},
		{
			name:          "Empty API Key",
			authHeader:    "ApiKey ",
			expectedKey:   "",
			expectedError: nil,
		},
		{
			name:          "Malformed Header",
			authHeader:    "InvalidHeader",
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock HTTP request
			req := &http.Request{Header: http.Header{}}
			req.Header.Set("Authorization", tt.authHeader)

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
