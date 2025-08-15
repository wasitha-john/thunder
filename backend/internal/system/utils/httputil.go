/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package utils

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	"github.com/asgardeo/thunder/internal/system/log"
)

// ExtractBasicAuthCredentials extracts the basic authentication credentials from the request header.
func ExtractBasicAuthCredentials(r *http.Request) (string, string, error) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Basic ") {
		return "", "", errors.New("invalid authorization header")
	}

	// Decode the base64 encoded credentials.
	encodedCredentials := strings.TrimPrefix(authHeader, "Basic ")
	decodedCredentials, err := base64.StdEncoding.DecodeString(encodedCredentials)
	if err != nil {
		return "", "", errors.New("failed to decode authorization header")
	}

	credentials := strings.SplitN(string(decodedCredentials), ":", 2)
	if len(credentials) != 2 {
		return "", "", errors.New("invalid authorization header format")
	}

	return credentials[0], credentials[1], nil
}

// WriteJSONError writes a JSON error response with the given details.
func WriteJSONError(w http.ResponseWriter, code, desc string, statusCode int, respHeaders []map[string]string) {
	logger := log.GetLogger()
	logger.Error("Error in HTTP response", log.String("error", code), log.String("description", desc))

	// Set the response headers.
	for _, header := range respHeaders {
		for key, value := range header {
			w.Header().Set(key, value)
		}
	}
	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(statusCode)
	err := json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": desc,
	})
	if err != nil {
		logger.Error("Failed to write JSON error response", log.Error(err))
		return
	}
}

// ParseURL parses the given URL string and returns a URL object.
func ParseURL(urlStr string) (*url.URL, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	return parsedURL, nil
}

// IsValidURI checks if the provided URI is valid.
func IsValidURI(uri string) bool {
	if uri == "" {
		return false
	}
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	return true
}

// GetURIWithQueryParams constructs a URI with the given query parameters.
func GetURIWithQueryParams(uri string, queryParams map[string]string) (string, error) {
	// Parse the URI.
	parsedURL, err := ParseURL(uri)
	if err != nil {
		return "", errors.New("failed to parse the return URI: " + err.Error())
	}

	// Return the URI if there are no query parameters.
	if len(queryParams) == 0 {
		return parsedURL.String(), nil
	}

	// Add the query parameters to the URI.
	query := parsedURL.Query()
	for key, value := range queryParams {
		query.Add(key, value)
	}
	parsedURL.RawQuery = query.Encode()

	// Return the constructed URI.
	return parsedURL.String(), nil
}

// DecodeJSONBody decodes JSON from the request body into any struct type T.
func DecodeJSONBody[T any](r *http.Request) (*T, error) {
	var data T
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		return nil, errors.New("failed to decode JSON: " + err.Error())
	}
	return &data, nil
}

// SanitizeString trims whitespace, removes control characters, and escapes HTML.
func SanitizeString(input string) string {
	if input == "" {
		return input
	}

	// Trim leading and trailing whitespace
	trimmed := strings.TrimSpace(input)

	// Remove non-printable/control characters (except newline and tab)
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, trimmed)

	// Escape HTML to prevent XSS
	safe := html.EscapeString(cleaned)

	return safe
}

// SanitizeStringMap sanitizes a map of strings.
// This function trim whitespace, removes control characters, and escapes HTML in each map entry.
func SanitizeStringMap(inputs map[string]string) map[string]string {
	if len(inputs) == 0 {
		return inputs
	}

	sanitized := make(map[string]string, len(inputs))
	for key, value := range inputs {
		sanitized[key] = SanitizeString(value)
	}
	return sanitized
}
