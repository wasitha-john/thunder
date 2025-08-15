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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type HTTPUtilTestSuite struct {
	suite.Suite
}

func TestHTTPUtilSuite(t *testing.T) {
	suite.Run(t, new(HTTPUtilTestSuite))
}

func (suite *HTTPUtilTestSuite) TestExtractBasicAuthCredentials() {
	testCases := []struct {
		name           string
		authHeader     string
		expectedUser   string
		expectedPass   string
		expectedErrMsg string
	}{
		{
			name:           "ValidBasicAuth",
			authHeader:     "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass")),
			expectedUser:   "user",
			expectedPass:   "pass",
			expectedErrMsg: "",
		},
		{
			name:           "MissingBasicPrefix",
			authHeader:     base64.StdEncoding.EncodeToString([]byte("user:pass")),
			expectedUser:   "",
			expectedPass:   "",
			expectedErrMsg: "invalid authorization header",
		},
		{
			name:           "InvalidBase64",
			authHeader:     "Basic invalid-base64",
			expectedUser:   "",
			expectedPass:   "",
			expectedErrMsg: "failed to decode authorization header",
		},
		{
			name:           "NoColonSeparator",
			authHeader:     "Basic " + base64.StdEncoding.EncodeToString([]byte("userpass")),
			expectedUser:   "",
			expectedPass:   "",
			expectedErrMsg: "invalid authorization header format",
		},
		{
			name:           "EmptyHeader",
			authHeader:     "",
			expectedUser:   "",
			expectedPass:   "",
			expectedErrMsg: "invalid authorization header",
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}

			user, pass, err := ExtractBasicAuthCredentials(req)

			if tc.expectedErrMsg != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				assert.Empty(t, user)
				assert.Empty(t, pass)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedUser, user)
				assert.Equal(t, tc.expectedPass, pass)
			}
		})
	}
}

func (suite *HTTPUtilTestSuite) TestWriteJSONError() {
	testCases := []struct {
		name        string
		code        string
		desc        string
		statusCode  int
		respHeaders []map[string]string
	}{
		{
			name:       "BasicError",
			code:       "invalid_request",
			desc:       "The request is missing a required parameter",
			statusCode: http.StatusBadRequest,
			respHeaders: []map[string]string{
				{"X-Custom-Header": "custom-value"},
			},
		},
		{
			name:       "UnauthorizedError",
			code:       "unauthorized",
			desc:       "Authentication is required to access this resource",
			statusCode: http.StatusUnauthorized,
			respHeaders: []map[string]string{
				{"WWW-Authenticate": "Basic"},
			},
		},
		{
			name:        "NoHeaders",
			code:        "server_error",
			desc:        "Internal server error occurred",
			statusCode:  http.StatusInternalServerError,
			respHeaders: []map[string]string{},
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			WriteJSONError(w, tc.code, tc.desc, tc.statusCode, tc.respHeaders)

			// Verify status code
			assert.Equal(t, tc.statusCode, w.Code)

			// Verify content type header
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

			// Verify custom headers
			for _, headerMap := range tc.respHeaders {
				for key, value := range headerMap {
					assert.Equal(t, value, w.Header().Get(key))
				}
			}

			// Verify response body
			var response map[string]string
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, tc.code, response["error"])
			assert.Equal(t, tc.desc, response["error_description"])
		})
	}
}

func (suite *HTTPUtilTestSuite) TestParseURL() {
	testCases := []struct {
		name        string
		url         string
		expectError bool
	}{
		{
			name:        "ValidURL",
			url:         "https://example.com/path?query=value",
			expectError: false,
		},
		{
			name:        "ValidURLWithPort",
			url:         "http://localhost:8080/api",
			expectError: false,
		},
		{
			name:        "InvalidURL",
			url:         "://invalid-url",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			parsedURL, err := ParseURL(tc.url)

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, parsedURL)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, parsedURL)
				assert.Equal(t, tc.url, parsedURL.String())
			}
		})
	}
}

func (suite *HTTPUtilTestSuite) TestGetURIWithQueryParams() {
	testCases := []struct {
		name        string
		uri         string
		queryParams map[string]string
		expected    string
		expectError bool
	}{
		{
			name:        "NoQueryParams",
			uri:         "https://example.com/path",
			queryParams: map[string]string{},
			expected:    "https://example.com/path",
			expectError: false,
		},
		{
			name: "SingleQueryParam",
			uri:  "https://example.com/path",
			queryParams: map[string]string{
				"param1": "value1",
			},
			expected:    "https://example.com/path?param1=value1",
			expectError: false,
		},
		{
			name: "MultipleQueryParams",
			uri:  "https://example.com/path",
			queryParams: map[string]string{
				"param1": "value1",
				"param2": "value2",
			},
			expected:    "https://example.com/path?param1=value1&param2=value2",
			expectError: false,
		},
		{
			name: "QueryParamsWithExistingParams",
			uri:  "https://example.com/path?existing=value",
			queryParams: map[string]string{
				"param1": "value1",
			},
			expected:    "https://example.com/path?existing=value&param1=value1",
			expectError: false,
		},
		{
			name:        "InvalidURI",
			uri:         "://invalid-uri",
			queryParams: map[string]string{},
			expected:    "",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			result, err := GetURIWithQueryParams(tc.uri, tc.queryParams)

			if tc.expectError {
				assert.Error(t, err)
				assert.Empty(t, result)
			} else {
				assert.NoError(t, err)

				// Parse both URLs to compare them without caring about parameter order
				expectedURL, err := url.Parse(tc.expected)
				assert.NoError(t, err)

				resultURL, err := url.Parse(result)
				assert.NoError(t, err)

				assert.Equal(t, expectedURL.Scheme, resultURL.Scheme)
				assert.Equal(t, expectedURL.Host, resultURL.Host)
				assert.Equal(t, expectedURL.Path, resultURL.Path)

				// Compare query parameters
				expectedQuery := expectedURL.Query()
				resultQuery := resultURL.Query()

				assert.Equal(t, len(expectedQuery), len(resultQuery))
				for key := range expectedQuery {
					assert.Equal(t, expectedQuery.Get(key), resultQuery.Get(key))
				}
			}
		})
	}
}

type testStruct struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

func (suite *HTTPUtilTestSuite) TestDecodeJSONBody() {
	testCases := []struct {
		name        string
		jsonBody    string
		expected    testStruct
		expectError bool
	}{
		{
			name:        "ValidJSON",
			jsonBody:    `{"name":"test","value":123}`,
			expected:    testStruct{Name: "test", Value: 123},
			expectError: false,
		},
		{
			name:        "EmptyJSON",
			jsonBody:    `{}`,
			expected:    testStruct{},
			expectError: false,
		},
		{
			name:        "InvalidJSON",
			jsonBody:    `{"name":"test","value":}`,
			expected:    testStruct{},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(tc.jsonBody))
			req.Header.Set("Content-Type", "application/json")

			result, err := DecodeJSONBody[testStruct](req)

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tc.expected.Name, result.Name)
				assert.Equal(t, tc.expected.Value, result.Value)
			}
		})
	}
}

func (suite *HTTPUtilTestSuite) TestSanitizeString() {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "NormalString",
			input:    "Normal string",
			expected: "Normal string",
		},
		{
			name:     "StringWithHTML",
			input:    "String with <script>alert('XSS')</script> HTML",
			expected: "String with &lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt; HTML",
		},
		{
			name:     "StringWithControlChars",
			input:    "String with control \x00 chars",
			expected: "String with control  chars",
		},
		{
			name:     "StringWithWhitespace",
			input:    "  Whitespace  ",
			expected: "Whitespace",
		},
		{
			name:     "EmptyString",
			input:    "",
			expected: "",
		},
		{
			name:     "OnlyWhitespace",
			input:    "   \t\n  ",
			expected: "",
		},
		{
			name:     "TabAndNewlinesPreserved",
			input:    "Line 1\nLine 2\tTabbed",
			expected: "Line 1\nLine 2\tTabbed",
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			result := SanitizeString(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func (suite *HTTPUtilTestSuite) TestSanitizeStringMap() {
	testCases := []struct {
		name     string
		input    map[string]string
		expected map[string]string
	}{
		{
			name:     "EmptyMap",
			input:    map[string]string{},
			expected: map[string]string{},
		},
		{
			name: "MapWithNormalStrings",
			input: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			expected: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		},
		{
			name: "MapWithStringsNeedingSanitizing",
			input: map[string]string{
				"key1": "  value with spaces  ",
				"key2": "<script>alert('XSS')</script>",
				"key3": "Control\x00Char",
			},
			expected: map[string]string{
				"key1": "value with spaces",
				"key2": "&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;",
				"key3": "ControlChar",
			},
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			result := SanitizeStringMap(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
