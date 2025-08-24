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

package authz

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// TestCase represents a test case for authorization code flow
type TestCase struct {
	Name           string
	ClientID       string
	RedirectURI    string
	ResponseType   string
	Scope          string
	State          string
	Username       string
	Password       string
	ExpectedStatus int
	ExpectedError  string
}

// User represents a test user for authorization code tests
type User struct {
	OrganizationUnit string                 `json:"organizationUnit"`
	Type             string                 `json:"type"`
	Attributes       map[string]interface{} `json:"attributes"`
}

// FlowResponse represents the response from flow execution
type FlowResponse struct {
	FlowID        string    `json:"flowId"`
	FlowStatus    string    `json:"flowStatus"`
	Type          string    `json:"type"`
	Data          *FlowData `json:"data,omitempty"`
	Assertion     string    `json:"assertion,omitempty"`
	FailureReason string    `json:"failureReason,omitempty"`
}

// FlowData represents the data returned by flow execution
type FlowData struct {
	Inputs []FlowInput `json:"inputs,omitempty"`
}

// FlowInput represents an input required by the flow
type FlowInput struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
}

// AuthorizationResponse represents the response from authorization completion
type AuthorizationResponse struct {
	RedirectURI string `json:"redirect_uri"`
}

// TokenResponse represents the response from token exchange
type TokenResponse struct {
	AccessToken  string  `json:"access_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    float64 `json:"expires_in"`
	Scope        string  `json:"scope,omitempty"`
	RefreshToken string  `json:"refresh_token,omitempty"`
}

// TokenHTTPResult captures raw HTTP response details from the token endpoint.
type TokenHTTPResult struct {
	StatusCode int
	Body       []byte
	Token      *TokenResponse
}

// FlowStep represents a single step in a flow execution
type FlowStep struct {
	FlowID        string    `json:"flowId"`
	FlowStatus    string    `json:"flowStatus"`
	Type          string    `json:"type"`
	Data          *FlowData `json:"data,omitempty"`
	Assertion     string    `json:"assertion,omitempty"`
	FailureReason string    `json:"failureReason,omitempty"`
}

// createTestUser creates a test user with the given credentials
func createTestUser(testServerURL string, username, password string) (string, error) {
	userData := User{
		OrganizationUnit: "456e8400-e29b-41d4-a716-446655440001",
		Type:             "person",
		Attributes: map[string]interface{}{
			"username":  username,
			"password":  password,
			"email":     username + "@example.com",
			"firstName": "Test",
			"lastName":  "User",
		},
	}

	userJSON, err := json.Marshal(userData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal user data: %w", err)
	}

	req, err := http.NewRequest("POST", testServerURL+"/users", bytes.NewBuffer(userJSON))
	if err != nil {
		return "", fmt.Errorf("failed to create user request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to create user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("user creation failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var createdUser map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&createdUser)
	if err != nil {
		return "", fmt.Errorf("failed to decode user response: %w", err)
	}

	userID, ok := createdUser["id"].(string)
	if !ok {
		return "", fmt.Errorf("user ID not found in response")
	}

	return userID, nil
}

// deleteTestUser deletes a test user by ID
func deleteTestUser(testServerURL string, userID string) error {
	req, err := http.NewRequest("DELETE", testServerURL+"/users/"+userID, nil)
	if err != nil {
		return fmt.Errorf("failed to create delete request: %w", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("user deletion failed with status %d", resp.StatusCode)
	}

	return nil
}

// initiateAuthorizationFlow starts the OAuth2 authorization flow
func initiateAuthorizationFlow(testServerURL string, clientID, redirectURI, responseType, scope, state string) (*http.Response, error) {
	authURL := testServerURL + "/oauth2/authorize"
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("response_type", responseType)
	params.Set("scope", scope)
	params.Set("state", state)

	req, err := http.NewRequest("GET", authURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create authorization request: %w", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send authorization request: %w", err)
	}

	return resp, nil
}

// ExecuteAuthenticationFlow executes an authentication flow and returns the flow step
func ExecuteAuthenticationFlow(testServerURL string, applicationId string, inputs map[string]string) (*FlowStep, error) {
	flowData := map[string]interface{}{
		"applicationId": applicationId,
		"flowType":      "AUTHENTICATION",
	}
	if len(inputs) > 0 {
		flowData["inputs"] = inputs
	}

	flowJSON, err := json.Marshal(flowData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal flow data: %w", err)
	}

	req, err := http.NewRequest("POST", testServerURL+"/flow/execute", bytes.NewBuffer(flowJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create flow request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute flow: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("flow execution failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var flowStep FlowStep
	err = json.NewDecoder(resp.Body).Decode(&flowStep)
	if err != nil {
		return nil, fmt.Errorf("failed to decode flow response: %w", err)
	}

	return &flowStep, nil
}

// completeAuthorization completes the authorization using the assertion
func completeAuthorization(testServerURL string, sessionDataKey, assertion string) (*AuthorizationResponse, error) {
	authzData := map[string]interface{}{
		"sessionDataKey": sessionDataKey,
		"assertion":      assertion,
	}

	authzJSON, err := json.Marshal(authzData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal authorization data: %w", err)
	}

	req, err := http.NewRequest("POST", testServerURL+"/oauth2/authorize", bytes.NewBuffer(authzJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create authorization completion request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to complete authorization: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("authorization completion failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var authzResponse AuthorizationResponse
	err = json.NewDecoder(resp.Body).Decode(&authzResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode authorization response: %w", err)
	}

	return &authzResponse, nil
}

// requestToken performs a token request and returns raw HTTP result for both success and failure scenarios.
// grantType, code, and redirectURI are sent in the form body, while client credentials are sent via HTTP Basic Auth header.
func requestToken(testServerURL string, clientID, clientSecret, code, redirectURI, grantType string) (*TokenHTTPResult, error) {
	tokenURL := testServerURL + "/oauth2/token"
	tokenData := url.Values{}

	tokenData.Set("grant_type", grantType)
	tokenData.Set("code", code)
	tokenData.Set("redirect_uri", redirectURI)

	req, err := http.NewRequest("POST", tokenURL, bytes.NewBufferString(tokenData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if clientID != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	result := &TokenHTTPResult{
		StatusCode: resp.StatusCode,
		Body:       body,
	}

	// Only try to decode token response if status is 200
	if resp.StatusCode == http.StatusOK {
		var tokenResponse TokenResponse
		if err := json.Unmarshal(body, &tokenResponse); err != nil {
			return nil, fmt.Errorf("failed to unmarshal token response: %w", err)
		}
		result.Token = &tokenResponse
	}

	return result, nil
}

// extractAuthorizationCode extracts the authorization code from the redirect URI
func extractAuthorizationCode(redirectURI string) (string, error) {
	parsedURL, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("failed to parse redirect URI: %w", err)
	}

	code := parsedURL.Query().Get("code")
	if code == "" {
		return "", fmt.Errorf("authorization code not found in redirect URI")
	}

	return code, nil
}

// extractSessionData extracts session data from the authorization redirect
func extractSessionData(location string) (string, string, error) {
	redirectURL, err := url.Parse(location)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse redirect URL: %w", err)
	}

	sessionDataKey := redirectURL.Query().Get("sessionDataKey")
	if sessionDataKey == "" {
		return "", "", fmt.Errorf("sessionDataKey not found in redirect")
	}

	applicationId := redirectURL.Query().Get("applicationId")
	if applicationId == "" {
		return "", "", fmt.Errorf("applicationId not found in redirect")
	}

	return sessionDataKey, applicationId, nil
}

// validateOAuth2ErrorRedirect validates OAuth2 error redirect responses
func validateOAuth2ErrorRedirect(location string, expectedError string, expectedErrorDescription string) error {
	parsedURL, err := url.Parse(location)
	if err != nil {
		return fmt.Errorf("failed to parse redirect URL: %w", err)
	}

	queryParams := parsedURL.Query()

	// First check for OAuth2 error parameters (error, error_description)
	actualError := queryParams.Get("error")
	if actualError != "" {
		if actualError != expectedError {
			return fmt.Errorf("expected OAuth2 error '%s', got '%s'", expectedError, actualError)
		}

		if expectedErrorDescription != "" {
			actualErrorDescription := queryParams.Get("error_description")
			if actualErrorDescription != expectedErrorDescription {
				return fmt.Errorf("expected error_description '%s', got '%s'", expectedErrorDescription, actualErrorDescription)
			}
		}

		return nil
	}

	// Check for Thunder error page parameters (errorCode, errorMessage)
	actualErrorCode := queryParams.Get("errorCode")
	if actualErrorCode != "" {
		if actualErrorCode != expectedError {
			return fmt.Errorf("expected error code '%s', got '%s'", expectedError, actualErrorCode)
		}

		if expectedErrorDescription != "" {
			actualErrorMessage := queryParams.Get("errorMessage")
			if actualErrorMessage != expectedErrorDescription {
				return fmt.Errorf("expected error message '%s', got '%s'", expectedErrorDescription, actualErrorMessage)
			}
		}

		return nil
	}

	return fmt.Errorf("no error parameters found in redirect URL (neither 'error'/'error_description' nor 'errorCode'/'errorMessage')")
}
