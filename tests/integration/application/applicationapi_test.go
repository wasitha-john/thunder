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

package application

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"
)

const (
	testServerURL = "https://localhost:8095"
)

var (
	preCreatedApp = Application{
		ID:                        "550e8400-e29b-41d4-a716-446655440000",
		Name:                      "Test SPA",
		Description:               "Initial testing App",
		ClientID:                  "client123",
		IsRegistrationFlowEnabled: false,
		// Default API values
		AuthFlowGraphID:         "auth_flow_config_basic",
		RegistrationFlowGraphID: "registration_flow_config_basic",
		Certificate: &ApplicationCert{
			Type:  "NONE",
			Value: "",
		},
	}

	appToCreate = Application{
		Name:                      "My App",
		Description:               "A demo application",
		IsRegistrationFlowEnabled: true,
		URL:                       "https://myapp.example.com",
		LogoURL:                   "https://myapp.example.com/logo.png",
		AuthFlowGraphID:           "auth_flow_config_basic",
		RegistrationFlowGraphID:   "registration_flow_config_basic",
		Certificate: &ApplicationCert{
			Type:  "NONE",
			Value: "",
		},
		InboundAuthConfig: []InboundAuthConfig{
			{
				Type: "oauth2",
				OAuthAppConfig: &OAuthAppConfig{
					ClientID:                "abc1237",
					ClientSecret:            "s3cret",
					RedirectURIs:            []string{"http://localhost/callback"},
					GrantTypes:              []string{"authorization_code", "client_credentials"},
					ResponseTypes:           []string{"code"},
					TokenEndpointAuthMethod: []string{"client_secret_basic", "client_secret_post"},
				},
			},
		},
	}

	appToUpdate = Application{
		Name:                      "Updated App",
		Description:               "Updated Description",
		IsRegistrationFlowEnabled: false,
		URL:                       "https://updatedapp.example.com",
		LogoURL:                   "https://updatedapp.example.com/logo.png",
		AuthFlowGraphID:           "auth_flow_config_basic",
		RegistrationFlowGraphID:   "registration_flow_config_basic",
		Certificate: &ApplicationCert{
			Type:  "NONE",
			Value: "",
		},
		InboundAuthConfig: []InboundAuthConfig{
			{
				Type: "oauth2",
				OAuthAppConfig: &OAuthAppConfig{
					ClientID:                "updated_client_id",
					ClientSecret:            "updated_secret",
					RedirectURIs:            []string{"http://localhost/callback2"},
					GrantTypes:              []string{"authorization_code"},
					ResponseTypes:           []string{"code"},
					TokenEndpointAuthMethod: []string{"client_secret_basic"},
				},
			},
		},
	}
)

var createdAppID string

type ApplicationAPITestSuite struct {
	suite.Suite
}

func TestApplicationAPITestSuite(t *testing.T) {

	suite.Run(t, new(ApplicationAPITestSuite))
}

// SetupSuite test application creation
func (ts *ApplicationAPITestSuite) SetupSuite() {

	id, err := createApplication(ts)
	if err != nil {
		ts.T().Fatalf("Failed to create application during setup: %v", err)
	} else {
		createdAppID = id
	}
}

// TearDownSuite test application deletion
func (ts *ApplicationAPITestSuite) TearDownSuite() {

	if createdAppID != "" {
		err := deleteApplication(createdAppID)
		if err != nil {
			ts.T().Fatalf("Failed to delete application during teardown: %v", err)
		}
	}
}

// Test application listing
func (ts *ApplicationAPITestSuite) TestApplicationListing() {

	req, err := http.NewRequest("GET", testServerURL+"/applications", nil)
	if err != nil {
		ts.T().Fatalf("Failed to create request: %v", err)
	}

	// Configure the HTTP client to skip TLS verification
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Skip certificate verification
		},
	}

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		ts.T().Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Validate the response
	if resp.StatusCode != http.StatusOK {
		ts.T().Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// Parse the response body
	var appList ApplicationList
	err = json.NewDecoder(resp.Body).Decode(&appList)
	if err != nil {
		ts.T().Fatalf("Failed to parse response body: %v", err)
	}

	totalResults := appList.TotalResults
	if totalResults == 0 {
		ts.T().Fatalf("Response does not contain a valid total results count")
	}

	appCount := appList.Count
	if appCount == 0 {
		ts.T().Fatalf("Response does not contain a valid application count")
	}

	applicationListLength := len(appList.Applications)
	if applicationListLength == 0 {
		ts.T().Fatalf("Response does not contain any applications")
	}

	if applicationListLength != 2 {
		ts.T().Fatalf("Expected 2 applications, got %d", applicationListLength)
	}

	// When listing applications, we need to compare to the BasicApplicationResponse structure
	// which might have different fields from what we expect in our test
	// Instead of direct comparison, let's check the core fields that we care about
	app1 := appList.Applications[0]
	if app1.ID != preCreatedApp.ID ||
		app1.Name != preCreatedApp.Name ||
		app1.Description != preCreatedApp.Description ||
		app1.ClientID != preCreatedApp.ClientID {
		ts.T().Fatalf("Application core fields mismatch for preCreatedApp")
	}

	app2 := appList.Applications[1]
	createdApp := buildCreatedAppBasic()
	if app2.ID != createdApp.ID ||
		app2.Name != createdApp.Name ||
		app2.Description != createdApp.Description ||
		app2.ClientID != createdApp.ClientID {
		ts.T().Fatalf("Application core fields mismatch for createdApp")
	}
}

// Test application get by ID
func (ts *ApplicationAPITestSuite) TestApplicationGetByID() {

	if createdAppID == "" {
		ts.T().Fatal("Application ID is not available for retrieval")
	}
	application := buildCreatedApp()
	retrieveAndValidateApplicationDetails(ts, application)
}

// Test application update
func (ts *ApplicationAPITestSuite) TestApplicationUpdate() {

	if createdAppID == "" {
		ts.T().Fatal("Application ID is not available for update")
	}

	// Add the ID to the application to update
	appToUpdateWithID := appToUpdate
	appToUpdateWithID.ID = createdAppID

	appJSON, err := json.Marshal(appToUpdateWithID)
	if err != nil {
		ts.T().Fatalf("Failed to marshal appToUpdate: %v", err)
	}

	reqBody := bytes.NewReader(appJSON)
	req, err := http.NewRequest("PUT", testServerURL+"/applications/"+createdAppID, reqBody)
	if err != nil {
		ts.T().Fatalf("Failed to create update request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		ts.T().Fatalf("Failed to send update request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		responseBody, _ := io.ReadAll(resp.Body)
		ts.T().Fatalf("Expected status 200, got %d. Response: %s", resp.StatusCode, string(responseBody))
	}

	// For update operations, verify the response directly
	var updatedApp Application
	if err = json.NewDecoder(resp.Body).Decode(&updatedApp); err != nil {
		responseBody, _ := io.ReadAll(resp.Body)
		ts.T().Fatalf("Failed to decode update response: %v. Response: %s", err, string(responseBody))
	}

	// Client secret should be present in the update response
	if len(updatedApp.InboundAuthConfig) > 0 &&
		updatedApp.InboundAuthConfig[0].OAuthAppConfig != nil &&
		updatedApp.InboundAuthConfig[0].OAuthAppConfig.ClientSecret == "" {
		ts.T().Fatalf("Expected client secret in update response but got empty string")
	}

	// Now validate by getting the application (which should not have client secret)
	// Make sure client ID is properly set in the root level before validation
	if len(appToUpdateWithID.InboundAuthConfig) > 0 &&
		appToUpdateWithID.InboundAuthConfig[0].OAuthAppConfig != nil {
		appToUpdateWithID.ClientID = appToUpdateWithID.InboundAuthConfig[0].OAuthAppConfig.ClientID
	}

	retrieveAndValidateApplicationDetails(ts, appToUpdateWithID)
}

func retrieveAndValidateApplicationDetails(ts *ApplicationAPITestSuite, expectedApp Application) {

	req, err := http.NewRequest("GET", testServerURL+"/applications/"+expectedApp.ID, nil)
	if err != nil {
		ts.T().Fatalf("Failed to create request: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		ts.T().Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		responseBody, _ := io.ReadAll(resp.Body)
		ts.T().Fatalf("Expected status 200, got %d. Response: %s", resp.StatusCode, string(responseBody))
	}

	// Check if the response Content-Type is application/json
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		ts.T().Fatalf("Expected Content-Type application/json, got %s", contentType)
	}

	var app Application
	body, _ := io.ReadAll(resp.Body)
	err = json.Unmarshal(body, &app)
	if err != nil {
		ts.T().Fatalf("Failed to parse response body: %v\nResponse body: %s", err, string(body))
	}

	// For GET operations, client secret should be empty in the response
	// Make sure expectedApp has client secret cleared for proper comparison
	appForComparison := expectedApp
	if len(appForComparison.InboundAuthConfig) > 0 && appForComparison.InboundAuthConfig[0].OAuthAppConfig != nil {
		// Make sure client ID is in root object
		appForComparison.ClientID = appForComparison.InboundAuthConfig[0].OAuthAppConfig.ClientID
		// Remove client secret for GET comparison
		appForComparison.InboundAuthConfig[0].OAuthAppConfig.ClientSecret = ""
	}

	// Ensure certificate is set in expected app if it's null
	if appForComparison.Certificate == nil {
		appForComparison.Certificate = &ApplicationCert{
			Type:  "NONE",
			Value: "",
		}
	}

	if !app.equals(appForComparison) {
		appJSON, _ := json.MarshalIndent(app, "", "  ")
		expectedJSON, _ := json.MarshalIndent(appForComparison, "", "  ")
		ts.T().Fatalf("Application mismatch:\nGot:\n%s\n\nExpected:\n%s", string(appJSON), string(expectedJSON))
	}
}

func createApplication(ts *ApplicationAPITestSuite) (string, error) {

	appJSON, err := json.Marshal(appToCreate)
	if err != nil {
		ts.T().Fatalf("Failed to marshal appToCreate: %v", err)
	}

	reqBody := bytes.NewReader(appJSON)
	req, err := http.NewRequest("POST", testServerURL+"/applications", reqBody)
	if err != nil {
		// print error
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		responseBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("expected status 201, got %d. Response: %s", resp.StatusCode, string(responseBody))
	}

	// For create operations, directly parse the response to a full Application
	var createdApp Application
	err = json.NewDecoder(resp.Body).Decode(&createdApp)
	if err != nil {
		return "", fmt.Errorf("failed to parse response body: %w", err)
	}

	// Verify client secret is present in the create response
	if len(createdApp.InboundAuthConfig) > 0 &&
		createdApp.InboundAuthConfig[0].OAuthAppConfig != nil &&
		createdApp.InboundAuthConfig[0].OAuthAppConfig.ClientSecret == "" {
		return "", fmt.Errorf("expected client secret in create response but got empty string")
	}

	id := createdApp.ID
	if id == "" {
		return "", fmt.Errorf("response does not contain id")
	}
	createdAppID = id
	return id, nil
}

func deleteApplication(appID string) error {
	req, err := http.NewRequest("DELETE", testServerURL+"/applications/"+appID, nil)
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
		return fmt.Errorf("failed to send delete request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		responseBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("expected status 204, got %d. Response: %s", resp.StatusCode, string(responseBody))
	}
	return nil
}

func buildCreatedApp() Application {
	createdApp := appToCreate
	createdApp.ID = createdAppID

	// Make sure ClientID is correctly set in the root level
	// Extract it from OAuth config if needed
	if len(createdApp.InboundAuthConfig) > 0 && createdApp.InboundAuthConfig[0].OAuthAppConfig != nil {
		createdApp.ClientID = createdApp.InboundAuthConfig[0].OAuthAppConfig.ClientID
		// For GET operations, client secret should not be expected in the response
		createdApp.InboundAuthConfig[0].OAuthAppConfig.ClientSecret = ""
	}

	// Ensure certificate is set
	if createdApp.Certificate == nil {
		createdApp.Certificate = &ApplicationCert{
			Type:  "NONE",
			Value: "",
		}
	}

	return createdApp
}

// For list operations, we use a basic application structure without client secret
func buildCreatedAppBasic() Application {
	return Application{
		ID:                        createdAppID,
		Name:                      appToCreate.Name,
		Description:               appToCreate.Description,
		ClientID:                  "abc1237", // Get client ID from the OAuth config
		IsRegistrationFlowEnabled: appToCreate.IsRegistrationFlowEnabled,
		AuthFlowGraphID:           appToCreate.AuthFlowGraphID,
		RegistrationFlowGraphID:   appToCreate.RegistrationFlowGraphID,
		Certificate: &ApplicationCert{
			Type:  "NONE",
			Value: "",
		},
	}
}
