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

package idp

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
	preCreatedIdpToList = []IDP{
		{
			ID:          "550e8400-e29b-41d4-a716-446655440000",
			Name:        "Local",
			Description: "Local Identity Provider",
			Properties:  []IDPProperty{},
		},
		{
			ID:          "550e8400-e29b-41d4-a716-446655440001",
			Name:        "Github",
			Description: "Login with Github",
			Properties: []IDPProperty{
				{
					Name:     "client_id",
					Value:    "client1",
					IsSecret: false,
				},
				{
					Name:     "client_secret",
					Value:    "secret1",
					IsSecret: true,
				},
				{
					Name:     "redirect_uri",
					Value:    "https://localhost:3000",
					IsSecret: false,
				},
				{
					Name:     "scopes",
					Value:    "user:email,read:user",
					IsSecret: false,
				},
			},
		},
		{
			ID:          "550e8400-e29b-41d4-a716-446655440002",
			Name:        "Google",
			Description: "Login with Google",
			Properties: []IDPProperty{
				{
					Name:     "client_id",
					Value:    "client2",
					IsSecret: false,
				},
				{
					Name:     "client_secret",
					Value:    "secret2",
					IsSecret: true,
				},
				{
					Name:     "redirect_uri",
					Value:    "https://localhost:3000",
					IsSecret: false,
				},
				{
					Name:     "scopes",
					Value:    "openid,email,profile",
					IsSecret: false,
				},
			},
		},
	}

	idpToCreate = IDP{
		Name:        "Google 2",
		Description: "Google User Login",
		Properties: []IDPProperty{
			{
				Name:     "client_id",
				Value:    "client2",
				IsSecret: false,
			},
			{
				Name:     "client_secret",
				Value:    "secret2",
				IsSecret: true,
			},
			{
				Name:     "redirect_uri",
				Value:    "https://localhost:3000",
				IsSecret: false,
			},
			{
				Name:     "scopes",
				Value:    "openid,email,profile",
				IsSecret: false,
			},
		},
	}

	idpToUpdate = IDP{
		Name:        "Github 2",
		Description: "Github User Login",
		Properties: []IDPProperty{
			{
				Name:     "client_id",
				Value:    "client3",
				IsSecret: false,
			},
			{
				Name:     "client_secret",
				Value:    "secret3",
				IsSecret: true,
			},
			{
				Name:     "redirect_uri",
				Value:    "https://localhost:3000",
				IsSecret: false,
			},
			{
				Name:     "scopes",
				Value:    "user:email,read:user",
				IsSecret: false,
			},
		},
	}
)

var createdIdpID string

type IdpAPITestSuite struct {
	suite.Suite
}

func TestIdpAPITestSuite(t *testing.T) {

	suite.Run(t, new(IdpAPITestSuite))
}

// SetupSuite test IdP creation
func (ts *IdpAPITestSuite) SetupSuite() {

	id, err := createIdp(ts)
	if err != nil {
		ts.T().Fatalf("Failed to create IdP during setup: %v", err)
	} else {
		createdIdpID = id
	}
}

// TearDownSuite test IdP deletion
func (ts *IdpAPITestSuite) TearDownSuite() {

	if createdIdpID != "" {
		err := deleteIdp(createdIdpID)
		if err != nil {
			ts.T().Fatalf("Failed to delete IdP during tear down: %v", err)
		}
	}
}

// Test IdP listing
func (ts *IdpAPITestSuite) TestIdpListing() {

	req, err := http.NewRequest("GET", testServerURL+"/identity-providers", nil)
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
	var idps []IDP
	err = json.NewDecoder(resp.Body).Decode(&idps)
	if err != nil {
		ts.T().Fatalf("Failed to parse response body: %v", err)
	}

	idpListLength := len(idps)
	if idpListLength == 0 {
		ts.T().Fatalf("Response does not contain any identity providers")
	}

	if idpListLength != 4 {
		ts.T().Fatalf("Expected 4 identity providers, got %d", idpListLength)
	}

	createdIdp := buildCreatedIdpToList()
	for _, idp := range idps {
		if createdIdp.Name == idp.Name {
			if !idp.equals(createdIdp) {
				ts.T().Fatalf("IdP mismatch, expected %+v, got %+v", createdIdp, idp)
			}
		} else {
			// Check if the idP is one of the pre-created IdPs
			found := false
			for _, preCreatedIdp := range preCreatedIdpToList {
				if idp.equals(preCreatedIdp) {
					found = true
					break
				}
			}
			if !found {
				ts.T().Fatalf("Unexpected IdP found: %+v", idp)
			}
		}
	}
}

// Test idP get by ID
func (ts *IdpAPITestSuite) TestIdpGetByID() {

	if createdIdpID == "" {
		ts.T().Fatal("IdP ID is not available for retrieval")
	}
	idp := buildCreatedIdp()
	retrieveAndValidateIdpDetails(ts, idp)
}

// Test idP update
func (ts *IdpAPITestSuite) TestIdpUpdate() {

	if createdIdpID == "" {
		ts.T().Fatal("IdP ID is not available for update")
	}

	idpJSON, err := json.Marshal(idpToUpdate)
	if err != nil {
		ts.T().Fatalf("Failed to marshal idPToUpdate: %v", err)
	}

	reqBody := bytes.NewReader(idpJSON)
	req, err := http.NewRequest("PUT", testServerURL+"/identity-providers/"+createdIdpID, reqBody)
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
		ts.T().Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// Validate the update by retrieving the idP
	retrieveAndValidateIdpDetails(ts, IDP{
		ID:          createdIdpID,
		Name:        idpToUpdate.Name,
		Description: idpToUpdate.Description,
		Properties:  idpToUpdate.Properties,
	})
}

func retrieveAndValidateIdpDetails(ts *IdpAPITestSuite, expectedIdp IDP) {

	req, err := http.NewRequest("GET", testServerURL+"/identity-providers/"+expectedIdp.ID, nil)
	if err != nil {
		ts.T().Fatalf("Failed to create get request: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		ts.T().Fatalf("Failed to send get request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		ts.T().Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// Check if the response Content-Type is application/json
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		rawBody, _ := io.ReadAll(resp.Body)
		ts.T().Fatalf("Unexpected Content-Type: %s. Raw body: %s", contentType, string(rawBody))
	}

	var idp IDP
	err = json.NewDecoder(resp.Body).Decode(&idp)
	if err != nil {
		ts.T().Fatalf("Failed to parse response body: %v", err)
	}

	if !idp.equals(expectedIdp) {
		ts.T().Fatalf("IdP mismatch, expected %+v, got %+v", expectedIdp, idp)
	}
}

func createIdp(ts *IdpAPITestSuite) (string, error) {

	idpJSON, err := json.Marshal(idpToCreate)
	if err != nil {
		ts.T().Fatalf("Failed to marshal idPToCreate: %v", err)
	}

	reqBody := bytes.NewReader(idpJSON)
	req, err := http.NewRequest("POST", testServerURL+"/identity-providers", reqBody)
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
		return "", fmt.Errorf("expected status 201, got %d", resp.StatusCode)
	}

	var respBody map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&respBody)
	if err != nil {
		return "", fmt.Errorf("failed to parse response body: %w", err)
	}

	id, ok := respBody["id"].(string)
	if !ok {
		return "", fmt.Errorf("response does not contain id")
	}
	createdIdpID = id
	return id, nil
}

func deleteIdp(idpId string) error {

	req, err := http.NewRequest("DELETE", testServerURL+"/identity-providers/"+idpId, nil)
	if err != nil {
		return err
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return err
	}
	return nil
}

func buildCreatedIdp() IDP {

	return IDP{
		ID:          createdIdpID,
		Name:        idpToCreate.Name,
		Description: idpToCreate.Description,
		Properties:  idpToCreate.Properties,
	}
}

func buildCreatedIdpToList() IDP {

	return IDP{
		ID:          createdIdpID,
		Name:        idpToCreate.Name,
		Description: idpToCreate.Description,
		Properties:  idpToCreate.Properties,
	}
}
