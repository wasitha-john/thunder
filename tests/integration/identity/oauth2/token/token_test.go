/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package token

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"
)

const (
	testServerURL = "https://localhost:8095"
	clientID      = "client123"
	clientSecret  = "secret123"
)

type TokenTestSuite struct {
	suite.Suite
}

func TestTokenTestSuite(t *testing.T) {

	suite.Run(t, new(TokenTestSuite))
}

func (ts *TokenTestSuite) TestClientCredentialsGrant() {

	// Prepare the request
	reqBody := bytes.NewBufferString("grant_type=client_credentials")
	req, err := http.NewRequest("POST", testServerURL+"/oauth2/token", reqBody)
	if err != nil {
		ts.T().Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

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
	var respBody map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&respBody)
	if err != nil {
		ts.T().Fatalf("Failed to parse response body: %v", err)
	}

	if _, ok := respBody["access_token"]; !ok {
		ts.T().Fatalf("Response does not contain access_token")
	}
	if _, ok := respBody["token_type"]; !ok {
		ts.T().Fatalf("Response does not contain token_type")
	}
	if _, ok := respBody["expires_in"]; !ok {
		ts.T().Fatalf("Response does not contain expires_in")
	}
}
