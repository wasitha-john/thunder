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

package flowauthn

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const testServerURL = "https://localhost:8095"

// Helper function to initiate the authentication flow
func initiateAuthFlow(appID string, inputs map[string]string) (*FlowStep, error) {
	flowReqBody := map[string]interface{}{
		"applicationId": appID,
	}
	if inputs != nil && len(inputs) > 0 {
		flowReqBody["inputs"] = inputs
	}

	reqBody, err := json.Marshal(flowReqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest("POST", testServerURL+"/flow/execution", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create flow request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send flow request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var flowStep FlowStep
	err = json.NewDecoder(resp.Body).Decode(&flowStep)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response body: %w", err)
	}

	return &flowStep, nil
}

// Helper function to initiate the authentication flow with error handling
func initiateAuthFlowWithError(appID string, inputs map[string]string) (*ErrorResponse, error) {
	flowReqBody := map[string]interface{}{
		"applicationId": appID,
	}
	if inputs != nil && len(inputs) > 0 {
		flowReqBody["inputs"] = inputs
	}

	reqBody, err := json.Marshal(flowReqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest("POST", testServerURL+"/flow/execution", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create flow request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send flow request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var errorResponse ErrorResponse
	err = json.NewDecoder(resp.Body).Decode(&errorResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse error response body: %w", err)
	}

	return &errorResponse, nil
}

// Helper function to complete the authentication flow
func completeAuthFlow(flowID string, inputs map[string]string) (*FlowStep, error) {
	flowReqBody := map[string]interface{}{
		"flowId": flowID,
		"inputs": inputs,
	}

	reqBody, err := json.Marshal(flowReqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest("POST", testServerURL+"/flow/execution", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create flow request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send flow request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var flowStep FlowStep
	err = json.NewDecoder(resp.Body).Decode(&flowStep)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response body: %w", err)
	}

	return &flowStep, nil
}

// Helper function to complete the authentication flow with error handling
func completeAuthFlowWithError(flowID string, inputs map[string]string) (*ErrorResponse, error) {
	flowReqBody := map[string]interface{}{
		"flowId": flowID,
		"inputs": inputs,
	}

	reqBody, err := json.Marshal(flowReqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest("POST", testServerURL+"/flow/execution", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create flow request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send flow request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var errorResponse ErrorResponse
	err = json.NewDecoder(resp.Body).Decode(&errorResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse error response body: %w", err)
	}

	return &errorResponse, nil
}

// Helper function to create a user
func createUser(user User) (string, error) {
	userJSON, err := json.Marshal(user)
	if err != nil {
		return "", fmt.Errorf("failed to marshal user: %w", err)
	}

	reqBody := bytes.NewReader(userJSON)
	req, err := http.NewRequest("POST", testServerURL+"/users", reqBody)
	if err != nil {
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
	return id, nil
}

// Helper function to delete a user
func deleteUser(userID string) error {
	req, err := http.NewRequest("DELETE", testServerURL+"/users/"+userID, nil)
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

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete user, status code: %d", resp.StatusCode)
	}
	return nil
}
