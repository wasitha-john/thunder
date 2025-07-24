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

package ou

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"
)

var (
	pathTestOU = CreateOURequest{
		Name:        "Engineering",
		Handle:      "engineering",
		Description: "Engineering Unit",
		Parent:      nil,
	}
)

var pathTestOUID string

type OUPathAPITestSuite struct {
	suite.Suite
}

func TestOUPathAPITestSuite(t *testing.T) {
	suite.Run(t, new(OUPathAPITestSuite))
}

func (suite *OUPathAPITestSuite) SetupSuite() {
	id, err := createOUForPath(pathTestOU)
	suite.Require().NoError(err, "Failed to create OU during setup: %v", err)
	pathTestOUID = id
}

func (suite *OUPathAPITestSuite) TearDownSuite() {
	if pathTestOUID != "" {
		err := deleteOUForPath(pathTestOU.Handle)
		if err != nil {
			suite.T().Logf("Failed to delete OU during teardown: %v", err)
		}
	}
}

// TestGetOrganizationUnitByPath tests retrieving an organization unit by handle path
func (suite *OUPathAPITestSuite) TestGetOrganizationUnitByPath() {
	if pathTestOUID == "" {
		suite.T().Fatal("OU ID is not available for path-based retrieval")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("GET", testServerURL+"/organization-units/tree/"+pathTestOU.Handle, nil)
	suite.Require().NoError(err)

	resp, err := client.Do(req)
	suite.Require().NoError(err)
	defer func() {
		if err := resp.Body.Close(); err != nil {
			suite.T().Logf("Failed to close response body: %v", err)
		}
	}()

	suite.Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err, "Failed to read response body: %v", err)

	var retrievedOU OrganizationUnit
	err = json.Unmarshal(body, &retrievedOU)
	suite.Require().NoError(err)

	// Verify the retrieved OU
	suite.Equal(pathTestOUID, retrievedOU.ID)
	suite.Equal(pathTestOU.Name, retrievedOU.Name)
	suite.Equal(pathTestOU.Handle, retrievedOU.Handle)
	suite.Equal(pathTestOU.Description, retrievedOU.Description)
	suite.Equal(pathTestOU.Parent, retrievedOU.Parent)
}

// TestGetOrganizationUnitByInvalidPath tests retrieving an organization unit by invalid handle path
func (suite *OUPathAPITestSuite) TestGetOrganizationUnitByInvalidPath() {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("GET", testServerURL+"/organization-units/tree/nonexistent", nil)
	suite.Require().NoError(err)

	resp, err := client.Do(req)
	suite.Require().NoError(err)
	defer func() {
		if err := resp.Body.Close(); err != nil {
			suite.T().Logf("Failed to close response body: %v", err)
		}
	}()

	suite.Equal(http.StatusNotFound, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err)

	var errorResp ErrorResponse
	err = json.Unmarshal(body, &errorResp)
	suite.Require().NoError(err)

	suite.Equal("OU-1003", errorResp.Code)
	suite.Equal("Organization unit not found", errorResp.Message)
}

// TestUpdateOrganizationUnitByPath tests updating an organization unit by handle path
func (suite *OUPathAPITestSuite) TestUpdateOrganizationUnitByPath() {
	if pathTestOUID == "" {
		suite.T().Fatal("OU ID is not available for path-based update test")
	}

	updateRequest := UpdateOURequest{
		Handle:      "engineering",
		Name:        "Updated OU via Path",
		Description: "Updated description via path",
	}

	jsonData, err := json.Marshal(updateRequest)
	suite.Require().NoError(err)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("PUT", testServerURL+"/organization-units/tree/"+pathTestOU.Handle, bytes.NewBuffer(jsonData))
	suite.Require().NoError(err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	suite.Require().NoError(err)
	defer resp.Body.Close()

	suite.Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err)

	var updatedOU OrganizationUnit
	err = json.Unmarshal(body, &updatedOU)
	suite.Require().NoError(err)

	// Verify the update
	suite.Equal(pathTestOUID, updatedOU.ID)
	suite.Equal(updateRequest.Name, updatedOU.Name)
	suite.Equal(updateRequest.Description, updatedOU.Description)
	suite.Equal(updateRequest.Handle, updatedOU.Handle)

	// Update the global test data for subsequent tests
	pathTestOU.Name = updateRequest.Name
	pathTestOU.Description = updateRequest.Description
}

// TestUpdateOrganizationUnitByInvalidPath tests updating an organization unit by invalid handle path
func (suite *OUPathAPITestSuite) TestUpdateOrganizationUnitByInvalidPath() {
	updateRequest := UpdateOURequest{
		Name:        "Updated OU via Invalid Path",
		Description: "Updated description via invalid path",
	}

	jsonData, err := json.Marshal(updateRequest)
	suite.Require().NoError(err)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("PUT", testServerURL+"/organization-units/tree/nonexistent", bytes.NewBuffer(jsonData))
	suite.Require().NoError(err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	suite.Require().NoError(err)
	defer resp.Body.Close()

	suite.Equal(http.StatusNotFound, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err)

	var errorResp ErrorResponse
	err = json.Unmarshal(body, &errorResp)
	suite.Require().NoError(err)

	suite.Equal("OU-1003", errorResp.Code)
	suite.Equal("Organization unit not found", errorResp.Message)
}

// TestUpdateOrganizationUnitByPathWithInvalidData tests updating an organization unit by path with invalid data
func (suite *OUPathAPITestSuite) TestUpdateOrganizationUnitByPathWithInvalidData() {
	if pathTestOUID == "" {
		suite.T().Fatal("OU ID is not available for path-based update test")
	}

	// Test with empty name
	updateRequest := UpdateOURequest{
		Name:        "",
		Description: "Testing empty name",
	}

	jsonData, err := json.Marshal(updateRequest)
	suite.Require().NoError(err)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("PUT", testServerURL+"/organization-units/tree/"+pathTestOU.Handle, bytes.NewBuffer(jsonData))
	suite.Require().NoError(err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	suite.Require().NoError(err)
	defer resp.Body.Close()

	suite.Equal(http.StatusBadRequest, resp.StatusCode)
}

// TestDeleteOrganizationUnitByInvalidPath tests deleting an organization unit by invalid handle path
func (suite *OUPathAPITestSuite) TestDeleteOrganizationUnitByInvalidPath() {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("DELETE", testServerURL+"/organization-units/tree/nonexistent", nil)
	suite.Require().NoError(err)

	resp, err := client.Do(req)
	suite.Require().NoError(err)
	defer func() {
		if err := resp.Body.Close(); err != nil {
			suite.T().Logf("Failed to close response body: %v", err)
		}
	}()

	suite.Equal(http.StatusNotFound, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err)

	var errorResp ErrorResponse
	err = json.Unmarshal(body, &errorResp)
	suite.Require().NoError(err)

	suite.Equal("OU-1003", errorResp.Code)
	suite.Equal("Organization unit not found", errorResp.Message)
}

// createOUForPath is a helper function to create an OU for path tests
func createOUForPath(ouRequest CreateOURequest) (string, error) {
	jsonData, err := json.Marshal(ouRequest)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", testServerURL+"/organization-units", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", err
	}

	var createdOU OrganizationUnit
	err = json.NewDecoder(resp.Body).Decode(&createdOU)
	if err != nil {
		return "", err
	}

	return createdOU.ID, nil
}

// deleteOUForPath is a helper function to delete an OU for path tests
func deleteOUForPath(path string) error {
	req, err := http.NewRequest("DELETE", testServerURL+"/organization-units/tree/"+path, nil)
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

	return nil
}
