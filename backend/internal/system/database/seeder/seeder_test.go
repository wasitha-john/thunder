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

package seeder

import (
	"testing"

	"github.com/asgardeo/thunder/tests/mocks/database/clientmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

// SeederTestSuite is the test suite for the seeder package.
type SeederTestSuite struct {
	suite.Suite
	mockDBClient *clientmock.DBClientInterfaceMock
	seeder       SeederInterface
}

// SetupTest sets up the test suite.
func (suite *SeederTestSuite) SetupTest() {
	suite.mockDBClient = clientmock.NewDBClientInterfaceMock(suite.T())
	suite.seeder = NewDBSeeder(suite.mockDBClient)
}

// TestNewDBSeeder tests the creation of a new DBSeeder instance.
func (suite *SeederTestSuite) TestNewDBSeeder() {
	seeder := NewDBSeeder(suite.mockDBClient)
	assert.NotNil(suite.T(), seeder)
	assert.IsType(suite.T(), &DBSeeder{}, seeder)
}

// TestSeedInitialData_Success tests successful data seeding.
func (suite *SeederTestSuite) TestSeedInitialData_Success() {
	// Mock all the Execute calls to return success
	suite.mockDBClient.On("Execute", mock.AnythingOfType("model.DBQuery"), mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(int64(1), nil).Maybe()
	suite.mockDBClient.On("Execute", mock.AnythingOfType("model.DBQuery"), mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(int64(1), nil).Maybe()
	suite.mockDBClient.On("Execute", mock.AnythingOfType("model.DBQuery"), mock.Anything, mock.Anything, mock.Anything).Return(int64(1), nil).Maybe()
	suite.mockDBClient.On("Execute", mock.AnythingOfType("model.DBQuery"), mock.Anything).Return(int64(1), nil).Maybe()
	suite.mockDBClient.On("Execute", mock.AnythingOfType("model.DBQuery"), mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(int64(1), nil).Maybe()

	err := suite.seeder.SeedInitialData()
	
	assert.NoError(suite.T(), err)
}

// TestSeedInitialData_DatabaseError tests data seeding with database error.
func (suite *SeederTestSuite) TestSeedInitialData_DatabaseError() {
	// Mock the first Execute call to return an error
	suite.mockDBClient.On("Execute", mock.AnythingOfType("model.DBQuery"), mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(int64(0), assert.AnError).Once()

	err := suite.seeder.SeedInitialData()
	
	assert.Error(suite.T(), err)
}

// TestGetSeedData tests the seed data retrieval.
func (suite *SeederTestSuite) TestGetSeedData() {
	data := getSeedData()
	
	// Verify that all expected data is present
	assert.NotEmpty(suite.T(), data.OrganizationUnits)
	assert.NotEmpty(suite.T(), data.Apps)
	assert.NotEmpty(suite.T(), data.OAuthConsumerApps)
	assert.NotEmpty(suite.T(), data.InboundAuth)
	assert.NotEmpty(suite.T(), data.AllowedOrigins)
	assert.NotEmpty(suite.T(), data.Users)
	assert.NotEmpty(suite.T(), data.IDPs)
	assert.NotEmpty(suite.T(), data.IDPProperties)

	// Verify specific data integrity
	assert.Equal(suite.T(), "550e8400-e29b-41d4-a716-446655440000", data.Apps[0].AppID)
	assert.Equal(suite.T(), "Test SPA", data.Apps[0].AppName)
	assert.Equal(suite.T(), "client123", data.OAuthConsumerApps[0].ConsumerKey)
	assert.Equal(suite.T(), "Root Organization", data.OrganizationUnits[0].Name)
	assert.Nil(suite.T(), data.OrganizationUnits[0].ParentID)
	assert.NotNil(suite.T(), data.OrganizationUnits[1].ParentID)
}

// TestSeederProvider tests the seeder provider functionality.
func (suite *SeederTestSuite) TestSeederProvider() {
	// This would require mocking the DBProvider as well
	// For now, we'll test the provider creation
	provider := NewSeederProvider(nil)
	assert.NotNil(suite.T(), provider)
	assert.IsType(suite.T(), &SeederProvider{}, provider)
}

// TestSeederTestSuite runs the test suite.
func TestSeederTestSuite(t *testing.T) {
	suite.Run(t, new(SeederTestSuite))
}