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

package databasemock

import (
	"github.com/asgardeo/thunder/internal/system/database/client"
)

// MockDBProvider is a mock implementation of the DBProviderInterface.
type MockDBProvider struct {
	// MockGetDBClient defines the behavior for the GetDBClient method.
	MockGetDBClient func(dbName string) (client.DBClientInterface, error)

	// GetDBClientCalls tracks the arguments passed to GetDBClient.
	GetDBClientCalls []string
}

// GetDBClient mocks the GetDBClient method of the DBProviderInterface.
func (m *MockDBProvider) GetDBClient(dbName string) (client.DBClientInterface, error) {
	m.GetDBClientCalls = append(m.GetDBClientCalls, dbName)

	if m.MockGetDBClient != nil {
		return m.MockGetDBClient(dbName)
	}

	// Return a default mock client by default
	return &MockDBClient{}, nil
}
