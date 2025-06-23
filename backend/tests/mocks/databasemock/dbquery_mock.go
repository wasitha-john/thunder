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

// MockDBQuery is a mock implementation of the DBQueryInterface.
type MockDBQuery struct {
	// ID to return from the GetID method.
	ID string

	// Query to return from the GetQuery method.
	Query string
}

// GetID returns the mocked ID.
func (m *MockDBQuery) GetID() string {
	return m.ID
}

// GetQuery returns the mocked query string.
func (m *MockDBQuery) GetQuery() string {
	return m.Query
}
