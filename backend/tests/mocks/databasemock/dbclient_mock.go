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

// Package mocks provides mock implementations of interfaces for testing.
package databasemock

import (
	"github.com/asgardeo/thunder/internal/system/database/model"
)

// MockDBClient is a mock implementation of the DBClientInterface.
type MockDBClient struct {
	// MockQuery defines the behavior for the Query method.
	MockQuery func(query model.DBQuery, args ...interface{}) ([]map[string]interface{}, error)

	// MockExecute defines the behavior for the Execute method.
	MockExecute func(query model.DBQuery, args ...interface{}) (int64, error)

	// MockBeginTx defines the behavior for the BeginTx method.
	MockBeginTx func() (model.TxInterface, error)

	// MockClose defines the behavior for the Close method.
	MockClose func() error

	// QueryCalls tracks the arguments passed to Query.
	QueryCalls []struct {
		Query model.DBQuery
		Args  []interface{}
	}

	// ExecuteCalls tracks the arguments passed to Execute.
	ExecuteCalls []struct {
		Query model.DBQuery
		Args  []interface{}
	}

	// BeginTxCalls tracks the calls to BeginTx.
	BeginTxCalls int

	// CloseCalls tracks the calls to Close.
	CloseCalls int
}

// Query mocks the Query method of the DBClientInterface.
func (m *MockDBClient) Query(query model.DBQuery, args ...interface{}) ([]map[string]interface{}, error) {
	m.QueryCalls = append(m.QueryCalls, struct {
		Query model.DBQuery
		Args  []interface{}
	}{query, args})

	if m.MockQuery != nil {
		return m.MockQuery(query, args...)
	}
	return []map[string]interface{}{}, nil
}

// Execute mocks the Execute method of the DBClientInterface.
func (m *MockDBClient) Execute(query model.DBQuery, args ...interface{}) (int64, error) {
	m.ExecuteCalls = append(m.ExecuteCalls, struct {
		Query model.DBQuery
		Args  []interface{}
	}{query, args})

	if m.MockExecute != nil {
		return m.MockExecute(query, args...)
	}
	return 0, nil
}

// BeginTx mocks the BeginTx method of the DBClientInterface.
func (m *MockDBClient) BeginTx() (model.TxInterface, error) {
	m.BeginTxCalls++

	if m.MockBeginTx != nil {
		return m.MockBeginTx()
	}
	return &MockTx{}, nil
}

// Close mocks the Close method of the DBClientInterface.
func (m *MockDBClient) Close() error {
	m.CloseCalls++

	if m.MockClose != nil {
		return m.MockClose()
	}
	return nil
}
