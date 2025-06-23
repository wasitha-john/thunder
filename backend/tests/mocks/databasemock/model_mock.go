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
	"database/sql"
)

// MockTx is a mock implementation of the TxInterface.
type MockTx struct {
	// MockCommit defines the behavior for the Commit method.
	MockCommit func() error

	// MockRollback defines the behavior for the Rollback method.
	MockRollback func() error

	// MockExec defines the behavior for the Exec method.
	MockExec func(query string, args ...any) (sql.Result, error)

	// CommitCalls tracks the calls to Commit.
	CommitCalls int

	// RollbackCalls tracks the calls to Rollback.
	RollbackCalls int

	// ExecCalls tracks the arguments passed to Exec.
	ExecCalls []struct {
		Query string
		Args  []any
	}
}

// Commit mocks the Commit method of the TxInterface.
func (m *MockTx) Commit() error {
	m.CommitCalls++

	if m.MockCommit != nil {
		return m.MockCommit()
	}
	return nil
}

// Rollback mocks the Rollback method of the TxInterface.
func (m *MockTx) Rollback() error {
	m.RollbackCalls++

	if m.MockRollback != nil {
		return m.MockRollback()
	}
	return nil
}

// Exec mocks the Exec method of the TxInterface.
func (m *MockTx) Exec(query string, args ...any) (sql.Result, error) {
	m.ExecCalls = append(m.ExecCalls, struct {
		Query string
		Args  []any
	}{query, args})

	if m.MockExec != nil {
		return m.MockExec(query, args...)
	}
	return &MockSQLResult{}, nil
}

// MockSQLResult is a mock implementation of sql.Result.
type MockSQLResult struct {
	// MockLastInsertID defines the behavior for the LastInsertId method.
	MockLastInsertID func() (int64, error)

	// MockRowsAffected defines the behavior for the RowsAffected method.
	MockRowsAffected func() (int64, error)
}

// LastInsertId mocks the LastInsertId method of sql.Result.
func (m *MockSQLResult) LastInsertId() (int64, error) {
	if m.MockLastInsertID != nil {
		return m.MockLastInsertID()
	}
	return 0, nil
}

// RowsAffected mocks the RowsAffected method of sql.Result.
func (m *MockSQLResult) RowsAffected() (int64, error) {
	if m.MockRowsAffected != nil {
		return m.MockRowsAffected()
	}
	return 0, nil
}
