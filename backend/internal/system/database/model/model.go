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

// Package model defines the data structures and interfaces for database operations.
package model

import "database/sql"

// TxInterface defines the wrapper interface for transaction management.
type TxInterface interface {
	// Commit commits the transaction.
	Commit() error
	// Rollback rolls back the transaction.
	Rollback() error
	// Exec executes a query with the given arguments.
	Exec(query string, args ...any) (sql.Result, error)
}

// Tx is the implementation of TxInterface for managing database transactions.
type Tx struct {
	internal *sql.Tx
}

// NewTx creates a new instance of Tx with the provided sql.Tx.
func NewTx(tx *sql.Tx) TxInterface {
	return &Tx{
		internal: tx,
	}
}

// Commit commits the transaction.
func (t *Tx) Commit() error {
	return t.internal.Commit()
}

// Rollback rolls back the transaction.
func (t *Tx) Rollback() error {
	return t.internal.Rollback()
}

// Exec executes a query with the given arguments.
func (t *Tx) Exec(query string, args ...any) (sql.Result, error) {
	return t.internal.Exec(query, args...)
}
