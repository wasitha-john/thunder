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

package model

// DBQueryInterface defines the interface for database queries.
type DBQueryInterface interface {
	GetId() string
	GetQuery() string
}

// DBQuery represents database queries with an identifier and the SQL query string.
type DBQuery struct {
	// Id is the unique identifier for the query.
	Id string `json:"id"`
	// Query is the SQL query string.
	Query string `json:"query"`
}

// GetId returns the unique identifier for the query.
func (d *DBQuery) GetId() string {

	return d.Id
}

// GetQuery returns the SQL query string.
func (d *DBQuery) GetQuery() string {

	return d.Query
}
