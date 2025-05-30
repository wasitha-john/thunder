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

// Package model defines the data structures and interfaces for user management.
package model

import (
	"encoding/json"
	"errors"
)

// User represents a user in the system.
type User struct {
	ID               string          `json:"id,omitempty"`
	OrganizationUnit string          `json:"organizationUnit,omitempty"`
	Type             string          `json:"type,omitempty"`
	Attributes       json.RawMessage `json:"attributes,omitempty"`
}

// ErrUserNotFound is returned when the user is not found in the system.
var ErrUserNotFound = errors.New("user not found")

// ErrBadAttributesInRequest is returned when the attributes in the request are invalid.
var ErrBadAttributesInRequest = errors.New("failed to marshal attributes")
