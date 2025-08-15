/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

// Package model defines the data structures and interfaces for IdP management.
package model

import (
	"errors"
)

// IDP represents an identity provider in the system.
type IDP struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`                  // Display name
	Description string        `json:"description,omitempty"` // Description shown in UI
	Properties  []IDPProperty `json:"properties,omitempty"`  // Properties of the IdP
}

// IDPProperty represents a property of an identity provider.
type IDPProperty struct {
	Name     string `json:"name"`      // Property name
	Value    string `json:"value"`     // Property value
	IsSecret bool   `json:"is_secret"` // Indicates if the property is a secret
}

// ErrIDPNotFound is returned when the IdP is not found in the system.
var ErrIDPNotFound = errors.New("IdP not found")

// ErrBadScopesInRequest is returned when the scopes in the request are invalid.
var ErrBadScopesInRequest = errors.New("failed to marshal scopes")
