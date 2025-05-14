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

// Package validator provides functionality for validating scopes.
package validator

import (
	"strings"

	"github.com/asgardeo/thunder/internal/oauth/scope/constants"
	"github.com/asgardeo/thunder/internal/system/database/provider"
	"github.com/asgardeo/thunder/internal/system/log"
)

// ScopeError represents an error during scope validation.
type ScopeError struct {
	Error            string
	ErrorDescription string
}

// ScopeValidatorInterface defines the interface for scope validation.
type ScopeValidatorInterface interface {
	ValidateScopes(requestedScopes, clientID string) (string, *ScopeError)
}

// APIScopeValidator is the implementation of API scope validation.
type APIScopeValidator struct{}

// NewAPIScopeValidator creates a new instance of the APIScopeValidator.
func NewAPIScopeValidator() *APIScopeValidator {
	return &APIScopeValidator{}
}

// ValidateScopes validates and filters the requested scopes against the authorized scopes for the application.
func (sv *APIScopeValidator) ValidateScopes(requestedScopes, clientID string) (string, *ScopeError) {
	if requestedScopes == "" {
		return "", nil
	}

	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "APIScopeValidator"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return "", &ScopeError{
			Error:            "server_error",
			ErrorDescription: "Failed to validate scopes",
		}
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Error closing database client", log.Error(closeErr))
		}
	}()

	// Query authorized scopes for the client.
	results, err := dbClient.ExecuteQuery(constants.QueryGetAuthorizedScopesByClientID, clientID)
	if err != nil {
		logger.Error("Failed to execute scope query", log.Error(err))
		return "", &ScopeError{
			Error:            "server_error",
			ErrorDescription: "Failed to validate scopes",
		}
	}

	// Extract authorized scopes into a map for faster lookup.
	authorizedScopeMap := make(map[string]struct{})
	for _, row := range results {
		if scopeName, ok := row["name"].(string); ok {
			authorizedScopeMap[scopeName] = struct{}{}
		}
	}

	// Filter requested scopes using the map.
	requestedScopeList := strings.Fields(requestedScopes)
	validScopes := make([]string, 0, len(requestedScopeList))
	for _, scope := range requestedScopeList {
		if _, ok := authorizedScopeMap[scope]; ok {
			validScopes = append(validScopes, scope)
		}
	}

	return strings.Join(validScopes, " "), nil
}
