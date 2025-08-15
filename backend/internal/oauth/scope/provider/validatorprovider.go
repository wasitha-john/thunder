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

// Package provider provides functionality for managing scope validator instances.
package provider

import "github.com/asgardeo/thunder/internal/oauth/scope/validator"

// ScopeValidatorProviderInterface defines the interface for providing a scope validator.
type ScopeValidatorProviderInterface interface {
	GetScopeValidator() validator.ScopeValidatorInterface
}

// ScopeValidatorProvider is the default implementation of the ScopeValidatorProviderInterface.
type ScopeValidatorProvider struct{}

// NewScopeValidatorProvider creates a new instance of ScopeValidatorProvider.
func NewScopeValidatorProvider() ScopeValidatorProviderInterface {
	return &ScopeValidatorProvider{}
}

// GetScopeValidator returns the scope validator instance.
func (svp *ScopeValidatorProvider) GetScopeValidator() validator.ScopeValidatorInterface {
	return validator.NewAPIScopeValidator()
}
