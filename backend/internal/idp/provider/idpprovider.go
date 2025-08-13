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

// Package provider provides the implementation for IdP management operations.
package provider

import (
	"github.com/asgardeo/thunder/internal/idp/service"
)

// IDPProviderInterface defines the interface for the IdP provider.
type IDPProviderInterface interface {
	GetIDPService() service.IDPServiceInterface
}

// IDPProvider is the default implementation of the IdPProviderInterface.
type IDPProvider struct{}

// NewIDPProvider creates a new instance of IdPProvider.
func NewIDPProvider() IDPProviderInterface {
	return &IDPProvider{}
}

// GetIDPService returns the IdP service instance.
func (ap *IDPProvider) GetIDPService() service.IDPServiceInterface {
	return service.GetIDPService()
}
