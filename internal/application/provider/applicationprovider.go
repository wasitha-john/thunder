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

package provider

import (
	"github.com/asgardeo/thunder/internal/application/service"
	"github.com/asgardeo/thunder/internal/system/config"
)

// ApplicationProviderInterface defines the interface for the application provider.
type ApplicationProviderInterface interface {
	GetApplicationService() service.ApplicationServiceInterface
}

// ApplicationProvider is the default implementation of the ApplicationProviderInterface.
type ApplicationProvider struct {
	config *config.Config
}

// NewApplicationProvider creates a new instance of ApplicationProvider.
func NewApplicationProvider(cfg *config.Config) ApplicationProviderInterface {

	return &ApplicationProvider{
		config: cfg,
	}
}

// GetApplicationService returns the application service instance.
func (ap *ApplicationProvider) GetApplicationService() service.ApplicationServiceInterface {

	return service.GetApplicationService(ap.config)
}
