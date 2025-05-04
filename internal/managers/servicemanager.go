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

package managers

import (
	"net/http"

	"github.com/asgardeo/thunder/internal/services"
	"github.com/asgardeo/thunder/internal/system/config"
)

type ServiceManagerInterface interface {
	RegisterServices() error
}

type ServiceManager struct {
	mux    *http.ServeMux
	config *config.Config
}

// NewServiceManager creates a new instance of ServiceManager.
func NewServiceManager(mux *http.ServeMux, cfg *config.Config) ServiceManagerInterface {

	return &ServiceManager{
		mux:    mux,
		config: cfg,
	}
}

func (sm *ServiceManager) RegisterServices() error {

	// Register the token service.
	services.NewTokenService(sm.mux, sm.config)

	return nil
}
