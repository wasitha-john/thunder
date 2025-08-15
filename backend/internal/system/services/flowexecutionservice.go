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

package services

import (
	"net/http"

	"github.com/asgardeo/thunder/internal/flow/handler"
	"github.com/asgardeo/thunder/internal/system/server"
)

// FlowExecutionService defines the service for handling flow execution requests.
type FlowExecutionService struct {
	ServerOpsService     server.ServerOperationServiceInterface
	flowExecutionHandler *handler.FlowExecutionHandler
}

// NewFlowExecutionService creates a new instance of FlowExecutionService.
func NewFlowExecutionService(mux *http.ServeMux) ServiceInterface {
	instance := &FlowExecutionService{
		ServerOpsService:     server.NewServerOperationService(),
		flowExecutionHandler: handler.NewFlowExecutionHandler(),
	}
	instance.RegisterRoutes(mux)

	return instance
}

// RegisterRoutes registers the routes for the FlowExecutionService.
func (s *FlowExecutionService) RegisterRoutes(mux *http.ServeMux) {
	// TODO: Ideally this should be renamed to "/flow/authn". Keeping it as "/flow/execute" until the
	//  previous authenticator implementation is removed.
	opts := server.RequestWrapOptions{
		Cors: &server.Cors{
			AllowedMethods:   "POST",
			AllowedHeaders:   "Content-Type, Authorization",
			AllowCredentials: true,
		},
	}
	s.ServerOpsService.WrapHandleFunction(mux, "POST /flow/execute", &opts,
		s.flowExecutionHandler.HandleFlowExecutionRequest)
	s.ServerOpsService.WrapHandleFunction(mux, "OPTIONS /flow/execute", &opts,
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
}
