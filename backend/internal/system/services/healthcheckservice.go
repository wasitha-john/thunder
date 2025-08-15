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

	"github.com/asgardeo/thunder/internal/system/healthcheck/handler"
	"github.com/asgardeo/thunder/internal/system/server"
)

// HealthCheckService defines the service for handling readiness and liveness checks.
type HealthCheckService struct {
	ServerOpsService   server.ServerOperationServiceInterface
	healthCheckHandler *handler.HealthCheckHandler
}

// NewHealthCheckService creates a new instance of HealthCheckService.
func NewHealthCheckService(mux *http.ServeMux) ServiceInterface {
	instance := &HealthCheckService{
		ServerOpsService:   server.NewServerOperationService(),
		healthCheckHandler: handler.NewHealthCheckHandler(),
	}
	instance.RegisterRoutes(mux)

	return instance
}

// RegisterRoutes registers the routes for the HealthCheckService.
//
//nolint:dupl // Ignoring false positive duplicate code
func (h *HealthCheckService) RegisterRoutes(mux *http.ServeMux) {
	opts1 := server.RequestWrapOptions{
		Cors: &server.Cors{
			AllowedMethods:   "GET",
			AllowedHeaders:   "Content-Type, Authorization",
			AllowCredentials: true,
		},
	}

	h.ServerOpsService.WrapHandleFunction(mux, "OPTIONS /health/liveness", &opts1,
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
	h.ServerOpsService.WrapHandleFunction(mux, "GET /health/liveness", &opts1,
		h.healthCheckHandler.HandleLivenessRequest)

	h.ServerOpsService.WrapHandleFunction(mux, "OPTIONS /health/readiness", &opts1,
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
	h.ServerOpsService.WrapHandleFunction(mux, "GET /health/readiness", &opts1,
		h.healthCheckHandler.HandleReadinessRequest)
}
