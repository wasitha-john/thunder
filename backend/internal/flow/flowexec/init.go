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

package flowexec

import (
	"net/http"

	appservice "github.com/asgardeo/thunder/internal/application/service"
	"github.com/asgardeo/thunder/internal/flow/flowmgt"
	"github.com/asgardeo/thunder/internal/system/middleware"
)

// Initialize creates and configures the flow execution service components.
func Initialize(mux *http.ServeMux, flowMgtService flowmgt.FlowMgtServiceInterface,
	applicationService appservice.ApplicationServiceInterface) FlowExecServiceInterface {
	flowEngine := newFlowEngine()
	flowExecService := newFlowExecService(flowMgtService, applicationService, flowEngine)
	handler := newFlowExecutionHandler(flowExecService)
	registerRoutes(mux, handler)
	return flowExecService
}

func registerRoutes(mux *http.ServeMux, handler *flowExecutionHandler) {
	opts := middleware.CORSOptions{
		AllowedMethods:   "POST",
		AllowedHeaders:   "Content-Type, Authorization",
		AllowCredentials: true,
	}
	mux.HandleFunc(middleware.WithCORS("POST /flow/execute",
		handler.HandleFlowExecutionRequest, opts))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /flow/execute",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, opts))
}
