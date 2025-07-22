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

// Package services handles the registration of routes and services for the system.
//
//nolint:dupl // Ignoring false positive duplicate code
package services

import (
	"net/http"

	"github.com/asgardeo/thunder/internal/ou/handler"
	"github.com/asgardeo/thunder/internal/system/server"
)

// OrganizationUnitService is the service for organization unit management operations.
type OrganizationUnitService struct {
	serverOpsService server.ServerOperationServiceInterface
	ouHandler        *handler.OrganizationUnitHandler
}

// NewOrganizationUnitService creates a new instance of OrganizationUnitService.
func NewOrganizationUnitService(mux *http.ServeMux) ServiceInterface {
	instance := &OrganizationUnitService{
		serverOpsService: server.NewServerOperationService(),
		ouHandler:        handler.NewOrganizationUnitHandler(),
	}
	instance.RegisterRoutes(mux)

	return instance
}

// RegisterRoutes registers the routes for organization unit management operations.
func (s *OrganizationUnitService) RegisterRoutes(mux *http.ServeMux) {
	opts1 := server.RequestWrapOptions{
		Cors: &server.Cors{
			AllowedMethods:   "GET, POST",
			AllowedHeaders:   "Content-Type, Authorization",
			AllowCredentials: true,
		},
	}
	s.serverOpsService.WrapHandleFunction(
		mux, "POST /organization-units", &opts1, s.ouHandler.HandleOUPostRequest)
	s.serverOpsService.WrapHandleFunction(
		mux, "GET /organization-units", &opts1, s.ouHandler.HandleOUListRequest)
	s.serverOpsService.WrapHandleFunction(
		mux, "OPTIONS /organization-units", &opts1, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})

	opts2 := server.RequestWrapOptions{
		Cors: &server.Cors{
			AllowedMethods:   "GET, PUT, DELETE",
			AllowedHeaders:   "Content-Type, Authorization",
			AllowCredentials: true,
		},
	}
	s.serverOpsService.WrapHandleFunction(
		mux, "GET /organization-units/{id}", &opts2, s.ouHandler.HandleOUGetRequest)
	s.serverOpsService.WrapHandleFunction(
		mux, "PUT /organization-units/{id}", &opts2, s.ouHandler.HandleOUPutRequest)
	s.serverOpsService.WrapHandleFunction(
		mux, "DELETE /organization-units/{id}", &opts2, s.ouHandler.HandleOUDeleteRequest)
	s.serverOpsService.WrapHandleFunction(
		mux,
		"OPTIONS /organization-units/{id}",
		&opts2,
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		},
	)

	opts3 := server.RequestWrapOptions{
		Cors: &server.Cors{
			AllowedMethods:   "GET",
			AllowedHeaders:   "Content-Type, Authorization",
			AllowCredentials: true,
		},
	}
	s.serverOpsService.WrapHandleFunction(
		mux, "GET /organization-units/{id}/ous", &opts3, s.ouHandler.HandleOUChildrenListRequest)
	s.serverOpsService.WrapHandleFunction(
		mux, "OPTIONS /organization-units/{id}/ous", &opts3, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})

	s.serverOpsService.WrapHandleFunction(
		mux, "GET /organization-units/{id}/users", &opts3, s.ouHandler.HandleOUUsersListRequest)
	s.serverOpsService.WrapHandleFunction(
		mux, "OPTIONS /organization-units/{id}/users", &opts3, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})

	s.serverOpsService.WrapHandleFunction(
		mux, "GET /organization-units/{id}/groups", &opts3, s.ouHandler.HandleOUGroupsListRequest)
	s.serverOpsService.WrapHandleFunction(
		mux, "OPTIONS /organization-units/{id}/groups", &opts3, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
}
