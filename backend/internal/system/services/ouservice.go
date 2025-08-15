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

// Package services handles the registration of routes and services for the system.
//
//nolint:dupl // Ignoring false positive duplicate code
package services

import (
	"net/http"
	"strings"

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
	s.serverOpsService.WrapHandleFunction(mux, "GET /organization-units/", &opts2,
		func(w http.ResponseWriter, r *http.Request) {
			path := strings.TrimPrefix(r.URL.Path, "/organization-units/")
			segments := strings.Split(path, "/")
			r.SetPathValue("id", segments[0])

			if len(segments) == 1 {
				s.ouHandler.HandleOUGetRequest(w, r)
			} else if len(segments) == 2 {
				switch segments[1] {
				case "ous":
					s.ouHandler.HandleOUChildrenListRequest(w, r)
				case "users":
					s.ouHandler.HandleOUUsersListRequest(w, r)
				case "groups":
					s.ouHandler.HandleOUGroupsListRequest(w, r)
				default:
					http.NotFound(w, r)
				}
			} else {
				http.NotFound(w, r)
			}
		})
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

	s.serverOpsService.WrapHandleFunction(mux, "GET /organization-units/tree/{path...}", &opts2,
		func(w http.ResponseWriter, r *http.Request) {
			pathValue := r.PathValue("path")
			handlers := map[string]func(http.ResponseWriter, *http.Request){
				"/ous":    s.ouHandler.HandleOUChildrenListByPathRequest,
				"/users":  s.ouHandler.HandleOUUsersListByPathRequest,
				"/groups": s.ouHandler.HandleOUGroupsListByPathRequest,
			}

			for suffix, handlerFunc := range handlers {
				if strings.HasSuffix(pathValue, suffix) {
					newPath := strings.TrimSuffix(pathValue, suffix)
					r.SetPathValue("path", newPath)
					handlerFunc(w, r)
					return
				}
			}

			newPath := "/organization-units/tree/" + pathValue
			r.URL.Path = newPath
			s.ouHandler.HandleOUGetByPathRequest(w, r)
		})
	s.serverOpsService.WrapHandleFunction(
		mux, "PUT /organization-units/tree/{path...}", &opts2, s.ouHandler.HandleOUPutByPathRequest)
	s.serverOpsService.WrapHandleFunction(
		mux, "DELETE /organization-units/tree/{path...}", &opts2, s.ouHandler.HandleOUDeleteByPathRequest)
	s.serverOpsService.WrapHandleFunction(
		mux, "OPTIONS /organization-units/tree/{path...}", &opts2, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
}
