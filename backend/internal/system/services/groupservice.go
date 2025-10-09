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

	"github.com/asgardeo/thunder/internal/group/handler"
	"github.com/asgardeo/thunder/internal/system/middleware"
)

// GroupService is the service for group management operations.
type GroupService struct {
	groupHandler *handler.GroupHandler
}

// NewGroupService creates a new instance of GroupService.
func NewGroupService(mux *http.ServeMux) ServiceInterface {
	instance := &GroupService{
		groupHandler: handler.NewGroupHandler(),
	}
	instance.RegisterRoutes(mux)

	return instance
}

// RegisterRoutes registers the routes for group management operations.
func (s *GroupService) RegisterRoutes(mux *http.ServeMux) {
	opts1 := middleware.CORSOptions{
		AllowedMethods:   "GET, POST",
		AllowedHeaders:   "Content-Type, Authorization",
		AllowCredentials: true,
	}
	mux.HandleFunc(middleware.WithCORS("POST /groups", s.groupHandler.HandleGroupPostRequest, opts1))
	mux.HandleFunc(middleware.WithCORS("GET /groups", s.groupHandler.HandleGroupListRequest, opts1))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /groups", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}, opts1))

	opts2 := middleware.CORSOptions{
		AllowedMethods:   "GET, PUT, DELETE",
		AllowedHeaders:   "Content-Type, Authorization",
		AllowCredentials: true,
	}
	mux.HandleFunc(middleware.WithCORS("GET /groups/",
		func(w http.ResponseWriter, r *http.Request) {
			path := strings.TrimPrefix(r.URL.Path, "/groups/")
			segments := strings.Split(path, "/")
			r.SetPathValue("id", segments[0])

			if len(segments) == 1 {
				s.groupHandler.HandleGroupGetRequest(w, r)
			} else if len(segments) == 2 && segments[1] == "members" {
				s.groupHandler.HandleGroupMembersGetRequest(w, r)
			} else {
				http.NotFound(w, r)
			}
		}, opts2))
	mux.HandleFunc(middleware.WithCORS("PUT /groups/{id}", s.groupHandler.HandleGroupPutRequest, opts2))
	mux.HandleFunc(middleware.WithCORS("DELETE /groups/{id}", s.groupHandler.HandleGroupDeleteRequest, opts2))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /groups/{id}",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, opts2))

	opts3 := middleware.CORSOptions{
		AllowedMethods:   "GET, POST",
		AllowedHeaders:   "Content-Type, Authorization",
		AllowCredentials: true,
	}
	mux.HandleFunc(middleware.WithCORS("GET /groups/tree/{path...}",
		s.groupHandler.HandleGroupListByPathRequest, opts3))
	mux.HandleFunc(middleware.WithCORS("POST /groups/tree/{path...}",
		s.groupHandler.HandleGroupPostByPathRequest, opts3))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /groups/tree/{path...}",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, opts3))
}
