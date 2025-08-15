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

// Package services provides a way to register and manage HTTP routes for the server.
package services

import "net/http"

// The Route struct represents an HTTP route with its method, path, and handler function.
type Route struct {
	Method      string
	Path        string
	HandlerFunc *http.HandlerFunc
}

// The ServiceInterface struct defines the service that will handle the routes.
type ServiceInterface interface {
	RegisterRoutes(mux *http.ServeMux)
}
