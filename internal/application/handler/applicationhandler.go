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

package handler

import (
	"encoding/json"
	"github.com/asgardeo/thunder/internal/application/model"
	appprovider "github.com/asgardeo/thunder/internal/application/provider"
	"github.com/asgardeo/thunder/internal/system/log"
	"net/http"
	"strings"
	"sync"
)

type ApplicationHandler struct {
	store map[string]model.Application
	mu    *sync.RWMutex
}

func NewApplicationHandler() *ApplicationHandler {

	return &ApplicationHandler{
		store: make(map[string]model.Application),
		mu:    &sync.RWMutex{},
	}
}

// HandleApplicationPostRequest handles the application request.
func (ah *ApplicationHandler) HandleApplicationPostRequest(w http.ResponseWriter, r *http.Request) {

	logger := log.GetLogger().With(log.String(log.LOGGER_KEY_COMPONENT_NAME, "ApplicationHandler"))

	var appInCreationRequest model.Application
	if err := json.NewDecoder(r.Body).Decode(&appInCreationRequest); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Create the app using the application service.
	appProvider := appprovider.NewApplicationProvider()
	appService := appProvider.GetApplicationService()
	createdApplication, err := appService.CreateApplication(&appInCreationRequest)
	if err != nil {
		http.Error(w, "Failed to create application", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	err = json.NewEncoder(w).Encode(createdApplication)
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	// Log the application creation response.
	logger.Debug("Application POST response sent", log.String("app id", createdApplication.Id))
}

// HandleApplicationListRequest handles the application request.
func (ah *ApplicationHandler) HandleApplicationListRequest(w http.ResponseWriter, r *http.Request) {

	logger := log.GetLogger().With(log.String(log.LOGGER_KEY_COMPONENT_NAME, "ApplicationHandler"))

	// Get the application list using the application service.
	appProvider := appprovider.NewApplicationProvider()
	appService := appProvider.GetApplicationService()
	applications, err := appService.GetApplicationList()
	if err != nil {
		http.Error(w, "Failed get application list", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(applications)
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	// Log the application response.
	logger.Debug("Application GET (list) response sent")
}

// HandleApplicationGetRequest handles the application request.
func (ah *ApplicationHandler) HandleApplicationGetRequest(w http.ResponseWriter, r *http.Request) {

	logger := log.GetLogger().With(log.String(log.LOGGER_KEY_COMPONENT_NAME, "ApplicationHandler"))

	id := strings.TrimPrefix(r.URL.Path, "/application/")
	if id == "" {
		http.Error(w, "Missing application id", http.StatusBadRequest)
		return
	}

	// Get the application using the application service.
	appProvider := appprovider.NewApplicationProvider()
	appService := appProvider.GetApplicationService()
	application, err := appService.GetApplication(id)
	if err != nil {
		http.Error(w, "Failed get application", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(application)
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	// Log the application response.
	logger.Debug("Application GET response sent", log.String("app id", id))
}

// HandleApplicationPutRequest handles the application request.
func (ah *ApplicationHandler) HandleApplicationPutRequest(w http.ResponseWriter, r *http.Request) {

	logger := log.GetLogger().With(log.String(log.LOGGER_KEY_COMPONENT_NAME, "ApplicationHandler"))

	id := strings.TrimPrefix(r.URL.Path, "/application/")
	if id == "" {
		http.Error(w, "Missing application id", http.StatusBadRequest)
		return
	}

	var updatedApp model.Application
	if err := json.NewDecoder(r.Body).Decode(&updatedApp); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	updatedApp.Id = id

	// Update the application using the application service.
	appProvider := appprovider.NewApplicationProvider()
	appService := appProvider.GetApplicationService()
	application, err := appService.UpdateApplication(id, &updatedApp)
	if err != nil {
		http.Error(w, "Failed get application", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(application)

	// Log the application response.
	logger.Debug("Application PUT response sent", log.String("app id", id))
}

// HandleApplicationDeleteRequest handles the application request.
func (ah *ApplicationHandler) HandleApplicationDeleteRequest(w http.ResponseWriter, r *http.Request) {

	logger := log.GetLogger().With(log.String(log.LOGGER_KEY_COMPONENT_NAME, "ApplicationHandler"))

	id := strings.TrimPrefix(r.URL.Path, "/application/")
	if id == "" {
		http.Error(w, "Missing application id", http.StatusBadRequest)
		return
	}

	// Delete the application using the application service.
	appProvider := appprovider.NewApplicationProvider()
	appService := appProvider.GetApplicationService()
	err := appService.DeleteApplication(id)
	if err != nil {
		http.Error(w, "Failed delete application", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)

	// Log the application response.
	logger.Debug("Application DELETE response sent", log.String("app id", id))
}
