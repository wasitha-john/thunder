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

// Package handler provides the implementation for identity provider management operations.
package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/asgardeo/thunder/internal/idp/model"
	idpprovider "github.com/asgardeo/thunder/internal/idp/provider"
	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/system/utils"
)

// IDPHandler is the handler for identity provider management operations.
type IDPHandler struct {
}

// HandleIDPPostRequest handles the post identity provider request.
func (ih *IDPHandler) HandleIDPPostRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IDPHandler"))

	createRequest, err := utils.DecodeJSONBody[model.IDP](r)
	if err != nil {
		http.Error(w, "Bad Request: The request body is malformed or contains invalid data.", http.StatusBadRequest)
		return
	}

	// Create the IdP using the IdP service.
	idpProvider := idpprovider.NewIDPProvider()
	idpService := idpProvider.GetIDPService()
	createdIDP, err := idpService.CreateIdentityProvider(createRequest)
	if err != nil {
		if errors.Is(err, model.ErrBadScopesInRequest) {
			http.Error(w, "Bad Request: The scopes element is malformed or contains invalid data.", http.StatusBadRequest)
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	idpResponse := getIDPResponse(*createdIDP)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	err = json.NewEncoder(w).Encode(idpResponse)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Log the IdP creation response.
	logger.Debug("IdP POST response sent", log.String("IdP id", idpResponse.ID))
}

// HandleIDPListRequest handles the get identity providers request.
func (ih *IDPHandler) HandleIDPListRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IDPHandler"))

	// Get the IdP list using the IdP service.
	idpProvider := idpprovider.NewIDPProvider()
	idpService := idpProvider.GetIDPService()
	idps, err := idpService.GetIdentityProviderList()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Prepare the response with IdP details.
	idpList := make([]model.IDP, 0, len(idps))
	for _, idp := range idps {
		idpList = append(idpList, getIDPResponse(idp))
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(idpList)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Log the IdP response.
	logger.Debug("IdP GET (list) response sent")
}

// HandleIDPGetRequest handles the get identity provider request.
func (ih *IDPHandler) HandleIDPGetRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IDPHandler"))

	id := strings.TrimPrefix(r.URL.Path, "/identity-providers/")
	if id == "" {
		http.Error(w, "Bad Request: Missing identity provider id.", http.StatusBadRequest)
		return
	}

	// Get the IdP using the IdP service.
	idpProvider := idpprovider.NewIDPProvider()
	idpService := idpProvider.GetIDPService()
	idp, err := idpService.GetIdentityProvider(id)
	if err != nil {
		if errors.Is(err, model.ErrIDPNotFound) {
			http.Error(w, "Not Found: The identity provider with the specified id does not exist.", http.StatusNotFound)
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	properties := make([]model.IDPProperty, 0, len(idp.Properties))
	for _, property := range idp.Properties {
		if property.IsSecret {
			properties = append(properties, model.IDPProperty{
				Name:     property.Name,
				Value:    "******",
				IsSecret: property.IsSecret,
			})
		} else {
			properties = append(properties, property)
		}
	}

	idpMap := map[string]interface{}{
		"id":          idp.ID,
		"name":        idp.Name,
		"description": idp.Description,
		"properties":  properties,
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(idpMap)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Log the IdP response.
	logger.Debug("IdP GET response sent", log.String("IdP id", id))
}

// HandleIDPPutRequest handles the put identity provider request.
func (ih *IDPHandler) HandleIDPPutRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IDPHandler"))

	id := strings.TrimPrefix(r.URL.Path, "/identity-providers/")
	if id == "" {
		http.Error(w, "Bad Request: Missing identity provider id.", http.StatusBadRequest)
		return
	}

	updateRequest, err := utils.DecodeJSONBody[model.IDP](r)
	if err != nil {
		http.Error(w, "Bad Request: The request body is malformed or contains invalid data.", http.StatusBadRequest)
		return
	}
	updateRequest.ID = id

	// Update the IdP using the IdP service.
	idpProvider := idpprovider.NewIDPProvider()
	idpService := idpProvider.GetIDPService()
	idp, err := idpService.UpdateIdentityProvider(id, updateRequest)
	if err != nil {
		if errors.Is(err, model.ErrIDPNotFound) {
			http.Error(w, "Not Found: The identity provider with the specified id does not exist.",
				http.StatusNotFound)
		} else if errors.Is(err, model.ErrBadScopesInRequest) {
			http.Error(w, "Bad Request: The scopes element is malformed or contains invalid data.",
				http.StatusBadRequest)
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	idpResponse := getIDPResponse(*idp)

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(idpResponse)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Log the IdP response.
	logger.Debug("IdP PUT response sent", log.String("IdP id", idpResponse.ID))
}

// HandleIDPDeleteRequest handles the delete identity provider request.
func (ih *IDPHandler) HandleIDPDeleteRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IDPHandler"))

	id := strings.TrimPrefix(r.URL.Path, "/identity-providers/")
	if id == "" {
		http.Error(w, "Bad Request: Missing identity provider id.", http.StatusBadRequest)
		return
	}

	// Delete the IdP using the IdP service.
	idpProvider := idpprovider.NewIDPProvider()
	idpService := idpProvider.GetIDPService()
	err := idpService.DeleteIdentityProvider(id)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)

	// Log the IdP response.
	logger.Debug("IdP DELETE response sent", log.String("IdP id", id))
}

// getIDPResponse constructs the response for a identity provider.
func getIDPResponse(idp model.IDP) model.IDP {
	returnIDP := model.IDP{
		ID:          idp.ID,
		Name:        idp.Name,
		Description: idp.Description,
	}

	// Mask secret properties in the response.
	idpProperties := make([]model.IDPProperty, 0, len(idp.Properties))
	for _, property := range idp.Properties {
		if property.IsSecret {
			idpProperties = append(idpProperties, model.IDPProperty{
				Name:     property.Name,
				Value:    "******",
				IsSecret: property.IsSecret,
			})
		} else {
			idpProperties = append(idpProperties, property)
		}
	}
	returnIDP.Properties = idpProperties

	return returnIDP
}
