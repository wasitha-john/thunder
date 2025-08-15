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

// Package handler provides the HTTP handler for retrieving JSON Web Key Sets (JWKS).
package handler

import (
	"encoding/json"
	"net/http"

	"github.com/asgardeo/thunder/internal/oauth/jwks"
	serverconst "github.com/asgardeo/thunder/internal/system/constants"
	"github.com/asgardeo/thunder/internal/system/error/apierror"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
)

// JWKSHandler handles requests for the JSON Web Key Set (JWKS).
type JWKSHandler struct {
	jwksService jwks.JWKSServiceInterface
}

// NewJWKSHandler creates a new instance of JWKSHandler.
func NewJWKSHandler() *JWKSHandler {
	return &JWKSHandler{
		jwksService: jwks.NewJWKSService(),
	}
}

// HandleJWKSRequest handles the HTTP request to retrieve the JSON Web Key Set (JWKS).
func (h *JWKSHandler) HandleJWKSRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "JWKSHandler"))

	jwksResponse, svcErr := h.jwksService.GetJWKS()
	if svcErr != nil {
		h.handleError(w, logger, svcErr)
		return
	}

	w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(jwksResponse); err != nil {
		logger.Error("Error encoding JWKS response", log.Error(err))
		http.Error(w, "Failed to encode JWKS response", http.StatusInternalServerError)
		return
	}
	logger.Debug("JWKS response successfully sent")
}

// handleError handles errors by writing an appropriate error response to the HTTP response writer.
func (h *JWKSHandler) handleError(w http.ResponseWriter, logger *log.Logger,
	svcErr *serviceerror.ServiceError) {
	w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)

	errResp := apierror.ErrorResponse{
		Code:        svcErr.Code,
		Message:     svcErr.Error,
		Description: svcErr.ErrorDescription,
	}

	statusCode := http.StatusInternalServerError
	if svcErr.Type == serviceerror.ClientErrorType {
		statusCode = http.StatusBadRequest
	}
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(errResp); err != nil {
		logger.Error("Error encoding error response", log.Error(err))
		http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
	}
}
