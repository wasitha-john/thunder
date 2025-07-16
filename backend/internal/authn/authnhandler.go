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

// Package authn provides the implementation of the authentication handler and related functionalities.
package authn

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/asgardeo/thunder/internal/authn/constants"
	authndto "github.com/asgardeo/thunder/internal/authn/dto"
	"github.com/asgardeo/thunder/internal/authn/model"
	"github.com/asgardeo/thunder/internal/flow"
	flowconst "github.com/asgardeo/thunder/internal/flow/constants"
	flowmodel "github.com/asgardeo/thunder/internal/flow/model"
	"github.com/asgardeo/thunder/internal/oauth/jwt"
	authzutils "github.com/asgardeo/thunder/internal/oauth/oauth2/authz/utils"
	oauthmodel "github.com/asgardeo/thunder/internal/oauth/oauth2/model"
	sessionmodel "github.com/asgardeo/thunder/internal/oauth/session/model"
	sessionstore "github.com/asgardeo/thunder/internal/oauth/session/store"
	sessionutils "github.com/asgardeo/thunder/internal/oauth/session/utils"
	serverconst "github.com/asgardeo/thunder/internal/system/constants"
	"github.com/asgardeo/thunder/internal/system/error/apierror"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
	systemutils "github.com/asgardeo/thunder/internal/system/utils"
)

// AuthenticationHandlerInterface defines the interface for handling authentication requests.
type AuthenticationHandlerInterface interface {
	HandleAuthenticationRequest(w http.ResponseWriter, r *http.Request)
}

// AuthenticationHandler implements the AuthenticationHandlerInterface to handle authentication requests.
type AuthenticationHandler struct {
}

// NewAuthenticationHandler creates a new instance of AuthenticationHandler.
func NewAuthenticationHandler() AuthenticationHandlerInterface {
	return &AuthenticationHandler{}
}

// HandleAuthenticationRequest handles the authentication request received.
func (ah *AuthenticationHandler) HandleAuthenticationRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "AuthenticationHandler"))
	logger.Debug("Handling authentication request")

	authR, err := systemutils.DecodeJSONBody[model.AuthNRequest](r)
	if err != nil {
		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(w).Encode(constants.APIErrorJSONDecodeError); err != nil {
			logger.Error("Error encoding error response", log.Error(err))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
		}
		return
	}

	// Sanitize the inputs
	sessionDataKey := systemutils.SanitizeString(authR.SessionDataKey)
	flowID := systemutils.SanitizeString(authR.FlowID)
	actionID := systemutils.SanitizeString(authR.ActionID)
	inputs := systemutils.SanitizeStringMap(authR.Inputs)

	if sessionDataKey == "" && flowID == "" {
		if err := json.NewEncoder(w).Encode(constants.APIErrorInvalidRequest); err != nil {
			logger.Error("Error encoding error response", log.Error(err))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
		}
		return
	}

	var sessionData sessionmodel.SessionData
	appID := ""

	sessionDataStore := sessionstore.GetSessionDataStore()
	if sessionDataKey != "" {
		// Check if the session data is already stored with a session data key.
		logger.Info("Retrieving session data for session data key", log.String("sessionDataKey", sessionDataKey))

		var ok bool
		ok, sessionData = sessionDataStore.GetSession(sessionDataKey)
		if !ok {
			if err := json.NewEncoder(w).Encode(constants.APIErrorSessionNotFound); err != nil {
				logger.Error("Error encoding error response", log.Error(err))
				http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
			}
			return
		}

		// Remove the previous session data if it exists.
		sessionDataStore.ClearSession(sessionDataKey)

		// Retrieve app id.
		appID = sessionData.OAuthParameters.AppID
		if appID == "" {
			if err := json.NewEncoder(w).Encode(constants.APIErrorAppIDNotFound); err != nil {
				logger.Error("Error encoding error response", log.Error(err))
				http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
			}
			return
		}
	}

	flowSvc := flow.GetFlowService()
	flowStep, flowErr := flowSvc.Execute(appID, flowID, actionID, flowconst.FlowTypeAuthentication, inputs)

	if flowErr != nil {
		handleFlowError(w, logger, flowErr)
		return
	}

	if sessionDataKey != "" && flowID == "" {
		// If the flow is incomplete, add a new session data with the flow ID as the key.
		if flowStep.Status == flowconst.FlowStatusIncomplete {
			logger.Debug("Flow execution is incomplete, storing session data", log.String("flowID", flowStep.FlowID))
			sessionDataStore.AddSession(flowStep.FlowID, sessionData)
		}
	} else {
		// If the flow is completed or received an error, clear the session data for the flow ID.
		if flowStep.Status == flowconst.FlowStatusComplete {
			var ok bool
			ok, sessionData = sessionDataStore.GetSession(flowStep.FlowID)
			if !ok {
				if err := json.NewEncoder(w).Encode(constants.APIErrorSessionNotFound); err != nil {
					logger.Error("Error encoding error response", log.Error(err))
					http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
				}
				return
			}
		}
		if flowStep.Status != flowconst.FlowStatusIncomplete {
			sessionDataStore.ClearSession(flowStep.FlowID)
		}
	}

	var authResp model.AuthNResponse
	if flowStep.Status == flowconst.FlowStatusComplete {
		logger.Debug("Flow execution completed successfully", log.String("flowID", flowStep.FlowID))

		// Retrieve authenticated user information from the assertion.
		assertion := flowStep.Assertion
		if assertion == "" {
			if err := json.NewEncoder(w).Encode(constants.ServerErrorFlowAssertionNotFound); err != nil {
				logger.Error("Error encoding error response", log.Error(err))
				http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
			}
			return
		}

		_, jwtPayload, err := jwt.DecodeJWT(assertion)
		if err != nil {
			if err := json.NewEncoder(w).Encode(constants.ServerErrorJWTDecodeError); err != nil {
				logger.Error("Error encoding error response", log.Error(err))
				http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
			}
			return
		}

		userAttributes := make(map[string]string)
		userID := ""
		for key, value := range jwtPayload {
			switch key {
			case "sub":
				userID = value.(string)
			case "username":
				userAttributes["username"] = value.(string)
			case "email":
				userAttributes["email"] = value.(string)
			case "firstName":
				userAttributes["firstName"] = value.(string)
			case "lastName":
				userAttributes["lastName"] = value.(string)
			}
		}

		// Update the session data with the flow step data.
		newSessionDataKey := sessionutils.GenerateNewSessionDataKey()
		newSessionData := &sessionmodel.SessionData{
			OAuthParameters: oauthmodel.OAuthParameters{
				SessionDataKey: newSessionDataKey,
				ClientID:       sessionData.OAuthParameters.ClientID,
				RedirectURI:    sessionData.OAuthParameters.RedirectURI,
				Scopes:         sessionData.OAuthParameters.Scopes,
				State:          sessionData.OAuthParameters.State,
			},
			AuthTime: time.Now(),
			AuthenticatedUser: authndto.AuthenticatedUser{
				IsAuthenticated: true,
				UserID:          userID,
				Attributes:      userAttributes,
			},
		}

		// Remove the old session data from the session store and add the new entry.
		sessionDataStore.ClearSession(flowStep.FlowID)
		sessionDataStore.AddSession(newSessionDataKey, *newSessionData)

		// Construct the redirect URI with the new session data key.
		redirectURI := authzutils.GetAuthorizationEndpoint()
		queryParams := map[string]string{
			"sessionDataKey": newSessionDataKey,
		}
		redirectURI, err = systemutils.GetURIWithQueryParams(redirectURI, queryParams)
		if err != nil {
			if err := json.NewEncoder(w).Encode(constants.ServerErrorRedirectURIConstructionError); err != nil {
				logger.Error("Error encoding error response", log.Error(err))
				http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
			}
			return
		}

		authResp = model.AuthNResponse{
			FlowID:     flowStep.FlowID,
			FlowStatus: string(flowStep.Status),
			Data: flowmodel.FlowData{
				RedirectURL: redirectURI,
			},
		}
	} else {
		authResp = model.AuthNResponse{
			FlowID:        flowStep.FlowID,
			StepID:        flowStep.StepID,
			FlowStatus:    string(flowStep.Status),
			Type:          string(flowStep.Type),
			Data:          flowStep.Data,
			FailureReason: flowStep.FailureReason,
		}
	}

	w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)

	err = json.NewEncoder(w).Encode(authResp)
	if err != nil {
		logger.Error("Error encoding response", log.Error(err))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleFlowError handles errors that occur during auth flow as an API error response.
func handleFlowError(w http.ResponseWriter, logger *log.Logger, flowErr *serviceerror.ServiceError) {
	logger.Error("Error occurred during authentication flow", log.Any("flowError", flowErr))

	w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)

	var errResp *apierror.ErrorResponse
	if flowErr.Type == serviceerror.ClientErrorType {
		errResp = &constants.APIErrorFlowExecutionError
		w.WriteHeader(http.StatusBadRequest)
	} else {
		errResp = &constants.ServerErrorFlowExecutionError
		w.WriteHeader(http.StatusInternalServerError)
	}

	if err := json.NewEncoder(w).Encode(errResp); err != nil {
		logger.Error("Error encoding error response", log.Error(err))
		http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
	}
}
