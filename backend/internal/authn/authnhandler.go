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
	"errors"
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
		writeAPIErrorResponse(w, logger, constants.APIErrorJSONDecodeError, http.StatusBadRequest)
		return
	}

	// Sanitize the inputs
	sessionDataKey := systemutils.SanitizeString(authR.SessionDataKey)
	flowID := systemutils.SanitizeString(authR.FlowID)
	actionID := systemutils.SanitizeString(authR.ActionID)
	inputs := systemutils.SanitizeStringMap(authR.Inputs)

	if sessionDataKey == "" && flowID == "" {
		writeAPIErrorResponse(w, logger, constants.APIErrorInvalidRequest, http.StatusBadRequest)
		return
	}

	var sessionData sessionmodel.SessionData
	appID := ""

	// Check if the session data is already stored with a session data key.
	sessionDataStore := sessionstore.GetSessionDataStore()
	if sessionDataKey != "" {
		var ok bool
		ok, sessionData = getSessionData(sessionDataStore, sessionDataKey, w, logger)
		if !ok {
			return
		}
		// Remove the previous session data if it exists.
		sessionDataStore.ClearSession(sessionDataKey)

		appID = sessionData.OAuthParameters.AppID
		if appID == "" {
			writeAPIErrorResponse(w, logger, constants.APIErrorAppIDNotFound, http.StatusBadRequest)
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
		if flowStep.Status == flowconst.FlowStatusIncomplete {
			logger.Debug("Flow execution is incomplete, storing session data", log.String("flowID", flowStep.FlowID))
			sessionDataStore.AddSession(flowStep.FlowID, sessionData)
		}
	} else {
		if flowStep.Status == flowconst.FlowStatusComplete {
			var ok bool
			ok, sessionData = getSessionData(sessionDataStore, flowStep.FlowID, w, logger)
			if !ok {
				return
			}
		}
		if flowStep.Status != flowconst.FlowStatusIncomplete {
			sessionDataStore.ClearSession(flowStep.FlowID)
		}
	}

	authResp, err := buildAuthNResponse(flowStep, sessionData, sessionDataStore, logger)
	if err != nil {
		return
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

// getSessionData retrieves the session data for the given key from the session data store.
// If the session data is not found, it writes an error response to the provided http.ResponseWriter.
func getSessionData(sessionDataStore sessionstore.SessionDataStoreInterface, key string,
	w http.ResponseWriter, logger *log.Logger) (bool, sessionmodel.SessionData) {
	logger.Info("Retrieving session data for key", log.String("key", key))
	ok, sessionData := sessionDataStore.GetSession(key)
	if !ok {
		writeAPIErrorResponse(w, logger, constants.APIErrorSessionNotFound, http.StatusNotFound)
	}
	return ok, sessionData
}

// buildAuthNResponse constructs the authentication response based on the flow step and session data.
func buildAuthNResponse(flowStep *flowmodel.FlowStep, sessionData sessionmodel.SessionData,
	sessionDataStore sessionstore.SessionDataStoreInterface, logger *log.Logger) (model.AuthNResponse, error) {
	if flowStep.Status == flowconst.FlowStatusComplete {
		logger.Debug("Flow execution completed successfully", log.String("flowID", flowStep.FlowID))
		return buildAuthNResponseForCompletedFlow(flowStep, sessionData, sessionDataStore, logger)
	}

	return model.AuthNResponse{
		FlowID:        flowStep.FlowID,
		StepID:        flowStep.StepID,
		FlowStatus:    string(flowStep.Status),
		Type:          string(flowStep.Type),
		Data:          flowStep.Data,
		FailureReason: flowStep.FailureReason,
	}, nil
}

// buildAuthNResponseForCompletedFlow constructs the authentication response for a completed flow.
func buildAuthNResponseForCompletedFlow(flowStep *flowmodel.FlowStep, sessionData sessionmodel.SessionData,
	sessionDataStore sessionstore.SessionDataStoreInterface, logger *log.Logger) (model.AuthNResponse, error) {
	userID, userAttributes, err := decodeAttributesFromAssertion(flowStep.Assertion)
	if err != nil {
		logger.Error("Error decoding user attributes from assertion", log.Error(err))
		return model.AuthNResponse{}, err
	}

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

	sessionDataStore.ClearSession(flowStep.FlowID)
	sessionDataStore.AddSession(newSessionDataKey, *newSessionData)

	redirectURI := authzutils.GetAuthorizationEndpoint()
	queryParams := map[string]string{
		"sessionDataKey": newSessionDataKey,
	}

	redirectURI, err = systemutils.GetURIWithQueryParams(redirectURI, queryParams)
	if err != nil {
		logger.Error("Error encoding error response: redirect URI construction error")
		return model.AuthNResponse{}, err
	}

	return model.AuthNResponse{
		FlowID:     flowStep.FlowID,
		FlowStatus: string(flowStep.Status),
		Data: flowmodel.FlowData{
			RedirectURL: redirectURI,
		},
	}, nil
}

// decodeAttributesFromAssertion decodes user attributes from the flow assertion JWT.
// It returns the user ID and a map of user attributes.
func decodeAttributesFromAssertion(assertion string) (string, map[string]string, error) {
	if assertion == "" {
		return "", nil, errors.New("flow assertion not found")
	}

	_, jwtPayload, err := jwt.DecodeJWT(assertion)
	if err != nil {
		return "", nil, errors.New("JWT decode error: " + err.Error())
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

	return userID, userAttributes, nil
}

// writeAPIErrorResponse writes an API error response to the provided http.ResponseWriter.
func writeAPIErrorResponse(w http.ResponseWriter, logger *log.Logger, errResp any, statusCode int) {
	w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(errResp); err != nil {
		logger.Error("Error encoding error response", log.Error(err))
		http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
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
