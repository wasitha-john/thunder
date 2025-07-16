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

// Package utils provides utility functions for OAuth2 operations.
package utils

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"

	authzmodel "github.com/asgardeo/thunder/internal/oauth/oauth2/authz/model"
	"github.com/asgardeo/thunder/internal/oauth/oauth2/constants"
	sessionmodel "github.com/asgardeo/thunder/internal/oauth/session/model"
	sessionstore "github.com/asgardeo/thunder/internal/oauth/session/store"
	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/system/utils"
)

// GetOAuthMessage extracts the OAuth message from the request and response writer.
func GetOAuthMessage(r *http.Request, w http.ResponseWriter) (*authzmodel.OAuthMessage, error) {
	if r == nil || w == nil {
		return nil, errors.New("request or response writer is nil")
	}

	logger := log.GetLogger()

	// Parse the query parameters.
	if err := r.ParseForm(); err != nil {
		return nil, errors.New("failed to parse form data: " + err.Error())
	}

	// Check if the session data is already stored with a session data key.
	sessionDataKey := r.FormValue(constants.SessionDataKey)
	var sessionData sessionmodel.SessionData
	if sessionDataKey != "" {
		sessionDataStore := sessionstore.GetSessionDataStore()
		var ok bool
		ok, sessionData = sessionDataStore.GetSession(sessionDataKey)
		if !ok {
			logger.Debug("Session data not found for session data key",
				log.String("sessionDataKey", sessionDataKey))
		}
	}

	// Determine the request type.
	var requestType string
	if sessionDataKey != "" && r.FormValue(constants.SessionDataKeyConsent) == "" {
		requestType = constants.TypeAuthorizationResponseFromEngine
	} else if r.FormValue(constants.ClientID) != "" && sessionDataKey == "" &&
		r.FormValue(constants.SessionDataKeyConsent) == "" {
		requestType = constants.TypeInitialAuthorizationRequest
	} else {
		return nil, errors.New("invalid request type")
	}

	// Extract headers.
	headers := make(map[string][]string)
	for name, values := range r.Header {
		if len(values) > 0 {
			headers[name] = append([]string{}, values...)
		}
	}

	// Extract query parameters.
	queryParams := make(map[string]string)
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			queryParams[key] = values[0]
		}
	}

	// Extract form/body parameters.
	bodyParams := make(map[string]string)
	for key, values := range r.PostForm {
		if len(values) > 0 {
			bodyParams[key] = values[0]
		}
	}

	return &authzmodel.OAuthMessage{
		RequestType:        requestType,
		SessionData:        &sessionData,
		RequestHeaders:     headers,
		RequestQueryParams: queryParams,
		RequestBodyParams:  bodyParams,
	}, nil
}

// GetURIWithQueryParams constructs a URI with the given query parameters.
// It validates the error code and error description according to the spec.
func GetURIWithQueryParams(uri string, queryParams map[string]string) (string, error) {
	// Validate the error params if present.
	if err := validateErrorParams(queryParams[constants.Error], queryParams[constants.ErrorDescription]); err != nil {
		return "", err
	}

	return utils.GetURIWithQueryParams(uri, queryParams)
}

// validateErrorParams validates the error code and error description parameters.
func validateErrorParams(err, desc string) error {
	// Define a regex pattern for the allowed character set: %x20-21 / %x23-5B / %x5D-7E
	allowedCharPattern := `^[\x20-\x21\x23-\x5B\x5D-\x7E]*$`
	allowedCharRegex := regexp.MustCompile(allowedCharPattern)

	// Validate the error code.
	if err != "" && !allowedCharRegex.MatchString(err) {
		return fmt.Errorf("invalid error code: %s", err)
	}

	// Validate the error description.
	if desc != "" && !allowedCharRegex.MatchString(desc) {
		return fmt.Errorf("invalid error description: %s", desc)
	}

	return nil
}
