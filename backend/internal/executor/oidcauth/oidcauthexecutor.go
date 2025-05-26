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

// Package oidcauth provides the OIDC authentication executor for handling OIDC-based authentication flows.
package oidcauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	authnmodel "github.com/asgardeo/thunder/internal/authn/model"
	authnutils "github.com/asgardeo/thunder/internal/authn/utils"
	"github.com/asgardeo/thunder/internal/executor/oidcauth/model"
	"github.com/asgardeo/thunder/internal/executor/oidcauth/utils"
	flowconst "github.com/asgardeo/thunder/internal/flow/constants"
	flowmodel "github.com/asgardeo/thunder/internal/flow/model"
	oauth2const "github.com/asgardeo/thunder/internal/oauth/oauth2/constants"
	"github.com/asgardeo/thunder/internal/system/constants"
	"github.com/asgardeo/thunder/internal/system/log"
	systemutils "github.com/asgardeo/thunder/internal/system/utils"
)

// OIDCAuthExecutorInterface defines the interface for OIDC authentication executors.
type OIDCAuthExecutorInterface interface {
	flowmodel.ExecutorInterface
	BuildAuthorizeFlow(ctx *flowmodel.FlowContext, execResp *flowmodel.ExecutorResponse)
	ProcessAuthFlowResponse(ctx *flowmodel.FlowContext, execResp *flowmodel.ExecutorResponse)
	GetOIDCProperties() model.OIDCExecProperties
	GetCallBackURL() string
	GetAuthorizationEndpoint() string
	GetTokenEndpoint() string
	GetUserInfoEndpoint() string
	GetLogoutEndpoint() string
	ExchangeCodeForToken(ctx *flowmodel.FlowContext, code string) (*model.OIDCTokenResponse, error)
	GetUserInfo(ctx *flowmodel.FlowContext, accessToken string) (map[string]string, error)
}

// OIDCAuthExecutor implements the OIDCAuthExecutorInterface for handling generic OIDC authentication flows.
type OIDCAuthExecutor struct {
	internal       flowmodel.Executor
	oidcProperties model.OIDCExecProperties
}

// NewOIDCAuthExecutor creates a new instance of OIDCAuthExecutor.
func NewOIDCAuthExecutor(id, name string, oidcProps *model.OIDCExecProperties) OIDCAuthExecutorInterface {
	return &OIDCAuthExecutor{
		internal: flowmodel.Executor{
			Properties: flowmodel.ExecutorProperties{
				ID:   id,
				Name: name,
			},
		},
		oidcProperties: *oidcProps,
	}
}

// GetID returns the ID of the OIDCAuthExecutor.
func (o *OIDCAuthExecutor) GetID() string {
	return o.internal.GetID()
}

// GetName returns the name of the OIDCAuthExecutor.
func (o *OIDCAuthExecutor) GetName() string {
	return o.internal.GetName()
}

// GetProperties returns the properties of the OIDCAuthExecutor.
func (o *OIDCAuthExecutor) GetProperties() flowmodel.ExecutorProperties {
	return o.internal.Properties
}

// GetOIDCProperties returns the OIDC properties of the executor.
func (o *OIDCAuthExecutor) GetOIDCProperties() model.OIDCExecProperties {
	return o.oidcProperties
}

// GetCallBackURL returns the callback URL for the OIDC authentication.
func (o *OIDCAuthExecutor) GetCallBackURL() string {
	return o.oidcProperties.RedirectURI
}

// GetAuthorizationEndpoint returns the authorization endpoint of the OIDC authentication.
func (o *OIDCAuthExecutor) GetAuthorizationEndpoint() string {
	return o.oidcProperties.AuthorizationEndpoint
}

// GetTokenEndpoint returns the token endpoint of the OIDC authentication.
func (o *OIDCAuthExecutor) GetTokenEndpoint() string {
	return o.oidcProperties.TokenEndpoint
}

// GetUserInfoEndpoint returns the user info endpoint of the OIDC authentication.
func (o *OIDCAuthExecutor) GetUserInfoEndpoint() string {
	return o.oidcProperties.UserInfoEndpoint
}

// GetLogoutEndpoint returns the logout endpoint of the OIDC authentication.
func (o *OIDCAuthExecutor) GetLogoutEndpoint() string {
	return o.oidcProperties.LogoutEndpoint
}

// Execute executes the OIDC authentication logic.
func (o *OIDCAuthExecutor) Execute(ctx *flowmodel.FlowContext) (*flowmodel.ExecutorResponse, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "OIDCAuthExecutor"))
	logger.Debug("Executing OIDC authentication executor",
		log.String("executorID", o.GetID()), log.String("flowID", ctx.FlowID))

	execResp := &flowmodel.ExecutorResponse{
		Status: flowconst.ExecIncomplete,
	}

	// Check if the required input data is provided
	if o.requiredInputData(ctx, execResp) {
		// If required input data is not provided, return incomplete status with redirection to OIDC provider.
		logger.Debug("Required input data for OIDC authentication executor is not provided",
			log.String("executorID", o.GetID()), log.String("flowID", ctx.FlowID))
		o.BuildAuthorizeFlow(ctx, execResp)
	} else {
		o.ProcessAuthFlowResponse(ctx, execResp)
	}

	logger.Debug("OIDC authentication executor execution completed",
		log.String("executorID", o.GetID()), log.String("flowID", ctx.FlowID),
		log.String("status", string(execResp.Status)), log.Bool("isAuthenticated", ctx.AuthenticatedUser.IsAuthenticated))

	return execResp, nil
}

// BuildAuthorizeFlow constructs the redirection to the external OIDC provider for user authentication.
func (o *OIDCAuthExecutor) BuildAuthorizeFlow(ctx *flowmodel.FlowContext, execResp *flowmodel.ExecutorResponse) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "OIDCAuthExecutor"))
	logger.Debug("Initiating OIDC authentication flow",
		log.String("executorID", o.GetID()), log.String("flowID", ctx.FlowID))

	execResp.Status = flowconst.ExecIncomplete

	// Construct and add the redirect URL for OIDC authentication
	var queryParams = make(map[string]string)
	queryParams[oauth2const.ClientID] = o.oidcProperties.ClientID
	queryParams[oauth2const.RedirectURI] = o.oidcProperties.RedirectURI
	queryParams[oauth2const.ResponseType] = oauth2const.Code
	queryParams[oauth2const.Scope] = authnutils.GetScopesString(o.oidcProperties.Scopes)

	// append any configured additional parameters as query params.
	additionalParams := o.oidcProperties.AdditionalParams
	if len(additionalParams) > 0 {
		for key, value := range additionalParams {
			if key != "" && value != "" {
				resolvedValue, err := utils.GetResolvedAdditionalParam(key, value, ctx)
				if err != nil {
					logger.Error("Failed to resolve additional parameter", log.String("key", key), log.Error(err))
					execResp.Status = flowconst.ExecUserError
					execResp.Error = "Failed to resolve additional parameter: " + err.Error()
					return
				}
				queryParams[key] = resolvedValue
			}
		}
	}

	// Construct the authorization URL
	authURL, err := systemutils.GetURIWithQueryParams(o.GetAuthorizationEndpoint(), queryParams)
	if err != nil {
		logger.Error("Failed to prepare authorization URL", log.Error(err))
		execResp.Status = flowconst.ExecError
		execResp.Error = "Failed to prepare authorization URL: " + err.Error()
		return
	}

	// Set the response to redirect the user to the OIDC provider
	execResp.Status = flowconst.ExecExternalRedirection
	execResp.Type = flowconst.ExecRedirection
	execResp.AdditionalInfo = map[string]string{
		flowconst.DataRedirectURL: authURL,
	}
}

// ProcessAuthFlowResponse processes the response from the OIDC authentication flow and authenticates the user.
func (o *OIDCAuthExecutor) ProcessAuthFlowResponse(ctx *flowmodel.FlowContext, execResp *flowmodel.ExecutorResponse) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "OIDCAuthExecutor"))
	logger.Debug("Processing OIDC authentication response",
		log.String("executorID", o.GetID()), log.String("flowID", ctx.FlowID))

	execResp.Status = flowconst.ExecIncomplete

	// Process authorization code if available
	code, ok := ctx.UserInputData["code"]
	if ok && code != "" {
		// Exchange authorization code for tokenResp
		tokenResp, err := o.ExchangeCodeForToken(ctx, code)
		if err != nil {
			logger.Error("Failed to exchange code for a token", log.Error(err))
			execResp.Status = flowconst.ExecError
			execResp.Error = "Failed to authenticate with OIDC provider: " + err.Error()
			return
		}

		// Validate the token response
		if tokenResp.AccessToken == "" {
			logger.Debug("Access token is empty in the token response",
				log.String("executorID", o.GetID()), log.String("flowID", ctx.FlowID))
			execResp.Status = flowconst.ExecUserError
			execResp.Error = "Access token is empty in the token response. Please provide a valid authorization code."
			return
		}

		if tokenResp.Scope == "" {
			logger.Debug("Scope is empty in the token response",
				log.String("executorID", o.GetID()), log.String("flowID", ctx.FlowID))
			ctx.AuthenticatedUser = &authnmodel.AuthenticatedUser{
				IsAuthenticated:        true,
				UserID:                 "143e87c1-ccfc-440d-b0a5-bb23c9a2f39e",
				Username:               "143e87c1-ccfc-440d-b0a5-bb23c9a2f39e",
				Domain:                 o.GetName(),
				AuthenticatedSubjectID: "143e87c1-ccfc-440d-b0a5-bb23c9a2f39e",
			}
		} else {
			// Get user info using the access token
			userInfo, err := o.GetUserInfo(ctx, tokenResp.AccessToken)
			if err != nil {
				logger.Error("Failed to get user info", log.Error(err))
				execResp.Status = flowconst.ExecUserError
				execResp.Error = "Failed to get user information: " + err.Error()
				return
			}

			// Populate authenticated user from user info
			username := userInfo["username"]

			attributes := make(map[string]string)
			for key, value := range userInfo {
				if key != "username" && key != "sub" {
					attributes[key] = value
				}
			}

			ctx.AuthenticatedUser = &authnmodel.AuthenticatedUser{
				IsAuthenticated:        true,
				UserID:                 "143e87c1-ccfc-440d-b0a5-bb23c9a2f39e",
				Username:               username,
				Domain:                 o.GetName(),
				AuthenticatedSubjectID: username,
				Attributes:             attributes,
			}
		}
	} else {
		// Fail the authentication if the authorization code is not provided
		ctx.AuthenticatedUser = &authnmodel.AuthenticatedUser{
			IsAuthenticated: false,
		}
	}

	// Set the flow response status based on the authentication result.
	if ctx.AuthenticatedUser.IsAuthenticated {
		execResp.Status = flowconst.ExecComplete
	} else {
		execResp.Status = flowconst.ExecUserError
		execResp.Type = flowconst.ExecRedirection
		execResp.Error = "User is not authenticated. Please provide a valid authorization code."
	}
}

// requiredInputData adds the required input data for the OIDC authentication flow to the executor response.
// Returns true if input data should be requested from the user.
func (o *OIDCAuthExecutor) requiredInputData(ctx *flowmodel.FlowContext, execResp *flowmodel.ExecutorResponse) bool {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "OIDCAuthExecutor"))

	// Check if the authorization code is already provided
	if code, ok := ctx.UserInputData["code"]; ok && code != "" {
		return false
	}

	// Define the authenticator specific required input data.
	gitReqData := []flowmodel.InputData{
		{
			Name:     "code",
			Type:     "string",
			Required: true,
		},
	}

	// Check for the required input data. Also appends the authenticator specific input data.
	// TODO: This validation should be moved to the flow composer. Ideally the validation and appending
	//  should happen during the flow definition creation.
	requiredData := ctx.CurrentNode.GetInputData()
	if len(requiredData) == 0 {
		logger.Debug("No required input data defined for OIDC authentication executor",
			log.String("executorID", o.GetID()), log.String("flowID", ctx.FlowID))
		// If no required input data is defined, use the default required data.
		requiredData = gitReqData
	} else {
		// Append the default required data if not already present.
		for _, inputData := range gitReqData {
			exists := false
			for _, existingInputData := range requiredData {
				if existingInputData.Name == inputData.Name {
					exists = true
					break
				}
			}
			// If the input data already exists, skip adding it again.
			if !exists {
				requiredData = append(requiredData, inputData)
			}
		}
	}

	requireData := false

	if execResp.RequiredData == nil {
		execResp.RequiredData = make([]flowmodel.InputData, 0)
	}

	if len(ctx.UserInputData) == 0 {
		execResp.RequiredData = append(execResp.RequiredData, requiredData...)
		return true
	}

	// Check if the required input data is provided by the user.
	for _, inputData := range requiredData {
		if _, ok := ctx.UserInputData[inputData.Name]; !ok {
			if !inputData.Required {
				logger.Debug("Skipping optional input data that is not provided by user",
					log.String("executorID", o.GetID()), log.String("flowID", ctx.FlowID),
					log.String("inputDataName", inputData.Name))
				continue
			}
			execResp.RequiredData = append(execResp.RequiredData, inputData)
			requireData = true
			logger.Debug("Required input data not provided by user",
				log.String("executorID", o.GetID()), log.String("flowID", ctx.FlowID),
				log.String("inputDataName", inputData.Name))
		}
	}

	return requireData
}

// ExchangeCodeForToken exchanges the authorization code for an access token.
func (o *OIDCAuthExecutor) ExchangeCodeForToken(ctx *flowmodel.FlowContext,
	code string) (*model.OIDCTokenResponse, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "OIDCAuthExecutor"))
	logger.Debug("Exchanging authorization code for a token",
		log.String("executorID", o.GetID()), log.String("flowID", ctx.FlowID),
		log.String("tokenEndpoint", o.GetTokenEndpoint()))

	// Prepare the token request
	data := url.Values{}
	data.Set(oauth2const.ClientID, o.oidcProperties.ClientID)
	data.Set(oauth2const.ClientSecret, o.oidcProperties.ClientSecret)
	data.Set(oauth2const.RedirectURI, o.oidcProperties.RedirectURI)
	data.Set(oauth2const.Code, code)
	data.Set(oauth2const.GrantType, oauth2const.GrantTypeAuthorizationCode)

	// Create HTTP request
	req, err := http.NewRequest("POST", o.GetTokenEndpoint(), strings.NewReader(data.Encode()))
	if err != nil {
		logger.Error("Failed to create token request", log.Error(err))
		return nil, fmt.Errorf("failed to create token request: %v", err)
	}

	req.Header.Add(constants.ContentTypeHeaderName, "application/x-www-form-urlencoded")
	req.Header.Add(constants.AcceptHeaderName, "application/json")

	// Execute the request
	logger.Debug("Sending token request to OIDC provider",
		log.String("executorID", o.GetID()), log.String("flowID", ctx.FlowID))
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Failed to send token request", log.Error(err))
		return nil, fmt.Errorf("failed to send token request: %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Failed to close response body", log.Error(closeErr))
		}
	}()
	logger.Debug("Token response received from OIDC provider",
		log.String("executorID", o.GetID()), log.String("flowID", ctx.FlowID),
		log.Int("statusCode", resp.StatusCode))

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logger.Error("Token request failed", log.String("status", resp.Status), log.String("body", string(body)))
		return nil, fmt.Errorf("token request failed with status %s: %s", resp.Status, string(body))
	}

	// Parse the response
	var tokenResp model.OIDCTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		logger.Error("Failed to parse token response", log.Error(err))
		return nil, fmt.Errorf("failed to parse token response: %v", err)
	}

	return &tokenResp, nil
}

// GetUserInfo fetches user information from the OIDC provider using the access token.
func (o *OIDCAuthExecutor) GetUserInfo(ctx *flowmodel.FlowContext, accessToken string) (map[string]string, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "OIDCAuthExecutor"))
	logger.Debug("Fetching user info from OIDC provider",
		log.String("executorID", o.GetID()), log.String("flowID", ctx.FlowID),
		log.String("userInfoEndpoint", o.GetUserInfoEndpoint()))

	// Create HTTP request
	req, err := http.NewRequest("GET", o.GetUserInfoEndpoint(), nil)
	if err != nil {
		logger.Error("Failed to create userinfo request", log.Error(err))
		return nil, fmt.Errorf("failed to create userinfo request: %v", err)
	}
	req.Header.Set(constants.AuthorizationHeaderName, constants.TokenTypeBearer+" "+accessToken)
	req.Header.Set(constants.AcceptHeaderName, "application/json")

	// Execute the request
	logger.Debug("Sending userinfo request to OIDC provider",
		log.String("executorID", o.GetID()), log.String("flowID", ctx.FlowID))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Failed to send userinfo request", log.Error(err))
		return nil, fmt.Errorf("failed to send userinfo request: %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Failed to close userinfo response body", log.Error(closeErr))
		}
	}()
	logger.Debug("Userinfo response received from OIDC provider",
		log.String("executorID", o.GetID()), log.String("flowID", ctx.FlowID),
		log.Int("statusCode", resp.StatusCode))

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logger.Error("Userinfo request failed", log.String("status", resp.Status), log.String("body", string(body)))
		return nil, fmt.Errorf("userinfo request failed with status %s: %s", resp.Status, string(body))
	}

	// Parse the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Failed to read userinfo response", log.Error(err))
		return nil, fmt.Errorf("failed to read userinfo response: %v", err)
	}

	var userInfo map[string]interface{}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		logger.Error("Failed to parse userinfo response", log.Error(err))
		return nil, fmt.Errorf("failed to parse userinfo response: %v", err)
	}

	return systemutils.ConvertInterfaceMapToStringMap(userInfo), nil
}
