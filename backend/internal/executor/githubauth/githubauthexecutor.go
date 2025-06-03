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

// Package githubauth provides the GitHub OIDC authentication executor.
package githubauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	authnmodel "github.com/asgardeo/thunder/internal/authn/model"
	"github.com/asgardeo/thunder/internal/executor/oidcauth"
	"github.com/asgardeo/thunder/internal/executor/oidcauth/model"
	flowconst "github.com/asgardeo/thunder/internal/flow/constants"
	flowmodel "github.com/asgardeo/thunder/internal/flow/model"
	"github.com/asgardeo/thunder/internal/system/constants"
	"github.com/asgardeo/thunder/internal/system/log"
	systemutils "github.com/asgardeo/thunder/internal/system/utils"
)

const loggerComponentName = "GithubAuthExecutor"

// GithubOIDCAuthExecutor implements the OIDC authentication executor for GitHub.
type GithubOIDCAuthExecutor struct {
	*oidcauth.OIDCAuthExecutor
}

// NewGithubOIDCAuthExecutorFromProps creates a new instance of GithubOIDCAuthExecutor with the provided properties.
func NewGithubOIDCAuthExecutorFromProps(execProps flowmodel.ExecutorProperties,
	oidcProps *model.BasicOIDCExecProperties) oidcauth.OIDCAuthExecutorInterface {
	// Prepare the complete OIDC properties for GitHub
	compOIDCProps := &model.OIDCExecProperties{
		AuthorizationEndpoint: githubAuthorizeEndpoint,
		TokenEndpoint:         githubTokenEndpoint,
		UserInfoEndpoint:      githubUserInfoEndpoint,
		ClientID:              oidcProps.ClientID,
		ClientSecret:          oidcProps.ClientSecret,
		RedirectURI:           oidcProps.RedirectURI,
		Scopes:                oidcProps.Scopes,
		AdditionalParams:      oidcProps.AdditionalParams,
	}

	base := oidcauth.NewOIDCAuthExecutor("github_oidc_auth_executor", execProps.Name, compOIDCProps)

	exec, ok := base.(*oidcauth.OIDCAuthExecutor)
	if !ok {
		panic("failed to cast GithubOIDCAuthExecutor to OIDCAuthExecutor")
	}
	return &GithubOIDCAuthExecutor{
		OIDCAuthExecutor: exec,
	}
}

// NewGithubOIDCAuthExecutor creates a new instance of GithubOIDCAuthExecutor with the provided details.
func NewGithubOIDCAuthExecutor(id, name, clientID, clientSecret, redirectURI string,
	scopes []string, additionalParams map[string]string) oidcauth.OIDCAuthExecutorInterface {
	// Prepare the OIDC properties for GitHub
	oidcProps := &model.OIDCExecProperties{
		AuthorizationEndpoint: githubAuthorizeEndpoint,
		TokenEndpoint:         githubTokenEndpoint,
		UserInfoEndpoint:      githubUserInfoEndpoint,
		ClientID:              clientID,
		ClientSecret:          clientSecret,
		RedirectURI:           redirectURI,
		Scopes:                scopes,
		AdditionalParams:      additionalParams,
	}

	base := oidcauth.NewOIDCAuthExecutor(id, name, oidcProps)

	exec, ok := base.(*oidcauth.OIDCAuthExecutor)
	if !ok {
		panic("failed to cast GithubOIDCAuthExecutor to OIDCAuthExecutor")
	}
	return &GithubOIDCAuthExecutor{
		OIDCAuthExecutor: exec,
	}
}

// Execute executes the GitHub OIDC authentication flow.
func (g *GithubOIDCAuthExecutor) Execute(ctx *flowmodel.NodeContext) (*flowmodel.ExecutorResponse, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Executing GitHub OIDC auth executor",
		log.String("executorID", g.GetID()), log.String("flowID", ctx.FlowID))

	execResp := &flowmodel.ExecutorResponse{}

	// Check if the required input data is provided
	if g.requiredInputData(ctx, execResp) {
		// If required input data is not provided, return incomplete status with redirection to github.
		logger.Debug("Required input data for GitHub OIDC auth executor is not provided")

		g.BuildAuthorizeFlow(ctx, execResp)

		logger.Debug("GitHub OIDC auth executor execution completed",
			log.String("status", string(execResp.Status)))
	} else {
		g.ProcessAuthFlowResponse(ctx, execResp)

		logger.Debug("GitHub OIDC auth executor execution completed",
			log.String("status", string(execResp.Status)),
			log.Bool("isAuthenticated", ctx.AuthenticatedUser.IsAuthenticated))
	}

	return execResp, nil
}

// ProcessAuthFlowResponse processes the response from the GitHub OIDC authentication flow.
func (o *GithubOIDCAuthExecutor) ProcessAuthFlowResponse(ctx *flowmodel.NodeContext,
	execResp *flowmodel.ExecutorResponse) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName),
		log.String("executorID", o.GetID()), log.String("flowID", ctx.FlowID))
	logger.Debug("Processing GitHub OIDC auth flow response")

	// Process authorization code if available
	code, ok := ctx.UserInputData["code"]
	if ok && code != "" {
		// Exchange authorization code for tokenResp
		tokenResp, err := o.ExchangeCodeForToken(ctx, execResp, code)
		if err != nil {
			logger.Error("Failed to exchange code for a token", log.Error(err))
			return fmt.Errorf("failed to exchange code for a token: %w", err)
		}

		// Validate the token response
		if tokenResp.AccessToken == "" {
			logger.Debug("Access token is empty in the token response")
			execResp.Status = flowconst.ExecFailure
			execResp.FailureReason = "Access token is empty in the token response."
			return nil
		}

		if tokenResp.Scope == "" {
			logger.Debug("Scope is empty in the token response")
			ctx.AuthenticatedUser = authnmodel.AuthenticatedUser{
				IsAuthenticated:        true,
				UserID:                 "143e87c1-ccfc-440d-b0a5-bb23c9a2f39e",
				Username:               "143e87c1-ccfc-440d-b0a5-bb23c9a2f39e",
				Domain:                 o.GetName(),
				AuthenticatedSubjectID: "143e87c1-ccfc-440d-b0a5-bb23c9a2f39e",
			}
		} else {
			// Get user info using the access token
			userInfo, err := o.GetUserInfo(ctx, execResp, tokenResp.AccessToken)
			if err != nil {
				logger.Error("Failed to get user info", log.Error(err))
				return fmt.Errorf("failed to get user info: %w", err)
			}
			if execResp.Status == flowconst.ExecFailure {
				return nil
			}

			// Populate authenticated user from user info
			username := userInfo["username"]

			attributes := make(map[string]string)
			for key, value := range userInfo {
				if key != "username" && key != "sub" {
					attributes[key] = value
				}
			}

			ctx.AuthenticatedUser = authnmodel.AuthenticatedUser{
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
		ctx.AuthenticatedUser = authnmodel.AuthenticatedUser{
			IsAuthenticated: false,
		}
	}

	// Set the flow response status based on the authentication result.
	if ctx.AuthenticatedUser.IsAuthenticated {
		execResp.Status = flowconst.ExecComplete
	} else {
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = "Authentication failed. Authorization code not provided or invalid."
	}

	return nil
}

// requiredInputData adds the required input data for the GitHub OIDC authentication flow.
// Returns true if input data should be requested from the user.
func (g *GithubOIDCAuthExecutor) requiredInputData(ctx *flowmodel.NodeContext,
	execResp *flowmodel.ExecutorResponse) bool {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

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
	requiredData := ctx.NodeInputData
	if len(requiredData) == 0 {
		logger.Debug("No required input data defined for GitHub OIDC auth executor")
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
					log.String("inputDataName", inputData.Name))
				continue
			}
			execResp.RequiredData = append(execResp.RequiredData, inputData)
			requireData = true
			logger.Debug("Required input data not provided by user", log.String("inputDataName", inputData.Name))
		}
	}

	return requireData
}

// GetUserInfo fetches user information from the GitHub OIDC provider using the access token.
func (o *GithubOIDCAuthExecutor) GetUserInfo(ctx *flowmodel.NodeContext, execResp *flowmodel.ExecutorResponse,
	accessToken string) (map[string]string, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Fetching user info from Github OIDC provider",
		log.String("userInfoEndpoint", o.GetUserInfoEndpoint()))

	// Create HTTP request
	req, err := http.NewRequest("GET", o.GetUserInfoEndpoint(), nil)
	if err != nil {
		logger.Error("Failed to create userinfo request", log.Error(err))
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}
	req.Header.Set(constants.AuthorizationHeaderName, constants.TokenTypeBearer+" "+accessToken)
	req.Header.Set(constants.AcceptHeaderName, "application/json")

	// Execute the request
	logger.Debug("Sending userinfo request to GitHub OIDC provider")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Failed to send userinfo request", log.Error(err))
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = "Failed to fetch user information: " + err.Error()
		return nil, nil
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Failed to close userinfo response body", log.Error(closeErr))
		}
	}()
	logger.Debug("Userinfo response received from GitHub OIDC provider",
		log.Int("statusCode", resp.StatusCode))

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = fmt.Sprintf("Userinfo request failed with status %s: %s", resp.Status, string(body))
		return nil, nil
	}

	// Parse the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Failed to read userinfo response body", log.Error(err))
		return nil, fmt.Errorf("failed to read userinfo response body: %w", err)
	}

	var userInfo map[string]interface{}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		logger.Error("Failed to parse userinfo response", log.Error(err))
		return nil, fmt.Errorf("failed to parse userinfo response: %w", err)
	}

	// If the user info doesn't contain the email, but scopes contain "user" or "user:email",
	// then fetch the primary email from the email endpoint.
	email := userInfo["email"]
	scopes := o.GetOIDCProperties().Scopes
	if (email == nil || email == "") &&
		(slices.Contains(scopes, userScope) || slices.Contains(scopes, userEmailScope)) {
		logger.Debug("Fetching user email from Github email endpoint",
			log.String("githubUserEmailEndpoint", githubUserEmailEndpoint))

		req, err = http.NewRequest("GET", githubUserEmailEndpoint, nil)
		if err != nil {
			logger.Error("Failed to create user email request: ", log.Error(err))
			return nil, errors.New("failed to create user email request: " + err.Error())
		}
		req.Header.Set(constants.AuthorizationHeaderName, constants.TokenTypeBearer+" "+accessToken)
		req.Header.Set(constants.AcceptHeaderName, "application/json")

		resp, err = client.Do(req)
		if err != nil {
			execResp.Status = flowconst.ExecFailure
			execResp.FailureReason = "Failed to fetch user email: " + err.Error()
			return nil, nil
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				logger.Error("Failed to close response body: ", log.Error(err))
			}
		}()
		logger.Debug("User email response received from GitHub", log.Int("statusCode", resp.StatusCode))

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			execResp.Status = flowconst.ExecFailure
			execResp.FailureReason = fmt.Sprintf("User email request failed with status %s: %s",
				resp.Status, string(body))
			return nil, nil
		}

		var emails []map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
			logger.Error("Failed to decode email response: ", log.Error(err))
			return nil, errors.New("failed to decode email response: " + err.Error())
		}

		// Set the primary email in the user info map.
		for _, emailEntry := range emails {
			if isPrimary, ok := emailEntry["primary"].(bool); ok && isPrimary {
				if primaryEmail, ok := emailEntry["email"].(string); ok {
					userInfo["email"] = primaryEmail
					break
				}
			}
		}
	}

	return systemutils.ConvertInterfaceMapToStringMap(userInfo), nil
}
