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

// Package basicauth provides the basic authentication executor for handling username and password authentication.
package basicauth

import (
	authnmodel "github.com/asgardeo/thunder/internal/authn/model"
	flowconst "github.com/asgardeo/thunder/internal/flow/constants"
	flowmodel "github.com/asgardeo/thunder/internal/flow/model"
	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/internal/system/log"
)

// BasicAuthExecutor implements the ExecutorInterface for basic authentication.
type BasicAuthExecutor struct {
	internal flowmodel.Executor
}

// NewBasicAuthExecutor creates a new instance of BasicAuthExecutor.
func NewBasicAuthExecutor(id, name string) flowmodel.ExecutorInterface {
	return &BasicAuthExecutor{
		internal: flowmodel.Executor{
			Properties: flowmodel.ExecutorProperties{
				ID:   id,
				Name: name,
			},
		},
	}
}

// GetID returns the ID of the BasicAuthExecutor.
func (b *BasicAuthExecutor) GetID() string {
	return b.internal.GetID()
}

// GetName returns the name of the BasicAuthExecutor.
func (b *BasicAuthExecutor) GetName() string {
	return b.internal.GetName()
}

// GetProperties returns the properties of the BasicAuthExecutor.
func (b *BasicAuthExecutor) GetProperties() flowmodel.ExecutorProperties {
	return b.internal.Properties
}

// Execute executes the basic authentication logic.
func (b *BasicAuthExecutor) Execute(ctx *flowmodel.FlowContext) (*flowmodel.ExecutorResponse, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "BasicAuthExecutor"))
	logger.Debug("Executing basic authentication executor",
		log.String("executorID", b.GetID()), log.String("flowID", ctx.FlowID))

	execResp := &flowmodel.ExecutorResponse{
		Status: flowconst.FlowStatusIncomplete,
	}

	// Validate for the required input data.
	if b.addRequiredInputData(ctx, execResp) {
		// If required input data is not provided, return incomplete status.
		logger.Debug("Required input data for basic authentication executor is not provided",
			log.String("executorID", b.GetID()), log.String("flowID", ctx.FlowID))
		execResp.Status = flowconst.ExecutorStatusUserInputRequired
		execResp.Type = flowconst.FlowStepTypeView
		return execResp, nil
	}

	// Read the valid username and password from the configuration.
	config := config.GetThunderRuntime().Config
	validUsername := config.UserStore.DefaultUser.Username
	validPassword := config.UserStore.DefaultUser.Password

	username := ctx.UserInputData["username"]

	if username == validUsername && ctx.UserInputData["password"] == validPassword {
		ctx.AuthenticatedUser = &authnmodel.AuthenticatedUser{
			IsAuthenticated:        true,
			UserID:                 "143e87c1-ccfc-440d-b0a5-bb23c9a2f39e",
			Username:               username,
			Domain:                 "PRIMARY",
			AuthenticatedSubjectID: username,
			Attributes: map[string]string{
				"email":     "admin@wso2.com",
				"firstName": "Admin",
				"lastName":  "User",
			},
		}
	} else {
		ctx.AuthenticatedUser = &authnmodel.AuthenticatedUser{
			IsAuthenticated: false,
		}
	}

	// Set the flow response status based on the authentication result.
	if ctx.AuthenticatedUser.IsAuthenticated {
		execResp.Status = flowconst.ExecutorStatusComplete
	} else {
		execResp.Status = flowconst.ExecutorStatusUserError
		execResp.Type = flowconst.FlowStepTypeView
		execResp.Error = "Invalid credentials provided for basic authentication."
	}

	logger.Debug("Basic authentication executor execution completed",
		log.String("executorID", b.GetID()), log.String("flowID", ctx.FlowID),
		log.String("status", execResp.Status), log.Bool("isAuthenticated", ctx.AuthenticatedUser.IsAuthenticated))

	return execResp, nil
}

// addRequiredInputData checks and adds the required input data for basic authentication.
// Returns true if needed to request user input data.
func (b *BasicAuthExecutor) addRequiredInputData(ctx *flowmodel.FlowContext, resp *flowmodel.ExecutorResponse) bool {
	requiredData := map[string]flowmodel.InputData{
		"username": {
			Name:     "username",
			Type:     "string",
			Required: true,
		},
		// TODO: Convert password to a secure type (i.e. byte_array)
		"password": {
			Name:     "password",
			Type:     "string",
			Required: true,
		},
	}

	requireData := false

	if resp.RequiredData == nil {
		resp.RequiredData = make([]flowmodel.InputData, 0)
	}

	if len(ctx.UserInputData) == 0 {
		for _, inputData := range requiredData {
			resp.RequiredData = append(resp.RequiredData, inputData)
		}
		return true
	}

	if _, ok := ctx.UserInputData["username"]; !ok {
		resp.RequiredData = append(resp.RequiredData, requiredData["username"])
		requireData = true
	}
	if _, ok := ctx.UserInputData["password"]; !ok {
		resp.RequiredData = append(resp.RequiredData, requiredData["password"])
		requireData = true
	}

	return requireData
}
