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

// Package flow provides the FlowService interface and its implementation.
package flow

import (
	"errors"
	"sync"

	"github.com/asgardeo/thunder/internal/flow/constants"
	"github.com/asgardeo/thunder/internal/flow/dao"
	"github.com/asgardeo/thunder/internal/flow/engine"
	"github.com/asgardeo/thunder/internal/flow/model"
	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/system/services/apierror"
	sysutils "github.com/asgardeo/thunder/internal/system/utils"
)

var (
	instance *FlowService
	once     sync.Once
)

// FlowServiceInterface defines the interface for flow orchestration and acts as the entry point for flow execution
type FlowServiceInterface interface {
	Init() error
	Execute(appID, flowID, actionID string, inputData map[string]string) (*model.FlowStep, *model.FlowServiceError)
}

// FlowService is the implementation of FlowServiceInterface
type FlowService struct {
	store map[string]model.FlowContext
	mu    sync.Mutex
}

// GetFlowService returns a singleton instance of FlowService
func GetFlowService() FlowServiceInterface {
	once.Do(func() {
		instance = &FlowService{
			store: make(map[string]model.FlowContext),
		}
	})
	return instance
}

// Init initializes the FlowService by loading the necessary components.
func (s *FlowService) Init() error {
	flowDAO := dao.GetFlowDAO()
	if err := flowDAO.Init(); err != nil {
		return errors.New("failed to initialize flow service: " + err.Error())
	}

	return nil
}

// Execute executes a flow with the given data
func (s *FlowService) Execute(appID, flowID, actionID string,
	inputData map[string]string) (*model.FlowStep, *model.FlowServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "FlowService"))

	context, svcErr := s.loadContext(appID, flowID, actionID, inputData, logger)
	if svcErr != nil {
		return nil, svcErr
	}

	engine := engine.GetFlowEngine()
	flowStep, flowErr := engine.Execute(context)
	if flowErr != nil {
		logger.Error("Failed to execute flow", log.Error(flowErr))

		// Remove the flow context from the store
		s.mu.Lock()
		delete(s.store, context.FlowID)
		s.mu.Unlock()

		return nil, &model.FlowServiceError{
			Type:             "server",
			Error:            "Flow Execution Error",
			ErrorDescription: "An error occurred while executing the flow: " + flowErr.Error(),
		}
	}

	s.updateContext(context, &flowStep, logger)

	return &flowStep, nil
}

// loadContext loads or initializes a flow context based on the provided parameters.
func (s *FlowService) loadContext(appID, flowID, actionID string, inputData map[string]string,
	logger *log.Logger) (*model.FlowContext, *model.FlowServiceError) {
	var context model.FlowContext
	if flowID == "" && actionID == "" && len(inputData) == 0 {
		ctx, err := s.initContext(appID, logger)
		if err != nil {
			return nil, err
		}
		context = *ctx
	} else {
		ctx, err := s.loadContextFromStore(flowID, actionID, inputData, logger)
		if err != nil {
			return nil, err
		}
		context = *ctx
	}

	return &context, nil
}

// initContext initializes a new flow context with the given details.
func (s *FlowService) initContext(appID string, logger *log.Logger) (*model.FlowContext, *model.FlowServiceError) {
	if appID == "" {
		return nil, &model.FlowServiceError{
			Type:             apierror.ClientErrorType,
			Error:            "Invalid Request",
			ErrorDescription: "appID is required",
		}
	}

	ctx := model.FlowContext{}
	flowID := sysutils.GenerateUUID()
	ctx.FlowID = flowID

	flowDAO := dao.GetFlowDAO()
	// TODO: This needs to be retrieved from the app config.
	graph, ok := flowDAO.GetGraph("auth_flow_config_basic")
	if !ok {
		logger.Error("Graph not found")
		return nil, &model.FlowServiceError{
			Type:             "server",
			Error:            "Graph Not Found",
			ErrorDescription: "Graph not found for the graph ID",
		}
	}
	ctx.Graph = graph
	ctx.AppID = appID

	return &ctx, nil
}

// loadContextFromStore retrieves the flow context from the store based on the given details.
func (s *FlowService) loadContextFromStore(flowID, actionID string, inputData map[string]string,
	logger *log.Logger) (*model.FlowContext, *model.FlowServiceError) {
	if flowID == "" {
		return nil, &model.FlowServiceError{
			Type:             apierror.ClientErrorType,
			Error:            "Invalid Request",
			ErrorDescription: "flowID is required",
		}
	}
	if len(inputData) == 0 {
		return nil, &model.FlowServiceError{
			Type:             apierror.ClientErrorType,
			Error:            "Invalid Request",
			ErrorDescription: "One or more input data is required",
		}
	}

	s.mu.Lock()
	ctx, ok := s.store[flowID]
	if !ok {
		s.mu.Unlock()
		logger.Error("Flow context not found in the store")
		return nil, &model.FlowServiceError{
			Type:             apierror.ClientErrorType,
			Error:            "Invalid Request",
			ErrorDescription: "Flow context not found for the flow ID",
		}
	}

	delete(s.store, flowID)
	s.mu.Unlock()

	ctx.UserInputData = sysutils.MergeStringMaps(ctx.UserInputData, inputData)
	ctx.CurrentActionID = actionID

	return &ctx, nil
}

// updateContext updates the flow context in the store based on the flow step status.
func (s *FlowService) updateContext(ctx *model.FlowContext, flowStep *model.FlowStep, logger *log.Logger) {
	if flowStep.Status != "" && flowStep.Status == constants.FlowStatusComplete {
		s.mu.Lock()
		delete(s.store, ctx.FlowID)
		s.mu.Unlock()
	} else {
		logger.Debug("Flow execution is incomplete, storing the flow context",
			log.String("flowID", ctx.FlowID))

		s.mu.Lock()
		s.store[ctx.FlowID] = *ctx
		s.mu.Unlock()
	}
}
