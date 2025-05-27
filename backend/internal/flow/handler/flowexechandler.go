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

// Package handler provides HTTP handlers for managing flow related API requests.
package handler

import (
	"encoding/json"
	"net/http"

	"github.com/asgardeo/thunder/internal/flow"
	"github.com/asgardeo/thunder/internal/flow/constants"
	"github.com/asgardeo/thunder/internal/flow/model"
	"github.com/asgardeo/thunder/internal/system/error/apierror"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
)

// FlowExecutionHandler handles flow execution requests.
type FlowExecutionHandler struct{}

// NewFlowExecutionHandler creates a new instance of FlowExecutionHandler.
func NewFlowExecutionHandler() *FlowExecutionHandler {
	return &FlowExecutionHandler{}
}

// HandleFlowExecutionRequest handles the flow execution request.
func (h *FlowExecutionHandler) HandleFlowExecutionRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "FlowExecutionHandler"))

	var flowR model.FlowRequest
	if err := json.NewDecoder(r.Body).Decode(&flowR); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		if err := json.NewEncoder(w).Encode(constants.APIErrorFlowRequestJSONDecodeError); err != nil {
			logger.Error("Error encoding error response", log.Error(err))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
		}

		return
	}

	svc := flow.GetFlowService()
	flowStep, flowErr := svc.Execute(flowR.ApplicationID, flowR.FlowID, flowR.ActionID, flowR.Inputs)

	if flowErr != nil {
		errResp := apierror.ErrorResponse{
			Code:        flowErr.Code,
			Message:     flowErr.Error,
			Description: flowErr.ErrorDescription,
		}

		w.Header().Set("Content-Type", "application/json")
		if flowErr.Type == serviceerror.ClientErrorType {
			w.WriteHeader(http.StatusBadRequest)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}

		if err := json.NewEncoder(w).Encode(errResp); err != nil {
			logger.Error("Error encoding error response", log.Error(err))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
		}

		return
	}

	flowResp := model.FlowResponse{
		FlowID:         flowStep.FlowID,
		StepID:         flowStep.StepID,
		FlowStatus:     string(flowStep.Status),
		Actions:        flowStep.Actions,
		Inputs:         flowStep.InputData,
		AdditionalInfo: flowStep.AdditionalInfo,
		Assertion:      flowStep.Assertion,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	err := json.NewEncoder(w).Encode(flowResp)
	if err != nil {
		logger.Error("Error encoding response", log.Error(err))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	logger.Debug("Flow execution request handled successfully", log.String("flowID", flowResp.FlowID))
}
