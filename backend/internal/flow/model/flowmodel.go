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

package model

// FlowContext holds the overall context for flow execution
type FlowContext struct {
	FlowID        string
	AppID         string
	CallBackURL   string
	UserInputData map[string]string

	CurrentNode     NodeInterface
	CurrentActionID string

	Graph GraphInterface
}

// FlowStep represents the outcome of a individual flow step
type FlowStep struct {
	StepID    string
	Status    string
	InputData []InputData
	Actions   []Action
	Assertion string
}

type InputData struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
}

type Action struct {
	Type     string         `json:"type"`
	Executor *ExecutorModel `json:"executor,omitempty"`
}

// ExecutorModel represents an executor configuration within an action
type ExecutorModel struct {
	Name string `json:"name"`
}

// -------------------

// FlowServiceError represents an error response from the flow service
type FlowServiceError struct {
	Type             string `json:"type,omitempty"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// FlowRequest represents the flow execution API request body
type FlowRequest struct {
	ApplicationID string            `json:"applicationId"`
	CallbackURL   string            `json:"callbackUrl"`
	FlowID        string            `json:"flowId"`
	ActionID      string            `json:"actionId"`
	Inputs        map[string]string `json:"inputs"`
}

// FlowResponse represents the flow execution API response body
type FlowResponse struct {
	Type       string           `json:"type"`
	FlowID     string           `json:"flowId"`
	FlowStatus string           `json:"flowStatus"`
	Data       FlowResponseData `json:"data"`
}

// FlowResponseData represents the data in the flow execution API response
type FlowResponseData struct {
}
