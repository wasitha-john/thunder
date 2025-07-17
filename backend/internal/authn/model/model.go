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

// Package model defines the data structures for authentication.
package model

import (
	flowmodel "github.com/asgardeo/thunder/internal/flow/model"
)

// AuthNRequest represents the authentication request body.
type AuthNRequest struct {
	SessionDataKey string            `json:"sessionDataKey"`
	FlowID         string            `json:"flowId"`
	ActionID       string            `json:"actionId"`
	Inputs         map[string]string `json:"inputs"`
}

// AuthNResponse represents the authentication response body.
type AuthNResponse struct {
	FlowID        string             `json:"flowId"`
	StepID        string             `json:"stepId,omitempty"`
	FlowStatus    string             `json:"flowStatus"`
	Type          string             `json:"type,omitempty"`
	Data          flowmodel.FlowData `json:"data,omitempty"`
	FailureReason string             `json:"failureReason,omitempty"`
}
