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

import "github.com/asgardeo/thunder/internal/flow/constants"

// ExecutorResponse represents the response from an executor
type ExecutorResponse struct {
	Status         constants.ExecutorStatus       `json:"status"`
	Type           constants.ExecutorResponseType `json:"type"`
	Error          string                         `json:"error,omitempty"`
	RequiredData   []InputData                    `json:"required_data,omitempty"`
	AdditionalInfo map[string]string              `json:"additional_info,omitempty"`
	Assertion      string                         `json:"assertion,omitempty"`
}

// ExecutorProperties holds the properties of an executor.
type ExecutorProperties struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	DisplayName string            `json:"display_name"`
	Properties  map[string]string `json:"properties,omitempty"`
}

// ExecutorConfig holds the configuration for an executor.
type ExecutorConfig struct {
	Name     string `json:"name"`
	IdpName  string `json:"idp_name,omitempty"`
	Executor ExecutorInterface
}

// ExecutorInterface defines the interface for executors.
type ExecutorInterface interface {
	Execute(ctx *NodeContext) (*ExecutorResponse, error)
	GetID() string
	GetName() string
	GetProperties() ExecutorProperties
}

var _ ExecutorInterface = (*Executor)(nil)

// Executor represents the basic implementation of an executor.
type Executor struct {
	Properties ExecutorProperties
}

// GetID returns the ID of the executor.
func (e *Executor) GetID() string {
	return e.Properties.ID
}

// GetName returns the name of the executor.
func (e *Executor) GetName() string {
	return e.Properties.Name
}

// GetProperties returns the properties of the executor.
func (e *Executor) GetProperties() ExecutorProperties {
	return e.Properties
}

// Execute executes the executor logic.
func (e *Executor) Execute(ctx *NodeContext) (*ExecutorResponse, error) {
	// Implement the logic for executing the executor here.
	// This is just a placeholder implementation
	return nil, nil
}
