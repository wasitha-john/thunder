/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

// Package jsonmodel provides the structure for representing a graph definition in JSON format.
package jsonmodel

// GraphDefinition represents the direct graph structure from JSON
type GraphDefinition struct {
	ID    string           `json:"id"`
	Type  string           `json:"type"`
	Nodes []NodeDefinition `json:"nodes"`
}

// NodeDefinition represents a node in the graph definition
type NodeDefinition struct {
	ID        string             `json:"id"`
	Type      string             `json:"type"`
	InputData []InputDefinition  `json:"inputData"`
	Executor  ExecutorDefinition `json:"executor"`
	Next      []string           `json:"next,omitempty"`
}

// InputDefinition represents an input parameter for a node
type InputDefinition struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
}

// ExecutorDefinition represents the executor configuration for a node
type ExecutorDefinition struct {
	Name       string            `json:"name"`
	IdpName    string            `json:"idpName,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}
