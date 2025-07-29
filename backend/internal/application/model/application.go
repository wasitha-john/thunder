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

// Package model defines the data structures for the application module.
package model

// ApplicationDTO represents the data transfer object for application service operations.
type ApplicationDTO struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description"`

	ClientID            string   `json:"client_id"`
	ClientSecret        string   `json:"client_secret"`
	CallbackURLs        []string `json:"callback_url"`
	SupportedGrantTypes []string `json:"supported_grant_types"`

	AuthFlowGraphID         string `json:"auth_flow_graph_id,omitempty"`
	RegistrationFlowGraphID string `json:"registration_flow_graph_id,omitempty"`

	InboundAuthConfig InboundAuthConfig `json:"inbound_auth_config,omitempty"`
}

// ApplicationProcessedDTO represents the processed data transfer object for application service operations.
type ApplicationProcessedDTO struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description"`

	ClientID            string   `json:"client_id"`
	HashedClientSecret  string   `json:"hashed_client_secret,omitempty"`
	CallbackURLs        []string `json:"callback_url"`
	SupportedGrantTypes []string `json:"supported_grant_types"`

	AuthFlowGraphID         string `json:"auth_flow_graph_id,omitempty"`
	RegistrationFlowGraphID string `json:"registration_flow_graph_id,omitempty"`

	InboundAuthConfig InboundAuthConfigProcessed `json:"inbound_auth_config,omitempty"`
}

// TODO: Integrate InboundAuthConfig and InboundAuthConfigProcessed with the application service.

// InboundAuthConfig represents the inbound authentication configuration for an application.
type InboundAuthConfig struct {
	Type           string          `json:"type"`
	OAuthAppConfig *OAuthAppConfig `json:"oauth_app_config,omitempty"`
}

// InboundAuthConfigProcessed represents the processed inbound authentication configuration for an application.
type InboundAuthConfigProcessed struct {
	Type           string                   `json:"type"`
	OAuthAppConfig *OAuthAppConfigProcessed `json:"oauth_app_config,omitempty"`
}

// ApplicationRequest represents the request structure for creating or updating an application.
type ApplicationRequest struct {
	Name                    string   `json:"name"`
	Description             string   `json:"description"`
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	CallbackURLs            []string `json:"callback_url"`
	SupportedGrantTypes     []string `json:"supported_grant_types"`
	AuthFlowGraphID         string   `json:"auth_flow_graph_id,omitempty"`
	RegistrationFlowGraphID string   `json:"registration_flow_graph_id,omitempty"`
}

// ApplicationResponse represents the response structure for an application.
type ApplicationResponse struct {
	ID                      string   `json:"id,omitempty"`
	Name                    string   `json:"name"`
	Description             string   `json:"description"`
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	CallbackURLs            []string `json:"callback_url"`
	SupportedGrantTypes     []string `json:"supported_grant_types"`
	AuthFlowGraphID         string   `json:"auth_flow_graph_id,omitempty"`
	RegistrationFlowGraphID string   `json:"registration_flow_graph_id,omitempty"`
}

// BasicApplicationResponse represents a simplified response structure for an application.
type BasicApplicationResponse struct {
	ID                      string   `json:"id,omitempty"`
	Name                    string   `json:"name"`
	Description             string   `json:"description"`
	ClientID                string   `json:"client_id"`
	CallbackURLs            []string `json:"callback_url"`
	SupportedGrantTypes     []string `json:"supported_grant_types"`
	AuthFlowGraphID         string   `json:"auth_flow_graph_id,omitempty"`
	RegistrationFlowGraphID string   `json:"registration_flow_graph_id,omitempty"`
}
