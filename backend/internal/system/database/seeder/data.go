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

package seeder

// seedData holds all the initial data to be seeded into the database.
type seedData struct {
	Apps               []AppData               `json:"apps"`
	OAuthConsumerApps  []OAuthConsumerAppData  `json:"oauth_consumer_apps"`
	InboundAuth        []InboundAuthData       `json:"inbound_auth"`
	AllowedOrigins     []AllowedOriginsData    `json:"allowed_origins"`
	Users              []UserData              `json:"users"`
	IDPs               []IDPData               `json:"idps"`
	IDPProperties      []IDPPropertyData       `json:"idp_properties"`
	OrganizationUnits  []OrganizationUnitData  `json:"organization_units"`
}

// AppData represents application data to be seeded.
type AppData struct {
	AppName                string `json:"app_name"`
	AppID                  string `json:"app_id"`
	Description            string `json:"description"`
	AuthFlowGraphID        string `json:"auth_flow_graph_id"`
	RegistrationFlowGraphID string `json:"registration_flow_graph_id"`
}

// OAuthConsumerAppData represents OAuth consumer application data to be seeded.
type OAuthConsumerAppData struct {
	ConsumerKey               string `json:"consumer_key"`
	ConsumerSecret            string `json:"consumer_secret"`
	AppID                     string `json:"app_id"`
	CallbackURIs              string `json:"callback_uris"`
	GrantTypes                string `json:"grant_types"`
	ResponseTypes             string `json:"response_types"`
	TokenEndpointAuthMethods  string `json:"token_endpoint_auth_methods"`
}

// InboundAuthData represents inbound authentication data to be seeded.
type InboundAuthData struct {
	InboundAuthKey  string `json:"inbound_auth_key"`
	InboundAuthType string `json:"inbound_auth_type"`
	AppID           string `json:"app_id"`
}

// AllowedOriginsData represents allowed origins data to be seeded.
type AllowedOriginsData struct {
	AllowedOrigins string `json:"allowed_origins"`
}

// UserData represents user data to be seeded.
type UserData struct {
	UserID     string `json:"user_id"`
	OUID       string `json:"ou_id"`
	Type       string `json:"type"`
	Attributes string `json:"attributes"`
}

// IDPData represents identity provider data to be seeded.
type IDPData struct {
	IDPID       string `json:"idp_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// IDPPropertyData represents identity provider property data to be seeded.
type IDPPropertyData struct {
	IDPID         string `json:"idp_id"`
	PropertyName  string `json:"property_name"`
	PropertyValue string `json:"property_value"`
	IsSecret      string `json:"is_secret"`
}

// OrganizationUnitData represents organization unit data to be seeded.
type OrganizationUnitData struct {
	OUID        string  `json:"ou_id"`
	ParentID    *string `json:"parent_id,omitempty"`
	Handle      string  `json:"handle"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
}