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

// getSeedData returns the predefined seed data for database initialization.
func getSeedData() seedData {
	return seedData{
		OrganizationUnits: []OrganizationUnitData{
			{
				OUID:        "456e8400-e29b-41d4-a716-446655440001",
				ParentID:    nil,
				Handle:      "root",
				Name:        "Root Organization",
				Description: "Root organization unit",
			},
			{
				OUID:        "456e8400-e29b-41d4-a716-446655440002",
				ParentID:    stringPtr("456e8400-e29b-41d4-a716-446655440001"),
				Handle:      "engineering",
				Name:        "Engineering",
				Description: "Engineering department",
			},
			{
				OUID:        "456e8400-e29b-41d4-a716-446655440003",
				ParentID:    stringPtr("456e8400-e29b-41d4-a716-446655440001"),
				Handle:      "sales",
				Name:        "Sales",
				Description: "Sales department",
			},
			{
				OUID:        "456e8400-e29b-41d4-a716-446655440004",
				ParentID:    stringPtr("456e8400-e29b-41d4-a716-446655440002"),
				Handle:      "frontend",
				Name:        "Frontend Team",
				Description: "Frontend development team",
			},
		},
		Apps: []AppData{
			{
				AppName:                "Test SPA",
				AppID:                  "550e8400-e29b-41d4-a716-446655440000",
				Description:            "Initial testing App",
				AuthFlowGraphID:        "auth_flow_config_basic",
				RegistrationFlowGraphID: "registration_flow_config_basic",
			},
		},
		OAuthConsumerApps: []OAuthConsumerAppData{
			{
				ConsumerKey:              "client123",
				ConsumerSecret:           "fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e4",
				AppID:                    "550e8400-e29b-41d4-a716-446655440000",
				CallbackURIs:             "https://localhost:3000",
				GrantTypes:               "client_credentials,authorization_code,refresh_token",
				ResponseTypes:            "code",
				TokenEndpointAuthMethods: "client_secret_basic,client_secret_post",
			},
		},
		InboundAuth: []InboundAuthData{
			{
				InboundAuthKey:  "client123",
				InboundAuthType: "oauth2",
				AppID:           "550e8400-e29b-41d4-a716-446655440000",
			},
		},
		AllowedOrigins: []AllowedOriginsData{
			{
				AllowedOrigins: "https://localhost:3000,https://localhost:9001,https://localhost:9090",
			},
		},
		Users: []UserData{
			{
				UserID:     "550e8400-e29b-41d4-a716-446655440000",
				OUID:       "456e8400-e29b-41d4-a716-446655440001",
				Type:       "person",
				Attributes: `{"age": 30, "roles": ["admin", "user"], "address": {"city": "Colombo", "zip": "00100"}}`,
			},
		},
		IDPs: []IDPData{
			{
				IDPID:       "550e8400-e29b-41d4-a716-446655440000",
				Name:        "Local",
				Description: "Local Identity Provider",
			},
			{
				IDPID:       "550e8400-e29b-41d4-a716-446655440001",
				Name:        "Github",
				Description: "Login with Github",
			},
			{
				IDPID:       "550e8400-e29b-41d4-a716-446655440002",
				Name:        "Google",
				Description: "Login with Google",
			},
		},
		IDPProperties: []IDPPropertyData{
			// Github IDP properties
			{
				IDPID:         "550e8400-e29b-41d4-a716-446655440001",
				PropertyName:  "client_id",
				PropertyValue: "client1",
				IsSecret:      "0",
			},
			{
				IDPID:         "550e8400-e29b-41d4-a716-446655440001",
				PropertyName:  "client_secret",
				PropertyValue: "secret1",
				IsSecret:      "1",
			},
			{
				IDPID:         "550e8400-e29b-41d4-a716-446655440001",
				PropertyName:  "redirect_uri",
				PropertyValue: "https://localhost:3000",
				IsSecret:      "0",
			},
			{
				IDPID:         "550e8400-e29b-41d4-a716-446655440001",
				PropertyName:  "scopes",
				PropertyValue: "user:email,read:user",
				IsSecret:      "0",
			},
			// Google IDP properties
			{
				IDPID:         "550e8400-e29b-41d4-a716-446655440002",
				PropertyName:  "client_id",
				PropertyValue: "client2",
				IsSecret:      "0",
			},
			{
				IDPID:         "550e8400-e29b-41d4-a716-446655440002",
				PropertyName:  "client_secret",
				PropertyValue: "secret2",
				IsSecret:      "1",
			},
			{
				IDPID:         "550e8400-e29b-41d4-a716-446655440002",
				PropertyName:  "redirect_uri",
				PropertyValue: "https://localhost:3000",
				IsSecret:      "0",
			},
			{
				IDPID:         "550e8400-e29b-41d4-a716-446655440002",
				PropertyName:  "scopes",
				PropertyValue: "openid,email,profile",
				IsSecret:      "0",
			},
		},
	}
}

// stringPtr returns a pointer to the provided string value.
func stringPtr(s string) *string {
	return &s
}