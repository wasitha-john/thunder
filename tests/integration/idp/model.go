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

package idp

import (
	"encoding/json"
)

type IDP struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`          // Display name
	Description  string          `json:"description"`   // Description shown in UI
	ClientID     string          `json:"client_id"`     // OAuth client ID
	ClientSecret string          `json:"client_secret"` // OAuth client secret
	RedirectURI  string          `json:"redirect_uri"`  // OAuth redirect URI
	Scopes       json.RawMessage `json:"scopes"`        // JSON format scopes
}

func compareStringSlices(a, b []string) bool {

	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// compare and validate whether two IdPs have equal content
func (idp *IDP) equals(expectedIdp IDP) bool {
	if idp.ID != expectedIdp.ID || idp.Name != expectedIdp.Name || idp.Description != expectedIdp.Description || idp.ClientID != expectedIdp.ClientID || idp.ClientSecret != expectedIdp.ClientSecret || idp.RedirectURI != expectedIdp.RedirectURI {
		return false
	}

	// Compare the Scopes JSON
	var scopes1, scopes2 []string
	if err := json.Unmarshal(idp.Scopes, &scopes1); err != nil {
		return false
	}
	if err := json.Unmarshal(expectedIdp.Scopes, &scopes2); err != nil {
		return false
	}

	return compareStringSlices(scopes1, scopes2)
}
