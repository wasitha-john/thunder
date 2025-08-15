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

package idp

type IDPProperty struct {
	Name     string `json:"name"`      // Name of the property
	Value    string `json:"value"`     // Value of the property
	IsSecret bool   `json:"is_secret"` // Whether the property is a secret
}

type IDP struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`        // Display name
	Description string        `json:"description"` // Description shown in UI
	Properties  []IDPProperty `json:"properties"`  // Additional properties for the IDP
}

// compare and validate whether two IdPs have equal content
func (idp *IDP) equals(expectedIdp IDP) bool {
	if idp.ID != expectedIdp.ID || idp.Name != expectedIdp.Name || idp.Description != expectedIdp.Description {
		return false
	}

	// Compare the Properties
	for _, expProp := range expectedIdp.Properties {
		found := false
		for _, p := range idp.Properties {
			if p.Name == expProp.Name {
				found = true
				if !expProp.IsSecret {
					if p.Value != expProp.Value {
						return false
					}
				}
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}
