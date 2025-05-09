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

package granthandlers

import (
	appmodel "github.com/asgardeo/thunder/internal/application/model"
	"github.com/asgardeo/thunder/internal/oauth/oauth2/model"
)

// GrantHandler defines the interface for handling OAuth 2.0 grants.
type GrantHandler interface {
	ValidateGrant(tokenRequest *model.TokenRequest) *model.ErrorResponse
	HandleGrant(tokenRequest *model.TokenRequest,
		oauthApp *appmodel.OAuthApplication) (*model.TokenResponse, *model.ErrorResponse)
}
