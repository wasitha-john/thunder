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

package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/asgardeo/thunder/internal/system/config"
)

// GetJWTTokenValidityPeriod retrieves the JWT token validity period from the configuration.
func GetJWTTokenValidityPeriod() int64 {
	conf := config.GetThunderRuntime().Config
	validityPeriod := conf.OAuth.JWT.ValidityPeriod

	if validityPeriod == 0 {
		validityPeriod = defaultTokenValidity
	}

	return validityPeriod
}

// GetJWTTokenIssuer retrieves the JWT token issuer from the configuration.
func GetJWTTokenIssuer() string {
	conf := config.GetThunderRuntime().Config
	issuer := conf.OAuth.JWT.Issuer

	if issuer == "" {
		issuer = defaultIssuer
	}

	return issuer
}

// DecodeJWT decodes a JWT string and returns its header and payload as maps.
func DecodeJWT(token string) (map[string]interface{}, map[string]interface{}, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, nil, errors.New("invalid JWT format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, errors.New("failed to decode JWT header: " + err.Error())
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, errors.New("failed to decode JWT payload: " + err.Error())
	}

	header := make(map[string]interface{})
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, errors.New("failed to unmarshal JWT header: " + err.Error())
	}
	payload := make(map[string]interface{})
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, errors.New("failed to unmarshal JWT payload: " + err.Error())
	}

	return header, payload, nil
}
