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

// Package utils provides utility functions for OAuth flow executors.
package utils

import (
	"errors"
	"strings"

	flowmodel "github.com/asgardeo/thunder/internal/flow/model"
	"github.com/asgardeo/thunder/internal/system/log"
)

// paramPlaceHolderStart is the start delimiter for parameter placeholders in flow configurations.
const paramPlaceHolderStart = "${"

// paramPlaceHolderEnd is the end delimiter for parameter placeholders in flow configurations.
const paramPlaceHolderEnd = "}"

// GetResolvedAdditionalParam resolves the additional parameter value by replacing placeholders
// with actual values.
func GetResolvedAdditionalParam(paramName, paramValue string, ctx *flowmodel.NodeContext) (string, error) {
	if strings.Contains(paramValue, paramPlaceHolderStart) && strings.Contains(paramValue, paramPlaceHolderEnd) {
		startIndex := strings.Index(paramValue, paramPlaceHolderStart)
		endIndex := strings.Index(paramValue, paramPlaceHolderEnd)

		if startIndex < 0 || endIndex < 0 || endIndex <= startIndex {
			return "", errors.New("invalid parameter placeholder format for '" + paramName + "'")
		}

		resolvedParamName := paramValue[startIndex+len(paramPlaceHolderStart) : endIndex]
		if resolvedParamName == "" {
			return "", errors.New("empty parameter placeholder in '" + paramName + "'")
		}
		if resolvedParamName == "flowId" {
			return ctx.FlowID, nil
		}

		log.GetLogger().Warn("Parameter placeholder is not supported. Returning the original value.",
			log.String("paramName", paramName), log.String("paramValue", paramValue),
			log.String("resolvedParamName", resolvedParamName))
	}

	return paramValue, nil
}
