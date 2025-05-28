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

package utils

import "strings"

// ParseStringArray parses a comma-separated string into a slice of strings.
func ParseStringArray(value interface{}) []string {
	if value == nil {
		return []string{}
	}
	return strings.Split(value.(string), ",")
}

// ConvertInterfaceMapToStringMap converts a map with string keys and interface{} values
// to a map with string keys and string values. If the value is a slice, it converts
// the slice elements to a comma-separated string.
// If the value is a string, it adds it directly to the output map.
func ConvertInterfaceMapToStringMap(input map[string]interface{}) map[string]string {
	if input == nil {
		return nil
	}

	output := make(map[string]string)
	for key, value := range input {
		// If the value is a string, add it to the output map.
		if strValue, ok := value.(string); ok {
			output[key] = strValue
		}
		// If the value is a slice, convert it to a string and add it to the output map.
		if sliceValue, ok := value.([]interface{}); ok {
			var strValue string
			for _, v := range sliceValue {
				if str, ok := v.(string); ok {
					strValue += str + ","
				}
			}
			if len(strValue) > 0 {
				strValue = strings.TrimSuffix(strValue, ",")
			}
			output[key] = strValue
		}
	}
	return output
}

// MergeStringMaps merges two maps of strings and returns the result.
func MergeStringMaps(dst, src map[string]string) map[string]string {
	if dst == nil {
		dst = make(map[string]string)
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
