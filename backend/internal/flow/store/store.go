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

// Package store provides the implementation for flow context persistence operations.
package store

import (
	"errors"
	"fmt"

	"github.com/asgardeo/thunder/internal/flow/model"
	"github.com/asgardeo/thunder/internal/system/database/provider"
	"github.com/asgardeo/thunder/internal/system/log"
)

const loggerComponentName = "FlowStore"

// StoreFlowContext stores the complete flow context in the database.
func StoreFlowContext(ctx model.EngineContext) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("runtime")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	// Convert engine context to database model
	dbModel, err := FromEngineContext(ctx)
	if err != nil {
		logger.Error("Failed to convert engine context to database model", log.Error(err))
		return fmt.Errorf("failed to convert engine context to database model: %w", err)
	}

	logger.Debug("Storing flow context to database",
		log.String("flowID", dbModel.FlowID),
		log.String("currentNodeID", getStringValue(dbModel.CurrentNodeID)),
		log.Bool("isAuthenticated", dbModel.IsAuthenticated),
		log.String("userID", getStringValue(dbModel.UserID)))

	// Store flow context
	_, err = dbClient.Execute(QueryCreateFlowContext,
		dbModel.FlowID, dbModel.AppID,
		dbModel.CurrentNodeID, dbModel.CurrentActionID, dbModel.GraphID, dbModel.RuntimeData)
	if err != nil {
		logger.Error("Failed to create flow context", log.Error(err))
		return fmt.Errorf("failed to create flow context: %w", err)
	}

	// Store flow user data
	_, err = dbClient.Execute(QueryCreateFlowUserData,
		dbModel.FlowID, dbModel.IsAuthenticated, dbModel.UserID,
		dbModel.UserInputs, dbModel.UserAttributes)
	if err != nil {
		logger.Error("Failed to create flow user data", log.Error(err))
		return fmt.Errorf("failed to create flow user data: %w", err)
	}

	return nil
}

// GetFlowContext retrieves the flow context from the database.
func GetFlowContext(flowID string) (*FlowContextWithUserDataDB, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("runtime")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return nil, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	results, err := dbClient.Query(QueryGetFlowContextWithUserData, flowID)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	if len(results) == 0 {
		logger.Debug("Flow context not found", log.String("flowID", flowID))
		return nil, nil
	}

	if len(results) != 1 {
		logger.Error("Unexpected number of results", log.Int("resultCount", len(results)))
		return nil, fmt.Errorf("unexpected number of results: %d", len(results))
	}

	row := results[0]
	return buildFlowContextFromResultRow(row)
}

// UpdateFlowContext updates the flow context in the database.
func UpdateFlowContext(ctx model.EngineContext) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("runtime")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	// Convert engine context to database model
	dbModel, err := FromEngineContext(ctx)
	if err != nil {
		logger.Error("Failed to convert engine context to database model", log.Error(err))
		return fmt.Errorf("failed to convert engine context to database model: %w", err)
	}

	logger.Debug("Updating flow context in database",
		log.String("flowID", dbModel.FlowID),
		log.String("currentNodeID", getStringValue(dbModel.CurrentNodeID)),
		log.String("currentActionID", getStringValue(dbModel.CurrentActionID)),
		log.Bool("isAuthenticated", dbModel.IsAuthenticated),
		log.String("userID", getStringValue(dbModel.UserID)))

	// Update flow context
	_, err = dbClient.Execute(QueryUpdateFlowContext,
		dbModel.FlowID, dbModel.CurrentNodeID, dbModel.CurrentActionID, dbModel.RuntimeData)
	if err != nil {
		logger.Error("Failed to update flow context", log.Error(err))
		return fmt.Errorf("failed to update flow context: %w", err)
	}

	// Update flow user data
	_, err = dbClient.Execute(QueryUpdateFlowUserData,
		dbModel.FlowID, dbModel.IsAuthenticated, dbModel.UserID,
		dbModel.UserInputs, dbModel.UserAttributes)
	if err != nil {
		logger.Error("Failed to update flow user data", log.Error(err))
		return fmt.Errorf("failed to update flow user data: %w", err)
	}

	return nil
}

// DeleteFlowContext removes the flow context from the database.
func DeleteFlowContext(flowID string) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("runtime")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	logger.Debug("Deleting flow context from database", log.String("flowID", flowID))

	// Delete flow user data first (due to foreign key constraint)
	_, err = dbClient.Execute(QueryDeleteFlowUserData, flowID)
	if err != nil {
		logger.Error("Failed to delete flow user data", log.Error(err))
		return fmt.Errorf("failed to delete flow user data: %w", err)
	}

	// Delete flow context
	_, err = dbClient.Execute(QueryDeleteFlowContext, flowID)
	if err != nil {
		logger.Error("Failed to delete flow context", log.Error(err))
		return fmt.Errorf("failed to delete flow context: %w", err)
	}

	logger.Debug("Successfully deleted flow context from database", log.String("flowID", flowID))
	return nil
}

// buildFlowContextFromResultRow builds a FlowContextWithUserDataDB from a database result row.
func buildFlowContextFromResultRow(row map[string]interface{}) (*FlowContextWithUserDataDB, error) {
	// Parse required fields
	flowID, ok := row["flow_id"].(string)
	if !ok {
		return nil, errors.New("failed to parse flow_id as string")
	}

	appID, ok := row["app_id"].(string)
	if !ok {
		return nil, errors.New("failed to parse app_id as string")
	}

	graphID, ok := row["graph_id"].(string)
	if !ok {
		return nil, errors.New("failed to parse graph_id as string")
	}

	// Parse optional fields
	currentNodeID := parseOptionalString(row["current_node_id"])
	currentActionID := parseOptionalString(row["current_action_id"])
	userID := parseOptionalString(row["user_id"])
	userInputs := parseOptionalString(row["user_inputs"])
	runtimeData := parseOptionalString(row["runtime_data"])
	userAttributes := parseOptionalString(row["user_attributes"])

	// Parse boolean field with type conversion support
	isAuthenticated := parseBoolean(row["is_authenticated"])

	return &FlowContextWithUserDataDB{
		FlowID:          flowID,
		AppID:           appID,
		CurrentNodeID:   currentNodeID,
		CurrentActionID: currentActionID,
		GraphID:         graphID,
		RuntimeData:     runtimeData,
		IsAuthenticated: isAuthenticated,
		UserID:          userID,
		UserInputs:      userInputs,
		UserAttributes:  userAttributes,
	}, nil
}

// parseOptionalString safely parses an optional string field from the database row
func parseOptionalString(value interface{}) *string {
	if value == nil {
		return nil
	}
	if str, ok := value.(string); ok {
		return &str
	}
	return nil
}

// parseBoolean safely parses a boolean field from the database row with type conversion support
func parseBoolean(value interface{}) bool {
	if value == nil {
		return false
	}

	if boolVal, ok := value.(bool); ok {
		return boolVal
	}

	if intVal, ok := value.(int64); ok {
		return intVal != 0
	}

	return false
}

// getStringValue safely returns the string value of a pointer, or "nil" if the pointer is nil
func getStringValue(s *string) string {
	if s == nil {
		return "nil"
	}
	return *s
}
