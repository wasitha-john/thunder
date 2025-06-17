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

// Package store provides the implementation for user persistence operations.
package store

import (
	"encoding/json"
	"fmt"

	"github.com/asgardeo/thunder/internal/system/database/provider"
	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/user/model"
)

// CreateUser handles the user creation in the database.
func CreateUser(user model.User, credentials model.Credentials) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "UserPersistence"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	// Convert attributes to JSON string
	attributes, err := json.Marshal(user.Attributes)
	if err != nil {
		logger.Error("Failed to marshal attributes", log.Error(err))
		return model.ErrBadAttributesInRequest
	}

	// Correct the handling of credentialsJSON to convert []byte to string.
	var credentialsJSON string
	if (model.Credentials{}) == credentials {
		credentialsJSON = "{}"
	} else {
		credentialsBytes, err := json.Marshal(credentials)
		if err != nil {
			logger.Error("Failed to marshal credentials", log.Error(err))
			return model.ErrBadAttributesInRequest
		}
		credentialsJSON = string(credentialsBytes)
	}

	_, err = dbClient.Execute(
		QueryCreateUser,
		user.ID,
		user.OrganizationUnit,
		user.Type,
		string(attributes),
		credentialsJSON,
	)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return fmt.Errorf("failed to execute query: %w", err)
	}

	return nil
}

// GetUserList retrieves a list of users from the database.
func GetUserList() ([]model.User, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "UserPersistence"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return nil, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	results, err := dbClient.Query(QueryGetUserList)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	users := make([]model.User, 0)

	for _, row := range results {
		user, err := buildUserFromResultRow(row)
		if err != nil {
			logger.Error("failed to build user from result row", log.Error(err))
			return nil, fmt.Errorf("failed to build user from result row: %w", err)
		}
		users = append(users, user)
	}

	return users, nil
}

// GetUser retrieves a specific user by its ID from the database.
func GetUser(id string) (model.User, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "UserStore"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return model.User{}, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	results, err := dbClient.Query(QueryGetUserByUserID, id)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return model.User{}, fmt.Errorf("failed to execute query: %w", err)
	}

	if len(results) == 0 {
		logger.Error("user not found with id: " + id)
		return model.User{}, model.ErrUserNotFound
	}

	if len(results) != 1 {
		logger.Error("unexpected number of results")
		return model.User{}, fmt.Errorf("unexpected number of results: %d", len(results))
	}

	row := results[0]

	user, err := buildUserFromResultRow(row)
	if err != nil {
		logger.Error("failed to build user from result row")
		return model.User{}, fmt.Errorf("failed to build user from result row: %w", err)
	}
	return user, nil
}

// UpdateUser updates the user in the database.
func UpdateUser(user *model.User) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "UserStore"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	// Convert attributes to JSON string
	attributes, err := json.Marshal(user.Attributes)
	if err != nil {
		logger.Error("Failed to marshal attributes", log.Error(err))
		return model.ErrBadAttributesInRequest
	}

	rowsAffected, err := dbClient.Execute(
		QueryUpdateUserByUserID, user.ID, user.OrganizationUnit, user.Type, string(attributes))
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return fmt.Errorf("failed to execute query: %w", err)
	}

	if rowsAffected == 0 {
		logger.Error("user not found with id: " + user.ID)
		return model.ErrUserNotFound
	}

	return nil
}

// DeleteUser deletes the user from the database.
func DeleteUser(id string) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "UserStore"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	rowsAffected, err := dbClient.Execute(QueryDeleteUserByUserID, id)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return fmt.Errorf("failed to execute query: %w", err)
	}

	if rowsAffected == 0 {
		logger.Error("user not found with id: " + id)
	}

	return nil
}

// IdentifyUser identify user with the given attributes.
func IdentifyUser(attrName, attrValue string) (*string, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "UserStore"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return nil, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	filters := map[string]interface{}{attrName: attrValue}
	identifyUserQuery, args, err := buildIdentifyQuery(filters)
	if err != nil {
		logger.Error("Failed to build identify query", log.Error(err))
		return nil, fmt.Errorf("failed to build identify query: %w", err)
	}

	results, err := dbClient.Query(identifyUserQuery, args...)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	if len(results) == 0 {
		logger.Error("user not found with attribute name: " + attrName + " and value: " + log.MaskString(attrValue))
		return nil, model.ErrUserNotFound
	}

	if len(results) != 1 {
		logger.Error("unexpected number of results for attribute name: " + attrName + " and value: " +
			log.MaskString(attrValue))
		return nil, fmt.Errorf("unexpected number of results: %d", len(results))
	}

	row := results[0]
	userID, ok := row["user_id"].(string)
	if !ok {
		logger.Error("failed to parse user_id as string")
		return nil, fmt.Errorf("failed to parse user_id as string")
	}

	return &userID, nil
}

// VerifyUser validate the user specified user using the given credentials from the database.
func VerifyUser(id string) (model.User, model.Credentials, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "UserStore"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return model.User{}, model.Credentials{}, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	results, err := dbClient.Query(QueryValidateUserWithCredentials, id)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return model.User{}, model.Credentials{}, fmt.Errorf("failed to execute query: %w", err)
	}

	if len(results) == 0 {
		logger.Error("user not found with id: " + id)
		return model.User{}, model.Credentials{}, model.ErrUserNotFound
	}

	if len(results) != 1 {
		logger.Error("unexpected number of results")
		return model.User{}, model.Credentials{}, fmt.Errorf("unexpected number of results: %d", len(results))
	}

	row := results[0]

	user, err := buildUserFromResultRow(row)
	if err != nil {
		logger.Error("failed to build user from result row")
		return model.User{}, model.Credentials{}, fmt.Errorf("failed to build user from result row: %w", err)
	}

	// build the UserDTO with credentials.
	credentialsJSON, ok := row["credentials"].(string)
	if !ok {
		logger.Error("failed to parse credentials as string")
		return model.User{}, model.Credentials{}, fmt.Errorf("failed to parse credentials as string")
	}

	var credentials model.Credentials
	if err := json.Unmarshal([]byte(credentialsJSON), &credentials); err != nil {
		logger.Error("Failed to unmarshal credentials", log.Error(err))
		return model.User{}, model.Credentials{}, fmt.Errorf("failed to unmarshal credentials: %w", err)
	}

	return user, credentials, nil
}

func buildUserFromResultRow(row map[string]interface{}) (model.User, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "UserStore"))

	userID, ok := row["user_id"].(string)
	if !ok {
		logger.Error("failed to parse user_id as string")
		return model.User{}, fmt.Errorf("failed to parse user_id as string")
	}

	orgID, ok := row["ou_id"].(string)
	if !ok {
		logger.Error("failed to parse org_id as string")
		return model.User{}, fmt.Errorf("failed to parse org_id as string")
	}

	userType, ok := row["type"].(string)
	if !ok {
		logger.Error("failed to parse type as string")
		return model.User{}, fmt.Errorf("failed to parse type as string")
	}

	var attributes string
	switch v := row["attributes"].(type) {
	case string:
		attributes = v
	case []byte:
		attributes = string(v) // Convert byte slice to string
	default:
		logger.Error("failed to parse attributes", log.Any("raw_value", row["attributes"]), log.String("type",
			fmt.Sprintf("%T", row["attributes"])))
		return model.User{}, fmt.Errorf("failed to parse attributes as string")
	}

	user := model.User{
		ID:               userID,
		OrganizationUnit: orgID,
		Type:             userType,
	}

	// Unmarshal JSON attributes
	if err := json.Unmarshal([]byte(attributes), &user.Attributes); err != nil {
		logger.Error("Failed to unmarshal attributes")
		return model.User{}, fmt.Errorf("failed to unmarshal attributes")
	}

	return user, nil
}
