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

// Package store provides the implementation for group persistence operations.
package store

import (
	"errors"
	"fmt"

	"github.com/asgardeo/thunder/internal/group/model"
	"github.com/asgardeo/thunder/internal/system/database/client"
	dbmodel "github.com/asgardeo/thunder/internal/system/database/model"
	"github.com/asgardeo/thunder/internal/system/database/provider"
	"github.com/asgardeo/thunder/internal/system/log"
)

const loggerComponentName = "GroupStore"

// GetGroupList retrieves all root groups.
func GetGroupList() ([]model.GroupBasicDAO, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return nil, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	var results []map[string]interface{}

	results, err = dbClient.Query(QueryGetGroupList)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	groups := make([]model.GroupBasicDAO, 0)
	for _, row := range results {
		group, err := buildGroupFromResultRow(row, logger)
		if err != nil {
			logger.Error("Failed to build group from result row", log.Error(err))
			return nil, fmt.Errorf("failed to build group from result row: %w", err)
		}

		groupBasic := model.GroupBasicDAO{
			ID:          group.ID,
			Name:        group.Name,
			Description: group.Description,
			Parent:      group.Parent,
			OU:          group.OU,
		}

		groups = append(groups, groupBasic)
	}

	return groups, nil
}

// CreateGroup creates a new group in the database.
func CreateGroup(group model.GroupDAO) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	// Begin transaction
	tx, err := dbClient.BeginTx()
	if err != nil {
		logger.Error("Failed to begin transaction", log.Error(err))
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Create the group
	_, err = tx.Exec(
		QueryCreateGroup.Query,
		group.ID,
		group.Parent,
		group.OU,
		group.Name,
		group.Description,
	)
	if err != nil {
		logger.Error("Failed to execute create group query", log.Error(err))
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Error("Failed to rollback transaction", log.Error(rollbackErr))
			err = errors.Join(err, fmt.Errorf("failed to rollback transaction: %w", rollbackErr))
		}
		return fmt.Errorf("failed to execute query: %w", err)
	}

	// Add users to the group
	err = addUsersToGroup(tx, group.ID, group.Users, logger)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Error("Failed to rollback transaction", log.Error(rollbackErr))
			err = errors.Join(err, fmt.Errorf("failed to rollback transaction: %w", rollbackErr))
		}
		return err
	}

	// Commit the transaction
	if err = tx.Commit(); err != nil {
		logger.Error("Failed to commit transaction", log.Error(err))
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetGroup retrieves a group by its id.
func GetGroup(id string) (model.GroupDAO, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return model.GroupDAO{}, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	results, err := dbClient.Query(QueryGetGroupByID, id)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return model.GroupDAO{}, fmt.Errorf("failed to execute query: %w", err)
	}

	if len(results) == 0 {
		logger.Error("Group not found with id: " + id)
		return model.GroupDAO{}, model.ErrGroupNotFound
	}

	if len(results) != 1 {
		logger.Error("Unexpected number of results")
		return model.GroupDAO{}, fmt.Errorf("unexpected number of results: %d", len(results))
	}

	row := results[0]
	group, err := buildGroupFromResultRow(row, logger)
	if err != nil {
		return model.GroupDAO{}, err
	}

	// Get child groups
	childGroups, err := GetChildGroups(id)
	if err != nil {
		return model.GroupDAO{}, err
	}
	group.Groups = *childGroups

	// Get users
	users, err := getGroupUsers(dbClient, id, logger)
	if err != nil {
		return model.GroupDAO{}, err
	}
	group.Users = users

	return group, nil
}

// UpdateGroup updates an existing group.
func UpdateGroup(group model.GroupDAO) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	// Begin transaction
	tx, err := dbClient.BeginTx()
	if err != nil {
		logger.Error("Failed to begin transaction", log.Error(err))
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Update the group
	result, err := tx.Exec(
		QueryUpdateGroup.Query,
		group.ID,
		group.Parent,
		group.OU,
		group.Name,
		group.Description,
	)
	if err != nil {
		logger.Error("Failed to execute update group query", log.Error(err))
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Error("Failed to rollback transaction", log.Error(rollbackErr))
			err = errors.Join(err, fmt.Errorf("failed to rollback transaction: %w", rollbackErr))
		}
		return fmt.Errorf("failed to execute query: %w", err)
	}

	// Check if group was found and updated
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		logger.Error("Failed to get rows affected", log.Error(err))
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Error("Failed to rollback transaction", log.Error(rollbackErr))
			err = errors.Join(err, fmt.Errorf("failed to rollback transaction: %w", rollbackErr))
		}
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		logger.Error("Group not found with id: " + group.ID)
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Error("Failed to rollback transaction", log.Error(rollbackErr))
		}
		return model.ErrGroupNotFound
	}

	// Update group users
	err = updateGroupUsers(tx, group.ID, group.Users, logger)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Error("Failed to rollback transaction", log.Error(rollbackErr))
			err = errors.Join(err, fmt.Errorf("failed to rollback transaction: %w", rollbackErr))
		}
		return err
	}

	// Commit the transaction
	if err = tx.Commit(); err != nil {
		logger.Error("Failed to commit transaction", log.Error(err))
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// DeleteGroup deletes a group.
func DeleteGroup(id string) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	// Begin transaction
	tx, err := dbClient.BeginTx()
	if err != nil {
		logger.Error("Failed to begin transaction", log.Error(err))
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Delete group users first
	_, err = tx.Exec(QueryDeleteGroupUsers.Query, id)
	if err != nil {
		logger.Error("Failed to delete group users", log.Error(err))
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Error("Failed to rollback transaction", log.Error(rollbackErr))
			err = errors.Join(err, fmt.Errorf("failed to rollback transaction: %w", rollbackErr))
		}
		return fmt.Errorf("failed to delete group users: %w", err)
	}

	// Delete the group
	result, err := tx.Exec(QueryDeleteGroup.Query, id)
	if err != nil {
		logger.Error("Failed to execute delete group query", log.Error(err))
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Error("Failed to rollback transaction", log.Error(rollbackErr))
			err = errors.Join(err, fmt.Errorf("failed to rollback transaction: %w", rollbackErr))
		}
		return fmt.Errorf("failed to execute query: %w", err)
	}

	// Commit the transaction
	if err = tx.Commit(); err != nil {
		logger.Error("Failed to commit transaction", log.Error(err))
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Check rows affected after successful commit
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		logger.Error("Failed to get rows affected", log.Error(err))
		// Transaction is already committed, so we don't return an error for this
	} else if rowsAffected == 0 {
		logger.Debug("Group not found with id: " + id)
	}

	return nil
}

// buildGroupFromResultRow constructs a model.Group from a database result row.
func buildGroupFromResultRow(row map[string]interface{}, logger *log.Logger) (model.GroupDAO, error) {
	groupID, ok := row["group_id"].(string)
	if !ok {
		logger.Error("Failed to parse group_id as string")
		return model.GroupDAO{}, fmt.Errorf("failed to parse group_id as string")
	}

	name, ok := row["name"].(string)
	if !ok {
		logger.Error("Failed to parse name as string")
		return model.GroupDAO{}, fmt.Errorf("failed to parse name as string")
	}

	description, ok := row["description"].(string)
	if !ok {
		logger.Error("Failed to parse description as string")
		return model.GroupDAO{}, fmt.Errorf("failed to parse description as string")
	}

	ouID, ok := row["ou_id"].(string)
	if !ok {
		logger.Error("Failed to parse ou_id as string")
		return model.GroupDAO{}, fmt.Errorf("failed to parse ou_id as string")
	}

	var parentID *string
	if row["parent_id"] != nil {
		if pgid, ok := row["parent_id"].(string); ok {
			parentID = &pgid
		}
	}

	group := model.GroupDAO{
		ID:          groupID,
		Name:        name,
		Description: description,
		Parent:      parentID,
		OU:          ouID,
	}

	return group, nil
}

// GetChildGroups retrieves the child groups of a given group ID.
func GetChildGroups(groupID string) (*[]string, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return nil, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	results, err := dbClient.Query(QueryGetChildGroups, groupID)
	if err != nil {
		logger.Error("Failed to get child groups", log.Error(err))
		return nil, fmt.Errorf("failed to get child groups: %w", err)
	}

	childGroups := make([]string, 0)
	for _, row := range results {
		if childID, ok := row["group_id"].(string); ok {
			childGroups = append(childGroups, childID)
		}
	}

	return &childGroups, nil
}

// getChildGroups retrieves the child groups of a given group ID.
func getGroupUsers(dbClient client.DBClientInterface, groupID string, logger *log.Logger) ([]string, error) {
	results, err := dbClient.Query(QueryGetGroupUsers, groupID)
	if err != nil {
		logger.Error("Failed to get group users", log.Error(err))
		return nil, fmt.Errorf("failed to get group users: %w", err)
	}

	users := make([]string, 0)
	for _, row := range results {
		if userID, ok := row["user_id"].(string); ok {
			users = append(users, userID)
		}
	}

	return users, nil
}

// addUsersToGroup adds a list of users to a group.
func addUsersToGroup(tx dbmodel.TxInterface, groupID string, users []string, logger *log.Logger) error {
	for _, userID := range users {
		_, err := tx.Exec(QueryAddUserToGroup.Query, groupID, userID)
		if err != nil {
			logger.Error("Failed to add user to group", log.String("userID", userID), log.Error(err))
			return fmt.Errorf("failed to add user to group: %w", err)
		}
	}
	return nil
}

// updateGroupUsers updates the users in a group by first deleting existing users and then adding new ones.
func updateGroupUsers(tx dbmodel.TxInterface, groupID string, users []string, logger *log.Logger) error {
	// Delete existing users
	_, err := tx.Exec(QueryDeleteGroupUsers.Query, groupID)
	if err != nil {
		logger.Error("Failed to delete existing group users", log.Error(err))
		return fmt.Errorf("failed to delete existing group users: %w", err)
	}

	// Add new users
	return addUsersToGroup(tx, groupID, users, logger)
}

// CheckGroupNameConflictForCreate checks if the new group name conflicts with existing groups under the same parent.
func CheckGroupNameConflictForCreate(name string, parent model.Parent) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	return checkGroupNameConflictForCreate(dbClient, name, parent, logger)
}

// CheckGroupNameConflictForUpdate checks if the new group name conflicts with other groups under the same parent.
func CheckGroupNameConflictForUpdate(name string, parent model.Parent, groupID string) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	return checkGroupNameConflictForUpdate(dbClient, name, parent, groupID, logger)
}

// checkGroupNameConflictForCreate checks if the new group name conflicts with existing groups under the same parent.
func checkGroupNameConflictForCreate(
	dbClient client.DBClientInterface,
	name string,
	parent model.Parent,
	logger *log.Logger,
) error {
	var results []map[string]interface{}
	var err error

	// Use appropriate query based on parent type and whether this is an update operation
	if parent.Type == model.ParentTypeGroup {
		results, err = dbClient.Query(QueryCheckGroupNameConflict, name, parent.ID)
	} else if parent.Type == model.ParentTypeOrganizationUnit {
		results, err = dbClient.Query(QueryCheckGroupNameConflictInOU, name, parent.ID)
	} else {
		return fmt.Errorf("invalid parent type: %s", parent.Type)
	}

	if err != nil {
		logger.Error("Failed to check group name conflict", log.Error(err))
		return fmt.Errorf("failed to check group name conflict: %w", err)
	}

	if len(results) > 0 {
		if count, ok := results[0]["count"].(int64); ok && count > 0 {
			return model.ErrGroupNameConflict
		}
	}

	return nil
}

// checkGroupNameConflictForUpdate checks if the new group name conflicts with other groups under the same parent.
func checkGroupNameConflictForUpdate(
	dbClient client.DBClientInterface,
	name string,
	parent model.Parent,
	groupID string,
	logger *log.Logger,
) error {
	var results []map[string]interface{}
	var err error

	// Use appropriate query based on parent type and whether this is an update operation
	if parent.Type == model.ParentTypeGroup {
		results, err = dbClient.Query(QueryCheckGroupNameConflictForUpdate, name, parent.ID, groupID)
	} else if parent.Type == model.ParentTypeOrganizationUnit {
		results, err = dbClient.Query(QueryCheckGroupNameConflictInOUForUpdate, name, parent.ID, groupID)
	} else {
		return fmt.Errorf("invalid parent type: %s", parent.Type)
	}

	if err != nil {
		logger.Error("Failed to check group name conflict", log.Error(err))
		return fmt.Errorf("failed to check group name conflict: %w", err)
	}

	if len(results) > 0 {
		if count, ok := results[0]["count"].(int64); ok && count > 0 {
			return model.ErrGroupNameConflict
		}
	}

	return nil
}
