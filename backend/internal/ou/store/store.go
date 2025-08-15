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

// Package store provides the implementation for organization unit persistence operations.
package store

import (
	"fmt"

	"github.com/asgardeo/thunder/internal/ou/constants"
	"github.com/asgardeo/thunder/internal/ou/model"
	dbmodel "github.com/asgardeo/thunder/internal/system/database/model"
	"github.com/asgardeo/thunder/internal/system/database/provider"
	"github.com/asgardeo/thunder/internal/system/log"
)

const loggerComponentName = "OrganizationUnitStore"

// GetOrganizationUnitListCount retrieves the total count of organization units.
func GetOrganizationUnitListCount() (int, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		return 0, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	results, err := dbClient.Query(QueryGetRootOrganizationUnitListCount)
	if err != nil {
		return 0, fmt.Errorf("failed to execute count query: %w", err)
	}

	var total int
	if len(results) > 0 {
		if count, ok := results[0]["total"].(int64); ok {
			total = int(count)
		} else {
			return 0, fmt.Errorf("unexpected type for total: %T", results[0]["total"])
		}
	}

	return total, nil
}

// GetOrganizationUnitList retrieves organization units with pagination.
func GetOrganizationUnitList(limit, offset int) ([]model.OrganizationUnitBasic, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		return nil, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	results, err := dbClient.Query(QueryGetRootOrganizationUnitList, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	ous := make([]model.OrganizationUnitBasic, 0, len(results))
	for _, row := range results {
		ou, err := buildOrganizationUnitBasicFromResultRow(row)
		if err != nil {
			return nil, fmt.Errorf("failed to build organization unit basic: %w", err)
		}
		ous = append(ous, ou)
	}

	return ous, nil
}

// CreateOrganizationUnit creates a new organization unit in the database.
func CreateOrganizationUnit(ou model.OrganizationUnit) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	_, err = dbClient.Execute(
		QueryCreateOrganizationUnit,
		ou.ID,
		ou.Parent,
		ou.Handle,
		ou.Name,
		ou.Description,
	)
	if err != nil {
		return fmt.Errorf("failed to execute query: %w", err)
	}

	return nil
}

// GetOrganizationUnit retrieves an organization unit by its id.
func GetOrganizationUnit(id string) (model.OrganizationUnit, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		return model.OrganizationUnit{}, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	results, err := dbClient.Query(QueryGetOrganizationUnitByID, id)
	if err != nil {
		return model.OrganizationUnit{}, fmt.Errorf("failed to execute query: %w", err)
	}

	if len(results) == 0 {
		return model.OrganizationUnit{}, constants.ErrOrganizationUnitNotFound
	}

	ou, err := buildOrganizationUnitFromResultRow(results[0])
	if err != nil {
		return model.OrganizationUnit{}, fmt.Errorf("failed to build organization unit: %w", err)
	}

	return ou, nil
}

// GetOrganizationUnitByPath retrieves an organization unit by its hierarchical handle path.
func GetOrganizationUnitByPath(handlePath []string) (model.OrganizationUnit, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	if len(handlePath) == 0 {
		return model.OrganizationUnit{}, constants.ErrOrganizationUnitNotFound
	}

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		return model.OrganizationUnit{}, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	var currentOU model.OrganizationUnit
	var parentID *string
	var fullPath string

	for i, handle := range handlePath {
		fullPath = fullPath + "/" + handle
		var results []map[string]interface{}

		if parentID == nil {
			results, err = dbClient.Query(QueryGetRootOrganizationUnitByHandle, handle)
		} else {
			results, err = dbClient.Query(QueryGetOrganizationUnitByHandle, handle, *parentID)
		}

		if err != nil {
			return model.OrganizationUnit{}, fmt.Errorf("failed to execute query for handle %s: %w", handle, err)
		}

		if len(results) == 0 {
			logger.Debug("Organization unit not found in path",
				log.String("handle", handle),
				log.Int("pathIndex", i),
				log.String("fullPath", fullPath))
			return model.OrganizationUnit{}, constants.ErrOrganizationUnitNotFound
		}

		currentOU, err = buildOrganizationUnitFromResultRow(results[0])
		if err != nil {
			return model.OrganizationUnit{}, fmt.Errorf("failed to build organization unit for handle %s: %w", handle, err)
		}

		parentID = &currentOU.ID
	}

	return currentOU, nil
}

// IsOrganizationUnitExists checks if an organization unit exists by ID.
func IsOrganizationUnitExists(id string) (bool, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		return false, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	results, err := dbClient.Query(QueryCheckOrganizationUnitExists, id)
	if err != nil {
		return false, fmt.Errorf("failed to execute existence check query: %w", err)
	}

	if len(results) == 0 {
		return false, nil
	}

	if countInterface, exists := results[0]["count"]; exists {
		if count, ok := countInterface.(int64); ok {
			return count > 0, nil
		}
	}

	return false, fmt.Errorf("failed to parse existence check result")
}

// UpdateOrganizationUnit updates an existing organization unit.
func UpdateOrganizationUnit(ou model.OrganizationUnit) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	_, err = dbClient.Execute(
		QueryUpdateOrganizationUnit,
		ou.ID,
		ou.Parent,
		ou.Handle,
		ou.Name,
		ou.Description,
	)
	if err != nil {
		return fmt.Errorf("failed to execute query: %w", err)
	}

	return nil
}

// DeleteOrganizationUnit deletes an organization unit.
func DeleteOrganizationUnit(id string) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	_, err = dbClient.Execute(QueryDeleteOrganizationUnit, id)
	if err != nil {
		return fmt.Errorf("failed to execute query: %w", err)
	}

	return nil
}

// GetOrganizationUnitChildrenCount retrieves the total count of child organization units for a given parent ID.
func GetOrganizationUnitChildrenCount(parentID string) (int, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		return 0, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	results, err := dbClient.Query(QueryGetOrganizationUnitChildrenCount, parentID)
	if err != nil {
		return 0, fmt.Errorf("failed to execute count query: %w", err)
	}

	if len(results) == 0 {
		return 0, nil
	}

	if totalInterface, exists := results[0]["total"]; exists {
		if total, ok := totalInterface.(int64); ok {
			return int(total), nil
		}
	}

	return 0, fmt.Errorf("failed to parse count result")
}

// GetOrganizationUnitChildrenList retrieves a paginated list of child organization units for a given parent ID.
func GetOrganizationUnitChildrenList(parentID string, limit, offset int) ([]model.OrganizationUnitBasic, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		return nil, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	results, err := dbClient.Query(QueryGetOrganizationUnitChildrenList, parentID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	childOUs := make([]model.OrganizationUnitBasic, 0, len(results))
	for _, row := range results {
		childOU, err := buildOrganizationUnitBasicFromResultRow(row)
		if err != nil {
			return nil, fmt.Errorf("failed to build organization unit basic: %w", err)
		}
		childOUs = append(childOUs, childOU)
	}

	return childOUs, nil
}

// GetOrganizationUnitUsersCount retrieves the total count of users in a given organization unit.
func GetOrganizationUnitUsersCount(ouID string) (int, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		return 0, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	results, err := dbClient.Query(QueryGetOrganizationUnitUsersCount, ouID)
	if err != nil {
		return 0, fmt.Errorf("failed to execute count query: %w", err)
	}

	if len(results) == 0 {
		return 0, nil
	}

	if totalInterface, exists := results[0]["total"]; exists {
		if total, ok := totalInterface.(int64); ok {
			return int(total), nil
		}
	}

	return 0, fmt.Errorf("failed to parse count result")
}

// GetOrganizationUnitUsersList retrieves a paginated list of users in a given organization unit.
func GetOrganizationUnitUsersList(ouID string, limit, offset int) ([]model.User, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		return nil, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	results, err := dbClient.Query(QueryGetOrganizationUnitUsersList, ouID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	users := make([]model.User, 0, len(results))
	for _, row := range results {
		if userIDInterface, exists := row["user_id"]; exists {
			if userID, ok := userIDInterface.(string); ok {
				users = append(users, model.User{ID: userID})
			} else {
				return nil, fmt.Errorf("expected user_id to be a string")
			}
		}
	}

	return users, nil
}

// GetOrganizationUnitGroupsCount retrieves the total count of groups in a given organization unit.
func GetOrganizationUnitGroupsCount(ouID string) (int, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		return 0, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	results, err := dbClient.Query(QueryGetOrganizationUnitGroupsCount, ouID)
	if err != nil {
		return 0, fmt.Errorf("failed to execute count query: %w", err)
	}

	if len(results) == 0 {
		return 0, nil
	}

	if totalInterface, exists := results[0]["total"]; exists {
		if total, ok := totalInterface.(int64); ok {
			return int(total), nil
		}
	}

	return 0, fmt.Errorf("failed to parse count result")
}

// GetOrganizationUnitGroupsList retrieves a paginated list of groups in a given organization unit.
func GetOrganizationUnitGroupsList(ouID string, limit, offset int) ([]model.Group, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		return nil, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	results, err := dbClient.Query(QueryGetOrganizationUnitGroupsList, ouID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	groups := make([]model.Group, 0, len(results))
	for _, row := range results {
		var group model.Group

		if groupIDInterface, exists := row["group_id"]; exists {
			if groupID, ok := groupIDInterface.(string); ok {
				group.ID = groupID
			} else {
				return nil, fmt.Errorf("expected group_id to be a string")
			}
		}

		if nameInterface, exists := row["name"]; exists {
			if name, ok := nameInterface.(string); ok {
				group.Name = name
			} else {
				return nil, fmt.Errorf("expected name to be a string")
			}
		}

		groups = append(groups, group)
	}

	return groups, nil
}

// CheckOrganizationUnitNameConflict checks if an organization unit name conflicts under the same parent.
func CheckOrganizationUnitNameConflict(name string, parentID *string) (bool, error) {
	return checkConflict(
		QueryCheckOrganizationUnitNameConflict,
		QueryCheckOrganizationUnitNameConflictRoot,
		name,
		parentID,
	)
}

// CheckOrganizationUnitHandleConflict checks if an organization unit handle conflicts under the same parent.
func CheckOrganizationUnitHandleConflict(handle string, parentID *string) (bool, error) {
	return checkConflict(
		QueryCheckOrganizationUnitHandleConflict,
		QueryCheckOrganizationUnitHandleConflictRoot,
		handle,
		parentID,
	)
}

// CheckOrganizationUnitHasChildResources checks if an organization unit has users groups or sub-ous.
func CheckOrganizationUnitHasChildResources(ouID string) (bool, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		return false, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	results, err := dbClient.Query(QueryCheckOrganizationUnitHasUsersOrGroups, ouID)
	if err != nil {
		return false, fmt.Errorf("failed to execute query: %w", err)
	}

	if len(results) > 0 {
		if count, ok := results[0]["count"].(int64); ok && count > 0 {
			return true, nil
		}
	}

	return false, nil
}

// buildOrganizationUnitBasicFromResultRow constructs a model.OrganizationUnitBasic from a database result row.
func buildOrganizationUnitBasicFromResultRow(
	row map[string]interface{},
) (model.OrganizationUnitBasic, error) {
	ouID, ok := row["ou_id"].(string)
	if !ok {
		return model.OrganizationUnitBasic{}, fmt.Errorf("ou_id is not a string")
	}

	name, ok := row["name"].(string)
	if !ok {
		return model.OrganizationUnitBasic{}, fmt.Errorf("name is not a string")
	}

	handle, ok := row["handle"].(string)
	if !ok {
		return model.OrganizationUnitBasic{}, fmt.Errorf("handle is not a string")
	}

	description := ""
	if desc, ok := row["description"]; ok && desc != nil {
		if descStr, ok := desc.(string); ok {
			description = descStr
		}
	}

	return model.OrganizationUnitBasic{
		ID:          ouID,
		Handle:      handle,
		Name:        name,
		Description: description,
	}, nil
}

// buildOrganizationUnitFromResultRow constructs a model.OrganizationUnit from a database result row.
func buildOrganizationUnitFromResultRow(
	row map[string]interface{},
) (model.OrganizationUnit, error) {
	ou, err := buildOrganizationUnitBasicFromResultRow(row)
	if err != nil {
		return model.OrganizationUnit{}, fmt.Errorf("failed to build organization unit: %w", err)
	}

	var parentID *string
	if parent, ok := row["parent_id"]; ok && parent != nil {
		if parentStr, ok := parent.(string); ok {
			parentID = &parentStr
		}
	}

	return model.OrganizationUnit{
		ID:          ou.ID,
		Handle:      ou.Handle,
		Name:        ou.Name,
		Description: ou.Description,
		Parent:      parentID,
	}, nil
}

// checkConflict is a helper function to check for conflicts in organization unit attributes.
func checkConflict(
	queryWithParent, queryWithoutParent dbmodel.DBQuery,
	value string,
	parentID *string,
	extraArgs ...interface{},
) (bool, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		return false, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	var results []map[string]interface{}

	if parentID != nil {
		args := append([]interface{}{value, *parentID}, extraArgs...)
		results, err = dbClient.Query(queryWithParent, args...)
	} else {
		args := append([]interface{}{value}, extraArgs...)
		results, err = dbClient.Query(queryWithoutParent, args...)
	}

	if err != nil {
		return false, fmt.Errorf("failed to execute query: %w", err)
	}

	if len(results) > 0 {
		if count, ok := results[0]["count"].(int64); ok && count > 0 {
			return true, nil
		}
	}

	return false, nil
}
