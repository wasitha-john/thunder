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

// Package store provides the implementation for group persistence operations.
package store

import (
	"errors"
	"fmt"

	"github.com/asgardeo/thunder/internal/group/constants"
	"github.com/asgardeo/thunder/internal/group/model"
	"github.com/asgardeo/thunder/internal/system/database/client"
	dbmodel "github.com/asgardeo/thunder/internal/system/database/model"
	"github.com/asgardeo/thunder/internal/system/database/provider"
	"github.com/asgardeo/thunder/internal/system/log"
)

const loggerComponentName = "GroupStore"

// GetGroupListCount retrieves the total count of root groups.
func GetGroupListCount() (int, error) {
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

	countResults, err := dbClient.Query(QueryGetGroupListCount)
	if err != nil {
		return 0, fmt.Errorf("failed to execute count query: %w", err)
	}

	var totalCount int
	if len(countResults) > 0 {
		if total, ok := countResults[0]["total"].(int64); ok {
			totalCount = int(total)
		}
	}

	return totalCount, nil
}

// GetGroupList retrieves root groups.
func GetGroupList(limit, offset int) ([]model.GroupBasicDAO, error) {
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

	results, err := dbClient.Query(QueryGetGroupList, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to execute group list query: %w", err)
	}

	groups := make([]model.GroupBasicDAO, 0)
	for _, row := range results {
		group, err := buildGroupFromResultRow(row)
		if err != nil {
			return nil, fmt.Errorf("failed to build group from result row: %w", err)
		}

		groupBasic := model.GroupBasicDAO{
			ID:                 group.ID,
			Name:               group.Name,
			Description:        group.Description,
			OrganizationUnitID: group.OrganizationUnitID,
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
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	tx, err := dbClient.BeginTx()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	_, err = tx.Exec(
		QueryCreateGroup.Query,
		group.ID,
		group.OrganizationUnitID,
		group.Name,
		group.Description,
	)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to rollback transaction: %w", rollbackErr))
		}
		return fmt.Errorf("failed to execute query: %w", err)
	}

	err = addMembersToGroup(tx, group.ID, group.Members)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to rollback transaction: %w", rollbackErr))
		}
		return err
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetGroup retrieves a group by its id.
func GetGroup(id string) (model.GroupDAO, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		return model.GroupDAO{}, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
		}
	}()

	results, err := dbClient.Query(QueryGetGroupByID, id)
	if err != nil {
		return model.GroupDAO{}, fmt.Errorf("failed to execute query: %w", err)
	}

	if len(results) == 0 {
		return model.GroupDAO{}, constants.ErrGroupNotFound
	}

	if len(results) != 1 {
		return model.GroupDAO{}, fmt.Errorf("unexpected number of results: %d", len(results))
	}

	row := results[0]
	group, err := buildGroupFromResultRow(row)
	if err != nil {
		return model.GroupDAO{}, err
	}

	return group, nil
}

// GetGroupMembers retrieves members of a group with pagination.
func GetGroupMembers(groupID string, limit, offset int) ([]model.Member, error) {
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

	results, err := dbClient.Query(QueryGetGroupMembers, groupID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}

	members := make([]model.Member, 0)
	for _, row := range results {
		if memberID, ok := row["member_id"].(string); ok {
			if memberType, ok := row["member_type"].(string); ok {
				members = append(members, model.Member{
					ID:   memberID,
					Type: model.MemberType(memberType),
				})
			}
		}
	}

	return members, nil
}

// GetGroupMemberCount retrieves the total count of members in a group.
func GetGroupMemberCount(groupID string) (int, error) {
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

	countResults, err := dbClient.Query(QueryGetGroupMemberCount, groupID)
	if err != nil {
		return 0, fmt.Errorf("failed to get group member count: %w", err)
	}

	if len(countResults) == 0 {
		return 0, nil
	}

	if count, ok := countResults[0]["total"].(int64); ok {
		return int(count), nil
	}

	return 0, nil
}

// UpdateGroup updates an existing group.
func UpdateGroup(group model.GroupDAO) error {
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

	tx, err := dbClient.BeginTx()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	result, err := tx.Exec(
		QueryUpdateGroup.Query,
		group.ID,
		group.OrganizationUnitID,
		group.Name,
		group.Description,
	)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to rollback transaction: %w", rollbackErr))
		}
		return fmt.Errorf("failed to execute query: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to rollback transaction: %w", rollbackErr))
		}
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %w", rollbackErr)
		}
		return constants.ErrGroupNotFound
	}

	err = updateGroupMembers(tx, group.ID, group.Members)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to rollback transaction: %w", rollbackErr))
		}
		return err
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// DeleteGroup deletes a group.
func DeleteGroup(id string) error {
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

	tx, err := dbClient.BeginTx()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	_, err = tx.Exec(QueryDeleteGroupMembers.Query, id)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to rollback transaction: %w", rollbackErr))
		}
		return fmt.Errorf("failed to delete group members: %w", err)
	}

	result, err := tx.Exec(QueryDeleteGroup.Query, id)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to rollback transaction: %w", rollbackErr))
		}
		return fmt.Errorf("failed to execute query: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	} else if rowsAffected == 0 {
		logger.Debug("Group not found with id: " + id)
	}

	return nil
}

// ValidateGroupIDs checks if all provided group IDs exist.
func ValidateGroupIDs(groupIDs []string) ([]string, error) {
	if len(groupIDs) == 0 {
		return []string{}, nil
	}

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

	query, args, err := buildBulkGroupExistsQuery(groupIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to build bulk group exists query: %w", err)
	}

	results, err := dbClient.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	existingGroupIDs := make(map[string]bool)
	for _, row := range results {
		if groupID, ok := row["group_id"].(string); ok {
			existingGroupIDs[groupID] = true
		}
	}

	var invalidGroupIDs []string
	for _, groupID := range groupIDs {
		if !existingGroupIDs[groupID] {
			invalidGroupIDs = append(invalidGroupIDs, groupID)
		}
	}

	return invalidGroupIDs, nil
}

// buildGroupFromResultRow constructs a model.Group from a database result row.
func buildGroupFromResultRow(row map[string]interface{}) (model.GroupDAO, error) {
	groupID, ok := row["group_id"].(string)
	if !ok {
		return model.GroupDAO{}, fmt.Errorf("failed to parse group_id as string")
	}

	name, ok := row["name"].(string)
	if !ok {
		return model.GroupDAO{}, fmt.Errorf("failed to parse name as string")
	}

	description, ok := row["description"].(string)
	if !ok {
		return model.GroupDAO{}, fmt.Errorf("failed to parse description as string")
	}

	ouID, ok := row["ou_id"].(string)
	if !ok {
		return model.GroupDAO{}, fmt.Errorf("failed to parse ou_id as string")
	}

	group := model.GroupDAO{
		ID:                 groupID,
		Name:               name,
		Description:        description,
		OrganizationUnitID: ouID,
	}

	return group, nil
}

// addMembersToGroup adds a list of members to a group.
func addMembersToGroup(
	tx dbmodel.TxInterface,
	groupID string,
	members []model.Member,
) error {
	for _, member := range members {
		_, err := tx.Exec(QueryAddMemberToGroup.Query, groupID, member.Type, member.ID)
		if err != nil {
			return fmt.Errorf("failed to add member to group: %w", err)
		}
	}
	return nil
}

// updateGroupMembers updates the members assigned to the group by first deleting existing members and
// then adding new ones.
func updateGroupMembers(
	tx dbmodel.TxInterface,
	groupID string,
	members []model.Member,
) error {
	_, err := tx.Exec(QueryDeleteGroupMembers.Query, groupID)
	if err != nil {
		return fmt.Errorf("failed to delete existing group member assignments: %w", err)
	}

	err = addMembersToGroup(tx, groupID, members)
	if err != nil {
		return fmt.Errorf("failed to assign members to group: %w", err)
	}
	return nil
}

// CheckGroupNameConflictForCreate checks if the new group name conflicts with existing groups
// in the same organization unit.
func CheckGroupNameConflictForCreate(name string, organizationUnitID string) error {
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

	return checkGroupNameConflictForCreate(dbClient, name, organizationUnitID)
}

// CheckGroupNameConflictForUpdate checks if the new group name conflicts with other groups
// in the same organization unit.
func CheckGroupNameConflictForUpdate(name string, organizationUnitID string, groupID string) error {
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

	return checkGroupNameConflictForUpdate(dbClient, name, organizationUnitID, groupID)
}

// checkGroupNameConflictForCreate checks if the new group name conflicts with existing groups
// in the same organization unit.
func checkGroupNameConflictForCreate(
	dbClient client.DBClientInterface,
	name string,
	organizationUnitID string,
) error {
	var results []map[string]interface{}
	var err error

	results, err = dbClient.Query(QueryCheckGroupNameConflict, name, organizationUnitID)

	if err != nil {
		return fmt.Errorf("failed to check group name conflict: %w", err)
	}

	if len(results) > 0 {
		if count, ok := results[0]["count"].(int64); ok && count > 0 {
			return constants.ErrGroupNameConflict
		}
	}

	return nil
}

// checkGroupNameConflictForUpdate checks if the new group name conflicts with other groups
// in the same organization unit.
func checkGroupNameConflictForUpdate(
	dbClient client.DBClientInterface,
	name string,
	organizationUnitID string,
	groupID string,
) error {
	var results []map[string]interface{}
	var err error

	results, err = dbClient.Query(QueryCheckGroupNameConflictForUpdate, name, organizationUnitID, groupID)

	if err != nil {
		return fmt.Errorf("failed to check group name conflict: %w", err)
	}

	if len(results) > 0 {
		if count, ok := results[0]["count"].(int64); ok && count > 0 {
			return constants.ErrGroupNameConflict
		}
	}

	return nil
}

// GetGroupsByOrganizationUnitCount retrieves the total count of groups in a specific organization unit.
func GetGroupsByOrganizationUnitCount(organizationUnitID string) (int, error) {
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

	countResults, err := dbClient.Query(QueryGetGroupsByOrganizationUnitCount, organizationUnitID)
	if err != nil {
		return 0, fmt.Errorf("failed to get group count by organization unit: %w", err)
	}

	if len(countResults) == 0 {
		return 0, nil
	}

	if count, ok := countResults[0]["total"].(int64); ok {
		return int(count), nil
	}

	return 0, fmt.Errorf("unexpected response format for group count")
}

// GetGroupsByOrganizationUnit retrieves a list of groups in a specific organization unit with pagination.
func GetGroupsByOrganizationUnit(organizationUnitID string, limit, offset int) ([]model.GroupBasicDAO, error) {
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

	results, err := dbClient.Query(QueryGetGroupsByOrganizationUnit, organizationUnitID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get groups by organization unit: %w", err)
	}

	groups := make([]model.GroupBasicDAO, 0, len(results))
	for _, result := range results {
		group := model.GroupBasicDAO{
			ID:                 result["group_id"].(string),
			OrganizationUnitID: result["ou_id"].(string),
			Name:               result["name"].(string),
		}

		if description, ok := result["description"].(string); ok {
			group.Description = description
		}

		groups = append(groups, group)
	}

	return groups, nil
}
