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

// Package store provides the storage layer for message notification senders.
package store

import (
	"errors"
	"fmt"
	"sync"

	"github.com/asgardeo/thunder/internal/notification/message/constants"
	"github.com/asgardeo/thunder/internal/notification/message/model"
	dbmodel "github.com/asgardeo/thunder/internal/system/database/model"
	"github.com/asgardeo/thunder/internal/system/database/provider"
	"github.com/asgardeo/thunder/internal/system/log"
	sysutils "github.com/asgardeo/thunder/internal/system/utils"
)

var (
	instance *MessageNotificationStore
	once     sync.Once
)

const loggerComponentName = "MessageNotificationStore"

// MessageNotificationStoreInterface defines the interface for message notification sender storage operations.
type MessageNotificationStoreInterface interface {
	CreateSender(sender model.MessageNotificationSenderIn) (string, error)
	ListSenders() ([]model.MessageNotificationSender, error)
	GetSenderByID(id string) (*model.MessageNotificationSender, error)
	GetSenderByName(name string) (*model.MessageNotificationSender, error)
	UpdateSender(id string, sender model.MessageNotificationSenderIn) error
	DeleteSender(id string) error
}

// MessageNotificationStore is the implementation of MessageNotificationStoreInterface.
type MessageNotificationStore struct{}

// GetMessageNotificationStore returns a singleton instance of MessageNotificationStore.
func GetMessageNotificationStore() MessageNotificationStoreInterface {
	once.Do(func() {
		instance = &MessageNotificationStore{}
	})
	return instance
}

// CreateSender creates a new message notification sender.
func (s *MessageNotificationStore) CreateSender(sender model.MessageNotificationSenderIn) (string, error) {
	id := sysutils.GenerateUUID()

	queries := []func(tx dbmodel.TxInterface) error{
		func(tx dbmodel.TxInterface) error {
			_, err := tx.Exec(QueryCreateNotificationSender.Query, sender.Name, id,
				sender.Description, string(sender.Provider))
			return err
		},
	}
	for _, prop := range sender.Properties {
		queries = append(queries, func(tx dbmodel.TxInterface) error {
			_, err := tx.Exec(QueryCreateNotificationSenderProperty.Query, id,
				prop.Name, prop.Value, sysutils.BoolToNumString(prop.IsSecret))
			return err
		})
	}

	if err := executeTransaction(queries); err != nil {
		return "", fmt.Errorf("failed to execute transaction: %w", err)
	}

	return id, nil
}

// ListSenders retrieves all message notification senders
func (s *MessageNotificationStore) ListSenders() ([]model.MessageNotificationSender, error) {
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

	results, err := dbClient.Query(QueryGetAllNotificationSenders)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	senders := make([]model.MessageNotificationSender, 0, len(results))
	for _, row := range results {
		sender, err := s.buildSenderFromResultRow(row)
		if err != nil {
			return nil, fmt.Errorf("failed to build sender from result row: %w", err)
		}

		// Get properties for the sender
		properties, err := s.GetSenderProperties(sender.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get properties for sender %s: %w", sender.ID, err)
		}

		sender.Properties = properties
		senders = append(senders, *sender)
	}

	return senders, nil
}

// GetSenderProperties retrieves all properties of a message notification sender by ID.
func (s *MessageNotificationStore) GetSenderProperties(id string) ([]model.SenderProperty, error) {
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

	results, err := dbClient.Query(QueryGetNotificationSenderProperties, id)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	props, err := buildSenderPropertiesFromResultSet(results, id)
	if err != nil {
		return nil, fmt.Errorf("failed to build sender properties from result set: %w", err)
	}
	return props, nil
}

// GetSenderByID retrieves a message notification sender by ID.
func (s *MessageNotificationStore) GetSenderByID(id string) (*model.MessageNotificationSender, error) {
	return s.getSender(QueryGetNotificationSenderByID, id)
}

// GetSenderByName retrieves a message notification sender by name
func (s *MessageNotificationStore) GetSenderByName(name string) (*model.MessageNotificationSender, error) {
	return s.getSender(QueryGetNotificationSenderByName, name)
}

// getSender retrieves a message notification sender by a specific identifier (ID or name).
func (s *MessageNotificationStore) getSender(query dbmodel.DBQuery,
	identifier string) (*model.MessageNotificationSender, error) {
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

	results, err := dbClient.Query(query, identifier)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	if len(results) == 0 {
		logger.Debug("Notification sender not found", log.String("identifier", identifier))
		return nil, nil
	}
	if len(results) > 1 {
		return nil, fmt.Errorf("multiple senders found for identifier: %s", identifier)
	}

	sender, err := s.buildSenderFromResultRow(results[0])
	if err != nil {
		return nil, fmt.Errorf("failed to build sender from result row: %w", err)
	}

	// Get properties for the sender
	properties, err := s.GetSenderProperties(sender.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get properties for sender %s: %w", sender.ID, err)
	}
	sender.Properties = properties

	return sender, nil
}

// UpdateSender updates an existing message notification sender.
func (s *MessageNotificationStore) UpdateSender(id string, sender model.MessageNotificationSenderIn) error {
	queries := []func(tx dbmodel.TxInterface) error{
		func(tx dbmodel.TxInterface) error {
			_, err := tx.Exec(QueryUpdateNotificationSender.Query, sender.Name, sender.Description,
				string(sender.Provider), id)
			return err
		},
		func(tx dbmodel.TxInterface) error {
			_, err := tx.Exec(QueryDeleteNotificationSenderProperties.Query, id)
			return err
		},
	}
	for _, prop := range sender.Properties {
		queries = append(queries, func(tx dbmodel.TxInterface) error {
			_, err := tx.Exec(QueryCreateNotificationSenderProperty.Query, id, prop.Name,
				prop.Value, sysutils.BoolToNumString(prop.IsSecret))
			return err
		})
	}

	if err := executeTransaction(queries); err != nil {
		return fmt.Errorf("failed to execute transaction: %w", err)
	}

	return nil
}

// DeleteSender deletes a message notification sender.
func (s *MessageNotificationStore) DeleteSender(id string) error {
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

	rowsAffected, err := dbClient.Execute(QueryDeleteNotificationSender, id)
	if err != nil {
		return fmt.Errorf("failed to execute delete query: %w", err)
	}
	if rowsAffected == 0 {
		logger.Debug("No sender found to delete", log.String("id", id))
	}

	return nil
}

// executeTransaction is a helper function to handle database transactions.
func executeTransaction(queries []func(tx dbmodel.TxInterface) error) error {
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

	for _, query := range queries {
		if err := query(tx); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				err = errors.Join(err, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error()))
			}
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// buildSenderFromResultRow constructs a MessageNotificationSenderResponse from a database result row.
func (s *MessageNotificationStore) buildSenderFromResultRow(
	row map[string]interface{}) (*model.MessageNotificationSender, error) {
	senderID, ok := row["sender_id"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to parse sender_id as string")
	}

	name, ok := row["name"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to parse name as string")
	}

	description, ok := row["description"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to parse description as string")
	}

	provider, ok := row["provider"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to parse provider as string")
	}

	sender := &model.MessageNotificationSender{
		ID:          senderID,
		Name:        name,
		Description: description,
		Provider:    constants.MessageProviderType(provider),
		Properties:  []model.SenderProperty{},
	}

	return sender, nil
}

// buildSenderPropertiesFromResultSet builds a list of SenderProperty from the result set.
func buildSenderPropertiesFromResultSet(results []map[string]interface{}, id string) ([]model.SenderProperty, error) {
	properties := make([]model.SenderProperty, 0, len(results))

	for _, row := range results {
		propName, ok := row["property_name"].(string)
		if !ok {
			return nil, fmt.Errorf("failed to parse property_name as string for sender ID: %s", id)
		}

		propValue, ok := row["property_value"].(string)
		if !ok {
			return nil, fmt.Errorf("failed to parse property_value as string for sender ID: %s", id)
		}

		isSecretStr, ok := row["is_secret"].(string)
		if !ok {
			return nil, fmt.Errorf("failed to parse is_secret as string for sender ID: %s", id)
		}
		isSecret := sysutils.NumStringToBool(isSecretStr)

		properties = append(properties, model.SenderProperty{
			Name:     propName,
			Value:    propValue,
			IsSecret: isSecret,
		})
	}

	return properties, nil
}
