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

package authz

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/asgardeo/thunder/internal/oauth/oauth2/authz/constants"
	"github.com/asgardeo/thunder/internal/oauth/oauth2/authz/model"
	"github.com/asgardeo/thunder/internal/system/database/provider"
	"github.com/asgardeo/thunder/internal/system/log"
)

// InsertAuthorizationCode inserts a new authorization code into the database.
func InsertAuthorizationCode(authzCode model.AuthorizationCode) error {
	logger := log.GetLogger()

	dbClient, err := provider.NewDBProvider().GetDBClient("runtime")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return err
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	tx, err := dbClient.BeginTx()
	if err != nil {
		logger.Error("Failed to begin transaction", log.Error(err))
		return errors.New("failed to begin transaction: " + err.Error())
	}

	// Insert authorization code.
	_, err = tx.Exec(constants.QueryInsertAuthorizationCode.Query, authzCode.CodeID, authzCode.Code,
		authzCode.ClientID, authzCode.RedirectURI, authzCode.AuthorizedUserID, authzCode.TimeCreated,
		authzCode.ExpiryTime, authzCode.State)
	if err != nil {
		logger.Error("Failed to insert authorization code", log.Error(err))
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Error("Failed to rollback transaction", log.Error(rollbackErr))
			err = errors.Join(err, errors.New("failed to rollback transaction: "+rollbackErr.Error()))
		}
		return errors.New("failed to insert authorization code: " + err.Error())
	}

	// Insert auth code scopes.
	_, err = tx.Exec(constants.QueryInsertAuthorizationCodeScopes.Query, authzCode.CodeID,
		authzCode.Scopes)
	if err != nil {
		logger.Error("Failed to insert authorization code scopes", log.Error(err))
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Error("Failed to rollback transaction", log.Error(rollbackErr))
			err = errors.Join(err, errors.New("failed to rollback transaction: "+rollbackErr.Error()))
		}
		return errors.New("failed to insert authorization code scopes: " + err.Error())
	}

	// Commit the transaction.
	if err = tx.Commit(); err != nil {
		logger.Error("Failed to commit transaction", log.Error(err))
		return errors.New("failed to commit transaction: " + err.Error())
	}

	return nil
}

// GetAuthorizationCode retrieves an authorization code by client Id and authorization code.
func GetAuthorizationCode(clientID, authCode string) (model.AuthorizationCode, error) {
	logger := log.GetLogger()

	dbClient, err := provider.NewDBProvider().GetDBClient("runtime")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return model.AuthorizationCode{}, err
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	results, err := dbClient.ExecuteQuery(constants.QueryGetAuthorizationCode, clientID, authCode)
	if err != nil {
		return model.AuthorizationCode{}, errors.New("error while retrieving authorization code: " + err.Error())
	}
	row := results[0]

	// Handle time_created field.
	timeCreated, err := parseTimeField(row["time_created"], "time_created")
	if err != nil {
		return model.AuthorizationCode{}, err
	}

	// Handle expiry_time field.
	expiryTime, err := parseTimeField(row["expiry_time"], "expiry_time")
	if err != nil {
		return model.AuthorizationCode{}, err
	}

	return model.AuthorizationCode{
		CodeID:           row["code_id"].(string),
		Code:             row["authorization_code"].(string),
		ClientID:         clientID,
		RedirectURI:      row["callback_url"].(string),
		AuthorizedUserID: row["authz_user"].(string),
		TimeCreated:      timeCreated,
		ExpiryTime:       expiryTime,
		State:            row["state"].(string),
	}, nil
}

// updateAuthorizationCodeState updates the state of an authorization code.
func updateAuthorizationCodeState(authzCode model.AuthorizationCode, newState string) error {
	logger := log.GetLogger()

	dbClient, err := provider.NewDBProvider().GetDBClient("runtime")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return err
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	_, err = dbClient.ExecuteQuery(constants.QueryUpdateAuthorizationCodeState, newState, authzCode.CodeID)
	return err
}

// DeactivateAuthorizationCode deactivates an authorization code.
func DeactivateAuthorizationCode(authzCode model.AuthorizationCode) error {
	return updateAuthorizationCodeState(authzCode, constants.AuthCodeStateInactive)
}

// RevokeAuthorizationCode revokes an authorization code.
func RevokeAuthorizationCode(authzCode model.AuthorizationCode) error {
	return updateAuthorizationCodeState(authzCode, constants.AuthCodeStateRevoked)
}

// ExpireAuthorizationCode expires an authorization code.
func ExpireAuthorizationCode(authzCode model.AuthorizationCode) error {
	return updateAuthorizationCodeState(authzCode, constants.AuthCodeStateExpired)
}

// Helper function to parse a time field from the database.
func parseTimeField(field interface{}, fieldName string) (time.Time, error) {
	const customTimeFormat = "2006-01-02 15:04:05.999999999"

	switch v := field.(type) {
	case string:
		trimmedTime := trimTimeString(v)
		parsedTime, err := time.Parse(customTimeFormat, trimmedTime)
		if err != nil {
			log.GetLogger().Error(fmt.Sprintf("Error parsing %s", fieldName), log.Error(err))
			return time.Time{}, fmt.Errorf("error parsing %s: %w", fieldName, err)
		}
		return parsedTime, nil
	case time.Time:
		return v, nil
	default:
		log.GetLogger().Error(fmt.Sprintf("Unexpected type for %s", fieldName), log.String("type", fmt.Sprintf("%T", v)))
		return time.Time{}, fmt.Errorf("unexpected type for %s", fieldName)
	}
}

// Helper function to trim a time string.
func trimTimeString(timeStr string) string {
	// Split the string into parts by spaces and retain only the first two parts.
	parts := strings.SplitN(timeStr, " ", 3)
	if len(parts) >= 2 {
		return parts[0] + " " + parts[1]
	}
	return timeStr
}
