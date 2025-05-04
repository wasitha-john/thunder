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

package service

import (
	"errors"

	"github.com/asgardeo/thunder/internal/application/constants"
	"github.com/asgardeo/thunder/internal/application/model"
	dbprovider "github.com/asgardeo/thunder/internal/system/database/provider"
	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/utils"
)

// ApplicationServiceInterface defines the interface for the application service.
type ApplicationServiceInterface interface {
	GetOAuthApplication(clientId string) (*model.OAuthApplication, error)
}

// ApplicationService is the default implementation of the ApplicationServiceInterface.
type ApplicationService struct{}

// GetApplicationService creates a new instance of ApplicationService.
func GetApplicationService() ApplicationServiceInterface {

	return &ApplicationService{}
}

// GetOAuthApplication retrieves the OAuth application based on the client Id.
func (as *ApplicationService) GetOAuthApplication(clientId string) (*model.OAuthApplication, error) {

	logger := log.GetLogger().With(log.String(log.LOGGER_KEY_COMPONENT_NAME, "ApplicationService"))
	logger.Info("Retrieving OAuth application", log.String("clientId", clientId))

	if clientId == "" {
		return nil, errors.New("client ID cannot be empty")
	}

	dbClient, err := dbprovider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return nil, err
	}
	defer dbClient.Close()

	results, err := dbClient.ExecuteQuery(constants.QueryGetApplicationByClientId, clientId)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, errors.New("OAuth application not found")
	}

	row := results[0]

	clientId, ok := row["consumer_key"].(string)
	if !ok {
		return nil, errors.New("failed to parse consumer_key as string")
	}

	clientSecret, ok := row["consumer_secret"].(string)
	if !ok {
		return nil, errors.New("failed to parse consumer_secret as string")
	}

	redirectURIs := []string{}
	if row["callback_uris"] != nil {
		if uris, ok := row["callback_uris"].(string); ok {
			redirectURIs = utils.ParseStringArray(uris)
		} else {
			return nil, errors.New("failed to parse callback_uris as string")
		}
	}

	allowedGrantTypes := []string{}
	if row["grant_types"] != nil {
		if grants, ok := row["grant_types"].(string); ok {
			allowedGrantTypes = utils.ParseStringArray(grants)
		} else {
			return nil, errors.New("failed to parse grant_types as string")
		}
	}

	return &model.OAuthApplication{
		ClientId:          clientId,
		ClientSecret:      clientSecret,
		RedirectURIs:      redirectURIs,
		AllowedGrantTypes: allowedGrantTypes,
	}, nil
}
