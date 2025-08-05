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

package seeder

import (
	"github.com/asgardeo/thunder/internal/system/database/client"
	"github.com/asgardeo/thunder/internal/system/database/model"
	"github.com/asgardeo/thunder/internal/system/log"
)

// DBSeeder implements SeederInterface for database data seeding.
type DBSeeder struct {
	dbClient client.DBClientInterface
}

// NewDBSeeder creates a new instance of DBSeeder.
func NewDBSeeder(dbClient client.DBClientInterface) SeederInterface {
	return &DBSeeder{
		dbClient: dbClient,
	}
}

// SeedInitialData seeds the initial data into the database.
func (s *DBSeeder) SeedInitialData() error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "DBSeeder"))
	logger.Info("Starting database seeding process")

	data := getSeedData()

	// Seed Organization Units first (as they are referenced by other tables)
	if err := s.seedOrganizationUnits(data.OrganizationUnits); err != nil {
		logger.Error("Failed to seed organization units", log.Error(err))
		return err
	}

	// Seed Applications
	if err := s.seedApps(data.Apps); err != nil {
		logger.Error("Failed to seed applications", log.Error(err))
		return err
	}

	// Seed OAuth Consumer Apps
	if err := s.seedOAuthConsumerApps(data.OAuthConsumerApps); err != nil {
		logger.Error("Failed to seed OAuth consumer apps", log.Error(err))
		return err
	}

	// Seed Inbound Auth
	if err := s.seedInboundAuth(data.InboundAuth); err != nil {
		logger.Error("Failed to seed inbound auth", log.Error(err))
		return err
	}

	// Seed Allowed Origins
	if err := s.seedAllowedOrigins(data.AllowedOrigins); err != nil {
		logger.Error("Failed to seed allowed origins", log.Error(err))
		return err
	}

	// Seed Users
	if err := s.seedUsers(data.Users); err != nil {
		logger.Error("Failed to seed users", log.Error(err))
		return err
	}

	// Seed IDPs
	if err := s.seedIDPs(data.IDPs); err != nil {
		logger.Error("Failed to seed IDPs", log.Error(err))
		return err
	}

	// Seed IDP Properties
	if err := s.seedIDPProperties(data.IDPProperties); err != nil {
		logger.Error("Failed to seed IDP properties", log.Error(err))
		return err
	}

	logger.Info("Database seeding process completed successfully")
	return nil
}

// seedOrganizationUnits seeds organization unit data.
func (s *DBSeeder) seedOrganizationUnits(orgUnits []OrganizationUnitData) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "DBSeeder"))
	
	for _, ou := range orgUnits {
		query := model.DBQuery{
			ID:            "SEED_INSERT_ORGANIZATION_UNIT",
			SQLiteQuery:   "INSERT OR IGNORE INTO ORGANIZATION_UNIT (OU_ID, PARENT_ID, HANDLE, NAME, DESCRIPTION, CREATED_AT, UPDATED_AT) VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))",
			PostgresQuery: "INSERT INTO ORGANIZATION_UNIT (OU_ID, PARENT_ID, HANDLE, NAME, DESCRIPTION) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (OU_ID) DO NOTHING",
		}

		_, err := s.dbClient.Execute(query, ou.OUID, ou.ParentID, ou.Handle, ou.Name, ou.Description)
		if err != nil {
			logger.Error("Failed to insert organization unit", log.String("ou_id", ou.OUID), log.Error(err))
			return err
		}
		logger.Debug("Seeded organization unit", log.String("ou_id", ou.OUID), log.String("name", ou.Name))
	}
	
	return nil
}

// seedApps seeds application data.
func (s *DBSeeder) seedApps(apps []AppData) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "DBSeeder"))
	
	for _, app := range apps {
		query := model.DBQuery{
			ID:            "SEED_INSERT_SP_APP",
			SQLiteQuery:   "INSERT OR IGNORE INTO SP_APP (APP_NAME, APP_ID, DESCRIPTION, AUTH_FLOW_GRAPH_ID, REGISTRATION_FLOW_GRAPH_ID) VALUES (?, ?, ?, ?, ?)",
			PostgresQuery: "INSERT INTO SP_APP (APP_NAME, APP_ID, DESCRIPTION, AUTH_FLOW_GRAPH_ID, REGISTRATION_FLOW_GRAPH_ID) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (APP_ID) DO NOTHING",
		}

		_, err := s.dbClient.Execute(query, app.AppName, app.AppID, app.Description, app.AuthFlowGraphID, app.RegistrationFlowGraphID)
		if err != nil {
			logger.Error("Failed to insert application", log.String("app_id", app.AppID), log.Error(err))
			return err
		}
		logger.Debug("Seeded application", log.String("app_id", app.AppID), log.String("name", app.AppName))
	}
	
	return nil
}

// seedOAuthConsumerApps seeds OAuth consumer application data.
func (s *DBSeeder) seedOAuthConsumerApps(oauthApps []OAuthConsumerAppData) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "DBSeeder"))
	
	for _, app := range oauthApps {
		query := model.DBQuery{
			ID:            "SEED_INSERT_OAUTH_CONSUMER_APP",
			SQLiteQuery:   "INSERT OR IGNORE INTO IDN_OAUTH_CONSUMER_APPS (CONSUMER_KEY, CONSUMER_SECRET, APP_ID, CALLBACK_URIS, GRANT_TYPES, RESPONSE_TYPES, TOKEN_ENDPOINT_AUTH_METHODS) VALUES (?, ?, ?, ?, ?, ?, ?)",
			PostgresQuery: "INSERT INTO IDN_OAUTH_CONSUMER_APPS (CONSUMER_KEY, CONSUMER_SECRET, APP_ID, CALLBACK_URIS, GRANT_TYPES, RESPONSE_TYPES, TOKEN_ENDPOINT_AUTH_METHODS) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (CONSUMER_KEY) DO NOTHING",
		}

		_, err := s.dbClient.Execute(query, app.ConsumerKey, app.ConsumerSecret, app.AppID, app.CallbackURIs, app.GrantTypes, app.ResponseTypes, app.TokenEndpointAuthMethods)
		if err != nil {
			logger.Error("Failed to insert OAuth consumer app", log.String("consumer_key", app.ConsumerKey), log.Error(err))
			return err
		}
		logger.Debug("Seeded OAuth consumer app", log.String("consumer_key", app.ConsumerKey))
	}
	
	return nil
}

// seedInboundAuth seeds inbound authentication data.
func (s *DBSeeder) seedInboundAuth(inboundAuths []InboundAuthData) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "DBSeeder"))
	
	for _, auth := range inboundAuths {
		query := model.DBQuery{
			ID:            "SEED_INSERT_INBOUND_AUTH",
			SQLiteQuery:   "INSERT OR IGNORE INTO SP_INBOUND_AUTH (INBOUND_AUTH_KEY, INBOUND_AUTH_TYPE, APP_ID) VALUES (?, ?, ?)",
			PostgresQuery: "INSERT INTO SP_INBOUND_AUTH (INBOUND_AUTH_KEY, INBOUND_AUTH_TYPE, APP_ID) VALUES ($1, $2, $3) ON CONFLICT (INBOUND_AUTH_KEY, INBOUND_AUTH_TYPE) DO NOTHING",
		}

		_, err := s.dbClient.Execute(query, auth.InboundAuthKey, auth.InboundAuthType, auth.AppID)
		if err != nil {
			logger.Error("Failed to insert inbound auth", log.String("auth_key", auth.InboundAuthKey), log.Error(err))
			return err
		}
		logger.Debug("Seeded inbound auth", log.String("auth_key", auth.InboundAuthKey), log.String("auth_type", auth.InboundAuthType))
	}
	
	return nil
}

// seedAllowedOrigins seeds allowed origins data.
func (s *DBSeeder) seedAllowedOrigins(origins []AllowedOriginsData) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "DBSeeder"))
	
	for _, origin := range origins {
		query := model.DBQuery{
			ID:            "SEED_INSERT_ALLOWED_ORIGINS",
			SQLiteQuery:   "INSERT OR IGNORE INTO IDN_OAUTH_ALLOWED_ORIGINS (ALLOWED_ORIGINS) VALUES (?)",
			PostgresQuery: "INSERT INTO IDN_OAUTH_ALLOWED_ORIGINS (ALLOWED_ORIGINS) VALUES ($1) ON CONFLICT (ALLOWED_ORIGINS) DO NOTHING",
		}

		_, err := s.dbClient.Execute(query, origin.AllowedOrigins)
		if err != nil {
			logger.Error("Failed to insert allowed origins", log.String("origins", origin.AllowedOrigins), log.Error(err))
			return err
		}
		logger.Debug("Seeded allowed origins", log.String("origins", origin.AllowedOrigins))
	}
	
	return nil
}

// seedUsers seeds user data.
func (s *DBSeeder) seedUsers(users []UserData) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "DBSeeder"))
	
	for _, user := range users {
		query := model.DBQuery{
			ID:            "SEED_INSERT_USER",
			SQLiteQuery:   "INSERT OR IGNORE INTO USER (USER_ID, OU_ID, TYPE, ATTRIBUTES, CREATED_AT, UPDATED_AT) VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))",
			PostgresQuery: "INSERT INTO \"USER\" (USER_ID, OU_ID, TYPE, ATTRIBUTES) VALUES ($1, $2, $3, $4) ON CONFLICT (USER_ID) DO NOTHING",
		}

		_, err := s.dbClient.Execute(query, user.UserID, user.OUID, user.Type, user.Attributes)
		if err != nil {
			logger.Error("Failed to insert user", log.String("user_id", user.UserID), log.Error(err))
			return err
		}
		logger.Debug("Seeded user", log.String("user_id", user.UserID), log.String("type", user.Type))
	}
	
	return nil
}

// seedIDPs seeds identity provider data.
func (s *DBSeeder) seedIDPs(idps []IDPData) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "DBSeeder"))
	
	for _, idp := range idps {
		query := model.DBQuery{
			ID:            "SEED_INSERT_IDP",
			SQLiteQuery:   "INSERT OR IGNORE INTO IDP (IDP_ID, NAME, DESCRIPTION, CREATED_AT, UPDATED_AT) VALUES (?, ?, ?, datetime('now'), datetime('now'))",
			PostgresQuery: "INSERT INTO IDP (IDP_ID, NAME, DESCRIPTION) VALUES ($1, $2, $3) ON CONFLICT (IDP_ID) DO NOTHING",
		}

		_, err := s.dbClient.Execute(query, idp.IDPID, idp.Name, idp.Description)
		if err != nil {
			logger.Error("Failed to insert IDP", log.String("idp_id", idp.IDPID), log.Error(err))
			return err
		}
		logger.Debug("Seeded IDP", log.String("idp_id", idp.IDPID), log.String("name", idp.Name))
	}
	
	return nil
}

// seedIDPProperties seeds identity provider property data.
func (s *DBSeeder) seedIDPProperties(properties []IDPPropertyData) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "DBSeeder"))
	
	for _, prop := range properties {
		query := model.DBQuery{
			ID:            "SEED_INSERT_IDP_PROPERTY",
			SQLiteQuery:   "INSERT OR IGNORE INTO IDP_PROPERTY (IDP_ID, PROPERTY_NAME, PROPERTY_VALUE, IS_SECRET) VALUES (?, ?, ?, ?)",
			PostgresQuery: "INSERT INTO IDP_PROPERTY (IDP_ID, PROPERTY_NAME, PROPERTY_VALUE, IS_SECRET) VALUES ($1, $2, $3, $4) ON CONFLICT (IDP_ID, PROPERTY_NAME) DO NOTHING",
		}

		_, err := s.dbClient.Execute(query, prop.IDPID, prop.PropertyName, prop.PropertyValue, prop.IsSecret)
		if err != nil {
			logger.Error("Failed to insert IDP property", log.String("idp_id", prop.IDPID), log.String("property", prop.PropertyName), log.Error(err))
			return err
		}
		logger.Debug("Seeded IDP property", log.String("idp_id", prop.IDPID), log.String("property", prop.PropertyName))
	}
	
	return nil
}