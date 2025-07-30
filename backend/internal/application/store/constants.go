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

package store

import dbmodel "github.com/asgardeo/thunder/internal/system/database/model"

var (
	// QueryCreateApplication is the query to create a new application with basic details.
	QueryCreateApplication = dbmodel.DBQuery{
		ID: "ASQ-APP_MGT-01",
		Query: "INSERT INTO SP_APP (APP_ID, APP_NAME, DESCRIPTION, AUTH_FLOW_GRAPH_ID, REGISTRATION_FLOW_GRAPH_ID, " +
			"IS_REGISTRATION_FLOW_ENABLED, URL, LOGO_URL) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
	}
	// QueryCreateOAuthApplication is the query to create a new OAuth application.
	QueryCreateOAuthApplication = dbmodel.DBQuery{
		ID: "ASQ-APP_MGT-02",
		Query: "INSERT INTO IDN_OAUTH_CONSUMER_APPS (APP_ID, CONSUMER_KEY, CONSUMER_SECRET, CALLBACK_URIS, " +
			"GRANT_TYPES) VALUES ($1, $2, $3, $4, $5)",
	}
	// QueryInsertApplicationProperties is the query to insert properties for a specific application.
	QueryInsertApplicationProperties = dbmodel.DBQuery{
		ID:    "ASQ-APP_MGT-03",
		Query: "INSERT INTO SP_APP_PROPERTY (APP_ID, PROPERTY_NAME, PROPERTY_VALUE, IS_SECRET) VALUES %s",
	}
	// QueryInsertApplicationCertificate is the query to insert a certificate for a specific application.
	QueryInsertApplicationCertificate = dbmodel.DBQuery{
		ID:    "ASQ-APP_MGT-04",
		Query: "INSERT INTO SP_APP_CERTIFICATE (APP_ID, TYPE, VALUE) VALUES ($1, $2, $3)",
	}
	// QueryGetApplicationByAppID is the query to retrieve application details by app ID.
	QueryGetApplicationByAppID = dbmodel.DBQuery{
		ID: "ASQ-APP_MGT-05",
		Query: "SELECT sp.APP_ID, sp.APP_NAME, sp.DESCRIPTION, sp.AUTH_FLOW_GRAPH_ID, " +
			"sp.REGISTRATION_FLOW_GRAPH_ID, sp.IS_REGISTRATION_FLOW_ENABLED, sp.URL, sp.LOGO_URL, " +
			"oauth.CONSUMER_KEY, oauth.CONSUMER_SECRET, oauth.CALLBACK_URIS, oauth.GRANT_TYPES " +
			"FROM SP_APP sp JOIN IDN_OAUTH_CONSUMER_APPS oauth ON sp.APP_ID = oauth.APP_ID WHERE sp.APP_ID = $1",
	}
	// QueryGetApplicationProperties is the query to retrieve properties for a specific application.
	QueryGetApplicationProperties = dbmodel.DBQuery{
		ID:    "ASQ-APP_MGT-06",
		Query: "SELECT PROPERTY_NAME, PROPERTY_VALUE, IS_SECRET FROM SP_APP_PROPERTY WHERE APP_ID = $1",
	}
	// QueryGetApplicationCertificate is the query to retrieve a certificate for a specific application.
	QueryGetApplicationCertificate = dbmodel.DBQuery{
		ID:    "ASQ-APP_MGT-07",
		Query: "SELECT TYPE, VALUE FROM SP_APP_CERTIFICATE WHERE APP_ID = $1",
	}
	// QueryGetOAuthApplicationByClientID is the query to retrieve oauth application details by client ID.
	QueryGetOAuthApplicationByClientID = dbmodel.DBQuery{
		ID: "ASQ-APP_MGT-08",
		Query: "SELECT APP_ID, CONSUMER_KEY, CONSUMER_SECRET, CALLBACK_URIS, GRANT_TYPES " +
			"FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY = $1",
	}
	// QueryGetApplicationList is the query to list all the applications.
	QueryGetApplicationList = dbmodel.DBQuery{
		ID: "ASQ-APP_MGT-09",
		Query: "SELECT sp.APP_ID, sp.APP_NAME, sp.DESCRIPTION, sp.AUTH_FLOW_GRAPH_ID, " +
			"sp.REGISTRATION_FLOW_GRAPH_ID, sp.IS_REGISTRATION_FLOW_ENABLED, sp.URL, sp.LOGO_URL, " +
			"oauth.CONSUMER_KEY, oauth.CONSUMER_SECRET, oauth.CALLBACK_URIS, " +
			"oauth.GRANT_TYPES FROM SP_APP sp JOIN IDN_OAUTH_CONSUMER_APPS oauth ON sp.APP_ID = oauth.APP_ID",
	}
	// QueryUpdateApplicationByAppID is the query to update application details by app ID.
	QueryUpdateApplicationByAppID = dbmodel.DBQuery{
		ID: "ASQ-APP_MGT-10",
		Query: "UPDATE SP_APP SET APP_NAME=$2, DESCRIPTION=$3, AUTH_FLOW_GRAPH_ID=$4, " +
			"REGISTRATION_FLOW_GRAPH_ID=$5, IS_REGISTRATION_FLOW_ENABLED=$6, URL=$7, LOGO_URL=$8 " +
			"WHERE APP_ID = $1",
	}
	// QueryUpdateOAuthApplicationByAppID is the query to update OAuth application details by app ID.
	QueryUpdateOAuthApplicationByAppID = dbmodel.DBQuery{
		ID: "ASQ-APP_MGT-11",
		Query: "UPDATE IDN_OAUTH_CONSUMER_APPS " +
			"SET CONSUMER_KEY=$2, CONSUMER_SECRET=$3, CALLBACK_URIS=$4, GRANT_TYPES=$5 WHERE APP_ID=$1",
	}
	// QueryUpdateApplicationCertificate is the query to update a certificate for a specific application.
	QueryUpdateApplicationCertificate = dbmodel.DBQuery{
		ID:    "ASQ-APP_MGT-12",
		Query: "UPDATE SP_APP_CERTIFICATE SET TYPE=$2, VALUE=$3 WHERE APP_ID=$1",
	}
	// QueryDeleteApplicationByAppID is the query to delete an application by app ID.
	QueryDeleteApplicationByAppID = dbmodel.DBQuery{
		ID:    "ASQ-APP_MGT-13",
		Query: "DELETE FROM SP_APP WHERE APP_ID = $1",
	}
	// QueryDeleteApplicationProperties is the query to delete all properties for a specific application.
	QueryDeleteApplicationProperties = dbmodel.DBQuery{
		ID:    "ASQ-APP_MGT-14",
		Query: "DELETE FROM SP_APP_PROPERTY WHERE APP_ID = $1",
	}
	// QueryDeleteApplicationCertificate is the query to delete a certificate for a specific application.
	QueryDeleteApplicationCertificate = dbmodel.DBQuery{
		ID:    "ASQ-APP_MGT-15",
		Query: "DELETE FROM SP_APP_CERTIFICATE WHERE APP_ID = $1",
	}
)
