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
	QueryGetApplicationByClientId = dbmodel.DBQuery{
		Id: "ASQ-APP_MGT-00",
		Query: "SELECT CONSUMER_KEY, CONSUMER_SECRET, CALLBACK_URIS, GRANT_TYPES " +
			"FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY = $1",
	}

	QueryCreateApplication = dbmodel.DBQuery{
		Id:    "ASQ-APP_MGT-01",
		Query: "INSERT INTO SP_APP (APP_ID, APP_NAME, DESCRIPTION) VALUES ($1, $2, $3)",
	}
	QueryCreateOAuthApplication = dbmodel.DBQuery{
		Id: "ASQ-APP_MGT-02",
		Query: "INSERT INTO IDN_OAUTH_CONSUMER_APPS (APP_ID, CONSUMER_KEY, CONSUMER_SECRET, CALLBACK_URIS, GRANT_TYPES) " +
			"VALUES ($1, $2, $3, $4, $5)",
	}
	QueryGetApplicationByAppId = dbmodel.DBQuery{
		Id: "ASQ-APP_MGT-03",
		Query: "SELECT sp.APP_ID, sp.APP_NAME, sp.DESCRIPTION," +
			"oauth.CONSUMER_KEY, oauth.CALLBACK_URIS, oauth.GRANT_TYPES " +
			"FROM SP_APP sp JOIN IDN_OAUTH_CONSUMER_APPS oauth ON sp.APP_ID = oauth.APP_ID " +
			"WHERE sp.APP_ID = $1",
	}
	QueryGetApplicationList = dbmodel.DBQuery{
		Id: "ASQ-APP_MGT-04",
		Query: "SELECT sp.APP_ID, sp.APP_NAME, sp.DESCRIPTION," +
			"oauth.CONSUMER_KEY, oauth.CALLBACK_URIS, oauth.GRANT_TYPES " +
			"FROM SP_APP sp JOIN IDN_OAUTH_CONSUMER_APPS oauth ON sp.APP_ID = oauth.APP_ID",
	}
	QueryUpdateApplicationByAppId = dbmodel.DBQuery{
		Id:    "ASQ-APP_MGT-05",
		Query: "UPDATE SP_APP SET APP_NAME = $2, DESCRIPTION = $3 WHERE APP_ID = $1;",
	}
	QueryUpdateOAuthApplicationByAppId = dbmodel.DBQuery{
		Id: "ASQ-APP_MGT-05",
		Query: "UPDATE IDN_OAUTH_CONSUMER_APPS " +
			"SET CONSUMER_KEY = $2, CONSUMER_SECRET = $3, CALLBACK_URIS = $4, GRANT_TYPES = $5 WHERE APP_ID = $1",
	}
	QueryDeleteApplicationByAppId = dbmodel.DBQuery{
		Id:    "ASQ-APP_MGT-06",
		Query: "DELETE FROM SP_APP WHERE APP_ID = $1",
	}
)
