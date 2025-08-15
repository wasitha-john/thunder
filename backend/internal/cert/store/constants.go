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

package store

import dbmodel "github.com/asgardeo/thunder/internal/system/database/model"

var (
	// QueryGetCertificateByID retrieves a certificate by its ID.
	QueryGetCertificateByID = dbmodel.DBQuery{
		ID:    "CER_MGT-01",
		Query: "SELECT CERT_ID, REF_TYPE, REF_ID, TYPE, VALUE FROM CERTIFICATE WHERE CERT_ID = $1",
	}
	// QueryGetCertificateByReference retrieves a certificate based on its reference type and ID.
	QueryGetCertificateByReference = dbmodel.DBQuery{
		ID:    "CER_MGT-02",
		Query: "SELECT CERT_ID, REF_TYPE, REF_ID, TYPE, VALUE FROM CERTIFICATE WHERE REF_TYPE = $1 AND REF_ID = $2",
	}
	// QueryInsertCertificate is the query to insert a certificate into the database.
	QueryInsertCertificate = dbmodel.DBQuery{
		ID:    "CER_MGT-03",
		Query: "INSERT INTO CERTIFICATE (CERT_ID, REF_TYPE, REF_ID, TYPE, VALUE) VALUES ($1, $2, $3, $4, $5)",
	}
	// QueryUpdateCertificateByID updates a certificate based on its ID.
	QueryUpdateCertificateByID = dbmodel.DBQuery{
		ID:    "CER_MGT-04",
		Query: "UPDATE CERTIFICATE SET TYPE = $2, VALUE = $3 WHERE CERT_ID = $1",
	}
	// QueryUpdateCertificateByReference updates a certificate based on its reference type and ID.
	QueryUpdateCertificateByReference = dbmodel.DBQuery{
		ID:    "CER_MGT-05",
		Query: "UPDATE CERTIFICATE SET TYPE = $3, VALUE = $4 WHERE REF_TYPE = $1 AND REF_ID = $2",
	}
	// QueryDeleteCertificateByID deletes a certificate by its ID.
	QueryDeleteCertificateByID = dbmodel.DBQuery{
		ID:    "CER_MGT-06",
		Query: "DELETE FROM CERTIFICATE WHERE CERT_ID = $1",
	}
	// QueryDeleteCertificateByReference deletes a certificate by its reference type and ID.
	QueryDeleteCertificateByReference = dbmodel.DBQuery{
		ID:    "CER_MGT-07",
		Query: "DELETE FROM CERTIFICATE WHERE REF_TYPE = $1 AND REF_ID = $2",
	}
)
