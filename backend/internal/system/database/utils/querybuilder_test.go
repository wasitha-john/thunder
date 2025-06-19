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

package utils

import (
	"testing"

	"github.com/asgardeo/thunder/internal/system/database/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type QueryBuilderTestSuite struct {
	suite.Suite
}

func TestQueryBuilderSuite(t *testing.T) {
	suite.Run(t, new(QueryBuilderTestSuite))
}

func (suite *QueryBuilderTestSuite) TestBuildFilterQuery() {
	queryID := "test_query"
	baseQuery := "SELECT * FROM users"
	columnName := "attributes"
	filters := map[string]interface{}{
		"role": "admin",
		"age":  30,
	}

	query, args, err := BuildFilterQuery(queryID, baseQuery, columnName, filters)

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), queryID, query.ID)
	assert.Contains(suite.T(), query.Query, baseQuery)
	assert.Contains(suite.T(), query.Query, "json_extract(attributes, '$.age') = ?")
	assert.Contains(suite.T(), query.Query, "json_extract(attributes, '$.role') = ?")
	assert.Len(suite.T(), args, 2)

	// Verify args order due to sorting of keys
	assert.Equal(suite.T(), int(30), args[0])
	assert.Equal(suite.T(), "admin", args[1])
}

func (suite *QueryBuilderTestSuite) TestBuildFilterQueryWithEmptyFilters() {
	queryID := "empty_filters"
	baseQuery := "SELECT * FROM users"
	columnName := "attributes"
	filters := map[string]interface{}{}

	query, args, err := BuildFilterQuery(queryID, baseQuery, columnName, filters)

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), queryID, query.ID)
	assert.Equal(suite.T(), baseQuery, query.Query)
	assert.Empty(suite.T(), args)
}

func (suite *QueryBuilderTestSuite) TestBuildFilterQueryWithInvalidColumnName() {
	queryID := "invalid_column"
	baseQuery := "SELECT * FROM users"
	columnName := "attributes;DROP TABLE users"
	filters := map[string]interface{}{
		"role": "admin",
	}

	query, args, err := BuildFilterQuery(queryID, baseQuery, columnName, filters)

	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "invalid column name")
	assert.Equal(suite.T(), model.DBQuery{}, query)
	assert.Nil(suite.T(), args)
}

func (suite *QueryBuilderTestSuite) TestBuildFilterQueryWithInvalidFilterKey() {
	queryID := "invalid_filter_key"
	baseQuery := "SELECT * FROM users"
	columnName := "attributes"
	filters := map[string]interface{}{
		"valid":              "value",
		"invalid-filter-key": "value", // Contains invalid character '-'
	}

	query, args, err := BuildFilterQuery(queryID, baseQuery, columnName, filters)

	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "invalid filter key")
	assert.Equal(suite.T(), model.DBQuery{}, query)
	assert.Nil(suite.T(), args)
}

func (suite *QueryBuilderTestSuite) TestValidateKey() {
	validKeys := []string{
		"name",
		"user_id",
		"role123",
		"UPPERCASE",
		"mixedCASE",
		"with_underscore",
		"_leading_underscore",
		"trailing_underscore_",
	}

	for _, key := range validKeys {
		err := validateKey(key)
		assert.NoError(suite.T(), err, "Key should be valid: %s", key)
	}
}

func (suite *QueryBuilderTestSuite) TestValidateKeyInvalid() {
	invalidKeys := []string{
		"space key",
		"hyphen-key",
		"special!char",
		"sql;injection",
		"quote'test",
		"double\"quote",
	}

	for _, key := range invalidKeys {
		err := validateKey(key)
		assert.Error(suite.T(), err, "Key should be invalid: %s", key)
		assert.Contains(suite.T(), err.Error(), "invalid characters")
	}
}
