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

package hash

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type HashTestSuite struct {
	suite.Suite
}

func TestHashSuite(t *testing.T) {
	suite.Run(t, new(HashTestSuite))
}

func (suite *HashTestSuite) TestHash() {
	testCases := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "EmptyInput",
			input:    []byte(""),
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "NormalInput",
			input:    []byte("hello world"),
			expected: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			hash := Hash(tc.input)
			suite.Equal(tc.expected, hash, "Hash should match expected value")
		})
	}
}

func (suite *HashTestSuite) TestHashString() {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "EmptyString",
			input:    "",
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "NormalString",
			input:    "hello world",
			expected: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			hash := HashString(tc.input)
			suite.Equal(tc.expected, hash, "Hash should match expected value")
		})
	}
}

func (suite *HashTestSuite) TestHashStringWithSalt() {
	testCases := []struct {
		name     string
		input    string
		salt     string
		expected string
	}{
		{
			name:     "EmptyStringAndSalt",
			input:    "",
			salt:     "",
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "NormalStringWithSalt",
			input:    "password",
			salt:     "somesalt",
			expected: "6bceb6d53d51a11c3bde77e8cafe1f152782c5e52a13e514da12a9e35b0c2bcb",
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			hash, err := HashStringWithSalt(tc.input, tc.salt)

			assert.NoError(t, err)
			assert.Equal(t, tc.expected, hash)
		})
	}
}

func (suite *HashTestSuite) TestHashStringWithSaltDeterministic() {
	input := "test-input"
	salt := "test-salt"

	hash1, err1 := HashStringWithSalt(input, salt)
	hash2, err2 := HashStringWithSalt(input, salt)

	assert.NoError(suite.T(), err1)
	assert.NoError(suite.T(), err2)
	assert.Equal(suite.T(), hash1, hash2, "Hash should be deterministic for the same input and salt")
}

func (suite *HashTestSuite) TestHashStringWithDifferentInputs() {
	salt := "common-salt"
	input1 := "input-one"
	input2 := "input-two"

	hash1, err1 := HashStringWithSalt(input1, salt)
	hash2, err2 := HashStringWithSalt(input2, salt)

	assert.NoError(suite.T(), err1)
	assert.NoError(suite.T(), err2)
	assert.NotEqual(suite.T(), hash1, hash2, "Different inputs should produce different hashes")
}

func (suite *HashTestSuite) TestHashStringWithDifferentSalts() {
	input := "common-input"
	salt1 := "salt-one"
	salt2 := "salt-two"

	hash1, err1 := HashStringWithSalt(input, salt1)
	hash2, err2 := HashStringWithSalt(input, salt2)

	assert.NoError(suite.T(), err1)
	assert.NoError(suite.T(), err2)
	assert.NotEqual(suite.T(), hash1, hash2, "Different salts should produce different hashes")
}

func (suite *HashTestSuite) TestGenerateSalt() {
	salt, err := GenerateSalt()
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), salt)
}

func (suite *HashTestSuite) TestGenerateSaltUniqueness() {
	salt1, err1 := GenerateSalt()
	salt2, err2 := GenerateSalt()

	assert.NoError(suite.T(), err1)
	assert.NoError(suite.T(), err2)
	assert.NotEqual(suite.T(), salt1, salt2, "Generated salts should be different")
}

func (suite *HashTestSuite) TestGenerateSaltIsValidBase64() {
	salt, err := GenerateSalt()

	assert.NoError(suite.T(), err)
	_, err = base64.StdEncoding.DecodeString(salt)
	assert.NoError(suite.T(), err, "Salt should be valid base64")
}

func (suite *HashTestSuite) TestGenerateSaltLength() {
	salt, err := GenerateSalt()

	assert.NoError(suite.T(), err)
	decoded, err := base64.StdEncoding.DecodeString(salt)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), 16, len(decoded), "Decoded salt should be 16 bytes")
}
