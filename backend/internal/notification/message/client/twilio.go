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

package client

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/asgardeo/thunder/internal/notification/message/constants"
	"github.com/asgardeo/thunder/internal/notification/message/model"
	"github.com/asgardeo/thunder/internal/system/log"
)

const (
	twilioURL                 = "https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json"
	twilioLoggerComponentName = "TwilioClient"
	sIDRegex                  = `^AC[0-9a-fA-F]{32}$`
)

// TwilioClient implements the MessageClientInterface for sending messages via Twilio API.
type TwilioClient struct {
	name       string
	url        string
	accountSID string
	authToken  string
	senderID   string
}

// NewTwilioClient creates a new instance of TwilioClient.
func NewTwilioClient(senderDTO model.MessageSenderDTO) (MessageClientInterface, error) {
	client := &TwilioClient{}

	err := client.validate(senderDTO)
	if err != nil {
		return nil, fmt.Errorf("failed to validate Twilio client: %w", err)
	}

	client.name = senderDTO.Name
	client.url = fmt.Sprintf(twilioURL, senderDTO.Properties[constants.TwilioPropKeyAccountSID])
	client.accountSID = senderDTO.Properties[constants.TwilioPropKeyAccountSID]
	client.authToken = senderDTO.Properties[constants.TwilioPropKeyAuthToken]
	client.senderID = senderDTO.Properties[constants.TwilioPropKeySenderID]

	return client, nil
}

// GetName returns the name of the Twilio client.
func (c *TwilioClient) GetName() string {
	return c.name
}

// validate checks if the Twilio client is properly configured.
func (c *TwilioClient) validate(senderDTO model.MessageSenderDTO) error {
	if senderDTO.Properties[constants.TwilioPropKeyAccountSID] == "" {
		return errors.New("Twilio account SID is required")
	}
	matched, err := regexp.MatchString(sIDRegex, senderDTO.Properties[constants.TwilioPropKeyAccountSID])
	if err != nil {
		return fmt.Errorf("failed to validate Twilio account SID: %w", err)
	}
	if !matched {
		return errors.New("Invalid Twilio account SID format")
	}

	if senderDTO.Properties[constants.TwilioPropKeyAuthToken] == "" {
		return errors.New("Twilio auth token is required")
	}
	if senderDTO.Properties[constants.TwilioPropKeySenderID] == "" {
		return errors.New("Twilio sender ID is required")
	}

	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, twilioLoggerComponentName))
	logger.Debug("Twilio client properties validated successfully")

	return nil
}

// SendSMS sends an SMS using the Twilio API.
func (c *TwilioClient) SendSMS(sms model.SMSData) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, twilioLoggerComponentName))
	logger.Debug("Sending SMS via Twilio", log.String("to", log.MaskString(sms.To)))

	requestURL := fmt.Sprintf(c.url, c.accountSID)
	formData := url.Values{}
	formData.Set("to", sms.To)
	formData.Set("from", c.senderID)
	formData.Set("body", sms.Body)

	req, err := http.NewRequest(http.MethodPost, requestURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.accountSID, c.authToken)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	logger.Debug("Received response from Twilio", log.Int("statusCode", resp.StatusCode))

	// Check the response status
	// TODO: Validate if this is the expected error assertion as per the twilio API documentation
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		logger.Error("Failed to send SMS", log.Int("statusCode", resp.StatusCode),
			log.String("response", string(bodyBytes)))
		return fmt.Errorf("failed to send SMS, status code: %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}
