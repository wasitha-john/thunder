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

// Package http provides a centralized HTTP client service for making outbound HTTP requests.
package http

import (
	"net/http"
	"sync"
	"time"
)

var (
	defaultClient HTTPClientInterface
	once          sync.Once
)

// HTTPClientInterface defines the interface for HTTP client operations.
type HTTPClientInterface interface {
	// Do executes an HTTP request and returns an HTTP response.
	Do(req *http.Request) (*http.Response, error)
	// Get issues a GET to the specified URL.
	Get(url string) (*http.Response, error)
}

// HTTPClient implements HTTPClientInterface and provides a centralized HTTP client.
type HTTPClient struct {
	client *http.Client
}

// NewHTTPClient creates a new HTTPClient with default settings.
func NewHTTPClient() HTTPClientInterface {
	return &HTTPClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewHTTPClientWithTimeout creates a new HTTPClient with a custom timeout.
func NewHTTPClientWithTimeout(timeout time.Duration) HTTPClientInterface {
	return &HTTPClient{
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// NewHTTPClientWithConfig creates a new HTTPClient with custom configuration.
func NewHTTPClientWithConfig(client *http.Client) HTTPClientInterface {
	return &HTTPClient{
		client: client,
	}
}

// GetHTTPClient returns the default singleton HTTPClient instance.
func GetHTTPClient() HTTPClientInterface {
	once.Do(func() {
		defaultClient = NewHTTPClient()
	})
	return defaultClient
}

// Do executes an HTTP request and returns an HTTP response.
func (c *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}

// Get issues a GET to the specified URL.
func (c *HTTPClient) Get(url string) (*http.Response, error) {
	return c.client.Get(url)
}