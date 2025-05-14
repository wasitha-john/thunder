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

import React, { useEffect, useState } from 'react';
import { Route, BrowserRouter as Router, Switch, useLocation } from 'react-router-dom';
import './App.css';
import ErrorPage from './components/ErrorPage';
import HomePage from './components/HomePage';
import LoginPage from './components/LoginPage';
import { exchangeCodeForToken } from './services/authService';

const App = () => {
  const [token, setToken] = useState(null);
  const [error, setError] = useState(null); // State to store token error

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const error = urlParams.get('error');
    const errorDescription = urlParams.get('error_description');

    if (error) {
      setError({
        error: error,
        error_description: errorDescription || 'No description available',
      });
    } else if (code && !token) {
      exchangeCodeForToken(code)
        .then(response => {
          setToken(response.access_token);
        })
        .catch(error => {
          console.error('Error fetching access token:', error);
          setError(
            error.response && error.response.data
              ? error.response.data
              : { message: 'Unknown error' }
          );
        });
    }
  }, [token]);

  const location = useLocation(); // Get the current location

  return (
    <Switch>
      <Route path="/" exact key={location.key}>
        {error ? (
          <ErrorPage
            errorCode={error.error || 'Unknown Error'}
            errorMessage={error.error_description || 'No description available'}
          />
        ) : token ? (
          <HomePage token={token} />
        ) : (
          <LoginPage />
        )}
      </Route>
    </Switch>
  );
};

const AppWrapper = () => (
  <Router>
    <App />
  </Router>
);

export default AppWrapper;
