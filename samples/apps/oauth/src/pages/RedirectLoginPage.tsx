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

import { useEffect, useState, useMemo, useRef } from 'react';
import { exchangeCodeForToken } from '../services/authService';
import useAuth from '../hooks/useAuth';
import ErrorPage from './ErrorPage';
import config from '../config';

interface TokenErrorInterface {
    error: string;
    error_description: string;
}

const RedirectLoginPage = () => {

    const { token, setToken } = useAuth();
    const [ error, setError ] = useState<TokenErrorInterface | null>(null); // State to store token error

    const hasFetched = useRef(false);

    const urlParams = useMemo(() => new URLSearchParams(window.location.search), []);

    const handleLogin = () => {
        const { clientId, redirectUri, authorizationEndpoint, scope } = config;
        const state = Math.random().toString(36).substring(2, 15); // Generate a random state.
        const loginUrl = `${authorizationEndpoint}?response_type=code&client_id=${clientId}&redirect_uri=${redirectUri}&scope=${scope}&state=${state}`;

        window.location.href = loginUrl;
    };

    useEffect(() => {
        const error = urlParams.get('error');
        const errorDescription = urlParams.get('error_description');

        if (error) {
        setError({
            error: error,
            error_description: errorDescription || 'No description available',
        });

        return;
        }
    }, [urlParams]);

    useEffect(() => {
        // Prevent double fetch calls
        if (hasFetched.current) return;
        hasFetched.current = true;

        const code = urlParams.get('code');
        
        if (code && !token) {
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
    }, [token, urlParams, setToken]);

    const Content = () => {
        if (error) {
            return (
                <ErrorPage
                    errorCode={error.error || 'Unknown Error'}
                    errorMessage={error.error_description || 'No description available'}
                />
            );
        } else {
            return (
                <div className="login-page">
                    <div className="login-container">
                        <h2>Oauth sample App</h2>
                        <button onClick={handleLogin} className="login-button">Login</button>
                    </div>
                </div>
            );
        }
    }

    return (<Content />);
};

export default RedirectLoginPage;
