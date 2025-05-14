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

const config = {
    authEndpoint: process.env.REACT_APP_SERVER_AUTHENTICATION_ENDPOINT || 'https://localhost:8090/oauth2/authorize',
    tokenEndpoint: process.env.REACT_APP_SERVER_TOKEN_ENDPOINT || 'https://localhost:8090/oauth2/token',
    clientId: process.env.REACT_APP_CLIENT_ID || 'client123',
    clientSecret: process.env.REACT_APP_CLIENT_SECRET || 'secret123',
    redirectUri: process.env.REACT_APP_REDIRECT_URI || 'https://localhost:3000',
    scope: process.env.REACT_APP_SCOPE || 'openid'
};

export default config;
