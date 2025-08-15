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

import axios from 'axios';
import config from '../config';

export const NativeAuthSubmitType = {
    INPUT: 'INPUT',
    SOCIAL: 'SOCIAL',
    OTP: 'OTP',
} as const;

export type NativeAuthSubmitType = (typeof NativeAuthSubmitType)[keyof typeof NativeAuthSubmitType];

type NativeAuthSubmitPayload =
  | { type: typeof NativeAuthSubmitType.INPUT; [key: string]: string }
  | { type: typeof NativeAuthSubmitType.SOCIAL; code: string }
  | { type: typeof NativeAuthSubmitType.OTP; otp: string };

const { applicationID, clientId, clientSecret, flowEndpoint, redirectUri, tokenEndpoint } = config;

/**
 * Initiates the OAuth 2.0 authorization code flow by redirecting the user to the authorization endpoint.
 * 
 * @returns {void}
 */
export const initiateRedirectAuth = () => {
    const state = Math.random().toString(36).substring(2, 15); // Generate a random state.
    const url = `${flowEndpoint}/authn?response_type=code&client_id=${clientId}&redirect_uri=${redirectUri}&scope=openid&state=${state}`;
    window.location.href = url;
};

/**
 * Initiates the native authentication or registration flow by sending a POST request to the flow endpoint.
 * 
 * @param {string} flowType - The type of flow to initiate. Defaults to 'LOGIN'.
 * @returns {Promise<object>} - A promise that resolves to the response data from the server.
 */
export const initiateNativeAuthFlow = async (flowType: 'LOGIN' | 'REGISTRATION' = 'LOGIN') => {
    const headers = {
        'Content-Type': 'application/json'
    };

    const data: Record<string, string> = {
        "applicationId": applicationID
    };

    if (flowType === 'REGISTRATION') {
        data.flowType = 'REGISTRATION';
    } else {
        data.flowType = 'AUTHENTICATION';
    }

    try {
        const response = await axios.post(`${flowEndpoint}/execute`, data, {
            headers,
        });

        return { data: response.data };
    } catch (error) {
        if (axios.isAxiosError(error)) {
            const flowTypeName = flowType === 'REGISTRATION' ? 'registration' : 'authentication';
            const message = error.response?.status === 400
              ? `Error initiating native ${flowTypeName} request.`
              : error.response?.data?.message || 'Server error occurred.';
            throw new Error(message);
        } else {
            throw new Error('Unexpected error occurred.');
        }
    }
};

/**
 * Initiates the native authentication or registration flow with additional data.
 * 
 * @param {string} flowType - The type of flow to initiate. Defaults to 'LOGIN'.
 * @param {string} actionId - The ID of the action to execute.
 * @param {object} inputs - Optional input data to include in the request.
 * @returns {Promise<object>} - A promise that resolves to the response data from the server.
 */
export const initiateNativeAuthFlowWithData = async (flowType: 'LOGIN' | 'REGISTRATION' = 'LOGIN', 
    actionId: string | null, inputs?: Record<string, unknown>) => {
    const headers = {
        'Content-Type': 'application/json'
    };

    const data: Record<string, unknown> = {
        "applicationId": applicationID,
    };

    if (actionId) {
        data.actionId = actionId;
    }

    if (flowType === 'REGISTRATION') {
        data.flowType = 'REGISTRATION';
    } else {
        data.flowType = 'AUTHENTICATION';
    }

    // Include inputs if provided
    if (inputs && Object.keys(inputs).length > 0) {
        data.inputs = inputs;
    }

    try {
        const response = await axios.post(`${flowEndpoint}/execute`, data, {
            headers,
        });

        return { data: response.data };
    } catch (error) {
        if (axios.isAxiosError(error)) {
            const flowTypeName = flowType === 'REGISTRATION' ? 'registration' : 'authentication';
            const message = error.response?.status === 400
              ? `Error initiating native ${flowTypeName} request.`
              : error.response?.data?.message || 'Server error occurred.';
            throw new Error(message);
        } else {
            throw new Error('Unexpected error occurred.');
        }
    }
};

/**
 * Submits the user's selected authentication option when multiple options are available.
 * 
 * @param {string} flowId - The flow ID received from the initiateNativeAuth response.
 * @param {string} actionId - The ID of the selected authentication action.
 * @param {object} inputs - Optional input data to submit with the decision.
 * @returns {Promise<object>} - A promise that resolves to the response data from the server.
 */
export const submitAuthDecision = async (flowId: string, actionId: string, inputs?: Record<string, unknown>) => {
    const headers = {
        'Content-Type': 'application/json'
    };

    const data: Record<string, unknown> = {
        flowId: flowId,
        actionId: actionId
    };

    // Include inputs if provided
    if (inputs && Object.keys(inputs).length > 0) {
        data.inputs = inputs;
    }

    try {
        const response = await axios.post(`${flowEndpoint}/execute`, data, {
            headers,
        });

        return { data: response.data };
    } catch (error) {
        if (axios.isAxiosError(error)) {
            const message = error.response?.status === 400
              ? 'Error processing authentication option.'
              : error.response?.data?.message || 'Server error occurred.';
            throw new Error(message);
        } else {
            throw new Error('Unexpected error occurred.');
        }
    }
};

/**
 * Submits the native authentication form data to the server.
 * 
 * @param {string} flowId - The flow ID received from the initiateNativeAuth response.
 * @param {object} payload - The payload containing the form data or other required information.
 * @returns {Promise<object>} - A promise that resolves to the response data from the server.
 */
export const submitNativeAuth = async (
    flowId: string,
    payload: Record<string, unknown> | NativeAuthSubmitPayload
) => {
    const headers = {
        'Content-Type': 'application/json'
    };

    const data: Record<string, unknown> = {
        flowId: flowId
    };

    if ('type' in payload) {
        if (payload.type === NativeAuthSubmitType.INPUT) {
            // For input type, include all fields except 'type'
            const { ...inputValues } = payload;
            data.inputs = inputValues;
        } else if (payload.type === NativeAuthSubmitType.SOCIAL) {
            data.inputs = {
                code: payload.code
            };
        } else if (payload.type === NativeAuthSubmitType.OTP) {
            data.inputs = {
                otp: payload.otp
            };
        }
    } else {
        // Handle as generic payload
        data.inputs = payload;
    }

    try {
        const response = await axios.post(`${flowEndpoint}/execute`, data, {
            headers,
        });

        return { data: response.data };
    } catch (error) {
        if (axios.isAxiosError(error)) {
            const message = error.response?.status === 400
              ? 'Login failed. Please check your credentials.'
              : error.response?.data?.message || 'Server error occurred.';
            throw new Error(message);
        } else {
            throw new Error('Unexpected error occurred.');
        }
    }
}

/**
 * Exchanges the authorization code for an access token.
 * 
 * @param {string} code - The authorization code received from the OAuth server.
 * @returns {Promise<object>} - A promise that resolves to the access token data.
 */
export const exchangeCodeForToken = async (code: string) => {
    const headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    };

    const data = new URLSearchParams();
    data.append('grant_type', 'authorization_code');
    data.append('redirect_uri', redirectUri);
    data.append('code', code);
    data.append('client_id', clientId);
    data.append('client_secret', clientSecret);

    try {
        const response = await axios.post(tokenEndpoint, data, {
            headers,
        });
        return response.data; // This will contain the access token
    } catch (error) {
        console.error('Error exchanging code for token:', error);
        throw error;
    }
};
