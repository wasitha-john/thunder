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

import Alert from '@mui/material/Alert';
import InputAdornment from '@mui/material/InputAdornment';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import CircularProgress from '@mui/material/CircularProgress';
import Checkbox from '@mui/material/Checkbox';
import Divider from '@mui/material/Divider';
import FormControlLabel from '@mui/material/FormControlLabel';
import Grid from '@mui/material/Grid';
import IconButton from '@mui/material/IconButton';
import InputLabel from '@mui/material/InputLabel';
import OutlinedInput from '@mui/material/OutlinedInput';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Link from '@mui/material/Link';
import GoogleIcon from '@mui/icons-material/Google';
import GitHubIcon from '@mui/icons-material/GitHub';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';
import AccountCircleIcon from '@mui/icons-material/AccountCircle';
import { useEffect, useRef, useState, useCallback } from 'react';
import Layout from '../components/Layout';
import ConnectionErrorModal from '../components/ConnectionErrorModal';
import { 
    NativeAuthSubmitType, 
    initiateNativeAuth, 
    submitNativeAuth, 
    submitAuthDecision 
} from '../services/authService';
import useAuth from '../hooks/useAuth';

// Define interfaces for login options
interface BasicAuthOption {
  type: 'BASIC';
}

interface InputPromptOption {
    type: 'INPUT_PROMPT';
}

interface OTPAuthOptionUser {
  type: 'OTP_USERNAME';
}

interface OTPAuthOptionOTP {
  type: 'OTP';
}

interface SocialAuthOption {
  type: 'SOCIAL';
  idpName: string;
  redirectURL: string;
}

type LoginOption = BasicAuthOption | OTPAuthOptionUser | SocialAuthOption | OTPAuthOptionOTP | InputPromptOption;

// Define the interface for the authentication input
interface AuthInput {
    name: string;
    type: string;
    required: boolean;
}

/**
 * LoginPage component renders the login page with dynamic options based on the server response.
 */
const LoginPage = () => {

    const START_INIT_KEY = 'startInit';
    const FLOW_ID_KEY = 'flowId';

    const isComponentReMount = useRef(false);
    const { setToken, clearToken } = useAuth();

    const [showSignUp] = useState<boolean>(false);
    const [showRememberMe] = useState<boolean>(false);
    const [showForgotPassword] = useState<boolean>(false);
    const [error, setError] = useState<boolean>(false);
    const [errorMessage, setErrorMessage] = useState<string>('Login failed');
    const [connectionError, setConnectionError] = useState<boolean>(false);

    const [loading, setLoading] = useState<boolean>(true);
    const [flowId, setFlowId] = useState<string>(sessionStorage.getItem(FLOW_ID_KEY) || '');
    const [startInit] = useState<boolean>(JSON.parse(sessionStorage.getItem(START_INIT_KEY) || 'true'));

    const [inputs, setInputs] = useState<AuthInput[]>([]);

    const [showPassword, setShowPassword] = useState(false);
    const [basicAuthFormData, setBasicAuthFormData] = useState({
        username: '',
        password: '',
    });
    const [otpAuthUserFormData, setOtpAuthUserFormData] = useState({
        username: '',
    });
    const [otpAuthFormData, setOtpAuthFormData] = useState({
        otp: '',
    });

    // Replace individual login option states with a unified structure
    const [loginOptions, setLoginOptions] = useState<LoginOption[]>([]);

    // Add new state variables to track auth flow
    const [needsDecision, setNeedsDecision] = useState<boolean>(false);
    const [availableActions, setAvailableActions] = useState<Array<{type: string, id: string}>>([]);
    
    const GradientCircularProgress = () => {
        return (
          <>
            <svg width={0} height={0}>
              <defs>
                <linearGradient id="my_gradient" x1="0%" y1="0%" x2="0%" y2="100%">
                  <stop offset="0%" stopColor="#fc4700" />
                  <stop offset="100%" stopColor="#f87643" />
                </linearGradient>
              </defs>
            </svg>
            <CircularProgress sx={{ 'svg circle': { stroke: 'url(#my_gradient)' } }} />
          </>
        );
    }

    const handleInputChange = (event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
        const { name, value } = event.target;
        setBasicAuthFormData(prev => ({ ...prev, [name]: value }));
    };

    const handleOTPUserInputChange = (event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
        const { name, value } = event.target;
        setOtpAuthUserFormData(prev => ({ ...prev, [name]: value }));
    };

    // OTP input handling
    const otpLength = 6;
    const [otpDigits, setOtpDigits] = useState(Array(otpLength).fill(''));
    const otpInputRefs = useRef<(HTMLInputElement | null)[]>([]);
    
    useEffect(() => {
        // Initialize refs array
        otpInputRefs.current = otpInputRefs.current.slice(0, otpDigits.length);
    }, [otpDigits.length]);
    
    const handleOTPDigitChange = (index: number, value: string) => {
        // Only allow a single digit
        if (value.length > 1) {
            value = value.slice(0, 1);
        }
        
        // Update the digit at the specified index
        const newOtpDigits = [...otpDigits];
        newOtpDigits[index] = value;
        setOtpDigits(newOtpDigits);
        
        // Combine digits for the form data
        const combinedOtp = newOtpDigits.join('');
        setOtpAuthFormData({ otp: combinedOtp });
        
        // Auto-advance to next input if a digit was entered
        if (value && index < otpDigits.length - 1) {
            otpInputRefs.current[index + 1]?.focus();
        }
    };
    
    const handleOTPKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
        // Handle backspace to go to previous input
        if (e.key === 'Backspace' && !otpDigits[index] && index > 0) {
            otpInputRefs.current[index - 1]?.focus();
        }
    };
    
    const handlePaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
        e.preventDefault();
        const pastedData = e.clipboardData.getData('text');
        
        // Only process if the pasted content looks like a valid OTP
        if (pastedData.match(/^\d+$/) && pastedData.length <= otpDigits.length) {
            const newOtpDigits = [...otpDigits];
            
            // Fill in the digits from the pasted content
            for (let i = 0; i < pastedData.length; i++) {
                newOtpDigits[i] = pastedData[i];
            }
            
            setOtpDigits(newOtpDigits);
            setOtpAuthFormData({ otp: newOtpDigits.join('') });
            
            // Focus the next empty digit or the last digit if all filled
            const nextEmptyIndex = pastedData.length < otpDigits.length ? pastedData.length : otpDigits.length - 1;
            otpInputRefs.current[nextEmptyIndex]?.focus();
        }
    };

    const handleTogglePasswordVisibility = () => {
        setShowPassword((prev) => !prev);
    };

    // To prevent focus loss of show/hide password toggle button
    const handleMouseDownPassword = (event: React.MouseEvent<HTMLButtonElement>) => {
        event.preventDefault(); // Prevent focus loss
    };

    const handleSocialLoginClick = (redirectURL: string) => {
        setLoading(true);
        sessionStorage.setItem(FLOW_ID_KEY, flowId);
        sessionStorage.setItem(START_INIT_KEY, "false");
        window.location.href = redirectURL;
    };

    // Add a handler for when user selects an auth option
    const handleAuthOptionSelection = (actionId: string) => {
        setLoading(true);
        
        submitAuthDecision(flowId, actionId)
            .then((result) => {
                const data = result.data;
                
                // Process the next step based on the response
                if (data.type === "VIEW") {
                    // Now we should have inputs for the selected auth method
                    setNeedsDecision(false);
                    
                    // Handle special case for social logins
                    if (actionId.includes("google") || actionId.includes("github")) {
                        const idpName = actionId.includes("google") ? "Google" : "GitHub";
                        const socialOptions = loginOptions.filter(
                            opt => opt.type === 'SOCIAL' && opt.idpName === idpName
                        ) as SocialAuthOption[];
                        
                        if (socialOptions.length > 0 && socialOptions[0].redirectURL) {
                            handleSocialLoginClick(socialOptions[0].redirectURL);
                            return;
                        }
                    }
                    
                    if (data.data?.inputs) {
                        setInputs([]);
                        data.data.inputs.forEach((input: AuthInput) => {
                            setInputs(prev => [...prev, input]);
                        });
                    }
                } else if (data.type === "REDIRECTION") {
                    // Handle redirection for social logins
                    // const idpName = data.data?.additionalData?.idpName || 'Social Login';
                    const redirectURL = data.data?.redirectURL;
                    
                    if (redirectURL) {
                        handleSocialLoginClick(redirectURL);
                    }
                }
                
                setLoading(false);
            })
            .catch((error) => {
                console.error("Error during authentication decision:", error);
                setError(true);
                setErrorMessage(error.message || 'Error processing your selection');
                setLoading(false);
            });
    };

    const init = useCallback(() => {
        clearToken();
        setConnectionError(false);
        setLoginOptions([]);
        setNeedsDecision(false);
        setAvailableActions([]);

        initiateNativeAuth()
            .then((result) => {
                const newLoginOptions: LoginOption[] = [];
                
                // Check if we need user to make a decision first
                if (result.data?.type === "VIEW" && result.data?.data?.actions) {
                    setNeedsDecision(true);
                    setAvailableActions(result.data.data.actions);
                    
                    // Create login options based on available actions
                    const actions = result.data.data.actions;
                    actions.forEach((action: {type: string, id: string}) => {
                        if (action.id === "basic_auth") {
                            newLoginOptions.push({ type: 'BASIC' });
                        } else if (action.id === "google_auth") {
                            newLoginOptions.push({
                                type: 'SOCIAL',
                                idpName: 'Google',
                                redirectURL: ""
                            });
                        } else if (action.id === "github_auth") {
                            newLoginOptions.push({
                                type: 'SOCIAL',
                                idpName: 'GitHub',
                                redirectURL: ""
                            });
                        } else if (action.id === "mobile_prompt_username") {
                            newLoginOptions.push({ type: 'OTP_USERNAME' });
                        }
                    });
                }
                // Regular flow with inputs for basic auth
                else if (result.data?.type === "VIEW" && result.data?.data?.inputs) {
                    let hasUsername = false
                    let hasPassword = false
                    result.data.data.inputs.forEach((input: AuthInput) => {
                        setInputs(prev => [...prev, input]);
                        if (input.name === "username") {
                            hasUsername = true;
                        } else if (input.name === "password") {
                            hasPassword = true;
                        } else if (input.name === "otp") {
                            newLoginOptions.push({ type: 'OTP' });
                        }
                    });
                    if (hasUsername && hasPassword) {
                        newLoginOptions.push({ type: 'BASIC' });
                    } else {
                        newLoginOptions.push({ type: 'INPUT_PROMPT' });
                    }
                }
                // Direct redirection for social login
                else if (result.data?.type === "REDIRECTION") {
                    const idpName = result.data?.data?.additionalData?.idpName || 'Social Login';
                    const redirectURL = result.data?.data?.redirectURL;
                    
                    if (redirectURL) {
                        newLoginOptions.push({
                            type: 'SOCIAL',
                            idpName,
                            redirectURL
                        });
                    }
                }
                
                setLoginOptions(newLoginOptions);
                setFlowId(result.data.flowId);
                setLoading(false);
            }).catch((error) => {
                console.error("Error during authentication:", error);
                setConnectionError(true);
                setLoading(false);
            });
    }, [clearToken]);

    const handleAuthInputSubmit = (event: React.FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        setLoading(true);

        // Create a payload that includes all necessary input values
        const inputPayload: Record<string, string> = {};
        
        // Add all input values from the form
        inputs.forEach(input => {
            const inputName = input.name;
            if (input.name === "username" || input.name === "password") {
                inputPayload[inputName] = basicAuthFormData[inputName as keyof typeof basicAuthFormData];
            } else if (input.name === "otp") {
                inputPayload[inputName] = otpAuthFormData.otp;
            } else {
                // For any other inputs, try to find their values in the form
                const formElement = event.currentTarget.elements.namedItem(inputName) as HTMLInputElement;
                if (formElement && formElement.value) {
                    inputPayload[inputName] = formElement.value;
                }
            }
        });

        submitNativeAuth(flowId, { type: NativeAuthSubmitType.INPUT, ...inputPayload })
            .then((result) => {
                const data = result?.data;

                // Handle successful authentication
                if (data.flowStatus && data.flowStatus === 'COMPLETE' && data.assertion) {
                    setToken(data.assertion);
                    setError(false);
                } else if (data.flowStatus && data.flowStatus === 'ERROR') {
                    setError(true);
                    setErrorMessage(data.failureReason || 'Login failed. Please check your credentials.');
                } else if (data.type === "VIEW" && data.data?.inputs) {
                    setInputs([]);
                    data.data.inputs.forEach((input: AuthInput) => {
                        setInputs(prev => [...prev, input]);
                    });
                }
                setFlowId(data.flowId);
                setLoading(false);
            }).catch((error) => {
                console.error("Error during authentication:", error);

                // Check if it's a network error or authentication error
                if (error.message && error.message.includes("Network Error")) {
                    setConnectionError(true);
                } else {
                    setError(true);
                    init();
                }

                setLoading(false);
            });
    };

    const handleRetry = () => {
        setTimeout(() => {
            init();
        }, 500);
    };
    
    // Helper function to get appropriate icon for social login
    const getSocialLoginIcon = (idpName: string) => {
        const lowerIdpName = idpName.toLowerCase();
        
        if (lowerIdpName.includes('github')) {
            return <GitHubIcon />;
        } else if (lowerIdpName.includes('google')) {
            return <GoogleIcon />;
        } else {
            return <AccountCircleIcon />;
        }
    };

    // This effect is to handle initial component mount
    useEffect(() => {
        // Prevent double mount due to React Strict Mode
        if (isComponentReMount.current) return;
        isComponentReMount.current = true;

        if (startInit) {
            // Initialize login execution flow if fresh start
            init();
        } else {
            // This effect is to handle when return from federated IDP login
            const params = new URLSearchParams(window.location.search);
            const code = params.get('code');

            if (code) {
                // Clear query parameters to avoid re-submission
                window.history.replaceState({}, document.title, window.location.pathname);

                submitNativeAuth(flowId, { type: NativeAuthSubmitType.SOCIAL, code: code })
                    .then((result) => {
                        setLoading(false);
                        const data = result.data;

                        // Handle successful authentication
                        if (data.flowStatus && data.flowStatus === 'COMPLETE' && data.assertion) {
                            setToken(data.assertion);
                            setError(false);
                        }
                    }).catch((error) => {
                        setLoading(false);
                        console.error("Error during social authentication:", error);

                        if (error.message && error.message.includes("Network Error")) {
                            setConnectionError(true);
                        }
                        else {
                            setError(true);
                        }
                    });
            } else {
                setError(true);
                setLoading(false);
            }

            sessionStorage.setItem(START_INIT_KEY, "true");
        }
    },[startInit, init, flowId, setToken]);

    // Check if we have any basic auth options
    const hasBasicAuth = loginOptions.some(option => option.type === 'BASIC');
    // Get all social auth options
    const socialOptions = loginOptions.filter(option => option.type === 'SOCIAL') as SocialAuthOption[];
    
    // Handle basic auth form submission directly from decision screen
    const handleBasicAuthDecision = (event: React.FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        setLoading(true);
        
        // Find the basic_auth action ID
        const basicAuthAction = availableActions.find(action => action.id === "basic_auth");
        if (!basicAuthAction) {
            setError(true);
            setErrorMessage("Basic authentication not available");
            setLoading(false);
            return;
        }
        
        // Submit both the decision and credentials together
        submitAuthDecision(flowId, basicAuthAction.id, {
            username: basicAuthFormData.username,
            password: basicAuthFormData.password
        })
            .then((result) => {
                const data = result.data;
                
                // Handle successful authentication
                if (data.flowStatus && data.flowStatus === 'COMPLETE' && data.assertion) {
                    setToken(data.assertion);
                    setError(false);
                } else if (data.type === "VIEW") {
                    // Additional steps might be needed
                    setNeedsDecision(false);
                    setLoginOptions([{ type: 'BASIC' }]);
                    setLoading(false);
                } else if (data.flowStatus && data.flowStatus === 'ERROR') {
                    setError(true);
                    setErrorMessage(data.failureReason || 'Login failed. Please check your credentials.');
                    setLoading(false);
                }
            })
            .catch((error) => {
                console.error("Error during authentication:", error);
                setError(true);
                setErrorMessage(error.message || 'Error during authentication');
                setLoading(false);
            });
    };

    // Handle OTP authentication decision directly from decision screen
    const handleOTPAuthDecision = (event: React.FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        setLoading(true);
        
        // Find the basic_auth action ID
        const smsOTPAuthAction = availableActions.find(action => action.id === "mobile_prompt_username");
        if (!smsOTPAuthAction) {
            setError(true);
            setErrorMessage("SMS OTP authentication not available");
            setLoading(false);
            return;
        }
        
        // Submit both the decision and username together
        submitAuthDecision(flowId, smsOTPAuthAction.id, {
            username: otpAuthUserFormData.username,
        })
            .then((result) => {
                const data = result.data;
                
                // Handle successful authentication
                if (data.flowStatus && data.flowStatus === 'COMPLETE' && data.assertion) {
                    setToken(data.assertion);
                    setError(false);
                } else if (data.type === "VIEW" && data.data?.inputs) {
                    setNeedsDecision(false);
                    setLoginOptions([{ type: 'OTP' }]);
                    setInputs([]);
                    data.data.inputs.forEach((input: AuthInput) => {
                        setInputs(prev => [...prev, input]);
                    });
                    setLoading(false);
                } else if (data.flowStatus && data.flowStatus === 'ERROR') {
                    setError(true);
                    setErrorMessage(data.failureReason || 'Login failed. Please check your credentials.');
                    setLoading(false);
                }
            })
            .catch((error) => {
                console.error("Error during authentication:", error);
                setError(true);
                setErrorMessage(error.message || 'Error during authentication');
                setLoading(false);
            });
    };

    const getInputPromptFields = () => {
        let isPasswordSubmit = false;
        let isOTPSubmit = false;
        
        const inputBoxes = inputs.map((input, index) => {
            const inputId = input.name || `input-${index}`;
            const isPassword = input.type === "password" || input.name === "password";
            const isOTP = input.type === "otp" || input.name === "otp";
            const isRequired = input.required;

            if (isPassword) {
                isPasswordSubmit = true;
            }
            if (isOTP) {
                isOTPSubmit = true;
            }
            
            // Determine appropriate label based on input name
            let label = input.name;
            // Capitalize first letter and replace underscores with spaces
            if (label) {
                label = label.charAt(0).toUpperCase() + label.slice(1).replace(/_/g, ' ');
            }
            // Add spaces between words
            label = label.replace(/([a-z])([A-Z])/g, '$1 $2');
            // Handle special case for OTP
            if (isOTP) {
                label = 'OTP Code';
            } else if (isPassword) {
                label = 'Password';
            }

            // Determine the placeholder text
            const placeholder = `Enter your ${label.toLowerCase()}`;

            return (
                <>
                    <Box key={inputId} display="flex" flexDirection="column" gap={0.5}>
                        <InputLabel htmlFor={inputId} sx={{ mb: 1 }}>{label}</InputLabel>
                        {isPassword ? (
                            <OutlinedInput
                                type={showPassword ? 'text' : 'password'}
                                id={inputId}
                                name={input.name}
                                placeholder={placeholder}
                                size="small"
                                onChange={handleInputChange}
                                required={isRequired}
                                endAdornment={
                                    <InputAdornment position="end">
                                        <IconButton
                                            aria-label="toggle password visibility"
                                            onClick={handleTogglePasswordVisibility}
                                            onMouseDown={handleMouseDownPassword}
                                            edge="end"
                                        >
                                            {showPassword ? <VisibilityOff /> : <Visibility />}
                                        </IconButton>
                                    </InputAdornment>
                                }
                            />
                        ) : isOTP ? (
                            <Box 
                                sx={{ 
                                    display: 'flex', 
                                    gap: 1,
                                    justifyContent: 'space-between'
                                }}
                            >
                                {otpDigits.map((digit, index) => (
                                    <OutlinedInput
                                        key={`otp-digit-${index}`}
                                        inputRef={el => otpInputRefs.current[index] = el}
                                        value={digit}
                                        onChange={(e) => handleOTPDigitChange(index, e.target.value)}
                                        onKeyDown={(e) => handleOTPKeyDown(index, e as React.KeyboardEvent<HTMLInputElement>)}
                                        onPaste={index === 0 ? handlePaste : undefined}
                                        inputProps={{
                                            maxLength: 1,
                                            style: { textAlign: 'center', padding: '8px 0' }
                                        }}
                                        sx={{
                                            width: '40px',
                                            height: '48px',
                                            '& input': { padding: 0 }
                                        }}
                                    />
                                ))}
                            </Box>
                        ) : (
                            <OutlinedInput
                                type={input.type || "text"}
                                id={inputId}
                                name={input.name}
                                placeholder={placeholder}
                                size="small"
                                onChange={handleInputChange}
                                required={isRequired}
                            />
                        )}
                    </Box>
                </>
            );
        });

        return (
            <>
                { inputBoxes }
                { (showRememberMe || showForgotPassword) && (
                    <Box
                        sx={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        }}
                    >
                        { showRememberMe && (
                            <FormControlLabel
                                control={<Checkbox name="remember-me-checkbox" />} 
                                label="Remember me" />
                        )}
                        { showForgotPassword &&
                            <Link href="">Forgot your password?</Link>
                        }
                    </Box>
                )}

                {isPasswordSubmit ? (
                    <Button
                        variant="contained"
                        color="primary"
                        type="submit"
                        fullWidth
                        sx={{ mt: 2 }}
                    >
                        Sign In
                    </Button>
                ) : isOTPSubmit ? (
                    <Button
                        variant="contained"
                        color="primary"
                        type="submit"
                        fullWidth
                        sx={{ mt: 2 }}
                    >
                        Verify OTP
                    </Button>
                ) : (
                    <Button
                        variant="contained"
                        color="primary"
                        type="submit"
                        fullWidth
                        sx={{ mt: 2 }}
                    >
                        Continue
                    </Button>
                )}
            </>
        )
    };

    const getRegularLoginForm = () => {
        return (
            <>
                {socialOptions.length > 0 && (
                    <>
                        <Box>
                            {socialOptions.map((option, index) => (
                                <Button
                                    key={`social-login-${index}`}
                                    fullWidth
                                    variant="contained"
                                    startIcon={getSocialLoginIcon(option.idpName)}
                                    color="secondary"
                                    onClick={() => handleSocialLoginClick(option.redirectURL)}
                                    sx={{ my: 1 }}
                                >
                                    Continue with {option.idpName}
                                </Button>
                            ))}
                        </Box>
                        
                        {hasBasicAuth && <Divider sx={{ my: 3 }}>or</Divider>}
                    </>
                )}

                <form onSubmit={handleAuthInputSubmit}>
                    <Box display="flex" flexDirection="column" gap={2}>
                        { getInputPromptFields() }
                    </Box>
                </form>
            </>
        )
    }

    const getBasicAndSocialLoginForm = () => {
        return (
            <Box sx={{ my: 2 }}>
                {/* Social auth options */}
                {hasSocialAuthOptions && (
                    <Box>
                        {availableActions.filter(action => (action.id !== "basic_auth" && action.id !== "mobile_prompt_username")).map((action, index) => (
                            <Button
                                key={`action-${index}`}
                                fullWidth
                                variant="contained"
                                color="secondary"
                                onClick={() => handleAuthOptionSelection(action.id)}
                                sx={{ my: 1 }}
                                startIcon={
                                    action.id === "google_auth" ? <GoogleIcon /> : 
                                    action.id === "github_auth" ? <GitHubIcon /> : 
                                    <AccountCircleIcon />
                                }
                            >
                                {action.id === "google_auth" ? "Continue with Google" :
                                action.id === "github_auth" ? "Continue with GitHub" : 
                                action.id}
                            </Button>
                        ))}
                    </Box>
                )}
                
                {/* Show divider if we have both social and basic auth options */}
                {hasBasicAuthOption && hasSocialAuthOptions && (
                    <Divider sx={{ my: 3 }}>or</Divider>
                )}
                
                {/* Basic auth form */}
                {hasBasicAuthOption && (
                    <form onSubmit={handleBasicAuthDecision}>
                        <Box display="flex" flexDirection="column" gap={2}>
                            <Box display="flex" flexDirection="column" gap={0.5}>
                                <InputLabel htmlFor="username">Username</InputLabel>
                                <OutlinedInput
                                    type="text"
                                    id="username"
                                    name="username"
                                    placeholder="Enter your username"
                                    size="small"
                                    value={basicAuthFormData.username}
                                    onChange={handleInputChange}
                                    required
                                />
                            </Box>
                            <Box display="flex" flexDirection="column" gap={0.5}>
                                <InputLabel htmlFor="password">Password</InputLabel>
                                <OutlinedInput
                                    type={showPassword ? 'text' : 'password'}
                                    id="password"
                                    name="password"
                                    placeholder="Enter your password"
                                    size="small"
                                    value={basicAuthFormData.password}
                                    onChange={handleInputChange}
                                    required
                                    endAdornment={
                                        <InputAdornment position="end">
                                            <IconButton
                                                aria-label="toggle password visibility"
                                                onClick={handleTogglePasswordVisibility}
                                                onMouseDown={handleMouseDownPassword}
                                                edge="end"
                                            >
                                                {showPassword ? 
                                                    <VisibilityOff /> : <Visibility />
                                                }
                                            </IconButton>
                                        </InputAdornment>
                                    }
                                />
                            </Box>
                            {(showRememberMe || showForgotPassword) && (
                                <Box
                                    sx={{
                                    display: 'flex',
                                    justifyContent: 'space-between',
                                    alignItems: 'center',
                                    }}
                                >
                                    { showRememberMe && (
                                        <FormControlLabel
                                            control={<Checkbox name="remember-me-checkbox" />} 
                                            label="Remember me" />
                                    )}
                                    { showForgotPassword &&
                                        <Link href="">Forgot your password?</Link>
                                    }
                                </Box>
                            )}
                            <Button
                                variant="contained"
                                color="primary"
                                type="submit"
                                fullWidth
                                sx={{ mt: 2 }}
                            >
                                Sign In
                            </Button>
                        </Box>
                    </form>
                )}

                {/* Show divider if we have both social and basic auth options */}
                {hasSMSOTPAuthOption && hasSocialAuthOptions && (
                    <Divider sx={{ my: 3 }}>or</Divider>
                )}

                {/* SMS OTP auth form */}
                {hasSMSOTPAuthOption && (
                    <form onSubmit={handleOTPAuthDecision}>
                        <Box display="flex" flexDirection="column" gap={2}>
                            <Box display="flex" flexDirection="column" gap={0.5}>
                                <InputLabel htmlFor="username">Username</InputLabel>
                                <OutlinedInput
                                    type="text"
                                    id="username"
                                    name="username"
                                    placeholder="Enter your username"
                                    size="small"
                                    value={otpAuthUserFormData.username}
                                    onChange={handleOTPUserInputChange}
                                    required
                                />
                            </Box>
                            <Button
                                variant="contained"
                                color="primary"
                                type="submit"
                                fullWidth
                                sx={{ mt: 2 }}
                            >
                                Continue with SMS OTP
                            </Button>
                        </Box>
                    </form>
                )}
            </Box>
        )
    }

    const getBasicAndSMSLoginForm = () => {
        return (
            <Box sx={{ my: 4 }}>
                <Box display="flex" gap={4}>
                    {/* Left: Basic Login */}
                    <Box sx={{ flex: 1 }}>
                        <form onSubmit={handleBasicAuthDecision}>
                            <Box display="flex" flexDirection="column" gap={2}>
                                <Typography variant="body1" color="textSecondary" sx={{ mb: 2, mt: 2.7 }}>
                                    Login with Username and Password
                                </Typography>
                                </Box>
                            <Box display="flex" flexDirection="column" gap={2} sx={{ mt: 3 }}>
                                <Box display="flex" flexDirection="column" gap={0.5}>
                                    <InputLabel htmlFor="username">Username</InputLabel>
                                    <OutlinedInput
                                        type="text"
                                        id="username"
                                        name="username"
                                        placeholder="Enter your username"
                                        size="small"
                                        value={basicAuthFormData.username}
                                        onChange={handleInputChange}
                                        required
                                    />
                                </Box>
                                <Box display="flex" flexDirection="column" gap={0.5} sx={{ mt: 1 }}>
                                    <InputLabel htmlFor="password">Password</InputLabel>
                                    <OutlinedInput
                                        type={showPassword ? 'text' : 'password'}
                                        id="password"
                                        name="password"
                                        placeholder="Enter your password"
                                        size="small"
                                        value={basicAuthFormData.password}
                                        onChange={handleInputChange}
                                        required
                                        endAdornment={
                                        <InputAdornment position="end">
                                            <IconButton
                                                aria-label="toggle password visibility"
                                                onClick={handleTogglePasswordVisibility}
                                                onMouseDown={handleMouseDownPassword}
                                                edge="end"
                                            >
                                                {showPassword ? <VisibilityOff /> : <Visibility />}
                                            </IconButton>
                                        </InputAdornment>
                                        }
                                    />
                                </Box>

                                {(showRememberMe || showForgotPassword) && (
                                <Box display="flex" justifyContent="space-between" alignItems="center">
                                    {showRememberMe && (
                                        <FormControlLabel
                                            control={<Checkbox name="remember-me-checkbox" />}
                                            label="Remember me"
                                        />
                                    )}
                                    {showForgotPassword && <Link href="#">Forgot your password?</Link>}
                                </Box>
                                )}

                                <Button
                                    variant="contained"
                                    color="primary"
                                    type="submit"
                                    fullWidth
                                    sx={{ mt: 3 }}
                                    >
                                    Sign In
                                </Button>
                            </Box>
                        </form>
                    </Box>

                    {/* Vertical Divider */}
                    <Divider orientation="vertical" flexItem sx={{ mx: 2 }} />

                    {/* Right: Social Auth and SMS Options */}
                    <Box sx={{ flex: 1 }}>
                        {/* Social auth options */}
                        {hasSocialAuthOptions && (
                            <Box>
                            {availableActions
                                .filter(
                                (action) =>
                                    action.id !== 'basic_auth' &&
                                    action.id !== 'mobile_prompt_username'
                                )
                                .map((action, index) => (
                                <Button
                                    key={`action-${index}`}
                                    fullWidth
                                    variant="contained"
                                    color="secondary"
                                    onClick={() => handleAuthOptionSelection(action.id)}
                                    sx={{ my: 1 }}
                                    startIcon={
                                    action.id === 'google_auth' ? (
                                        <GoogleIcon />
                                    ) : action.id === 'github_auth' ? (
                                        <GitHubIcon />
                                    ) : (
                                        <AccountCircleIcon />
                                    )
                                    }
                                >
                                    {action.id === 'google_auth'
                                    ? 'Continue with Google'
                                    : action.id === 'github_auth'
                                    ? 'Continue with GitHub'
                                    : action.id}
                                </Button>
                                ))}
                            </Box>
                        )}

                        {/* Show divider if we have both social and sms auth options */}
                        {hasSMSOTPAuthOption && hasSocialAuthOptions && (
                            <Divider sx={{ my: 3 }}>or</Divider>
                        )}

                        {/* SMS OTP Auth */}
                        {hasSMSOTPAuthOption && (
                            <form onSubmit={handleOTPAuthDecision} style={{ marginTop: '2rem' }}>
                            <Box display="flex" flexDirection="column" gap={2}>
                                <Box display="flex" flexDirection="column" gap={0.5}>
                                    <InputLabel htmlFor="username">Username</InputLabel>
                                    <OutlinedInput
                                        type="text"
                                        id="username"
                                        name="username"
                                        placeholder="Enter your username"
                                        size="small"
                                        value={otpAuthUserFormData.username}
                                        onChange={handleOTPUserInputChange}
                                        required
                                    />
                                </Box>
                                <Button
                                    variant="contained"
                                    color="primary"
                                    type="submit"
                                    fullWidth
                                    sx={{ mt: 2 }}
                                    >
                                    Continue with SMS OTP
                                </Button>
                            </Box>
                            </form>
                        )}
                    </Box>
                </Box>
            </Box>
        )
    }
    
    // Check if the current decision screen has basic auth option
    const hasBasicAuthOption = availableActions.some(action => action.id === "basic_auth");
    const hasSMSOTPAuthOption = availableActions.some(action => action.id === "mobile_prompt_username");
    const hasSocialAuthOptions = availableActions.some(action => action.id !== "basic_auth");

    const gridMdSize = needsDecision && hasBasicAuthOption && hasSMSOTPAuthOption ? 10 : 6;
    const containerBoxMaxWidth = needsDecision && hasBasicAuthOption && hasSMSOTPAuthOption ? 1000 : 500;

    return (
        <Layout>
            { loading ? (
                <GradientCircularProgress />
            ) : (
                <Grid size={{ xs: 12, md: gridMdSize }}>
                    <Paper
                        sx={{
                            display: "flex",
                            width: "100%",
                            height: "100%",
                            flexDirection: "column",
                        }}
                    >
                        <Box
                            sx={{
                                alignItems: "center",
                                justifyContent: "center",
                                padding: 6,
                                width: "100%",
                                maxWidth: containerBoxMaxWidth,
                                margin: "auto",
                            }}
                        >
                            <Box>
                                <Box sx={{ mb: 4 }}>
                                    <Typography variant="h5" gutterBottom>
                                    Login to Account
                                    </Typography>

                                    {showSignUp && (
                                    <Typography>
                                        Don&apos;t have an account <Link href="">Sign up!</Link>
                                    </Typography>
                                    )}
                                </Box>
                                
                                {connectionError && (
                                    <ConnectionErrorModal 
                                        onRetry={handleRetry}
                                    />
                                )}

                                {error && !connectionError && (
                                    <Alert severity="error" sx={{ my: 2 }}>
                                        {errorMessage}
                                    </Alert>
                                )}

                                {!connectionError && (
                                    <>
                                        {needsDecision ? (
                                            <>
                                                { hasBasicAuthOption && hasSMSOTPAuthOption ? (
                                                    getBasicAndSMSLoginForm()
                                                ) : (
                                                    getBasicAndSocialLoginForm()
                                                ) }
                                            </>
                                        ) : (
                                            getRegularLoginForm()
                                        )}
                                        <>
                                            {loginOptions.length === 0 && !connectionError && !loading && (
                                                <Alert severity="info">
                                                    No login options available. Please contact your administrator.
                                                </Alert>
                                            )}
                                        </>
                                    </>
                                )}
                                <Box component="footer" sx={{ mt: 6 }}>
                                    <Typography sx={{ textAlign: "center" }}>
                                        © Copyright {new Date().getFullYear()}
                                    </Typography>
                                </Box>
                            </Box>
                        </Box>
                    </Paper>
                </Grid>
            )}
        </Layout>
    );
};

export default LoginPage;
