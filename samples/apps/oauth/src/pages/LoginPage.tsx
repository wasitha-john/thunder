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

interface SocialAuthOption {
  type: 'SOCIAL';
  idpName: string;
  redirectURL: string;
}

type LoginOption = BasicAuthOption | SocialAuthOption;

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

    const [showPassword, setShowPassword] = useState(false);
    const [basicAuthFormData, setBasicAuthFormData] = useState({
        username: '',
        password: '',
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
                    
                    // For basic auth, we just update the UI to show the form
                    if (data.data?.inputs) {
                        // Check if inputs contain username and password fields
                        const hasUsername = data.data.inputs.some((input: AuthInput) => input.name === "username");
                        const hasPassword = data.data.inputs.some((input: AuthInput) => input.name === "password");
                        
                        if (hasUsername && hasPassword) {
                            // Update login options to only show basic auth
                            setLoginOptions([{ type: 'BASIC' }]);
                        }
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
                        }
                    });
                }
                // Regular flow with inputs for basic auth
                else if (result.data?.type === "VIEW" && result.data?.data?.inputs) {
                    newLoginOptions.push({ type: 'BASIC' });
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

    const handelBasicAuthSubmit = (event: React.FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        setLoading(true);

        submitNativeAuth(flowId, { type: NativeAuthSubmitType.BASIC, ...basicAuthFormData })
            .then((result) => {
                const data = result.data;

                // Handle successful authentication
                if (data.flowStatus && data.flowStatus === 'COMPLETE' && data.assertion) {
                    setToken(data.assertion);
                    setError(false);
                } else if (data.flowStatus && data.flowStatus === 'ERROR') {
                    setError(true);
                    setErrorMessage(data.failureReason || 'Login failed. Please check your credentials.');
                }

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
    
    // Check if the current decision screen has basic auth option
    const hasBasicAuthOption = availableActions.some(action => action.id === "basic_auth");
    const hasSocialAuthOptions = availableActions.some(action => action.id !== "basic_auth");

    return (
        <Layout>
            { loading ? (
                <GradientCircularProgress />
            ) : (
                <Grid size={{ xs: 12, md: 6 }}>
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
                                maxWidth: 500,
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
                                            <Box sx={{ my: 2 }}>
                                                {/* Social auth options */}
                                                {hasSocialAuthOptions && (
                                                    <Box>
                                                        {availableActions.filter(action => action.id !== "basic_auth").map((action, index) => (
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
                                            </Box>
                                        ) : (
                                            // Regular login UI with social and basic auth options
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

                                                {hasBasicAuth && (
                                                    <form onSubmit={handelBasicAuthSubmit}>
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
                                                                                { showPassword ?
                                                                                    <VisibilityOff /> : <Visibility />
                                                                                }
                                                                            </IconButton>
                                                                        </InputAdornment>
                                                                    }
                                                                />
                                                            </Box>
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

                                                {loginOptions.length === 0 && !connectionError && !loading && (
                                                    <Alert severity="info">
                                                        No login options available. Please contact your administrator.
                                                    </Alert>
                                                )}
                                            </>
                                        )}
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
