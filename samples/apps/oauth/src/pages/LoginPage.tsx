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
import { NativeAuthSubmitType, initiateNativeAuth, submitNativeAuth } from '../services/authService';
import useAuth from '../hooks/useAuth';

/**
 * LoginPage component renders the login page with options for username/password login,
 * 
 * @param props LoginPageProps
 * @returns 
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

    const [userNamePasswordLogin, setUserNamePasswordLogin] = useState<boolean>(false);
    const [showPassword, setShowPassword] = useState(false);
    const [basicAuthFormData, setBasicAuthFormData] = useState({
        username: '',
        password: '',
    });

    const [idpName, setIdpName] = useState<string>('Social Login');
    const [showGitHubLoginButton, setShowGithubLoginButton] = useState<boolean>(false);
    const [showGoogleLoginButton, setShowGoogleLoginButton] = useState<boolean>(false);
    const [showSocialLoginButton, setShowSocialLoginButton] = useState<boolean>(false);
    const [socialLoginRedirectURL, setSocialLoginRedirectURL] = useState<string>('');

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

    const handleSocialLoginClick = () => {
        sessionStorage.setItem(FLOW_ID_KEY, flowId);
        sessionStorage.setItem(START_INIT_KEY, "false");
        window.location.href = socialLoginRedirectURL;
    };

    const init = useCallback(() => {
        clearToken();
        setConnectionError(false);

        initiateNativeAuth()
            .then((result) => {
                if (result.data?.type === "VIEW") {
                    setUserNamePasswordLogin(true);
                }

                if (result.data?.type === "REDIRECTION") {
                    let idpName = result.data?.additionalInfo?.idp_name;

                    if (idpName) {
                        setIdpName(idpName);
                        
                        idpName = idpName?.toLowerCase();

                        if (idpName.includes("github")) {
                            setShowGithubLoginButton(true);
                        } else if (idpName.includes("google")) {
                            setShowGoogleLoginButton(true);
                        } else {
                            setShowSocialLoginButton(true);
                        }
                    } else {
                        setShowSocialLoginButton(true);
                    }

                    setSocialLoginRedirectURL(result.data?.additionalInfo?.redirect_url);
                }
                
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
                submitNativeAuth(flowId, { type: NativeAuthSubmitType.SOCIAL, code: code })
                    .then((result) => {
                        const data = result.data;

                        // Handle successful authentication
                        if (data.flowStatus && data.flowStatus === 'COMPLETE' && data.assertion) {
                            setToken(data.assertion);
                            setError(false);
                        }
                    }).catch((error) => {
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
            }

            sessionStorage.setItem(START_INIT_KEY, "true");
        }
    },[startInit, init, flowId, setToken]);

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
                                        {(showGoogleLoginButton || showGitHubLoginButton || showSocialLoginButton) && (
                                            <>
                                                <Box>
                                                    { showGoogleLoginButton && (
                                                        <Button
                                                            fullWidth
                                                            variant="contained"
                                                            startIcon={<GoogleIcon />}
                                                            color="secondary"
                                                            onClick={() => handleSocialLoginClick()}
                                                            sx={{ my: 1 }}
                                                        >
                                                            Continue with { idpName }
                                                        </Button>
                                                    )}
                                                    { showGitHubLoginButton && (
                                                        <Button
                                                            fullWidth
                                                            variant="contained"
                                                            startIcon={<GitHubIcon />}
                                                            color="secondary"
                                                            onClick={() => handleSocialLoginClick()}
                                                            sx={{ my: 1 }}
                                                        >
                                                            Continue with { idpName }
                                                        </Button>
                                                    )}
                                                    { showSocialLoginButton && (
                                                        <Button
                                                            fullWidth
                                                            variant="contained"
                                                            startIcon={<AccountCircleIcon />}
                                                            color="secondary"
                                                            onClick={() => handleSocialLoginClick()}
                                                            sx={{ my: 1 }}
                                                        >
                                                            Continue with { idpName }
                                                        </Button>
                                                    )}
                                                </Box>
                                                
                                                { userNamePasswordLogin &&
                                                    <Divider sx={{ my: 3 }}>or</Divider>
                                                }
                                            </>
                                        )}

                                        { userNamePasswordLogin &&
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
                                        }
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
