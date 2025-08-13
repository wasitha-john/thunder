@echo off
REM ----------------------------------------------------------------------------
REM Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
REM
REM WSO2 LLC. licenses this file to you under the Apache License,
REM Version 2.0 (the "License"); you may not use this file except
REM in compliance with the License.
REM You may obtain a copy of the License at
REM
REM http://www.apache.org/licenses/LICENSE-2.0
REM
REM Unless required by applicable law or agreed to in writing,
REM software distributed under the License is distributed on an
REM "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
REM KIND, either express or implied. See the License for the
REM specific language governing permissions and limitations
REM under the License.
REM ----------------------------------------------------------------------------

REM Server port
set BACKEND_PORT=8090

REM Kill processes using the port if any
echo Checking for processes using port %BACKEND_PORT%...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr :%BACKEND_PORT%') do (
    echo Found process using port %BACKEND_PORT% with PID: %%p
    taskkill /F /PID %%p 2>NUL
    if not errorlevel 1 (
        echo Process with PID %%p terminated successfully
    )
)

REM Run thunder
echo [92m⚡ Starting Thunder Server ...[0m
set BACKEND_PORT=%BACKEND_PORT%
start /B "" thunder.exe

echo.
echo [92m🚀 Server running[0m
echo [93mPress Ctrl+C to stop the server.[0m
echo [93mIf Ctrl+C doesn't work, close this window and use Task Manager to end the thunder.exe process.[0m

REM Keep the command window open
cmd /k
