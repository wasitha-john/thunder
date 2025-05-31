#!/bin/bash
# ----------------------------------------------------------------------------
# Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
#
# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.
# ----------------------------------------------------------------------------

# Server ports
BACKEND_PORT=8090

set -e  # Exit immediately if a command exits with a non-zero status

# Kill known ports
function kill_port() {
    local port=$1
    lsof -ti tcp:$port | xargs kill -9 2>/dev/null || true
}

# Kill ports before binding
kill_port $BACKEND_PORT

# Run thunder
echo "⚡ Starting Thunder Server ..."
BACKEND_PORT=$BACKEND_PORT ./thunder &
THUNDER_PID=$!

# Cleanup on Ctrl+C
trap 'echo -e "\n🛑 Stopping servers..."; kill $THUNDER_PID; exit' SIGINT

# Status
echo ""
echo "🚀 Servers running"
echo "Press Ctrl+C to stop the servers."

# Wait for background processes
wait $THUNDER_PID
