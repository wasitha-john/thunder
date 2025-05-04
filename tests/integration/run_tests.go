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

package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/asgardeo/thunder/tests/integration/testutils"
)

const (
	serverPort = "8090"
)

func main() {

	// Step 1: Unzip the product
	err := testutils.UnzipProduct()
	if err != nil {
		fmt.Printf("Failed to unzip product: %v\n", err)
		return // Use return instead of os.Exit(1)
	}

	// Step 2: Start the server
	serverCmd, err := testutils.StartServer(serverPort)
	if err != nil {
		fmt.Printf("Failed to start server: %v\n", err)
		return // Use return instead of os.Exit(1)
	}
	defer testutils.StopServer(serverCmd)

	// Wait for the server to start.
	// TODO: Should listen for the health check endpoint instead of sleeping.
	time.Sleep(5 * time.Second)

	// Step 3: Run all tests
	runTests()
}

func runTests() {

	cmd := exec.Command("go", "test", "./...")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Tests failed: %v\n", err)
		// Do not use os.Exit(1) here to ensure deferred functions are executed.
	}
}
