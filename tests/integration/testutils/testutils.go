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
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package testutils

import (
	"archive/zip"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	TargetDir          = "./target"
	ZipFilePattern     = "thunder-*.zip"
	ExtractedDir       = "./target/.test"
	ServerBinary       = "thunder"
	DeploymentYamlPath = "./tests/integration/resources/deployment.yaml"
	InitScriptPath     = "./scripts/init_script.sh"
	DatabaseFilePath   = "repository/database/thunderidentity.db"
	DatabaseSchemaFile = "dbscripts/sqlite.sql"
)

func UnzipProduct() error {

	// Find the zip file.
	files, err := filepath.Glob(filepath.Join(TargetDir, ZipFilePattern))
	if err != nil || len(files) == 0 {
		return fmt.Errorf("zip file not found in target directory")
	}

	// Unzip the file
	zipFile := files[0]
	r, err := zip.OpenReader(zipFile)
	if err != nil {
		return err
	}
	defer r.Close()

	os.MkdirAll(ExtractedDir, os.ModePerm)
	for _, f := range r.File {
		err := extractFile(f, ExtractedDir)
		if err != nil {
			return err
		}
	}

	// Set executable permissions for the server binary
	productHome, err := getExtractedProductHome()
	if err != nil {
		return err
	}
	serverPath := filepath.Join(productHome, ServerBinary)
	if err := os.Chmod(serverPath, 0755); err != nil {
		return fmt.Errorf("failed to set executable permissions for server binary: %v", err)
	}

	return nil
}

func extractFile(f *zip.File, dest string) error {

	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	path := filepath.Join(dest, f.Name)
	if f.FileInfo().IsDir() {
		return os.MkdirAll(path, os.ModePerm)
	}

	os.MkdirAll(filepath.Dir(path), os.ModePerm)
	outFile, err := os.Create(path)
	if err != nil {
		return err
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, rc)

	return err
}

// getExtractedProductHome constructs the path to the unzipped folder.
func getExtractedProductHome() (string, error) {

	files, err := filepath.Glob(filepath.Join(TargetDir, ZipFilePattern))
	if err != nil || len(files) == 0 {
		return "", fmt.Errorf("zip file not found in target directory")
	}
	zipFile := files[0]

	return filepath.Join(ExtractedDir, filepath.Base(zipFile[:len(zipFile)-4])), nil
}

func ReplaceDeploymentYaml() error {

	productHome, err := getExtractedProductHome()
	if err != nil {
		return err
	}

	destPath := filepath.Join(productHome, "repository/conf/deployment.yaml")
	err = copyFile(DeploymentYamlPath, destPath)
	if err != nil {
		return fmt.Errorf("failed to replace deployment.yaml: %v", err)
	}

	return nil
}

func copyFile(src, dest string) error {

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, srcFile)

	return err
}

func RunInitScript() error {

	productHome, err := getExtractedProductHome()
	if err != nil {
		return err
	}

	initScript := filepath.Join(productHome, InitScriptPath)
	dbPath := filepath.Join(productHome, DatabaseFilePath)

	cmd := exec.Command("bash", initScript, "sqlite", "", "", dbPath, "", "")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to run init script: %v", err)
	}

	return nil
}

func StartServer(port string) (*exec.Cmd, error) {

	log.Println("Starting server...")
	productHome, err := getExtractedProductHome()
	if err != nil {
		return nil, err
	}
	serverPath := filepath.Join(productHome, ServerBinary)
	cmd := exec.Command(serverPath, "-thunderHome="+productHome)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "PORT="+port)
	err = cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("failed to start server: %v", err)
	}

	return cmd, nil
}

func StopServer(cmd *exec.Cmd) {

	log.Println("Stopping server...")
	if cmd != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}
}
