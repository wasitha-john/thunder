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
	TargetDir      = "./target"
	ZipFilePattern = "thunder-*.zip"
	ExtractedDir   = "./target/extracted"
	ServerBinary   = "thunder"
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
	serverPath := filepath.Join(ExtractedDir, ServerBinary)
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

func StartServer(port string) (*exec.Cmd, error) {

	log.Println("Starting server...")
	serverPath := filepath.Join(ExtractedDir, ServerBinary)
	cmd := exec.Command(serverPath, "-dir="+ExtractedDir) // Pass the -dir argument
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "PORT="+port)
	err := cmd.Start()
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
