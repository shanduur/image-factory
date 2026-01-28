// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package spdx provides SPDX file extraction and bundling functionality.
package spdx

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

const (
	// ExtensionSPDXPrefix is the path prefix for SPDX files in extension images.
	ExtensionSPDXPrefix = "rootfs/usr/local/share/spdx/"

	// TalosSPDXPrefix is the path prefix for SPDX files in Talos images.
	TalosSPDXPrefix = "usr/share/spdx/"

	// SPDXFileSuffix is the file suffix for SPDX files.
	SPDXFileSuffix = ".spdx.json"
)

// File represents an extracted SPDX file.
type File struct {
	// Filename is the original filename (e.g., "extension-name.spdx.json").
	Filename string

	// Source is the source identifier (extension name or "talos").
	Source string

	// Content is the raw JSON content.
	Content []byte
}

// Bundle represents a collection of SPDX files for a schematic+version.
type Bundle struct {
	// SchematicID is the schematic identifier.
	SchematicID string

	// TalosVersion is the Talos version tag (e.g., "v1.7.4").
	TalosVersion string

	// Files contains the extracted SPDX files.
	Files []File
}

// ExtractSPDXFromTar extracts SPDX files from a tar stream.
//
// It handles both extension path (rootfs/usr/local/share/spdx/*.spdx.json)
// and Talos path (usr/share/spdx/*.spdx.json).
func ExtractSPDXFromTar(r io.Reader, source string) ([]File, error) {
	tr := tar.NewReader(r)

	var files []File

	for {
		hdr, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return nil, fmt.Errorf("error reading tar header: %w", err)
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		// Check if the file is an SPDX file
		if !strings.HasSuffix(hdr.Name, SPDXFileSuffix) {
			continue
		}

		// Check if the file is in one of the expected paths
		var filename string

		switch {
		case strings.HasPrefix(hdr.Name, ExtensionSPDXPrefix):
			filename = strings.TrimPrefix(hdr.Name, ExtensionSPDXPrefix)
		case strings.HasPrefix(hdr.Name, TalosSPDXPrefix):
			filename = strings.TrimPrefix(hdr.Name, TalosSPDXPrefix)
		default:
			continue
		}

		// Read the file content
		content, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("error reading SPDX file %q: %w", hdr.Name, err)
		}

		files = append(files, File{
			Filename: filename,
			Source:   source,
			Content:  content,
		})
	}

	return files, nil
}

// BundleToTar creates a tar archive from SPDX files.
//
// The archive structure is:
//
//	<source>/<filename>
//
// For example:
//
//	talos/talos.spdx.json
//	gvisor/gvisor.spdx.json
//
// TODO: Add function to merge all SPDX files into a single SPDX document
// with proper relationships between packages.
func BundleToTar(bundle *Bundle) (io.Reader, int64, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Track directories we've created
	createdDirs := make(map[string]bool)

	for _, file := range bundle.Files {
		// Create directory entry if needed
		dirPath := file.Source + "/"
		if !createdDirs[dirPath] {
			if err := tw.WriteHeader(&tar.Header{
				Name:     dirPath,
				Typeflag: tar.TypeDir,
				Mode:     0o755,
			}); err != nil {
				return nil, 0, fmt.Errorf("failed to write directory header for %q: %w", dirPath, err)
			}

			createdDirs[dirPath] = true
		}

		// Write the SPDX file
		filePath := filepath.Join(file.Source, file.Filename)

		if err := tw.WriteHeader(&tar.Header{
			Name:     filePath,
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     int64(len(file.Content)),
		}); err != nil {
			return nil, 0, fmt.Errorf("failed to write header for %q: %w", filePath, err)
		}

		if _, err := tw.Write(file.Content); err != nil {
			return nil, 0, fmt.Errorf("failed to write content for %q: %w", filePath, err)
		}
	}

	if err := tw.Close(); err != nil {
		return nil, 0, fmt.Errorf("failed to close tar writer: %w", err)
	}

	return bytes.NewReader(buf.Bytes()), int64(buf.Len()), nil
}

// CacheTag returns the cache tag for an SPDX bundle.
//
// The format is: spdx-<schematic_id>-<version>
// Version is sanitized to replace characters that are invalid in OCI tags.
func CacheTag(schematicID, version string) string {
	// OCI tags cannot contain '+', replace with '-'
	sanitizedVersion := strings.ReplaceAll(version, "+", "-")

	return fmt.Sprintf("spdx-%s-%s", schematicID, sanitizedVersion)
}
