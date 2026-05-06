// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build integration

package integration_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/image-factory/pkg/enterprise"
)

const (
	scanTestTalosVersion = "v1.13.0"
	scanTestArch         = "amd64"
)

func downloadScan(ctx context.Context, t *testing.T, baseURL, schematic, version, arch, report, method string) *http.Response {
	t.Helper()

	url := baseURL + "/scans/" + schematic + "/" + version + "/" + arch + "/" + report

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	require.NoError(t, err)

	addTestAuth(req)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	t.Cleanup(func() {
		resp.Body.Close()
	})

	return resp
}

func testScanFrontend(ctx context.Context, t *testing.T, baseURL string) {
	if !enterprise.Enabled() {
		t.Run("endpoint not registered", func(t *testing.T) {
			t.Parallel()

			resp := downloadScan(ctx, t, baseURL, emptySchematicID, scanTestTalosVersion, scanTestArch, "report.json", http.MethodGet)
			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		})

		return
	}

	t.Run("requires authentication", func(t *testing.T) {
		t.Parallel()

		url := baseURL + "/scans/" + emptySchematicID + "/" + scanTestTalosVersion + "/" + scanTestArch + "/report.json"

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)

		defer resp.Body.Close() //nolint:errcheck

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("invalid version", func(t *testing.T) {
		t.Parallel()

		resp := downloadScan(ctx, t, baseURL, emptySchematicID, "not-a-version", scanTestArch, "report.json", http.MethodGet)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("version below availableFrom", func(t *testing.T) {
		t.Parallel()

		resp := downloadScan(ctx, t, baseURL, emptySchematicID, "v1.12.0", scanTestArch, "report.json", http.MethodGet)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("invalid arch", func(t *testing.T) {
		t.Parallel()

		resp := downloadScan(ctx, t, baseURL, emptySchematicID, scanTestTalosVersion, "x86", "report.json", http.MethodGet)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("unknown format", func(t *testing.T) {
		t.Parallel()

		resp := downloadScan(ctx, t, baseURL, emptySchematicID, scanTestTalosVersion, scanTestArch, "report.xml", http.MethodGet)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}
