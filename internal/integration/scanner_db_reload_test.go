// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build integration

package integration_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pauseGrypeDBReload holds the listing request made while reopening the DB.
// Initialization and the scheduled download each GET the listing first.
// Ignore the downloader's HEAD probes. The third GET occurs after the old
// scanner is closed, under the DB write lock. Holding it lets the rotation
// test exercise that otherwise tiny window.
func pauseGrypeDBReload(t *testing.T, mirror *grypeDBMirror) (string, <-chan struct{}, func()) {
	t.Helper()

	entered := make(chan struct{})
	release := make(chan struct{})
	resume := sync.OnceFunc(func() { close(release) })

	var listings atomic.Uint32

	files := http.StripPrefix("/v6/", http.FileServer(http.Dir(mirror.dir)))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v6/latest.json" && listings.Add(1) == 3 {
			close(entered)

			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}

		files.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)

	return server.URL, entered, resume
}

// checkScanDuringReload requires one request to wait for the replacement DB,
// rather than accepting a transient 503 and retrying it. The short timer is a
// negative observation window, not a readiness or refresh deadline.
func checkScanDuringReload(ctx context.Context, t *testing.T, baseURL, schematicID string, resume func()) {
	t.Helper()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/readyz", nil)
	require.NoError(t, err)

	readiness, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.NoError(t, readiness.Body.Close())
	require.Equal(t, http.StatusServiceUnavailable, readiness.StatusCode,
		"the reload gate must hold the scanner replacement, not the download")

	req, err = http.NewRequestWithContext(ctx, http.MethodGet,
		baseURL+"/scans/"+schematicID+"/"+scanTestTalosVersion+"/"+scanTestArch+"/report.json", nil)
	require.NoError(t, err)
	addTestAuth(req)

	type result struct {
		err    error
		status int
	}

	done := make(chan result, 1)

	go func() {
		response, requestErr := http.DefaultClient.Do(req)
		if requestErr != nil {
			done <- result{err: requestErr}

			return
		}

		closeErr := response.Body.Close()
		done <- result{status: response.StatusCode, err: closeErr}
	}()

	var got result

	select {
	case got = <-done:
		resume()
		assert.Fail(t, "scan returned before the database reload completed")
	case <-time.After(time.Second):
		resume()

		got = <-done
	}

	require.NoError(t, got.err)
	require.Equal(t, http.StatusOK, got.status)
}
