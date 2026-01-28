// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package http

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/julienschmidt/httprouter"
)

// handleSPDX handles SPDX bundle download requests.
//
// The endpoint returns a tar archive containing all SPDX files for the given
// schematic and Talos version. The archive structure is:
//
//	<source>/<filename>
//
// For example:
//
//	talos-amd64/talos.spdx.json
//	gvisor-amd64/gvisor.spdx.json
func (f *Frontend) handleSPDX(ctx context.Context, w http.ResponseWriter, r *http.Request, p httprouter.Params) error {
	schematicID := p.ByName("schematic")

	// Validate schematic exists
	if _, err := f.schematicFactory.Get(ctx, schematicID); err != nil {
		return err
	}

	versionTag := p.ByName("version")
	if !strings.HasPrefix(versionTag, "v") {
		versionTag = "v" + versionTag
	}

	// Validate version format
	version, err := semver.Parse(versionTag[1:])
	if err != nil {
		return fmt.Errorf("error parsing version: %w", err)
	}

	// Build/retrieve SPDX bundle
	bundle, err := f.spdxBuilder.Build(ctx, schematicID, versionTag)
	if err != nil {
		return err
	}

	// Generate filename for download
	// Use first 12 characters of schematic ID for brevity
	shortID := schematicID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}

	filename := fmt.Sprintf("spdx-%s-%s.tar", shortID, version.String())

	// Set download headers
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Length", strconv.FormatInt(bundle.Size(), 10))
	w.WriteHeader(http.StatusOK)

	if r.Method == http.MethodHead {
		return nil
	}

	// Stream response
	reader, err := bundle.Reader()
	if err != nil {
		return err
	}

	defer reader.Close() //nolint:errcheck

	_, err = io.Copy(w, reader)

	return err
}
