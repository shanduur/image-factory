// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package storage defines the interface for SPDX bundle storage.
package storage

import (
	"context"
	"io"
)

// Storage is the SPDX bundle storage interface.
type Storage interface {
	// Head checks if a bundle exists for the given schematic and version.
	Head(ctx context.Context, schematicID, version string) error

	// Get retrieves a bundle for the given schematic and version.
	Get(ctx context.Context, schematicID, version string) (Bundle, error)

	// Put stores a bundle.
	Put(ctx context.Context, schematicID, version string, data io.Reader, size int64) error
}

// Bundle represents a stored SPDX bundle that can be read.
type Bundle interface {
	// Reader returns a reader for the bundle content.
	Reader() (io.ReadCloser, error)

	// Size returns the size of the bundle in bytes.
	Size() int64
}

// ErrNotFoundTag tags the errors when the SPDX bundle is not found.
type ErrNotFoundTag = struct{}
