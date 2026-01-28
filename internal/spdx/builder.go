// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package spdx

import (
	"context"
	"fmt"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/siderolabs/gen/value"
	"github.com/siderolabs/gen/xerrors"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"

	"github.com/siderolabs/image-factory/internal/artifacts"
	"github.com/siderolabs/image-factory/internal/schematic"
	"github.com/siderolabs/image-factory/internal/spdx/storage"
	schematicpkg "github.com/siderolabs/image-factory/pkg/schematic"
)

// SPDXExtractor defines the interface for extracting SPDX files from images.
type SPDXExtractor interface {
	// GetOfficialExtensions returns the list of official extensions for a version.
	GetOfficialExtensions(ctx context.Context, versionString string) ([]artifacts.ExtensionRef, error)

	// ExtractExtensionSPDX extracts SPDX files from an extension image.
	ExtractExtensionSPDX(ctx context.Context, arch artifacts.Arch, ref artifacts.ExtensionRef) ([]artifacts.SPDXFile, error)

	// ExtractInstallerSPDX extracts SPDX files from a Talos installer image.
	ExtractInstallerSPDX(ctx context.Context, arch artifacts.Arch, version string) ([]artifacts.SPDXFile, error)
}

// Builder orchestrates SPDX extraction and caching.
type Builder struct {
	storage          storage.Storage
	extractor        SPDXExtractor
	schematicFactory *schematic.Factory
	logger           *zap.Logger
	sf               singleflight.Group
}

// NewBuilder creates a new SPDX bundle builder.
func NewBuilder(
	logger *zap.Logger,
	storage storage.Storage,
	extractor SPDXExtractor,
	schematicFactory *schematic.Factory,
) *Builder {
	return &Builder{
		storage:          storage,
		extractor:        extractor,
		schematicFactory: schematicFactory,
		logger:           logger.With(zap.String("component", "spdx-builder")),
	}
}

// Build returns an SPDX bundle, building and caching if necessary.
func (b *Builder) Build(ctx context.Context, schematicID, versionTag string) (storage.Bundle, error) {
	// Normalize version tag
	if !strings.HasPrefix(versionTag, "v") {
		versionTag = "v" + versionTag
	}

	// Validate version format
	if _, err := semver.Parse(versionTag[1:]); err != nil {
		return nil, fmt.Errorf("invalid version: %w", err)
	}

	// Check cache first
	if err := b.storage.Head(ctx, schematicID, versionTag); err == nil {
		b.logger.Debug("SPDX bundle cache hit", zap.String("schematic", schematicID), zap.String("version", versionTag))

		return b.storage.Get(ctx, schematicID, versionTag)
	}

	// Build the bundle using singleflight to prevent duplicate work
	cacheKey := CacheTag(schematicID, versionTag)

	resultCh := b.sf.DoChan(cacheKey, func() (any, error) {
		return b.buildBundle(schematicID, versionTag) //nolint:contextcheck
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-resultCh:
		if result.Err != nil {
			return nil, result.Err
		}

		// Retrieve from cache after building
		return b.storage.Get(ctx, schematicID, versionTag)
	}
}

// buildBundle creates and stores an SPDX bundle.
func (b *Builder) buildBundle(schematicID, versionTag string) (any, error) {
	// Use a fresh context since we're in singleflight
	ctx := context.Background()

	logger := b.logger.With(zap.String("schematic", schematicID), zap.String("version", versionTag))

	logger.Info("building SPDX bundle")

	// Get the schematic to find extensions
	schematicData, err := b.schematicFactory.Get(ctx, schematicID)
	if err != nil {
		return nil, fmt.Errorf("failed to get schematic: %w", err)
	}

	bundle := &Bundle{
		SchematicID:  schematicID,
		TalosVersion: versionTag,
		Files:        []File{},
	}

	// Extract SPDX from Talos installer for both architectures
	for _, arch := range []artifacts.Arch{artifacts.ArchAmd64, artifacts.ArchArm64} {
		files, err := b.extractor.ExtractInstallerSPDX(ctx, arch, versionTag)
		if err != nil {
			logger.Warn("failed to extract SPDX from Talos installer",
				zap.String("arch", string(arch)),
				zap.Error(err))
		} else {
			// Convert and add arch suffix to source to distinguish
			for _, f := range files {
				logger.Debug("adding SPDX file from Talos installer",
					zap.String("filename", f.Filename),
					zap.String("arch", string(arch)))

				bundle.Files = append(bundle.Files, File{
					Filename: f.Filename,
					Source:   fmt.Sprintf("talos-%s", arch),
					Content:  f.Content,
				})
			}
		}
	}

	logger.Debug("building SPDX bundle from extensions",
		zap.Int("extensions", len(schematicData.Customization.SystemExtensions.OfficialExtensions)))

	// Extract SPDX from extensions
	if len(schematicData.Customization.SystemExtensions.OfficialExtensions) > 0 {
		if err := b.extractExtensionsSPDX(ctx, bundle, schematicData, versionTag); err != nil {
			logger.Warn("failed to extract SPDX from some extensions", zap.Error(err))
		}
	}

	// Check if we have any files
	if len(bundle.Files) == 0 {
		return nil, xerrors.NewTaggedf[storage.ErrNotFoundTag]("no SPDX files found for schematic %q version %q", schematicID, versionTag)
	}

	// Create tar archive
	tarReader, size, err := BundleToTar(bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to create tar archive: %w", err)
	}

	// Store the bundle
	if err := b.storage.Put(ctx, schematicID, versionTag, tarReader, size); err != nil {
		return nil, fmt.Errorf("failed to store SPDX bundle: %w", err)
	}

	logger.Info("SPDX bundle created", zap.Int("files", len(bundle.Files)))

	return nil, nil
}

// extractExtensionsSPDX extracts SPDX from all extensions in the schematic.
func (b *Builder) extractExtensionsSPDX(ctx context.Context, bundle *Bundle, schematicData *schematicpkg.Schematic, versionTag string) error {
	availableExtensions, err := b.extractor.GetOfficialExtensions(ctx, versionTag)
	if err != nil {
		return fmt.Errorf("failed to get official extensions: %w", err)
	}

	for _, extensionName := range schematicData.Customization.SystemExtensions.OfficialExtensions {
		extensionRef := findExtension(availableExtensions, extensionName)

		if value.IsZero(extensionRef) {
			// Try with aliases
			if aliasedName, ok := extensionNameAlias(extensionName); ok {
				extensionRef = findExtension(availableExtensions, aliasedName)
			}
		}

		if value.IsZero(extensionRef) {
			b.logger.Warn("extension not found, skipping SPDX extraction",
				zap.String("extension", extensionName),
				zap.String("version", versionTag))

			continue
		}

		// Extract SPDX for both architectures
		for _, arch := range []artifacts.Arch{artifacts.ArchAmd64, artifacts.ArchArm64} {
			files, err := b.extractor.ExtractExtensionSPDX(ctx, arch, extensionRef)
			if err != nil {
				b.logger.Warn("failed to extract SPDX from extension",
					zap.String("extension", extensionName),
					zap.String("arch", string(arch)),
					zap.Error(err))

				continue
			}

			if len(files) == 0 {
				b.logger.Debug("no SPDX files in extension",
					zap.String("extension", extensionName),
					zap.String("arch", string(arch)))

				continue
			}

			// Set the source to the extension name with arch
			shortName := extensionName
			if idx := strings.LastIndex(extensionName, "/"); idx >= 0 {
				shortName = extensionName[idx+1:]
			}

			for _, f := range files {
				bundle.Files = append(bundle.Files, File{
					Filename: f.Filename,
					Source:   fmt.Sprintf("%s-%s", shortName, arch),
					Content:  f.Content,
				})
			}
		}
	}

	return nil
}

// findExtension finds an extension by name in the available extensions list.
func findExtension(availableExtensions []artifacts.ExtensionRef, extensionName string) artifacts.ExtensionRef {
	for _, availableExtension := range availableExtensions {
		if availableExtension.TaggedReference.RepositoryStr() == extensionName {
			return availableExtension
		}
	}

	return artifacts.ExtensionRef{}
}

// extensionNameAlias returns the aliased name for an extension if it exists.
func extensionNameAlias(extensionName string) (string, bool) {
	switch extensionName {
	case "siderolabs/v4l-uvc":
		return "siderolabs/v4l-uvc-drivers", true
	case "siderolabs/usb-modem":
		return "siderolabs/usb-modem-drivers", true
	case "siderolabs/gasket":
		return "siderolabs/gasket-driver", true
	case "siderolabs/talos-vmtoolsd":
		return "siderolabs/vmtoolsd-guest-agent", true
	case "siderolabs/xe-guest-utilities":
		return "siderolabs/xen-guest-agent", true
	case "siderolabs/nvidia-container-toolkit":
		return "siderolabs/nvidia-container-toolkit-lts", true
	case "siderolabs/nvidia-open-gpu-kernel-modules":
		return "siderolabs/nvidia-open-gpu-kernel-modules-lts", true
	case "siderolabs/nonfree-kmod-nvidia":
		return "siderolabs/nonfree-kmod-nvidia-lts", true
	case "siderolabs/nvidia-fabricmanager":
		return "siderolabs/nvidia-fabric-manager-lts", true
	case "siderolabs/i915-ucode":
		return "siderolabs/i915", true
	case "siderolabs/amdgpu-firmware":
		return "siderolabs/amdgpu", true
	default:
		return "", false
	}
}
