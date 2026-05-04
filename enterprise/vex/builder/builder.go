// Copyright (c) 2026 Sidero Labs, Inc.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.

//go:build enterprise

// Package builder produces VEX documents from a signed OCI VEX data image.
package builder

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/siderolabs/go-vex/pkg/types/v1alpha1"
	"github.com/siderolabs/go-vex/pkg/vexgen"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"

	"github.com/siderolabs/image-factory/internal/image/verify"
	"github.com/siderolabs/image-factory/internal/remotewrap"
)

// FetchTimeout caps an OCI fetch + signature verification.
const FetchTimeout = 5 * time.Minute

// DefaultDataTag is the OCI tag pulled when no override is configured.
const DefaultDataTag = "latest"

// Builder produces VEX documents for a Talos version, with TTL caching and singleflight.
type Builder struct {
	puller        remotewrap.Puller
	sf            singleflight.Group
	logger        *zap.Logger
	cache         map[string]cachedDoc
	registry      string
	dataTag       string
	verifyOptions verify.VerifyOptions
	cacheTTL      time.Duration
	mu            sync.RWMutex
	insecure      bool
}

// Options configures Builder.
type Options struct {
	Registry        string
	DataTag         string
	RemoteOptions   []remote.Option
	VerifyOptions   verify.VerifyOptions
	RefreshInterval time.Duration
	CacheTTL        time.Duration
	Insecure        bool
}

type cachedDoc struct {
	expiresAt time.Time
	data      []byte
}

// NewBuilder constructs a Builder.
func NewBuilder(logger *zap.Logger, opts Options) (*Builder, error) {
	puller, err := remotewrap.NewPuller(opts.RefreshInterval, opts.RemoteOptions...)
	if err != nil {
		return nil, fmt.Errorf("error creating puller: %w", err)
	}

	dataTag := opts.DataTag
	if dataTag == "" {
		dataTag = DefaultDataTag
	}

	return &Builder{
		puller:        puller,
		registry:      opts.Registry,
		dataTag:       dataTag,
		insecure:      opts.Insecure,
		verifyOptions: opts.VerifyOptions,
		cacheTTL:      opts.CacheTTL,
		cache:         make(map[string]cachedDoc),
		logger:        logger.With(zap.String("component", "vex-builder")),
	}, nil
}

// Build returns a serialized VEX JSON document for the given Talos version tag.
//
// Cached per versionTag with TTL. Concurrent calls for the same tag share one OCI fetch
// via singleflight. The fetch runs under a detached context so request cancellations
// don't poison the shared work.
func (b *Builder) Build(ctx context.Context, versionTag string) ([]byte, error) {
	if data, ok := b.getCached(versionTag); ok {
		return data, nil
	}

	resultCh := b.sf.DoChan(versionTag, func() (any, error) { //nolint:contextcheck
		return b.buildAndCache(versionTag)
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resultCh:
		if res.Err != nil {
			return nil, res.Err
		}

		data, ok := res.Val.([]byte)
		if !ok {
			return nil, fmt.Errorf("unexpected result type: %T", res.Val)
		}

		return data, nil
	}
}

func (b *Builder) getCached(versionTag string) ([]byte, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	item, ok := b.cache[versionTag]
	if !ok {
		return nil, false
	}

	if time.Now().After(item.expiresAt) {
		return nil, false
	}

	return item.data, true
}

func (b *Builder) setCached(versionTag string, data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.cache[versionTag] = cachedDoc{
		data:      data,
		expiresAt: time.Now().Add(b.cacheTTL),
	}
}

// buildAndCache runs under singleflight with a detached context.
func (b *Builder) buildAndCache(versionTag string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), FetchTimeout)
	defer cancel()

	expData, err := b.fetchExploitabilityData(ctx)
	if err != nil {
		return nil, fmt.Errorf("error fetching VEX data: %w", err)
	}

	now := time.Now()

	doc, err := vexgen.Populate(expData, versionTag, &now, "image-factory")
	if err != nil {
		return nil, fmt.Errorf("error generating VEX document: %w", err)
	}

	var buf bytes.Buffer
	if err = vexgen.Serialize(doc, &buf); err != nil {
		return nil, fmt.Errorf("error serializing VEX document: %w", err)
	}

	data := buf.Bytes()
	b.setCached(versionTag, data)

	return data, nil
}

// fetchExploitabilityData heads the configured OCI tag, verifies the signature on the resolved digest,
// pulls the image, and extracts the first regular file from the first layer.
func (b *Builder) fetchExploitabilityData(ctx context.Context) (*v1alpha1.ExploitabilityData, error) {
	var nameOpts []name.Option

	if b.insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}

	tagRef, err := name.NewTag(fmt.Sprintf("%s:%s", b.registry, b.dataTag), nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("error parsing reference: %w", err)
	}

	descriptor, err := b.puller.Head(ctx, tagRef)
	if err != nil {
		return nil, fmt.Errorf("error heading VEX image: %w", err)
	}

	digestRef := tagRef.Digest(descriptor.Digest.String())

	logger := b.logger.With(zap.Stringer("image", digestRef))

	logger.Debug("verifying VEX image signature")

	verifyResult, err := verify.VerifySignatures(ctx, digestRef, b.verifyOptions, nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to verify VEX image signature for %s: %w", digestRef.Name(), err)
	}

	logger.Info("VEX image signature verified",
		zap.String("verification_method", verifyResult.Method),
		zap.Bool("bundle_verified", verifyResult.Verified))

	imgDesc, err := b.puller.Get(ctx, digestRef)
	if err != nil {
		return nil, fmt.Errorf("error fetching VEX image: %w", err)
	}

	img, err := imgDesc.Image()
	if err != nil {
		return nil, fmt.Errorf("error reading VEX image: %w", err)
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("error getting VEX layers: %w", err)
	}

	if len(layers) == 0 {
		return nil, fmt.Errorf("no layers found in VEX data image")
	}

	reader, err := layers[0].Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("error getting layer content: %w", err)
	}
	defer reader.Close() //nolint:errcheck

	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("error reading VEX data archive: %w", err)
		}

		if header.Typeflag == tar.TypeReg {
			return v1alpha1.LoadExploitabilityData(tarReader)
		}
	}

	return nil, fmt.Errorf("no data file found in VEX data image")
}
