// Copyright (c) 2026 Sidero Labs, Inc.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.

//go:build enterprise

package auth

import "context"

type authContextKey struct{}

func GetAuthUsername(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(authContextKey{}).(string)

	return username, ok
}

// WithAuthUsername returns a derived context carrying the authenticated username.
//
// Used to forward the request-bound identity across detached contexts (e.g.,
// singleflight callbacks running with context.Background()) so that downstream
// ownership checks continue to see the originating user.
func WithAuthUsername(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, authContextKey{}, username)
}
