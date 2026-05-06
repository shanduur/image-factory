// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package cache_test

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"golang.org/x/sync/errgroup"

	"github.com/siderolabs/image-factory/internal/cache"
)

func TestStartStop(t *testing.T) {
	t.Parallel()

	c := cache.New[string, int](cache.Options{
		MetricsName: "test_cache_size",
		MetricsHelp: "test",
		Capacity:    10,
	})

	var eg errgroup.Group

	eg.Go(c.Start)

	t.Cleanup(func() {
		time.Sleep(50 * time.Millisecond)
		c.Stop()
		require.NoError(t, eg.Wait())
	})

	c.TTL.Set("a", 1, time.Minute)
	item := c.TTL.Get("a")
	require.NotNil(t, item)
	assert.Equal(t, 1, item.Value())
}

func TestCapacityEviction(t *testing.T) {
	t.Parallel()

	c := cache.New[string, int](cache.Options{
		MetricsName: "test_cache_size",
		MetricsHelp: "test",
		Capacity:    2,
	})

	c.TTL.Set("a", 1, time.Minute)
	c.TTL.Set("b", 2, time.Minute)
	c.TTL.Set("c", 3, time.Minute)

	assert.LessOrEqual(t, c.TTL.Len(), 2)
}

func TestTTLExpiry(t *testing.T) {
	t.Parallel()

	c := cache.New[string, int](cache.Options{
		MetricsName: "test_cache_size",
		MetricsHelp: "test",
		Capacity:    10,
	})

	c.TTL.Set("a", 1, time.Nanosecond)

	time.Sleep(5 * time.Millisecond)

	item := c.TTL.Get("a")
	if item != nil {
		assert.True(t, item.IsExpired())
	}
}

func TestMetrics(t *testing.T) {
	t.Parallel()

	c := cache.New[string, int](cache.Options{
		MetricsName: "image_factory_test_cache_size",
		MetricsHelp: "test",
		Capacity:    10,
	})

	c.TTL.Set("a", 1, time.Minute)
	c.TTL.Set("b", 2, time.Minute)

	problems, err := testutil.CollectAndLint(c)
	require.NoError(t, err)
	assert.Empty(t, problems)

	assert.Equal(t, 1, testutil.CollectAndCount(c))
}

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
