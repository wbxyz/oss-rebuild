package localfiles

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	gcs "cloud.google.com/go/storage"
	"github.com/google/oss-rebuild/internal/gcb"
	"github.com/google/oss-rebuild/pkg/rebuild/rebuild"
	"github.com/pkg/errors"
)

type LocalCache struct {
	MetadataBucket string
	LogsBucket     string
	DebugBucket    string
	Mux            rebuild.RegistryMux
}

func NewLocalCache(metadataBucket, logsBucket, debugBucket string, mux rebuild.RegistryMux) *LocalCache {
	return &LocalCache{
		MetadataBucket: metadataBucket,
		LogsBucket:     logsBucket,
		DebugBucket:    debugBucket,
		Mux:            mux,
	}
}

func (c *LocalCache) Fetch(ctx context.Context, runID string, wasSmoketest bool, want rebuild.Asset) (path string, err error) {
	ctx = context.WithValue(ctx, rebuild.RunID, runID)
	localAssets, err := AssetStore(runID)
	if err != nil {
		return "", err
	}
	if _, err := localAssets.Reader(ctx, want); err == nil {
		return localAssets.URL(want).Path, nil
	}
	debugAssets, err := rebuild.DebugStoreFromContext(context.WithValue(ctx, rebuild.DebugStoreID, c.DebugBucket))
	if err != nil {
		return "", errors.Wrap(err, "failed to create debug asset store")
	}
	switch want.Type {
	case rebuild.DebugUpstreamAsset:
		if wasSmoketest {
			err = rebuild.AssetCopy(ctx, localAssets, debugAssets, want)
			if err != nil {
				return "", err
			}
			return localAssets.URL(want).Path, nil
		}
		// RebuildRemote doesn't store the upstream, so we have to re-download it.
		// If RebuildRemote stored the upstream in the debug bucket, this wouldn't be necessary.
		w, err := localAssets.Writer(ctx, want)
		if err != nil {
			return "", errors.Wrap(err, "making localAsset writer")
		}
		defer w.Close()
		r, err := rebuild.UpstreamArtifactReader(ctx, want.Target, c.Mux)
		if err != nil {
			return "", errors.Wrap(err, "making upstream artifact reader")
		}
		defer r.Close()
		if _, err := io.Copy(w, r); err != nil {
			return "", errors.Wrap(err, "failed to download upstream artifact")
		}
		return localAssets.URL(want).Path, nil
	case rebuild.RebuildAsset, rebuild.TetragonLogAsset:
		// RebuildRemote stores the RebuildAsset and TetragonLogAsset in the metadata bucket.
		// If rebuild remote copied the rebuild artifact into debug, this wouldn't be necessary.
		if wasSmoketest {
			return "", fmt.Errorf("asset type not supported during smoketest: %s", want.Type)
		}
		var bi rebuild.BuildInfo
		{
			r, err := debugAssets.Reader(ctx, rebuild.BuildInfoAsset.For(want.Target))
			if err != nil {
				return "", errors.Wrap(err, "reading build info")
			}
			if json.NewDecoder(r).Decode(&bi) != nil {
				return "", errors.Wrap(err, "parsing build info")
			}
		}
		metadata, err := rebuild.NewGCSStore(context.WithValue(ctx, rebuild.RunID, bi.ID), fmt.Sprintf("gs://%s", c.MetadataBucket))
		if err != nil {
			return "", errors.Wrap(err, "initializing metadata store")
		}
		if err := rebuild.AssetCopy(ctx, localAssets, metadata, want); err != nil {
			return "", errors.Wrap(err, "failed to copy rebuild asset")
		}
		return localAssets.URL(want).Path, nil
	case rebuild.DebugLogsAsset:
		if wasSmoketest {
			err = rebuild.AssetCopy(ctx, localAssets, debugAssets, want)
			if err != nil {
				return "", err
			}
			return localAssets.URL(want).Path, nil
		}
		// Rebuild Remote
		var bi rebuild.BuildInfo
		{
			r, err := debugAssets.Reader(ctx, rebuild.BuildInfoAsset.For(want.Target))
			if err != nil {
				return "", errors.Wrap(err, "reading build info")
			}
			if json.NewDecoder(r).Decode(&bi) != nil {
				return "", errors.Wrap(err, "parsing build info")
			}
		}
		if bi.BuildID == "" {
			return "", errors.New("BuildID is empty, cannot read gcb logs")
		}
		client, err := gcs.NewClient(ctx)
		if err != nil {
			return "", errors.Wrap(err, "creating gcs client")
		}
		obj := client.Bucket(c.LogsBucket).Object(gcb.MergedLogFile(bi.BuildID))
		r, err := obj.NewReader(ctx)
		if err != nil {
			return "", errors.Wrap(err, "reading gcb logs")
		}
		defer r.Close()
		w, err := localAssets.Writer(ctx, want)
		if err != nil {
			return "", errors.Wrap(err, "making localAsset writer")
		}
		defer w.Close()
		if _, err := io.Copy(w, r); err != nil {
			return "", errors.Wrap(err, "writing logs")
		}
		if err := w.Close(); err != nil {
			return "", errors.Wrap(err, "closing localAsset writer")
		}
		return localAssets.URL(want).Path, nil
	case rebuild.DebugRebuildAsset:
		err = rebuild.AssetCopy(ctx, localAssets, debugAssets, want)
		if err != nil {
			return "", err
		}
		return localAssets.URL(want).Path, nil
	default:
		return "", fmt.Errorf("Unsupported asset type: %s", want.Type)
	}
}
