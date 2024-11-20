// Copyright 2024 The OSS Rebuild Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package debian

import (
	"bytes"
	"context"
	"strings"

	billy "github.com/go-git/go-billy/v5"
	"github.com/google/oss-rebuild/pkg/rebuild/rebuild"
	"github.com/pkg/errors"
)

type Rebuilder struct{}

var _ rebuild.Rebuilder = Rebuilder{}

// We expect target.Packge to be in the form "<component>/<name>".
func ParseComponent(pkg string) (component, name string, err error) {
	component, name, found := strings.Cut(pkg, "/")
	if !found {
		return "", "", errors.Errorf("failed to parse debian component: %s", pkg)
	}
	return component, name, nil
}

func (Rebuilder) Rebuild(ctx context.Context, t rebuild.Target, inst rebuild.Instructions, fs billy.Filesystem) error {
	if _, err := rebuild.ExecuteScript(ctx, fs.Root(), inst.Source); err != nil {
		return errors.Wrap(err, "failed to execute strategy.Source")
	}
	if _, err := rebuild.ExecuteScript(ctx, fs.Root(), inst.Deps); err != nil {
		return errors.Wrap(err, "failed to execute strategy.Deps")
	}
	if _, err := rebuild.ExecuteScript(ctx, fs.Root(), inst.Build); err != nil {
		return errors.Wrap(err, "failed to execute strategy.Build")
	}
	return nil
}

func (Rebuilder) Compare(ctx context.Context, t rebuild.Target, rb, up rebuild.Asset, assets rebuild.AssetStore, inst rebuild.Instructions) (msg error, err error) {
	// TODO: Add content summary support for deb packages (rebuild.Summarize).
	rbb := new(bytes.Buffer)
	upb := new(bytes.Buffer)

	{
		rbr, err := assets.Reader(ctx, rb)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to find rebuilt artifact")
		}
		defer rbr.Close()
		if _, err = rbb.ReadFrom(rbr); err != nil {
			return nil, errors.Wrapf(err, "failed to read rebuilt artifact")
		}
	}
	{
		upr, err := assets.Reader(ctx, up)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to find upstream artifact")
		}
		defer upr.Close()
		if _, err = upb.ReadFrom(upr); err != nil {
			return nil, errors.Wrapf(err, "failed to read upstream artifact")
		}
	}

	if rbb.Len() > upb.Len() {
		return errors.New("rebuild is larger than upstream"), nil
	} else if rbb.Len() < upb.Len() {
		return errors.New("upstream is larger than rebuild"), nil
	}
	if !bytes.Equal(upb.Bytes(), rbb.Bytes()) {
		return errors.New("content differences found"), nil
	}
	return nil, nil
}

// RebuildMany executes rebuilds for each provided rebuild.Input returning their rebuild.Verdicts.
func RebuildMany(ctx context.Context, inputs []rebuild.Input, mux rebuild.RegistryMux) ([]rebuild.Verdict, error) {
	return rebuild.RebuildMany(ctx, Rebuilder{}, inputs, mux)
}

// RebuildRemote executes the given target strategy on a remote builder.
func RebuildRemote(ctx context.Context, input rebuild.Input, id string, opts rebuild.RemoteOptions) error {
	opts.UseTimewarp = false
	return rebuild.RebuildRemote(ctx, input, id, opts)
}