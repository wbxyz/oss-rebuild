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

package archive

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"io"

	"github.com/pkg/errors"
)

// Canonicalize selects and applies the canonicalization routine for the given archive format.
func Canonicalize(dst io.Writer, src io.Reader, f Format) error {
	switch f {
	case ZipFormat:
		srcReader, size, err := toZipCompatibleReader(src)
		if err != nil {
			return errors.Wrap(err, "converting reader")
		}
		zr, err := zip.NewReader(srcReader, size)
		if err != nil {
			return errors.Wrap(err, "initializing zip reader")
		}
		zw := zip.NewWriter(dst)
		defer zw.Close()
		err = CanonicalizeZip(zr, zw)
		if err != nil {
			return errors.Wrap(err, "canonicalizing zip")
		}
	case TarGzFormat:
		gzr, err := gzip.NewReader(src)
		if err != nil {
			return errors.Wrap(err, "initializing gzip reader")
		}
		defer gzr.Close()
		gzw := gzip.NewWriter(dst)
		defer gzw.Close()
		err = CanonicalizeTar(tar.NewReader(gzr), tar.NewWriter(gzw))
		if err != nil {
			return errors.Wrap(err, "canonicalizing tar")
		}
	default:
		return errors.New("unsupported archive type")
	}
	return nil
}

// NewContentSummary constructs a ContentSummary for the given archive format.
func NewContentSummary(src io.Reader, f Format) (*ContentSummary, error) {
	switch f {
	case ZipFormat:
		srcReader, size, err := toZipCompatibleReader(src)
		if err != nil {
			return nil, errors.Wrap(err, "converting reader")
		}
		zr, err := zip.NewReader(srcReader, size)
		if err != nil {
			return nil, errors.Wrap(err, "initializing zip reader")
		}
		return NewContentSummaryFromZip(zr)
	case TarGzFormat:
		gzr, err := gzip.NewReader(src)
		if err != nil {
			return nil, errors.Wrap(err, "initializing gzip reader")
		}
		defer gzr.Close()
		return NewContentSummaryFromTar(tar.NewReader(gzr))
	default:
		return nil, errors.New("unsupported archive type")
	}
}
