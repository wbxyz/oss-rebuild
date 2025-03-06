// Copyright 2025 Google LLC
// SPDX-License-Identifier: Apache-2.0

package debian

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/oss-rebuild/internal/httpx"
	"github.com/pkg/errors"
)

var (
	registryURL         = "https://deb.debian.org/debian/pool/"
	buildinfoURL        = "https://buildinfos.debian.net/buildinfo-pool/"
	snapshotURL         = "https://snapshot.debian.org/"
	binaryReleaseRegexp = regexp.MustCompile(`(\+b[\d\.]+)$`)
	versionRegex        = regexp.MustCompile(`^(?P<name>[^_]+)_(?P<nonbinary_version>[^_+]+)(?P<binary_version>\+.*)?_(?P<arch>[^_]+)\.deb$`)
)

type ControlStanza struct {
	Fields map[string][]string
}

type DSC struct {
	Stanzas []ControlStanza
}

// Registry is a debian package registry.
type Registry interface {
	Artifact(context.Context, string, string, string) (io.ReadCloser, error)
	DSC(context.Context, string, string, string) (string, *DSC, error)
}

// HTTPRegistry is a Registry implementation that uses the debian HTTP API.
type HTTPRegistry struct {
	Client httpx.BasicClient
}

func (r HTTPRegistry) get(ctx context.Context, url string) (io.ReadCloser, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, errors.Wrap(errors.New(resp.Status), "fetching artifact")
	}
	return resp.Body, nil
}

func poolDir(name string) string {
	// Most packages are in a prefix dir matching their first letter.
	prefixDir := name[0:1]
	// "lib" is such a common prefix that these packages are subdivided into lib* directories.
	if strings.HasPrefix(name, "lib") {
		prefixDir = name[0:4]
	}
	return prefixDir
}

func PoolURL(component, name, artifact string) string {
	return registryURL + fmt.Sprintf("%s/%s/%s/%s", component, poolDir(name), name, artifact)
}

func BuildInfoURL(name, version, arch string) string {
	file := fmt.Sprintf("%s_%s_%s.buildinfo", name, version, arch)
	return buildinfoURL + fmt.Sprintf("%s/%s/%s", poolDir(name), name, file)
}

func guessDSCURL(component, name, version string) string {
	cleanVersion := binaryReleaseRegexp.ReplaceAllString(version, "")
	return PoolURL(component, name, fmt.Sprintf("%s_%s.dsc", name, cleanVersion))
}

func parseDSC(r io.ReadCloser) (*DSC, error) {
	b := bufio.NewScanner(r)
	if !b.Scan() {
		return nil, errors.New("failed to scan .dsc file")
	}
	// Skip PGP signature header.
	if strings.HasPrefix(b.Text(), "-----BEGIN PGP SIGNED MESSAGE-----") {
		b.Scan()
	}
	d := DSC{}
	stanza := ControlStanza{Fields: map[string][]string{}}
	var lastField string
	for {
		// Check for PGP signature footer.
		if strings.HasPrefix(b.Text(), "-----BEGIN PGP SIGNATURE-----") {
			break
		}
		line := b.Text()
		if strings.TrimSpace(line) == "" {
			// Handle empty lines as stanza separators.
			if len(stanza.Fields) > 0 {
				d.Stanzas = append(d.Stanzas, stanza)
				stanza = ControlStanza{Fields: map[string][]string{}}
				lastField = ""
			}
		} else if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			// Handle continuation lines.
			if lastField != "" {
				stanza.Fields[lastField] = append(stanza.Fields[lastField], strings.TrimSpace(line))
			} else {
				return nil, errors.Errorf("unexpected continuation line")
			}
		} else {
			// Handle new field.
			field, value, found := strings.Cut(line, ":")
			if !found {
				return nil, errors.Errorf("expected new field: %v", line)
			}
			if _, ok := stanza.Fields[field]; ok {
				return nil, errors.Errorf("duplicate field in stanza: %s", field)
			}
			stanza.Fields[field] = []string{}
			// Skip empty first lines (start of a multiline field).
			if strings.TrimSpace(value) != "" {
				stanza.Fields[field] = []string{strings.TrimSpace(value)}
			}
			lastField = field
		}
		if !b.Scan() {
			break
		}
	}
	// Add the final stanza if it's not empty.
	if len(stanza.Fields) > 0 {
		d.Stanzas = append(d.Stanzas, stanza)
	}

	return &d, nil
}

func (r HTTPRegistry) DSC(ctx context.Context, component, name, version string) (string, *DSC, error) {
	DSCURI := guessDSCURL(component, name, version)
	re, err := r.get(ctx, DSCURI)
	if err != nil {
		return "", nil, errors.Wrapf(err, "failed to get .dsc file %s", DSCURI)
	}
	d, err := parseDSC(re)
	return DSCURI, d, err
}

type DebianArtifact struct {
	// Name is the name of the artifact (different from the source package)
	Name string
	// NonBinaryVersion is the version string, stripped of any binary-only suffix
	NonBinaryVersion string
	// BinaryVersion contains any binary-only suffix
	BinaryVersion string
	// Arch is the target architecture
	Arch string
}

func ParseDebianArtifact(artifact string) (DebianArtifact, error) {
	matches := versionRegex.FindStringSubmatch(artifact)
	if matches == nil {
		return DebianArtifact{}, errors.Errorf("unexpected artifact name: %s", artifact)
	}
	a := DebianArtifact{
		Name:             matches[versionRegex.SubexpIndex("name")],
		NonBinaryVersion: matches[versionRegex.SubexpIndex("nonbinary_version")],
		BinaryVersion:    matches[versionRegex.SubexpIndex("binary_version")],
		Arch:             matches[versionRegex.SubexpIndex("arch")],
	}
	if strings.HasPrefix(a.BinaryVersion, "+deb") {
		a.NonBinaryVersion += a.BinaryVersion
		a.BinaryVersion = ""
	}
	return a, nil
}

// fileInfo is the response from the binfiles endpoint on the snapshot service.
type fileInfo struct {
	// FileInfo is a map from file hash to extra info
	FileInfo map[string][]struct {
		Name string
	}
	// Result is a list of file hashes with architecture
	Result []struct {
		Architecture string
		Hash         string
	}
}

// Artifact returns the package artifact for the given package version.
func (r HTTPRegistry) Artifact(ctx context.Context, component, name, artifact string) (io.ReadCloser, error) {
	// Example series of urls to follow:
	// https://snapshot.debian.org/mr/binary/acl/
	// https://snapshot.debian.org/mr/package/acl/2.3.2-2/binfiles/libacl1/2.3.2-2+b1?fileinfo=1
	// https://snapshot.debian.org/file/53f2b0612c8ed8a60970f9a206ae65eb84681f6e
	a, err := ParseDebianArtifact(artifact)
	if err != nil {
		return nil, err
	}
	var response fileInfo
	{
		r, err := r.get(ctx, fmt.Sprintf("%s/mr/package/%s/%s/binfiles/%s/%s%s?fileinfo=1", snapshotURL, name, a.NonBinaryVersion, a.Name, a.NonBinaryVersion, a.BinaryVersion))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		if err = json.NewDecoder(r).Decode(&response); err != nil {
			return nil, err
		}
	}
	var hash string
	for _, f := range response.Result {
		if f.Architecture == a.Arch {
			hash = f.Hash
			break
		}
	}
	if hash == "" {
		return nil, errors.New("no matching architecture found")
	}
	// Verify we found the correct artifact
	{
		found, ok := response.FileInfo[hash]
		if !ok || len(found) != 1 || found[0].Name != artifact {
			return nil, errors.Errorf("artifact name doesn't match, want %s, found: %+v", artifact, found)
		}
	}
	return r.get(ctx, fmt.Sprintf("%s/file/%s", snapshotURL, hash))
}

var _ Registry = &HTTPRegistry{}
