// Copyright 2025 Google LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"path"
	"slices"
	"strings"

	gcs "cloud.google.com/go/storage"
	"github.com/google/oss-rebuild/pkg/attestation"
	"github.com/google/oss-rebuild/pkg/rebuild/rebuild"
	"github.com/pkg/errors"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/spf13/cobra"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

var (
	output       = flag.String("output", "payload", "Output format [bundle, payload, dockerfile, build, steps]")
	bucket       = flag.String("bucket", "google-rebuild-attestations", "GCS bucket from which to pull rebuild attestations")
	verify       = flag.Bool("verify", true, "whether to verify rebuild attestation signatures")
	verifyWith   = flag.String("verify-with", ossRebuildKeyURI, "comma-separated list of key URIs used to verify rebuild attestation signatures")
	verifyOnline = flag.Bool("verify-online", false, "whether to always fetch --verify-with key contents, ignoring embedded contents")
)

var rootCmd = &cobra.Command{
	Use:   "oss-rebuild [subcommand]",
	Short: "A CLI tool for OSS Rebuild",
}

func writeIndentedJson(out io.Writer, b []byte) error {
	var decoded any
	if err := json.NewDecoder(bytes.NewBuffer(b)).Decode(&decoded); err != nil {
		return errors.Wrap(err, "decoding json")
	}
	e := json.NewEncoder(out)
	e.SetIndent("", "  ")
	if err := e.Encode(decoded); err != nil {
		return errors.Wrap(err, "encoding json")
	}
	return nil
}

var getCmd = &cobra.Command{
	Use:   "get <ecosystem> <package> <version> [<artifact>]",
	Short: "Get rebuild attestation for a specific artifact.",
	Long: `Get rebuild attestation for a specific ecosystem/package/version/artifact.
The ecosystem is one of npm, pypi, or cratesio. For npm the artifact is the <package>-<version>.tar.gz file. For pypi the artifact is the wheel file. For cratesio the artifact is the <package>-<version>.crate file.`,
	Args: cobra.MinimumNArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 4 {
			log.Fatal("Too many arguments")
		}
		var t rebuild.Target
		{
			ecosystem := rebuild.Ecosystem(args[0])
			pkg := args[1]
			version := args[2]
			var artifact string
			if len(args) < 4 {
				switch ecosystem {
				case rebuild.CratesIO:
					artifact = fmt.Sprintf("%s-%s.crate", pkg, version)
				case rebuild.PyPI:
					artifact = fmt.Sprintf("%s-%s-py3-none-any.whl", strings.ReplaceAll(pkg, "-", "_"), version)
					l := log.New(cmd.OutOrStderr(), "", 0)
					l.Printf("pypi artifact is being inferred as %s\n", artifact)
				case rebuild.NPM:
					artifact = fmt.Sprintf("%s-%s.tgz", pkg, version)
				default:
					log.Fatalf("Unsupported ecosystem: \"%s\"", ecosystem)
				}
			} else {
				artifact = args[3]
			}
			t = rebuild.Target{
				Ecosystem: ecosystem,
				Package:   pkg,
				Version:   version,
				Artifact:  artifact,
			}
		}
		var bundle *attestation.Bundle
		var bundleBytes []byte
		{
			ctx := cmd.Context()
			ctx = context.WithValue(ctx, rebuild.RunID, "")
			ctx = context.WithValue(ctx, rebuild.GCSClientOptionsID, []option.ClientOption{option.WithoutAuthentication()})
			attestations, err := rebuild.NewGCSStore(ctx, "gs://"+*bucket)
			if err != nil {
				log.Fatal(errors.Wrap(err, "initializing GCS store"))
			}
			var verifiers []dsse.Verifier
			if !*verify {
				verifiers = append(verifiers, &trustAllVerifier{})
			} else {
				keysToAdd := slices.DeleteFunc(strings.Split(*verifyWith, ","), func(s string) bool { return s == "" })
				var keysAdded []string
				if !*verifyOnline {
					for _, key := range embeddedKeys {
						if !slices.Contains(keysToAdd, key.ID) {
							continue
						}
						verifiers = append(verifiers, &keyVerifier{key})
						keysAdded = append(keysAdded, key.ID)
					}
				}
				for _, uri := range keysToAdd {
					if slices.Contains(keysAdded, uri) {
						continue
					}
					switch {
					case strings.HasPrefix(uri, kmsV1API):
						verifier, err := makeKMSVerifier(ctx, ossRebuildKeyResource)
						if err != nil {
							log.Fatal(err)
						}
						verifiers = append(verifiers, verifier)
					default:
						log.Fatalf("unsupported key URI: %s", uri)
					}
					keysAdded = append(keysAdded, uri)
				}
			}
			dsseVerifier, err := dsse.NewEnvelopeVerifier(verifiers...)
			if err != nil {
				log.Fatal(errors.Wrap(err, "creating EnvelopeVerifier"))
			}
			r, err := attestations.Reader(ctx, rebuild.AttestationBundleAsset.For(t))
			if err != nil {
				log.Fatal(errors.Wrap(err, "creating attestation reader"))
			}
			bundleBytes, err = io.ReadAll(r)
			if err != nil {
				log.Fatal(errors.Wrap(err, "creating attestation reader"))
			}
			bundle, err = attestation.NewBundle(ctx, bundleBytes, dsseVerifier)
			if err != nil {
				log.Fatal(errors.Wrap(err, "creating bundle"))
			}
		}
		switch *output {
		case "bundle":
			cmd.OutOrStdout().Write(bundleBytes)
			return
		case "payload":
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			for _, s := range bundle.Statements() {
				if err := encoder.Encode(s); err != nil {
					log.Fatal(errors.Wrap(err, "pprinting payload"))
				}
			}
		case "dockerfile":
			rb, err := attestation.FilterForOne[attestation.RebuildAttestation](
				bundle,
				attestation.WithBuildType(attestation.BuildTypeRebuildV01))
			if err != nil {
				log.Fatal(err)
			}
			dockerfile := rb.Predicate.RunDetails.Byproducts.Dockerfile
			if _, err := cmd.OutOrStdout().Write(dockerfile.Content); err != nil {
				log.Fatal(errors.Wrap(err, "writing dockerfile"))
			}
		case "build":
			rb, err := attestation.FilterForOne[attestation.RebuildAttestation](
				bundle,
				attestation.WithBuildType(attestation.BuildTypeRebuildV01))
			if err != nil {
				log.Fatal(err)
			}
			strategy := rb.Predicate.RunDetails.Byproducts.BuildStrategy
			if err := writeIndentedJson(cmd.OutOrStdout(), strategy.Content); err != nil {
				log.Fatal(errors.Wrap(err, "writing dockerfile"))
			}
		case "steps":
			rb, err := attestation.FilterForOne[attestation.RebuildAttestation](
				bundle,
				attestation.WithBuildType(attestation.BuildTypeRebuildV01))
			if err != nil {
				log.Fatal(err)
			}
			steps := rb.Predicate.RunDetails.Byproducts.BuildSteps
			if err := writeIndentedJson(cmd.OutOrStdout(), steps.Content); err != nil {
				log.Fatal(errors.Wrap(err, "writing dockerfile"))
			}
		default:
			log.Fatal(errors.New("unsupported format: " + *output))
		}
	},
}

var listCmd = &cobra.Command{
	Use:   "list <ecosystem> <package> [<version>]",
	Short: "List artifacts with rebuild attestations for a given query",
	Args:  cobra.MaximumNArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 2 {
			log.Fatal("Please include at least an ecosystem and package")
		}
		gcsClient, err := gcs.NewClient(cmd.Context(), option.WithoutAuthentication())
		if err != nil {
			log.Fatal(errors.Wrap(err, "initializing GCS client"))
		}
		query := &gcs.Query{
			Prefix: path.Join(args...),
		}
		query.SetAttrSelection([]string{"Name"})
		it := gcsClient.Bucket(*bucket).Objects(cmd.Context(), query)
		for {
			obj, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				log.Fatal(errors.Wrap(err, "listing objects"))
			}
			io.WriteString(cmd.OutOrStdout(), obj.Name+"\n")
		}
	},
}

func init() {
	rootCmd.AddCommand(getCmd)

	getCmd.Flags().AddGoFlag(flag.Lookup("output"))
	getCmd.Flags().AddGoFlag(flag.Lookup("bucket"))
	getCmd.Flags().AddGoFlag(flag.Lookup("verify"))
	getCmd.Flags().AddGoFlag(flag.Lookup("verify-with"))
	getCmd.Flags().AddGoFlag(flag.Lookup("verify-online"))

	rootCmd.AddCommand(listCmd)

	listCmd.Flags().AddGoFlag(flag.Lookup("bucket"))
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
