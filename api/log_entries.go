// Copyright 2021 The Project Authors. All Rights Reserved.
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

// Package api contains public structures related to the log contents.
package api

// EcosystemV0 is the Checkpoint ecosystem string for this usecase.
const EcosystemV0 = "ArmoryDrive Log v0"

// FirmwareRelease represents a firmware release, and contains all of the
// information required to reconstruct the unsigned firmware image from source.
type FirmwareRelease struct {
	// Description is a human readable description of the firmware release.
	Description string `json:"description"`

	// PlatformID identifies the hardware platform this release targets.
	PlatformID string `json:"platform_id"`

	// ArtifactSHA256 contains the SHA256 hashes of the named release artifacts.
	ArtifactSHA256 map[string][]byte `json:"artifact_hashes"`

	// SourceURL is the location from which the source code used to produce this release can be downloaded.
	SourceURL string `json:"source"`

	// SourceSHA256 is the SHA256 hash of the contents of the source file at the location
	// pointed to by SourceURL.
	SourceSHA256 []byte `json:"source_sha256"`

	// ToolChain identifies the toolchain used to build the release from the source.
	ToolChain string `json:"tool_chain"`

	// BuildArgs identifies the set of build arguments used to build the firmware from the source.
	BuildArgs map[string]string `json:"build_args"`
}
