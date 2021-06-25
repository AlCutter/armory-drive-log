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

// Package verify provides verification functions for armory drive transparency.
package verify

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/f-secure-foundry/armory-drive-log/api"
	"golang.org/x/mod/sumdb/note"
)

// VerifyConsistency is the signature of a function which knows how to verify a consistency proof.
type VerifyConsistency func(snapshot1, snapshot2 int64, root1, root2 []byte, proof [][]byte) error

// VerifyInclusion is the signature of a function which knows how to verify an inclusion proof.
type VerifyInclusion func(leafIndex, treeSize int64, proof [][]byte, root []byte, leafHash []byte) error

// Bundle verifies that the Bundle is self-consistent, and consistent with the provided
// smaller checkpoint from the device.
func Bundle(pb api.ProofBundle, oldCP api.Checkpoint, logSigV note.Verifier, frSigV note.Verifier, cpVerifier VerifyConsistency, ipVerifier VerifyInclusion, firmwareHash []byte) error {
	// First, check the signature on the new CP.
	newCP := &api.Checkpoint{}
	{
		newCPRaw, err := note.Open(pb.NewCheckpoint, note.VerifierList(logSigV))
		if err != nil {
			return fmt.Errorf("failed to verify signature on NewCheckpoint: %v", err)
		}
		if err := newCP.Unmarshal([]byte(newCPRaw.Text)); err != nil {
			return fmt.Errorf("failed to unmarshal NewCheckpoint: %v", err)
		}
	}

	// Now verify that newCP is consistent with the CP we last saw.
	// Note that no consistency proof is needed from zero-sized logs.
	if oldCP.Size > 0 {
		cp, ok := pb.ConsistencyProofs[oldCP.Size]
		if !ok {
			return fmt.Errorf("no consistency proof provided from device Checkpoint size %d", oldCP.Size)
		}

		if err := cpVerifier(int64(oldCP.Size), int64(newCP.Size), oldCP.Hash, newCP.Hash, cp); err != nil {
			return fmt.Errorf("invalid consistency proof: %v", err)
		}
	}

	// Check that the FirmwareRelease provided is indeed present in the log
	lh := hashLeaf(pb.FirmwareRelease)
	if err := ipVerifier(int64(pb.LeafIndex), int64(newCP.Size), pb.InclusionProof, newCP.Hash, lh); err != nil {
		return fmt.Errorf("invalid inclusion proof: %v", err)
	}

	// Check the signature on the FirmwareRelease as we unmarshal it
	fr := &api.FirmwareRelease{}
	{
		frRaw, err := note.Open(pb.FirmwareRelease, note.VerifierList(frSigV))
		if err != nil {
			return fmt.Errorf("invalid signature on FirmwareRelease: %v", err)
		}
		if err := json.Unmarshal([]byte(frRaw.Text), fr); err != nil {
			return fmt.Errorf("failed to unmarshal FirmwareRelease: %v", err)
		}
	}

	// Lastly, check that the provided firmware update image is the same as the one
	// claimed by the FirmwareRelease manifest.
	expectedIMXHash, ok := fr.ArtifactSHA256[api.FirmwareArtifactName]
	if !ok {
		return fmt.Errorf("expected firmware artifact (%s) not present in FirmwareRelease", api.FirmwareArtifactName)
	}
	if !bytes.Equal(firmwareHash, expectedIMXHash) {
		return fmt.Errorf("firmware hash (%x) does not match claimed hash from FirmwareRelease (%x)", firmwareHash, expectedIMXHash)
	}

	return nil
}
