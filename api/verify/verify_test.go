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

package verify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/f-secure-foundry/armory-drive-log/api"
	"golang.org/x/mod/sumdb/note"
)

const (
	testLogSignerPrivate = "PRIVATE+KEY+test-log+2b51c375+Ad+qPnxRnV5XOivW9d42+7xewjKwjXwYr3z9SeP+OOVK"
	testLogSignerPublic  = "test-log+2b51c375+Ae73xsZZky/7/mv/jmPEAAVHi3KXBTz4F2DV6H/Htd4P"

	testFirmwarePrivate = "PRIVATE+KEY+test-firmware+ab2fae50+AaB6EfEYBzXsuL9Ad+aFOY7zanhCGIyq/YzdDgVllp7i"
	testFirmwarePublic  = "test-firmware+ab2fae50+ATbJye7l6/LavuMm5iBSu67hmxPv1yx+d9BhcEki1Q4Z"
)

var (
	testFirmwareHash      = []byte("GOLDEN_FIRMWARE_HASH")
	testOldCheckpointSize = 50
	testOldCheckpointHash = []byte("OldCheckpointRoot")
	testNewCheckpointHash = []byte("NewCheckpointRoot")
	testNewCheckpointSize = 100
	testConsistencyProof  = [][]byte{
		[]byte("it's"),
		[]byte("a"),
		[]byte("consistency"),
		[]byte("proof."),
	}
	testInclusionProof = [][]byte{
		[]byte("it's"),
		[]byte("an"),
		[]byte("inclusion"),
		[]byte("proof."),
	}
)

func TestBundle(t *testing.T) {
	logSig := mustMakeSigner(t, testLogSignerPrivate)
	fwSig := mustMakeSigner(t, testFirmwarePrivate)
	logSigV := mustMakeVerifier(t, testLogSignerPublic)
	fwSigV := mustMakeVerifier(t, testFirmwarePublic)

	for _, test := range []struct {
		desc    string
		pb      api.ProofBundle
		oldCP   api.Checkpoint
		fwHash  []byte
		wantErr bool
	}{
		{
			desc: "works",
			pb: api.ProofBundle{
				FirmwareRelease: makeFirmwareRelease(t, fwSig),
				LeafIndex:       101,
				NewCheckpoint:   makeCheckpoint(t, int64(testNewCheckpointSize), testNewCheckpointHash, logSig),
				InclusionProof:  testInclusionProof,
				ConsistencyProofs: map[uint64][][]byte{
					uint64(testOldCheckpointSize): testConsistencyProof,
				},
			},
			oldCP: api.Checkpoint{
				Size: uint64(testOldCheckpointSize),
				Hash: testOldCheckpointHash,
			},
			fwHash: testFirmwareHash,
		}, {
			desc: "wrong firmware",
			pb: api.ProofBundle{
				FirmwareRelease: makeFirmwareRelease(t, fwSig),
				LeafIndex:       101,
				NewCheckpoint:   makeCheckpoint(t, int64(testNewCheckpointSize), testNewCheckpointHash, logSig),
				InclusionProof:  testInclusionProof,
				ConsistencyProofs: map[uint64][][]byte{
					uint64(testOldCheckpointSize): testConsistencyProof,
				},
			},
			oldCP: api.Checkpoint{
				Size: uint64(testOldCheckpointSize),
				Hash: testOldCheckpointHash,
			},
			wantErr: true,
		}, {
			desc: "bad inclusion",
			pb: api.ProofBundle{
				FirmwareRelease: makeFirmwareRelease(t, fwSig),
				LeafIndex:       101,
				NewCheckpoint:   makeCheckpoint(t, int64(testNewCheckpointSize), testNewCheckpointHash, logSig),
				// This won't verify
				InclusionProof: [][]byte{
					[]byte("oh"),
					[]byte("noes!"),
				},
				ConsistencyProofs: map[uint64][][]byte{
					uint64(testOldCheckpointSize): testConsistencyProof,
				},
			},
			oldCP: api.Checkpoint{
				Size: uint64(testOldCheckpointSize),
				Hash: testOldCheckpointHash,
			},
			fwHash:  testFirmwareHash,
			wantErr: true,
		}, {
			desc: "bad consistency - incorrect proof",
			pb: api.ProofBundle{
				FirmwareRelease: makeFirmwareRelease(t, fwSig),
				LeafIndex:       101,
				NewCheckpoint:   makeCheckpoint(t, int64(testNewCheckpointSize), testNewCheckpointHash, logSig),
				InclusionProof:  testInclusionProof,
				ConsistencyProofs: map[uint64][][]byte{
					// This is an unexpected consistency proof
					uint64(testOldCheckpointSize): [][]byte{
						[]byte("whoops!"),
					},
				},
			},
			oldCP: api.Checkpoint{
				Size: uint64(testOldCheckpointSize),
				Hash: testOldCheckpointHash,
			},
			fwHash:  testFirmwareHash,
			wantErr: true,
		}, {
			desc: "bad consistency - wrong tree size",
			pb: api.ProofBundle{
				FirmwareRelease: makeFirmwareRelease(t, fwSig),
				LeafIndex:       101,
				NewCheckpoint:   makeCheckpoint(t, int64(testNewCheckpointSize), testNewCheckpointHash, logSig),
				InclusionProof:  testInclusionProof,
				ConsistencyProofs: map[uint64][][]byte{
					// Correct consistency proof, but associated with the wrong tree size
					uint64(testOldCheckpointSize + 100): testConsistencyProof,
				},
			},
			oldCP: api.Checkpoint{
				Size: uint64(testOldCheckpointSize),
				Hash: testOldCheckpointHash,
			},
			fwHash:  testFirmwareHash,
			wantErr: true,
		}, {
			desc: "invalid firmware manifest signature",
			pb: api.ProofBundle{
				// Invalid - signed by log's key
				FirmwareRelease: makeFirmwareRelease(t, logSig),
				LeafIndex:       101,
				NewCheckpoint:   makeCheckpoint(t, int64(testNewCheckpointSize), testNewCheckpointHash, logSig),
				InclusionProof:  testInclusionProof,
				ConsistencyProofs: map[uint64][][]byte{
					uint64(testOldCheckpointSize): testConsistencyProof,
				},
			},
			oldCP: api.Checkpoint{
				Size: uint64(testOldCheckpointSize),
				Hash: testOldCheckpointHash,
			},
			fwHash:  testFirmwareHash,
			wantErr: true,
		}, {
			desc: "invalid log checkpoint signature",
			pb: api.ProofBundle{
				FirmwareRelease: makeFirmwareRelease(t, fwSig),
				LeafIndex:       101,
				// Invalid - signed by firmware key
				NewCheckpoint:  makeCheckpoint(t, int64(testNewCheckpointSize), testNewCheckpointHash, fwSig),
				InclusionProof: testInclusionProof,
				ConsistencyProofs: map[uint64][][]byte{
					uint64(testOldCheckpointSize): testConsistencyProof,
				},
			},
			oldCP: api.Checkpoint{
				Size: uint64(testOldCheckpointSize),
				Hash: testOldCheckpointHash,
			},
			fwHash:  testFirmwareHash,
			wantErr: true,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			wantLH := hashLeaf(test.pb.FirmwareRelease)
			ipVerif := ipVerifier(test.pb.LeafIndex, int64(testNewCheckpointSize), testInclusionProof, testNewCheckpointHash, wantLH)
			cpVerif := cpVerifier(int64(test.oldCP.Size), int64(testNewCheckpointSize), test.oldCP.Hash, testNewCheckpointHash, testConsistencyProof)
			err := Bundle(test.pb, test.oldCP, logSigV, fwSigV, cpVerif, ipVerif, test.fwHash)
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Fatalf("wantErr: %v, but got: %v", test.wantErr, err)
			}
		})
	}
}

// ipVerifier returns a VerifyInclusion function which expects to see a particular set of arguments, and returns an error
// if it is called with anything else.
func ipVerifier(wantLeafIndex, wantTreeSize int64, wantProof [][]byte, wantRoot []byte, wantLeafHash []byte) VerifyInclusion {
	return func(leafIndex, treeSize int64, proof [][]byte, root []byte, leafHash []byte) error {
		errs := make([]string, 0)

		if got, want := leafIndex, wantLeafIndex; got != want {
			errs = append(errs, fmt.Sprintf("got leafIndex %d, want %d", got, want))
		}
		if got, want := treeSize, wantTreeSize; got != want {
			errs = append(errs, fmt.Sprintf("got treeSize %d, want %d", got, want))
		}
		if got, want := proof, wantProof; !reflect.DeepEqual(got, want) {
			errs = append(errs, fmt.Sprintf("got proof %x, want %x", got, want))
		}
		if got, want := root, wantRoot; !bytes.Equal(got, want) {
			errs = append(errs, fmt.Sprintf("got root %x, want %x", got, want))
		}
		if got, want := leafHash, wantLeafHash; !bytes.Equal(got, want) {
			errs = append(errs, fmt.Sprintf("got leafHash %x, want %x", got, want))
		}

		if len(errs) > 0 {
			return errors.New(strings.Join(errs, "\n"))
		}
		return nil
	}
}

// ipVerifier returns a VerifyConsistency function which expects to see a particular set of arguments, and returns an error
// if it is called with anything else.
func cpVerifier(wantSnapshot1, wantSnapshot2 int64, wantRoot1, wantRoot2 []byte, wantProof [][]byte) VerifyConsistency {
	return func(snapshot1, snapshot2 int64, root1, root2 []byte, proof [][]byte) error {
		errs := make([]string, 0)

		if got, want := snapshot1, wantSnapshot1; got != want {
			errs = append(errs, fmt.Sprintf("got snapshot1 %d, want %d", got, want))
		}
		if got, want := snapshot2, wantSnapshot2; got != want {
			errs = append(errs, fmt.Sprintf("got snapshot2 %d, want %d", got, want))
		}
		if got, want := root1, wantRoot1; !bytes.Equal(got, want) {
			errs = append(errs, fmt.Sprintf("got root1 %x, want %x", got, want))
		}
		if got, want := root2, wantRoot2; !bytes.Equal(got, want) {
			errs = append(errs, fmt.Sprintf("got root2 %x, want %x", got, want))
		}
		if got, want := proof, wantProof; !reflect.DeepEqual(got, want) {
			errs = append(errs, fmt.Sprintf("got proof %x, want %x", got, want))
		}

		if len(errs) > 0 {
			return errors.New(strings.Join(errs, "\n"))
		}
		return nil
	}
}

func mustMakeSigner(t *testing.T, secK string) note.Signer {
	t.Helper()
	s, err := note.NewSigner(secK)
	if err != nil {
		t.Fatalf("Failed to create signer from %q: %v", secK, err)
	}
	return s
}

func mustMakeVerifier(t *testing.T, pubK string) note.Verifier {
	t.Helper()
	v, err := note.NewVerifier(pubK)
	if err != nil {
		t.Fatalf("Failed to create verifier from %q: %v", pubK, err)
	}
	return v
}

func makeFirmwareRelease(t *testing.T, sig note.Signer) []byte {
	fr := api.FirmwareRelease{
		Description: "A release",
		PlatformID:  "7½",
		Revision:    "Helps with tests",
		ArtifactSHA256: map[string][]byte{
			api.FirmwareArtifactName: testFirmwareHash,
			"Art":                    []byte("Fact"),
		},
		SourceURL:    "https://www.youtube.com/watch?v=IC7l3V1nhWc&t=0s",
		SourceSHA256: []byte("One two three four five. Six seven eight nine ten. Eleven twelve."),
		ToolChain:    "Snap on",
		BuildArgs: map[string]string{
			"REV": "Lovejoy",
		},
	}
	frRaw, err := json.MarshalIndent(fr, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal FirmwareRelease: %v", err)
	}
	n, err := note.Sign(&note.Note{Text: string(frRaw) + "\n"}, sig)
	if err != nil {
		t.Fatalf("Failed to sign FirmwareRelease: %v", err)
	}
	return n
}

func makeCheckpoint(t *testing.T, size int64, hash []byte, sig note.Signer) []byte {
	t.Helper()
	cp := fmt.Sprintf("%s\n%d\n%s\n", api.EcosystemV0, size, base64.StdEncoding.EncodeToString(hash))
	n, err := note.Sign(&note.Note{Text: cp}, sig)
	if err != nil {
		t.Fatalf("Failed to sign checkpoint: %v", err)
	}
	return n
}
