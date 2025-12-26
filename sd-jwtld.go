package jwtld

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	sd "github.com/marques-ma/merkle-selective-disclosure"
	"github.com/hpe-usp-spire/schoco"
	"go.dedis.ch/kyber/v3"
)

// ----------------------------
// JSON-LD structs (payload)
// ----------------------------

type Payload struct {
	Ver  int8                   `json:"ver,omitempty"`
	Iat  int64                  `json:"iat,omitempty"`
	Iss  *IDClaim               `json:"iss,omitempty"`
	Aud  *IDClaim               `json:"aud,omitempty"`
	Sub  *IDClaim               `json:"sub,omitempty"`
	// Data stores SD metadata only (e.g. {"sd":{"alg":"sha256-merkle","root":"<b64>"}})
	Data map[string]interface{} `json:"data,omitempty"`
	List []*LDNode              `json:"@list,omitempty"`
}

type IDClaim struct {
	CN string  `json:"cn,omitempty"`
	PK []byte  `json:"pk,omitempty"`
	ID *string `json:"id,omitempty"`
}

type LDNode struct {
	ID      string   `json:"@id,omitempty"`
	Payload *Payload `json:"payload"`
}

// ----------------------------
// Helpers JWS (base64url w/o padding)
// ----------------------------
var b64 = base64.RawURLEncoding

func b64Encode(data []byte) string {
	return b64.EncodeToString(data)
}

func b64Decode(s string) ([]byte, error) {
	return b64.DecodeString(s)
}

func marshalCanonical(v interface{}) ([]byte, error) {
	// For PoC we use json.Marshal (not JSON-LD canonicalization).
	return json.Marshal(v)
}

// ----------------------------
// Data -> canonical leaves helper
// ----------------------------

// DataToLeaves: converts map[string]interface{} into canonical leaves slice and
// returns keysOrder (sorted) and leaves (bytes). Leaves are the serialized values
// (we keep leaf representation as canonicalized value bytes; sd package hashes domain-separated).
func DataToLeaves(data map[string]interface{}) (keys []string, leaves [][]byte, err error) {
	if data == nil {
		return nil, nil, fmt.Errorf("nil data")
	}
	keys = make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	leaves = make([][]byte, 0, len(keys))
	for _, k := range keys {
		v := data[k]
		b, e := marshalCanonical(v)
		if e != nil {
			return nil, nil, fmt.Errorf("canonicalize value for key %s: %v", k, e)
		}
		// leaf format: we use the raw canonical value bytes (sd package will domain-separate)
		leaves = append(leaves, b)
	}
	return keys, leaves, nil
}

// ----------------------------
// AttachSDRootToPayload
// - computes Merkle root from provided "data" (map[string]interface{})
// - sets payload.Data to a JSON-friendly SD metadata object:
//     payload.Data = { "sd": { "alg":"sha256-merkle", "root":"<base64url>" } }
// - returns keysOrder and leaves (so caller can create disclosures before or after)
func AttachSDRootToPayload(p *Payload, data map[string]interface{}) (keys []string, leaves [][]byte, err error) {
	if p == nil {
		return nil, nil, fmt.Errorf("nil payload")
	}
	if data == nil || len(data) == 0 {
		return nil, nil, fmt.Errorf("no data to attach")
	}
	keys, leaves, err = DataToLeaves(data)
	if err != nil {
		return nil, nil, err
	}
	root, err := sd.MerkleRoot(leaves)
	if err != nil {
		return nil, nil, err
	}
	// Replace payload.Data with sd metadata only
	p.Data = map[string]interface{}{
		"sd": map[string]string{
			"alg":  "sha256-merkle",
			"root": b64Encode(root),
		},
	}
	return keys, leaves, nil
}

// ExtractSDRootFromPayload returns raw root bytes and whether it was present.
func ExtractSDRootFromPayload(p *Payload) ([]byte, bool) {
	if p == nil || p.Data == nil {
		return nil, false
	}
	raw, ok := p.Data["sd"]
	if !ok {
		return nil, false
	}
	switch m := raw.(type) {
	case map[string]interface{}:
		rs, ok := m["root"].(string)
		if !ok {
			return nil, false
		}
		b, err := b64Decode(rs)
		if err != nil {
			return nil, false
		}
		return b, true
	case map[string]string:
		rs, ok := m["root"]
		if !ok {
			return nil, false
		}
		b, err := b64Decode(rs)
		if err != nil {
			return nil, false
		}
		return b, true
	default:
		return nil, false
	}
}

// ----------------------------
// Create / Extend / Validate (JWS, unchanged semantics)
// ----------------------------

// NOTE: CreateJWS **does not** compute SD roots. Caller MUST call AttachSDRootToPayload before signing if SD is desired.
func CreateJWS(payload *Payload, version int8, key interface{}) (string, error) {
	payloadBytes, err := marshalCanonical(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %v", err)
	}

	header := map[string]interface{}{"version": version}
	headerBytes, _ := json.Marshal(header)

	var sigBytes []byte
	switch version {
	case 0:
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("version 0 requires *ecdsa.PrivateKey")
		}
		h := sha256.Sum256(payloadBytes)
		sigBytes, err = ecdsaKey.Sign(rand.Reader, h[:], crypto.SHA256)
		if err != nil {
			return "", fmt.Errorf("ecdsa sign: %v", err)
		}
	case 1:
		eddsaKey, ok := key.(kyber.Scalar)
		if !ok {
			return "", fmt.Errorf("version 1 requires kyber.Scalar")
		}
		sig := schoco.StdSign(string(payloadBytes), eddsaKey)
		sigBytes, err = sig.ToByte()
		if err != nil {
			return "", fmt.Errorf("schoco sign: %v", err)
		}
	default:
		return "", fmt.Errorf("unsupported version: %d", version)
	}

	return strings.Join([]string{b64Encode(headerBytes), b64Encode(payloadBytes), b64Encode(sigBytes)}, "."), nil
}

// ExtendJWS: expects newPayload.Payload.Data already prepared (i.e., AttachSDRootToPayload already called if needed).
func ExtendJWS(jws string, newNode *LDNode, version int8, key ...interface{}) (string, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid jws format")
	}
	headerB, _ := b64Decode(parts[0])
	payloadB, _ := b64Decode(parts[1])
	sigB, _ := b64Decode(parts[2])

	var doc Payload
	if err := json.Unmarshal(payloadB, &doc); err != nil {
		return "", fmt.Errorf("unmarshal payload: %v", err)
	}

	switch version {
	case 0:
		// ID mode: previous full signature becomes node @id (base64)
		newNodeID := b64Encode(sigB)
		newNode.ID = newNodeID
		doc.List = append(doc.List, newNode)

		if len(key) == 0 {
			return "", fmt.Errorf("ecdsa key required")
		}
		ecdsaKey, ok := key[0].(*ecdsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("key is not *ecdsa.PrivateKey")
		}

		newPayloadBytes, _ := marshalCanonical(&doc)
		h := sha256.Sum256(newPayloadBytes)
		newSig, _ := ecdsaKey.Sign(rand.Reader, h[:], crypto.SHA256)

		var hdr map[string]interface{}
		_ = json.Unmarshal(headerB, &hdr)
		hdr["version"] = version
		hdrB, _ := json.Marshal(hdr)

		return strings.Join([]string{b64Encode(hdrB), b64Encode(newPayloadBytes), b64Encode(newSig)}, "."), nil

	case 1:
		// SchoCo mode: extract aggKey + R from previous signature, put R as @id, sign whole doc with aggKey
		prevSig, err := schoco.ByteToSignature(sigB)
		if err != nil {
			return "", fmt.Errorf("invalid previous signature: %v", err)
		}
		aggKey, partSig := prevSig.ExtractAggKey()
		partSigBytes, err := schoco.PointToByte(partSig)
		if err != nil {
			return "", fmt.Errorf("PointToByte(partSig): %v", err)
		}
		newNodeID := b64Encode(partSigBytes)
		newNode.ID = newNodeID

		doc.List = append(doc.List, newNode)

		newPayloadBytes, _ := marshalCanonical(&doc)
		newSig := schoco.StdSign(string(newPayloadBytes), aggKey)
		newSigBytes, _ := newSig.ToByte()

		var hdr map[string]interface{}
		_ = json.Unmarshal(headerB, &hdr)
		hdr["version"] = version
		hdrB, _ := json.Marshal(hdr)

		return strings.Join([]string{b64Encode(hdrB), b64Encode(newPayloadBytes), b64Encode(newSigBytes)}, "."), nil

	default:
		return "", fmt.Errorf("unsupported version: %d", version)
	}
}

// ValidateJWS validates signatures (ID mode / SchoCo). It DOES NOT verify SD proofs; that is done by ValidateJWSWithPresentations.
func ValidateJWS(jws string, version int8, bundle ...*Payload) (bool, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid jws format")
	}
	// headerB, _ := b64Decode(parts[0])
	payloadB, _ := b64Decode(parts[1])
	sigB, _ := b64Decode(parts[2])

	var doc Payload
	if err := json.Unmarshal(payloadB, &doc); err != nil {
		return false, fmt.Errorf("unmarshal payload: %v", err)
	}

	switch version {
	case 0:
		N := len(doc.List)
		for k := 0; k < N; k++ {
			partial := &Payload{
				Ver:  doc.Ver,
				Iat:  doc.Iat,
				Iss:  doc.Iss,
				Aud:  doc.Aud,
				Sub:  doc.Sub,
				Data: doc.Data,
				List: doc.List[:k+1],
			}
			partialBytes, _ := marshalCanonical(partial)

			var sigToCheck []byte
			if k == N-1 {
				sigToCheck = sigB
			} else {
				sigToCheck, _ = b64Decode(doc.List[k+1].ID)
			}

			var pubKeyBytes []byte
			if doc.List[k].Payload.Iss != nil && len(doc.List[k].Payload.Iss.PK) > 0 {
				pubKeyBytes = doc.List[k].Payload.Iss.PK
			} else if len(bundle) > 0 {
				// fallback bundle (TTP bundle style)
				if bundle[0].List != nil && len(bundle[0].List) > 0 && bundle[0].List[0].Payload.Sub != nil {
					pubKeyBytes = bundle[0].List[0].Payload.Sub.PK
				}
			}

			if len(pubKeyBytes) == 0 {
				return false, fmt.Errorf("no public key available for step %d", k)
			}

			pub, err := x509.ParsePKIXPublicKey(pubKeyBytes)
			if err != nil {
				return false, fmt.Errorf("parse pkix pubkey (k=%d): %v", k, err)
			}
			h := sha256.Sum256(partialBytes)
			if !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), h[:], sigToCheck) {
				return false, fmt.Errorf("signature failed at step %d", k)
			}
		}
		return true, nil

	case 1:
		N := len(doc.List)

		// non-extended (no nodes)
		if N == 0 {
			sig, err := schoco.ByteToSignature(sigB)
			if err != nil {
				return false, fmt.Errorf("byteToSignature: %v", err)
			}
			rootPK, err := schoco.ByteToPoint(doc.Iss.PK)
			if err != nil {
				return false, fmt.Errorf("byteToPoint rootPK: %v", err)
			}
			msgBytes, _ := marshalCanonical(&doc)
			if !schoco.StdVerify(string(msgBytes), sig, rootPK) {
				return false, fmt.Errorf("StdVerify failed for non-extended token")
			}
			return true, nil
		}

		// extended case:
		// build setMsg: OUTER (full list) -> ... -> INNER (empty list)
		var setMsg []string
		for i := N; i >= 0; i-- {
			partial := &Payload{
				Ver:  doc.Ver,
				Iat:  doc.Iat,
				Iss:  doc.Iss,
				Aud:  doc.Aud,
				Sub:  doc.Sub,
				Data: doc.Data,
				List: doc.List[:i], // i==0 -> empty slice
			}
			b, _ := marshalCanonical(partial)
			setMsg = append(setMsg, string(b))
		}

		// build setPartSig: R_{N-1}, R_{N-2}, ..., R_0  (reverse order of doc.List)
		var setPartSig []kyber.Point
		for i := N - 1; i >= 0; i-- {
			idBytes, err := b64Decode(doc.List[i].ID)
			if err != nil {
				return false, fmt.Errorf("decoding node ID to point (i=%d): %v", i, err)
			}
			pt, err := schoco.ByteToPoint(idBytes)
			if err != nil {
				return false, fmt.Errorf("ByteToPoint node ID (i=%d): %v", i, err)
			}
			setPartSig = append(setPartSig, pt)
		}

		// final aggregated signature
		lastSig, err := schoco.ByteToSignature(sigB)
		if err != nil {
			return false, fmt.Errorf("byteToSignature final: %v", err)
		}

		// root public key = Iss.PK of the overall payload (doc.Iss)
		rootPK, err := schoco.ByteToPoint(doc.Iss.PK)
		if err != nil {
			return false, fmt.Errorf("byteToPoint rootPK: %v", err)
		}

		// verify
		if !schoco.Verify(rootPK, setMsg, setPartSig, lastSig) {
			return false, fmt.Errorf("schoco verification failed")
		}
		return true, nil

	default:
		return false, fmt.Errorf("unsupported version: %d", version)
	}
}

// ----------------------------
// Presentation helpers (using your sd package)
// ----------------------------

// CreateDisclosureFromLeaves is a thin wrapper around sd.CreateDisclosure.
// leaves should be the canonical leaves used when creating the root (DataToLeaves).
func CreateDisclosureFromLeaves(leaves [][]byte, selectedIndices []int) (*sd.Disclosure, error) {
	return sd.CreateDisclosure(leaves, selectedIndices)
}

// CreatePresentationFromData convenience: given the original data map (the cleartext map),
// create canonical leaves, map selectedKeys -> indices, and call sd.CreateDisclosure.
func CreatePresentationFromData(data map[string]interface{}, selectedKeys []string) (*sd.Disclosure, error) {
	if data == nil {
		return nil, fmt.Errorf("nil data")
	}
	keysOrder, leaves, err := DataToLeaves(data)
	if err != nil {
		return nil, err
	}
	// map key -> index
	keyToIndex := make(map[string]int, len(keysOrder))
	for i, k := range keysOrder {
		keyToIndex[k] = i
	}
	indices := make([]int, 0, len(selectedKeys))
	for _, sk := range selectedKeys {
		idx, ok := keyToIndex[sk]
		if !ok {
			return nil, fmt.Errorf("selected key not found in data: %s", sk)
		}
		indices = append(indices, idx)
	}
	return sd.CreateDisclosure(leaves, indices)
}

// Validate presentation: check that disclosure is internally consistent and that its Root
// matches the root stored in the payload's Data metadata.
//
// presentations map: key = 0 -> root payload; key = i+1 -> doc.List[i]
func ValidateJWSWithPresentations(jws string, version int8, presentations map[int]*sd.Disclosure, bundle ...*Payload) (bool, error) {
	// validate signatures first
	ok, err := ValidateJWS(jws, version, bundle...)
	if err != nil || !ok {
		return false, err
	}

	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid jws format")
	}
	payloadB, _ := b64Decode(parts[1])

	var doc Payload
	if err := json.Unmarshal(payloadB, &doc); err != nil {
		return false, fmt.Errorf("unmarshal payload: %v", err)
	}

	// helper to verify a disclosure against a payload node
	verifyNode := func(nodePayload *Payload, pres *sd.Disclosure) (bool, error) {
		if nodePayload == nil {
			return false, fmt.Errorf("nil node payload")
		}
		root, ok := ExtractSDRootFromPayload(nodePayload)
		if !ok {
			return false, fmt.Errorf("node payload has no SD root")
		}
		okv, err := sd.VerifyDisclosure(pres)
		if err != nil || !okv {
			return false, fmt.Errorf("disclosure verification failed: %v", err)
		}
		if !bytes.Equal(root, pres.Root) {
			return false, fmt.Errorf("disclosure root mismatch")
		}
		return true, nil
	}

	// check root payload (presentation key 0)
	if pres, ok := presentations[0]; ok {
		if _, err := verifyNode(&doc, pres); err != nil {
			return false, err
		}
	}

	// check each child node -> presentation key i+1
	for i, node := range doc.List {
		if node == nil || node.Payload == nil {
			continue
		}
		pres, ok := presentations[i+1]
		if !ok {
			// if node declares SD root, presentation missing is a failure
			if _, has := ExtractSDRootFromPayload(node.Payload); has {
				return false, fmt.Errorf("missing presentation for node %d", i+1)
			}
			continue
		}
		if _, err := verifyNode(node.Payload, pres); err != nil {
			return false, err
		}
	}

	return true, nil
}
