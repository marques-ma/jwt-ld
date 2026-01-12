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
	"sync"

	sd "github.com/marques-ma/merkle-selective-disclosure"
	"github.com/hpe-usp-spire/schoco"
	"filippo.io/edwards25519"
)

/* ============================================================
   Version constants
============================================================ */
const (
	VerECDSA   = 0
	VerSchoCo  = 1
	VerSchnorr = 2 // Schnorr puro sequencial
)

/* ============================================================
   JSON-LD payload structures
============================================================ */

type Payload struct {
	Ver  int8                   `json:"ver,omitempty"`
	Iat  int64                  `json:"iat,omitempty"`
	Iss  *IDClaim               `json:"iss,omitempty"`
	Aud  *IDClaim               `json:"aud,omitempty"`
	Sub  *IDClaim               `json:"sub,omitempty"`
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

/* ============================================================
   Selective Disclosure claim
============================================================ */

type SDClaim struct {
	ID    string      `json:"id"`
	Value interface{} `json:"value"`
}

/* ============================================================
   Base64 helpers
============================================================ */

var b64 = base64.RawURLEncoding

func b64Encode(b []byte) string { return b64.EncodeToString(b) }
func b64Decode(s string) ([]byte, error) {
	return b64.DecodeString(s)
}

func marshalCanonical(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

/* ============================================================
   Data → Merkle leaves
============================================================ */

func DataToLeaves(data map[string]interface{}) (keys []string, leaves [][]byte, err error) {
	if data == nil {
		return nil, nil, fmt.Errorf("nil data")
	}

	keys = make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		leafObj := SDClaim{ID: k, Value: data[k]}
		b, err := marshalCanonical(leafObj)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal SDClaim %s: %v", k, err)
		}
		leaves = append(leaves, b)
	}
	return keys, leaves, nil
}

func AttachSDRootToPayload(p *Payload, data map[string]interface{}) (keys []string, leaves [][]byte, err error) {
	if p == nil {
		return nil, nil, fmt.Errorf("nil payload")
	}
	if len(data) == 0 {
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

	p.Data = map[string]interface{}{
		"sd": map[string]string{
			"alg":  "sha256-merkle",
			"root": b64Encode(root),
		},
	}
	return keys, leaves, nil
}

func ExtractSDRootFromPayload(p *Payload) ([]byte, bool) {
	if p == nil || p.Data == nil {
		return nil, false
	}
	m, ok := p.Data["sd"].(map[string]interface{})
	if !ok {
		return nil, false
	}
	rs, ok := m["root"].(string)
	if !ok {
		return nil, false
	}
	b, err := b64Decode(rs)
	if err != nil {
		return nil, false
	}
	return b, true
}

/* ============================================================
   Semantic extraction from disclosure
============================================================ */

func ExtractSDClaimsFromDisclosure(d *sd.Disclosure) ([]SDClaim, error) {
	if d == nil {
		return nil, fmt.Errorf("nil disclosure")
	}
	var claims []SDClaim
	for _, leaf := range d.Leaves {
		var c SDClaim
		if err := json.Unmarshal(leaf, &c); err != nil {
			return nil, fmt.Errorf("invalid SDClaim leaf: %v", err)
		}
		if c.ID == "" {
			return nil, fmt.Errorf("SDClaim missing id")
		}
		claims = append(claims, c)
	}
	return claims, nil
}

/* ============================================================
   Validate caching for SchoCo heavy prep work
   (cache key: exact payload bytes from JWS)
============================================================ */

var schocoVerifyCache sync.Map // map[string]*schocoCacheEntry

type schocoCacheEntry struct {
	rootPK   *edwards25519.Point
	messages [][]byte
	partSigs []*edwards25519.Point
}

/* ============================================================
   Create / Extend / Validate (JWS)
============================================================ */

func CreateJWS(payload *Payload, version int8, key interface{}) (string, error) {
	payloadBytes, err := marshalCanonical(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %v", err)
	}
	header := map[string]interface{}{"version": version}
	headerBytes, _ := json.Marshal(header)

	var sigBytes []byte
	switch version {
	case VerECDSA:
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("version %d requires *ecdsa.PrivateKey", version)
		}
		h := sha256.Sum256(payloadBytes)
		sigBytes, err = ecdsaKey.Sign(rand.Reader, h[:], crypto.SHA256)
		if err != nil {
			return "", fmt.Errorf("ecdsa sign: %v", err)
		}
	case VerSchoCo, VerSchnorr:
		sk, ok := key.(*edwards25519.Scalar)
		if !ok {
			return "", fmt.Errorf("version %d requires *edwards25519.Scalar", version)
		}
		sig, err := schoco.StdSign(payloadBytes, sk)
		if err != nil {
			return "", fmt.Errorf("StdSign: %v", err)
		}
		sigBytes, err = sig.MarshalBinary()
		if err != nil {
			return "", fmt.Errorf("MarshalBinary: %v", err)
		}
	default:
		return "", fmt.Errorf("unsupported version: %d", version)
	}

	return strings.Join([]string{b64Encode(headerBytes), b64Encode(payloadBytes), b64Encode(sigBytes)}, "."), nil
}

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
	case VerECDSA:
		newNode.ID = b64Encode(sigB)
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
		return strings.Join([]string{b64Encode(headerB), b64Encode(newPayloadBytes), b64Encode(newSig)}, "."), nil

	case VerSchoCo:
		// SchoCo: previous signature provides the aggregation key (S) and the partial (R) becomes node ID.
		prevSig, err := schoco.UnmarshalSignature(sigB)
		if err != nil {
			return "", fmt.Errorf("unmarshal previous signature: %v", err)
		}
		partSigB64 := b64Encode(prevSig.R.Bytes())
		newNode.ID = partSigB64
		doc.List = append(doc.List, newNode)

		// Use aggregation key from previous signature (prevSig.S) to sign the new payload.
		aggKey := prevSig.S
		newPayloadBytes, _ := marshalCanonical(&doc)
		newSig, err := schoco.StdSign(newPayloadBytes, aggKey)
		if err != nil {
			return "", fmt.Errorf("StdSign aggregate: %v", err)
		}
		newSigBytes, _ := newSig.MarshalBinary()

		var hdr map[string]interface{}
		_ = json.Unmarshal(headerB, &hdr)
		hdr["version"] = version
		hdrB, _ := json.Marshal(hdr)

		// Invalidate cache for this JWS payload (the payload bytes changed)
		// Note: old payloadB string was key for cache; it will be different for newPayloadBytes, so no need to delete explicitly.

		return strings.Join([]string{b64Encode(hdrB), b64Encode(newPayloadBytes), b64Encode(newSigBytes)}, "."), nil

	case VerSchnorr:
		// Schnorr puro sequencial: previous full signature becomes node ID, and caller must provide the schnorr private key
		newNodeID := b64Encode(sigB) // full previous signature as node ID (sequential semantics)
		newNode.ID = newNodeID
		doc.List = append(doc.List, newNode)

		if len(key) == 0 {
			return "", fmt.Errorf("schnorr key required for extension")
		}
		sk, ok := key[0].(*edwards25519.Scalar)
		if !ok {
			return "", fmt.Errorf("schnorr extension requires *edwards25519.Scalar key")
		}

		newPayloadBytes, err := marshalCanonical(&doc)
		if err != nil {
			return "", fmt.Errorf("marshal canonical: %v", err)
		}

		newSig, err := schoco.StdSign(newPayloadBytes, sk)
		if err != nil {
			return "", fmt.Errorf("StdSign schnorr: %v", err)
		}
		newSigBytes, _ := newSig.MarshalBinary()

		var hdr2 map[string]interface{}
		_ = json.Unmarshal(headerB, &hdr2)
		hdr2["version"] = version
		hdrB2, _ := json.Marshal(hdr2)

		return strings.Join([]string{b64Encode(hdrB2), b64Encode(newPayloadBytes), b64Encode(newSigBytes)}, "."), nil

	default:
		return "", fmt.Errorf("unsupported version: %d", version)
	}
}

func ValidateJWS(jws string, version int8, bundle ...*Payload) (bool, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid jws format")
	}
	payloadB, _ := b64Decode(parts[1])
	sigB, _ := b64Decode(parts[2])

	var doc Payload
	if err := json.Unmarshal(payloadB, &doc); err != nil {
		return false, fmt.Errorf("unmarshal payload: %v", err)
	}

	switch version {
	case VerECDSA:
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

	case VerSchoCo:
		// Agg verification path with caching of heavy prep work (messages, partSigs, rootPK)
		N := len(doc.List)
		lastSig, err := schoco.UnmarshalSignature(sigB)
		if err != nil {
			return false, fmt.Errorf("unmarshal lastSig: %v", err)
		}

		// key for cache is the exact payload bytes as present in the JWS
		cacheKey := string(payloadB)

		var entry *schocoCacheEntry
		if v, ok := schocoVerifyCache.Load(cacheKey); ok {
			entry = v.(*schocoCacheEntry)
		} else {
			// build fresh cache entry
			rootPK := new(edwards25519.Point)
			if _, err := rootPK.SetBytes(doc.Iss.PK); err != nil {
				return false, fmt.Errorf("SetBytes rootPK: %v", err)
			}

			// messages[0] = payload final (payloadB)
			// messages[1] = payload with List[:N-1]
			// messages[2] = payload with List[:N-2]
			// ...
			messages := make([][]byte, 0, N+1)
			messages = append(messages, payloadB)

			// partSigs in order: R_{N-1}, R_{N-2}, ..., R_0
			partSigs := make([]*edwards25519.Point, 0, N)
			for i := N - 1; i >= 0; i-- {
				node := doc.List[i]
				idBytes, _ := b64Decode(node.ID)
				pt, err := new(edwards25519.Point).SetBytes(idBytes)
				if err != nil {
					return false, fmt.Errorf("SetBytes partSig: %v", err)
				}
				partSigs = append(partSigs, pt)

				p := &Payload{
					Ver:  doc.Ver,
					Iat:  doc.Iat,
					Iss:  doc.Iss,
					Aud:  doc.Aud,
					Sub:  doc.Sub,
					Data: doc.Data,
					List: doc.List[:i],
				}
				b, _ := marshalCanonical(p)
				messages = append(messages, b)
			}

			entry = &schocoCacheEntry{
				rootPK:   rootPK,
				messages: messages,
				partSigs: partSigs,
			}
			schocoVerifyCache.Store(cacheKey, entry)
		}

		if !schoco.Verify(entry.rootPK, entry.messages, entry.partSigs, lastSig) {
			return false, fmt.Errorf("SchoCo verification failed")
		}
		return true, nil

	case VerSchnorr:
		// Sequential Schnorr verification (mirror ECDSA sequential, but using edwards25519 sigs)
		N := len(doc.List)

		// root public key (used for all steps in sequential mode)
		rootPK := new(edwards25519.Point)
		if _, err := rootPK.SetBytes(doc.Iss.PK); err != nil {
			return false, fmt.Errorf("SetBytes rootPK: %v", err)
		}

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

			sigStruct, err := schoco.UnmarshalSignature(sigToCheck)
			if err != nil {
				return false, fmt.Errorf("byteToSignature (k=%d): %v", k, err)
			}

			if !schoco.StdVerify(partialBytes, sigStruct, rootPK) {
				return false, fmt.Errorf("schnorr signature failed at step %d", k)
			}
		}
		return true, nil

	default:
		return false, fmt.Errorf("unsupported version: %d", version)
	}
}

/* ============================================================
   Presentation helpers
============================================================ */

func CreateDisclosureFromLeaves(leaves [][]byte, selectedIndices []int) (*sd.Disclosure, error) {
	return sd.CreateDisclosure(leaves, selectedIndices)
}

func CreatePresentationFromData(data map[string]interface{}, selectedKeys []string) (*sd.Disclosure, error) {
	keysOrder, leaves, err := DataToLeaves(data)
	if err != nil {
		return nil, err
	}
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

func ValidateJWSWithPresentations(jws string, version int8, presentations map[int]*sd.Disclosure, bundle ...*Payload) (bool, error) {
	ok, err := ValidateJWS(jws, version, bundle...)
	if err != nil || !ok {
		return false, err
	}
	parts := strings.Split(jws, ".")
	payloadB, _ := b64Decode(parts[1])
	var doc Payload
	if err := json.Unmarshal(payloadB, &doc); err != nil {
		return false, fmt.Errorf("unmarshal payload: %v", err)
	}

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

	if pres, ok := presentations[0]; ok {
		if _, err := verifyNode(&doc, pres); err != nil {
			return false, err
		}
	}

	for i, node := range doc.List {
		if node == nil || node.Payload == nil {
			continue
		}
		pres, ok := presentations[i+1]
		if !ok {
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
