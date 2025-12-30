package jwtld

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	sd "github.com/marques-ma/merkle-selective-disclosure"
	"github.com/hpe-usp-spire/schoco"
)

// pretty helper
func pretty(v interface{}) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

// find index for key in keysOrder
func indexOf(keys []string, key string) int {
	for i, k := range keys {
		if k == key {
			return i
		}
	}
	return -1
}

func Test_ECDSA_SimpleSDFlow(t *testing.T) {
	fmt.Println("=== ECDSA SD Flow ===")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa gen: %v", err)
	}
	pubBytes, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)

	orig := map[string]interface{}{
		"country": "NL",
		"status":  "student",
	}

	rootPayload := &Payload{
		Ver: VerECDSA,
		Iat: time.Now().Unix(),
		Iss: &IDClaim{CN: "root-ecdsa", PK: pubBytes},
	}

	keys, leaves, err := AttachSDRootToPayload(rootPayload, orig)
	if err != nil {
		t.Fatalf("AttachSDRootToPayload: %v", err)
	}
	fmt.Println("Root payload SD metadata:", pretty(rootPayload.Data))
	fmt.Println("Leaves count:", len(leaves), "keys:", keys)

	jws, err := CreateJWS(rootPayload, VerECDSA, priv)
	if err != nil {
		t.Fatalf("CreateJWS: %v", err)
	}
	fmt.Println("Root JWS:", jws)

	ok, err := ValidateJWS(jws, VerECDSA)
	if err != nil || !ok {
		t.Fatalf("ValidateJWS root failed: %v", err)
	}
	fmt.Println("Root JWS validated OK")

	idx := indexOf(keys, "country")
	disc, err := sd.CreateDisclosure(leaves, []int{idx})
	if err != nil {
		t.Fatalf("CreateDisclosure: %v", err)
	}

	presMap := map[int]*sd.Disclosure{0: disc}
	ok, err = ValidateJWSWithPresentations(jws, VerECDSA, presMap)
	if err != nil || !ok {
		t.Fatalf("ValidateJWSWithPresentations failed: %v", err)
	}
	fmt.Println("Presentation validated OK (root)")
}

func Test_SchoCo_SimpleSDFlow(t *testing.T) {
	fmt.Println("=== SchoCo SD Flow ===")
	rootSk, rootPk, _ := schoco.KeyPair()
	rootPKBytes := rootPk.Bytes()

	orig := map[string]interface{}{
		"repo.read":  true,
		"repo.write": false,
		"pr.open":    true,
	}

	rootPayload := &Payload{
		Ver: VerSchoCo,
		Iat: time.Now().Unix(),
		Iss: &IDClaim{CN: "root-schoco", PK: rootPKBytes},
	}

	keys, leaves, err := AttachSDRootToPayload(rootPayload, orig)
	if err != nil {
		t.Fatalf("AttachSDRootToPayload schoco: %v", err)
	}
	fmt.Println("Root payload SD metadata:", pretty(rootPayload.Data))
	fmt.Println("Leaves keys:", keys)

	jws, err := CreateJWS(rootPayload, VerSchoCo, rootSk)
	if err != nil {
		t.Fatalf("CreateJWS schoco: %v", err)
	}
	fmt.Println("Root JWS:", jws)

	ok, err := ValidateJWS(jws, VerSchoCo)
	if err != nil || !ok {
		t.Fatalf("ValidateJWS schoco root failed: %v", err)
	}
	fmt.Println("Schoco root validated OK")

	idx := indexOf(keys, "repo.read")
	disc, err := sd.CreateDisclosure(leaves, []int{idx})
	if err != nil {
		t.Fatalf("CreateDisclosure schoco: %v", err)
	}

	presMap := map[int]*sd.Disclosure{0: disc}
	ok, err = ValidateJWSWithPresentations(jws, VerSchoCo, presMap)
	if err != nil || !ok {
		t.Fatalf("ValidateJWSWithPresentations schoco failed: %v", err)
	}
	fmt.Println("Schoco presentation validated OK")
}

func Test_SchoCo_FullSDFlow(t *testing.T) {
	fmt.Println("=== SchoCo Full SD Flow ===")
	rootSk, rootPk, _ := schoco.KeyPair()
	rootPKBytes := rootPk.Bytes()

	orig := map[string]interface{}{
		"repo.read":  true,
		"repo.write": false,
		"pr.open":    true,
	}

	rootPayload := &Payload{
		Ver: VerSchoCo,
		Iat: time.Now().Unix(),
		Iss: &IDClaim{CN: "root-schoco", PK: rootPKBytes},
	}

	keys, leaves, err := AttachSDRootToPayload(rootPayload, orig)
	if err != nil {
		t.Fatalf("AttachSDRootToPayload schoco: %v", err)
	}
	fmt.Println("Root payload SD metadata:", pretty(rootPayload.Data))
	fmt.Println("Leaves keys:", keys)

	jws, err := CreateJWS(rootPayload, VerSchoCo, rootSk)
	if err != nil {
		t.Fatalf("CreateJWS schoco: %v", err)
	}

	ok, err := ValidateJWS(jws, VerSchoCo)
	if err != nil || !ok {
		t.Fatalf("ValidateJWS schoco root failed: %v", err)
	}

	idx := indexOf(keys, "repo.read")
	disc, err := sd.CreateDisclosure(leaves, []int{idx})
	if err != nil {
		t.Fatalf("CreateDisclosure schoco: %v", err)
	}

	presMap := map[int]*sd.Disclosure{0: disc}
	ok, err = ValidateJWSWithPresentations(jws, VerSchoCo, presMap)
	if err != nil || !ok {
		t.Fatalf("ValidateJWSWithPresentations schoco failed: %v", err)
	}

	claims, err := ExtractSDClaimsFromDisclosure(disc)
	if err != nil {
		t.Fatalf("ExtractSDClaimsFromDisclosure failed: %v", err)
	}
	if len(claims) != 1 || claims[0].ID != "repo.read" {
		t.Fatalf("unexpected revealed claims: %+v", claims)
	}
	fmt.Println("Revealed claim OK:", claims[0].ID, "=", claims[0].Value)
}
