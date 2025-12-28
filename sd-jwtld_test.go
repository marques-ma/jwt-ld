package jwtld

import (
	// "crypto/ecdsa"
	// "crypto/elliptic"
	// "crypto/rand"
	// "crypto/x509"
	// "encoding/base64"
	"encoding/json"
	"fmt"
	// "sort"
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

// func Test_ECDSA_SimpleSDFlow(t *testing.T) {
// 	fmt.Println("=== ECDSA SD Flow ===")
// 	// generate ECDSA key
// 	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	if err != nil {
// 		t.Fatalf("ecdsa gen: %v", err)
// 	}
// 	pubBytes, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)

// 	// original clear data for root
// 	orig := map[string]interface{}{
// 		"country": "NL",
// 		"status":  "student",
// 	}

// 	// build payload (empty Data for now)
// 	rootPayload := &Payload{
// 		Ver: 0,
// 		Iat: time.Now().Unix(),
// 		Iss: &IDClaim{CN: "root-ecdsa", PK: pubBytes},
// 	}

// 	// attach SD root - returns keys order and leaves (caller keeps leaves to create disclosures)
// 	keys, leaves, err := AttachSDRootToPayload(rootPayload, orig)
// 	if err != nil {
// 		t.Fatalf("AttachSDRootToPayload: %v", err)
// 	}
// 	fmt.Println("Root payload after attach (Data metadata):", pretty(rootPayload.Data))
// 	fmt.Println("Leaves count:", len(leaves), "keys:", keys)

// 	// create JWS (signs payload which contains only root under Data)
// 	jws, err := CreateJWS(rootPayload, 0, priv)
// 	if err != nil {
// 		t.Fatalf("CreateJWS: %v", err)
// 	}
// 	fmt.Println("Root JWS:", jws)

// 	// validate token
// 	ok, err := ValidateJWS(jws, 0)
// 	if err != nil || !ok {
// 		t.Fatalf("ValidateJWS root failed: %v", err)
// 	}
// 	fmt.Println("Root JWS validated OK")

// 	// create disclosure (reveal "country")
// 	idx := indexOf(keys, "country")
// 	if idx < 0 {
// 		t.Fatalf("country not found in keys")
// 	}
// 	disc, err := sd.CreateDisclosure(leaves, []int{idx})
// 	if err != nil {
// 		t.Fatalf("CreateDisclosure: %v", err)
// 	}
// 	fmt.Println("Disclosure (country):", pretty(disc))

// 	// validate presentation (present root + disclosure)
// 	presMap := map[int]*sd.Disclosure{0: disc} // 0 => root
// 	ok, err = ValidateJWSWithPresentations(jws, 0, presMap)
// 	if err != nil || !ok {
// 		t.Fatalf("ValidateJWSWithPresentations failed: %v", err)
// 	}
// 	fmt.Println("Presentation validated OK (root)")

// 	// now create a node/extension that also uses SD
// 	nodeData := map[string]interface{}{
// 		"role": "admin",
// 		"team": "research",
// 	}
// 	nodePayload := &Payload{
// 		Ver: 0,
// 		Iss: &IDClaim{CN: "node-1", PK: pubBytes},
// 	}
// 	keysNode, leavesNode, err := AttachSDRootToPayload(nodePayload, nodeData)
// 	if err != nil {
// 		t.Fatalf("AttachSDRootToPayload node: %v", err)
// 	}
// 	fmt.Println("Node payload Data metadata:", pretty(nodePayload.Data))

// 	// extend JWS with node (nodePayload already contains sd root)
// 	jws2, err := ExtendJWS(jws, &LDNode{Payload: nodePayload}, 0, priv)
// 	if err != nil {
// 		t.Fatalf("ExtendJWS: %v", err)
// 	}
// 	fmt.Println("Extended JWS:", jws2)

// 	// validate extended token
// 	ok, err = ValidateJWS(jws2, 0)
// 	if err != nil || !ok {
// 		t.Fatalf("ValidateJWS extended failed: %v", err)
// 	}
// 	fmt.Println("Extended JWS validated OK")

// 	// create disclosure for node (reveal "role")
// 	idxNode := indexOf(keysNode, "role")
// 	if idxNode < 0 {
// 		t.Fatalf("role not found in node keys")
// 	}
// 	discNode, err := sd.CreateDisclosure(leavesNode, []int{idxNode})
// 	if err != nil {
// 		t.Fatalf("CreateDisclosure node: %v", err)
// 	}

// 	// Now presentation map must include root (0) and node (1)
// 	presMap = map[int]*sd.Disclosure{0: disc, 1: discNode}
// 	ok, err = ValidateJWSWithPresentations(jws2, 0, presMap)
// 	if err != nil || !ok {
// 		t.Fatalf("ValidateJWSWithPresentations for extended token failed: %v", err)
// 	}
// 	fmt.Println("Extended token + presentations validated OK")
// }

// func Test_SchoCo_SimpleSDFlow(t *testing.T) {
// 	fmt.Println("=== SchoCo SD Flow ===")
// 	// schoco keypair (root)
// 	rootSk, rootPk := schoco.KeyPair("root")
// 	rootPKBytes, _ := schoco.PointToByte(rootPk)

// 	// original clear data for root
// 	orig := map[string]interface{}{
// 		"repo.read":  true,
// 		"repo.write": false,
// 		"pr.open":    true,
// 	}

// 	rootPayload := &Payload{
// 		Ver: 1,
// 		Iat: time.Now().Unix(),
// 		Iss: &IDClaim{CN: "root-schoco", PK: rootPKBytes},
// 	}

// 	keys, leaves, err := AttachSDRootToPayload(rootPayload, orig)
// 	if err != nil {
// 		t.Fatalf("AttachSDRootToPayload schoco: %v", err)
// 	}
// 	fmt.Println("Root payload sd metadata:", pretty(rootPayload.Data))
// 	fmt.Println("Leaves keys:", keys)

// 	// create JWS signed with schoco scalar
// 	jws, err := CreateJWS(rootPayload, 1, rootSk)
// 	if err != nil {
// 		t.Fatalf("CreateJWS schoco: %v", err)
// 	}
// 	fmt.Println("Root JWS:", jws)

// 	ok, err := ValidateJWS(jws, 1)
// 	if err != nil || !ok {
// 		t.Fatalf("ValidateJWS schoco root failed: %v", err)
// 	}
// 	fmt.Println("Schoco root validated OK")

// 	// create disclosure reveal repo.read
// 	idx := indexOf(keys, "repo.read")
// 	if idx < 0 {
// 		t.Fatalf("repo.read not found")
// 	}
// 	disc, err := sd.CreateDisclosure(leaves, []int{idx})
// 	if err != nil {
// 		t.Fatalf("CreateDisclosure schoco: %v", err)
// 	}
// 	fmt.Println("Disclosure:", pretty(disc))

// 	// validate presentation
// 	presMap := map[int]*sd.Disclosure{0: disc}
// 	ok, err = ValidateJWSWithPresentations(jws, 1, presMap)
// 	if err != nil || !ok {
// 		t.Fatalf("ValidateJWSWithPresentations schoco failed: %v", err)
// 	}
// 	fmt.Println("Schoco presentation validated OK")
// }

func Test_SchoCo_FullSDFlow(t *testing.T) {
	fmt.Println("=== SchoCo Mode Full SD Flow ===")

	// 1️⃣ Gerar chave do root (SchoCo)
	rootSk, rootPk := schoco.KeyPair("root")
	rootPKBytes, _ := schoco.PointToByte(rootPk)

	// 2️⃣ Definir claims originais (privilégios)
	orig := map[string]interface{}{
		"repo.read":  true,
		"repo.write": false,
		"pr.open":    true,
	}
	fmt.Println("Original data (cleartext):")
	fmt.Println(pretty(orig))

	// 3️⃣ Construir payload raiz
	rootPayload := &Payload{
		Ver: 1,
		Iat: time.Now().Unix(),
		Iss: &IDClaim{CN: "root-schoco", PK: rootPKBytes},
	}

	// 4️⃣ Anexar SD root (Merkle root)
	keys, leaves, err := AttachSDRootToPayload(rootPayload, orig)
	if err != nil {
		t.Fatalf("AttachSDRootToPayload schoco: %v", err)
	}
	fmt.Println("Root payload SD metadata:", pretty(rootPayload.Data))
	fmt.Println("Leaves keys:", keys)

	// 5️⃣ Criar JWS assinado com root SchoCo
	jws, err := CreateJWS(rootPayload, 1, rootSk)
	if err != nil {
		t.Fatalf("CreateJWS schoco: %v", err)
	}
	fmt.Println("Root JWS:", jws)

	// 6️⃣ Validar token raiz
	ok, err := ValidateJWS(jws, 1)
	if err != nil || !ok {
		t.Fatalf("ValidateJWS schoco root failed: %v", err)
	}
	fmt.Println("Schoco root validated OK")

	// 7️⃣ Criar disclosure seletivo (ex.: só "repo.read")
	fmt.Println("Creating disclosure for 'repo.read'")
	idx := indexOf(keys, "repo.read")
	if idx < 0 {
		t.Fatalf("repo.read not found in keys")
	}

	disc, err := sd.CreateDisclosure(leaves, []int{idx})
	if err != nil {
		t.Fatalf("CreateDisclosure schoco: %v", err)
	}
	fmt.Println("Disclosure (repo.read):", pretty(disc))

	// 8️⃣ Simular apresentação ao verificador
	fmt.Println("Validating presentation with 'repo.read' disclosure")
	presMap := map[int]*sd.Disclosure{0: disc}

	ok, err = ValidateJWSWithPresentations(jws, 1, presMap)
	if err != nil || !ok {
		t.Fatalf("ValidateJWSWithPresentations schoco failed: %v", err)
	}
	fmt.Println("Schoco presentation validated OK")

	// 9️⃣ Validar claim revelada (SEMÂNTICA)
	fmt.Println("Checking revealed SD claim")

	claims, err := ExtractSDClaimsFromDisclosure(disc)
	if err != nil {
		t.Fatalf("ExtractSDClaimsFromDisclosure failed: %v", err)
	}
	if len(claims) != 1 {
		t.Fatalf("expected 1 revealed claim, got %d", len(claims))
	}

	c := claims[0]

	if c.ID != "repo.read" {
		t.Fatalf("unexpected claim id: got %s, want repo.read", c.ID)
	}
	val, ok := c.Value.(bool)
	if !ok {
		t.Fatalf("claim value is not bool: %T", c.Value)
	}
	if val != true {
		t.Fatalf("claim 'repo.read' value mismatch: got %v, want true", val)
	}

	fmt.Println("Revealed claim OK:", c.ID, "=", c.Value)
}
