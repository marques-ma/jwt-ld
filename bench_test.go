package jwtld

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/hpe-usp-spire/schoco"
	sd "github.com/marques-ma/merkle-selective-disclosure"
	"filippo.io/edwards25519"
	"github.com/golang-jwt/jwt/v5"
)

var extCounts = []int{0, 2, 4, 8, 16, 32, 64}

var (
	ecdsaPriv *ecdsa.PrivateKey
	ecdsaPub  []byte

	schocoSk   *edwards25519.Scalar
	schocoPkPt *edwards25519.Point
	schocoPkB  []byte

	schnorrSk   *edwards25519.Scalar
	schnorrPkPt *edwards25519.Point
	schnorrPkB  []byte

	payloadECDSA   *Payload
	payloadSchoCo  *Payload
	payloadSchnorr *Payload

	sdData = map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}

	// JWT baseline keys
	jwtPriv *ecdsa.PrivateKey
	jwtPub  *ecdsa.PublicKey
)

func init() {
	// ECDSA
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	ecdsaPriv = priv
	ecdsaPub, _ = x509.MarshalPKIXPublicKey(&priv.PublicKey)

	// SchoCo
	sk, pk, err := schoco.KeyPair()
	if err != nil {
		panic(err)
	}
	schocoSk = sk
	schocoPkPt = pk
	schocoPkB = pk.Bytes()

	// Schnorr puro
	skS, pkS, err := schoco.KeyPair()
	if err != nil {
		panic(err)
	}
	schnorrSk = skS
	schnorrPkPt = pkS
	schnorrPkB = pkS.Bytes()

	// base payloads
	now := time.Now().Unix()
	payloadECDSA = &Payload{Ver: VerECDSA, Iat: now, Iss: &IDClaim{CN: "root-ecdsa", PK: ecdsaPub}}
	payloadSchoCo = &Payload{Ver: VerSchoCo, Iat: now, Iss: &IDClaim{CN: "root-schoco", PK: schocoPkB}}
	payloadSchnorr = &Payload{Ver: VerSchnorr, Iat: now, Iss: &IDClaim{CN: "root-schnorr", PK: schnorrPkB}}

	// JWT baseline
	jwtPriv, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwtPub = &jwtPriv.PublicKey
}

// ---------------- JWT BASELINE HELPERS ----------------

func buildJWTBaseline(scopes []string) (string, error) {
	claims := jwt.MapClaims{
		"iss":   "https://issuer.example",
		"sub":   "agent-123",
		"aud":   "server",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"scope": scopes,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return tok.SignedString(jwtPriv)
}

func parseAndValidateJWT(jws string) error {
	_, err := jwt.Parse(jws, func(token *jwt.Token) (interface{}, error) {
		return jwtPub, nil
	})
	return err
}
// buildToken atualizado
func buildToken(alg string, useSD bool, extCount int) (string, map[int]*sd.Disclosure, error) {
	var ver int8
	var root *Payload
	switch alg {
	case "ECDSA":
		ver = VerECDSA
		root = &Payload{Ver: ver, Iat: payloadECDSA.Iat, Iss: payloadECDSA.Iss}
	case "SchoCo":
		ver = VerSchoCo
		root = &Payload{Ver: ver, Iat: payloadSchoCo.Iat, Iss: payloadSchoCo.Iss}
	case "Schnorr":
		ver = VerSchnorr
		root = &Payload{Ver: ver, Iat: payloadSchnorr.Iat, Iss: payloadSchnorr.Iss}
	default:
		return "", nil, fmt.Errorf("unknown alg: %s", alg)
	}

	pres := make(map[int]*sd.Disclosure)

	if useSD {
		_, rootLeaves, err := AttachSDRootToPayload(root, sdData)
		if err != nil {
			return "", nil, fmt.Errorf("attach sd root: %v", err)
		}
		disc, err := CreateDisclosureFromLeaves(rootLeaves, []int{0})
		if err != nil {
			return "", nil, fmt.Errorf("create root disc: %v", err)
		}
		pres[0] = disc
	}

	var jws string
	var err error
	switch alg {
	case "ECDSA":
		jws, err = CreateJWS(root, ver, ecdsaPriv)
	case "SchoCo":
		jws, err = CreateJWS(root, ver, schocoSk)
	case "Schnorr":
		jws, err = CreateJWS(root, ver, schnorrSk)
	}
	if err != nil {
		return "", nil, fmt.Errorf("create root jws: %v", err)
	}

	for i := 0; i < extCount; i++ {
		node := &Payload{}
		// para SchoCo e Schnorr, não sobrescrever Iss.PK
		if alg == "ECDSA" {
			node.Iss = root.Iss
		} else if alg == "SchoCo" || alg == "Schnorr" {
			node.Iss = &IDClaim{CN: root.Iss.CN}
		}
		node.Ver = ver

		if useSD {
			_, nodeLeaves, err := AttachSDRootToPayload(node, map[string]interface{}{fmt.Sprintf("n%d", i): true})
			if err != nil {
				return "", nil, fmt.Errorf("attach sd node: %v", err)
			}
			disc, err := CreateDisclosureFromLeaves(nodeLeaves, []int{0})
			if err != nil {
				return "", nil, fmt.Errorf("create node disc: %v", err)
			}
			pres[i+1] = disc
		}

		switch alg {
		case "ECDSA":
			jws, err = ExtendJWS(jws, &LDNode{Payload: node}, ver, ecdsaPriv)
		case "SchoCo":
			jws, err = ExtendJWS(jws, &LDNode{Payload: node}, ver)
		case "Schnorr":
			jws, err = ExtendJWS(jws, &LDNode{Payload: node}, ver, schnorrSk)
		}
		if err != nil {
			return "", nil, fmt.Errorf("extend jws: %v", err)
		}
	}

	return jws, pres, nil
}

// ----------------------------- BENCHMARKS -----------------------------

func Benchmark_GenScaling(b *testing.B) {
	for _, alg := range []string{"ECDSA", "SchoCo", "Schnorr"} {
		for _, useSD := range []bool{false, true} {
			sdLabel := "NoSD"
			if useSD {
				sdLabel = "SD"
			}
			for _, ext := range extCounts {
				name := fmt.Sprintf("%s_%s_Ext_%d/Gen", alg, sdLabel, ext)
				b.Run(name, func(b *testing.B) {
					var totalSize uint64
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						jws, _, err := buildToken(alg, useSD, ext)
						if err != nil {
							b.Fatalf("buildToken error: %v", err)
						}
						totalSize += uint64(len(jws))
					}
					avg := float64(totalSize) / float64(b.N)
					b.ReportMetric(avg, "bytes")
				})
			}
		}
	}
}

func Benchmark_ExtendScaling(b *testing.B) {
	for _, alg := range []string{"ECDSA", "SchoCo", "Schnorr"} {
		for _, useSD := range []bool{false, true} {
			sdLabel := "NoSD"
			if useSD {
				sdLabel = "SD"
			}
			for _, ext := range extCounts {
				name := fmt.Sprintf("%s_%s_Ext_%d/ExtendOne", alg, sdLabel, ext)
				b.Run(name, func(b *testing.B) {
					baseLen := ext - 1
					if baseLen < 0 {
						baseLen = 0
					}
					baseJWS, _, err := buildToken(alg, useSD, baseLen)
					if err != nil {
						b.Fatalf("build base chain: %v", err)
					}

					var ver int8
					var rootIss *IDClaim
					switch alg {
					case "ECDSA":
						ver = VerECDSA
						rootIss = payloadECDSA.Iss
					case "SchoCo":
						ver = VerSchoCo
						rootIss = payloadSchoCo.Iss
					case "Schnorr":
						ver = VerSchnorr
						rootIss = payloadSchnorr.Iss
					}

					node := &LDNode{Payload: &Payload{Ver: ver, Iss: rootIss}}
					if useSD {
						AttachSDRootToPayload(node.Payload, map[string]interface{}{"added": true})
					}

					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						switch alg {
						case "ECDSA":
							_, err = ExtendJWS(baseJWS, node, ver, ecdsaPriv)
						case "SchoCo":
							_, err = ExtendJWS(baseJWS, node, ver)
						case "Schnorr":
							_, err = ExtendJWS(baseJWS, node, ver, schnorrSk)
						}
						if err != nil {
							b.Fatalf("extend failed: %v", err)
						}
					}

					if jws, _, err := buildToken(alg, useSD, ext); err == nil {
						b.ReportMetric(float64(len(jws)), "bytes")
					}
				})
			}
		}
	}
}

func Benchmark_ValidateScaling(b *testing.B) {
	for _, alg := range []string{"ECDSA", "SchoCo", "Schnorr"} {
		for _, useSD := range []bool{false, true} {
			sdLabel := "NoSD"
			if useSD {
				sdLabel = "SD"
			}
			for _, ext := range extCounts {
				name := fmt.Sprintf("%s_%s_Ext_%d/Validate", alg, sdLabel, ext)
				b.Run(name, func(b *testing.B) {
					jws, pres, err := buildToken(alg, useSD, ext)
					if err != nil {
						b.Fatalf("build token: %v", err)
					}

					b.ReportMetric(float64(len(jws)), "bytes")

					var ver int8
					switch alg {
					case "ECDSA":
						ver = VerECDSA
					case "SchoCo":
						ver = VerSchoCo
					case "Schnorr":
						ver = VerSchnorr
					}

					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if useSD {
							ok, err := ValidateJWSWithPresentations(jws, ver, pres)
							if err != nil || !ok {
								b.Fatalf("validate w/pres failed: %v", err)
							}
						} else {
							ok, err := ValidateJWS(jws, ver)
							if err != nil || !ok {
								b.Fatalf("validate failed: %v", err)
							}
						}
					}
				})
			}
		}
	}
}

func Benchmark_JWTBaseline_GenScaling(b *testing.B) {
	for _, ext := range extCounts {
		name := fmt.Sprintf("JWTBaseline_Ext_%d/Gen", ext)
		b.Run(name, func(b *testing.B) {
			var totalSize uint64
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for j := 0; j <= ext; j++ {
					scopes := make([]string, j+1)
					for k := 0; k <= j; k++ {
						scopes[k] = fmt.Sprintf("perm.%d", k)
					}
					jws, err := buildJWTBaseline(scopes)
					if err != nil {
						b.Fatalf("jwt gen failed: %v", err)
					}
					totalSize += uint64(len(jws))
				}
			}
			avg := float64(totalSize) / float64(b.N)
			b.ReportMetric(avg, "bytes")
		})
	}
}

func Benchmark_JWTBaseline_ExtendOne(b *testing.B) {
	for _, ext := range extCounts {
		name := fmt.Sprintf("JWTBaseline_Ext_%d/ExtendOne", ext)
		b.Run(name, func(b *testing.B) {
			scopes := make([]string, ext+1)
			for i := 0; i <= ext; i++ {
				scopes[i] = fmt.Sprintf("perm.%d", i)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := buildJWTBaseline(scopes)
				if err != nil {
					b.Fatalf("jwt extend failed: %v", err)
				}
			}
		})
	}
}

func Benchmark_JWTBaseline_ValidateScaling(b *testing.B) {
	for _, ext := range extCounts {
		name := fmt.Sprintf("JWTBaseline_Ext_%d/Validate", ext)
		b.Run(name, func(b *testing.B) {
			var tokens []string
			var totalSize uint64
			for j := 0; j <= ext; j++ {
				scopes := make([]string, j+1)
				for k := 0; k <= j; k++ {
					scopes[k] = fmt.Sprintf("perm.%d", k)
				}
				jws, err := buildJWTBaseline(scopes)
				if err != nil {
					b.Fatalf("jwt gen failed: %v", err)
				}
				tokens = append(tokens, jws)
				totalSize += uint64(len(jws))
			}
			b.ReportMetric(float64(totalSize), "bytes")

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, tok := range tokens {
					if err := parseAndValidateJWT(tok); err != nil {
						b.Fatalf("jwt validate failed: %v", err)
					}
				}
			}
		})
	}
}