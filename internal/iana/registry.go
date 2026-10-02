// Package iana provides a typed registry of IKEv1/IKEv2 transforms, exchange
// types, notify types, and authentication methods sourced from IANA registries
// and RFCs 7296, 2409, 4303, 4302, 8221, 8247, 9370.
//
// Design: no name strings are parsed anywhere else in the codebase. Controls
// and rules compare structured Transform fields, never strings. Unknown IDs
// become UNKNOWN(type,id).
package iana

import "fmt"

// RegistryVersion is the registry snapshot identifier.
const RegistryVersion = "iana-2026.10"

// TransformType identifies an IKEv2 transform type.
type TransformType uint8

const (
	TypeEncryption TransformType = 1
	TypePRF        TransformType = 2
	TypeIntegrity  TransformType = 3
	TypeDH         TransformType = 4
	TypeESN        TransformType = 5
	// Additional Key Exchange types (RFC 9370).
	TypeADDKE6  TransformType = 6
	TypeADDKE7  TransformType = 7
	TypeADDKE8  TransformType = 8
	TypeADDKE9  TransformType = 9
	TypeADDKE10 TransformType = 10
	TypeADDKE11 TransformType = 11
	TypeADDKE12 TransformType = 12
)

func (t TransformType) String() string {
	switch t {
	case TypeEncryption:
		return "ENCR"
	case TypePRF:
		return "PRF"
	case TypeIntegrity:
		return "INTEG"
	case TypeDH:
		return "DH"
	case TypeESN:
		return "ESN"
	default:
		if t >= 6 && t <= 12 {
			return fmt.Sprintf("ADDKE%d", t)
		}
		return fmt.Sprintf("TYPE(%d)", t)
	}
}

// Family categorises transforms by crypto family.
type Family string

const (
	FamilyAES      Family = "AES"
	FamilyCamellia Family = "Camellia"
	Family3DES     Family = "3DES"
	FamilyDES      Family = "DES"
	FamilyBlowfish Family = "Blowfish"
	FamilyCAST     Family = "CAST"
	FamilyIDEA     Family = "IDEA"
	FamilyNull     Family = "NULL"
	FamilySHA      Family = "SHA"
	FamilyMD5      Family = "MD5"
	FamilyTiger    Family = "Tiger"
	FamilyModp     Family = "MODP"
	FamilyECP      Family = "ECP"
	FamilyCurve    Family = "Curve"
	FamilyNTRU     Family = "NTRU"
	FamilyOther    Family = "Other"
)

// Transform represents a registry entry for one IKE/IPsec transform.
type Transform struct {
	// Type is the transform type (1=ENCR, 2=PRF, etc.).
	Type TransformType
	// ID is the IANA-assigned numeric identifier.
	ID uint16
	// KeyBits is the key length in bits (0 if not variable).
	KeyBits int
	// Name is the canonical name (for display and reports only).
	Name string
	// Family is the crypto family for grouping.
	Family Family
	// ICVBits is the integrity check value length for AEAD ciphers.
	ICVBits int
	// AEAD is true for combined-mode ciphers (GCM, CCM, ChaCha20-Poly1305).
	AEAD bool
	// Legacy marks algorithms that were once common but are now deprecated.
	Legacy bool
	// RFC is the primary reference RFC number.
	RFC int
}

// RegistryID returns a unique string key for this transform.
func (t Transform) RegistryID() string {
	if t.KeyBits > 0 {
		return fmt.Sprintf("%s-%d-%d", t.Type, t.ID, t.KeyBits)
	}
	return fmt.Sprintf("%s-%d", t.Type, t.ID)
}

// String returns a human-readable name.
func (t Transform) String() string {
	if t.Name != "" {
		return t.Name
	}
	return fmt.Sprintf("UNKNOWN(%s,%d)", t.Type, t.ID)
}

// Lookup finds a transform by type, ID and optional key bits.
// Returns the Transform and true if found, or a synthetic UNKNOWN transform and false.
func Lookup(typ TransformType, id uint16, keyBits int) (Transform, bool) {
	key := registryKey{typ, id, keyBits}
	if t, ok := registry[key]; ok {
		return t, true
	}
	// Try without key bits.
	if keyBits != 0 {
		key2 := registryKey{typ, id, 0}
		if t, ok := registry[key2]; ok {
			t.KeyBits = keyBits
			return t, true
		}
	}
	// Try finding any entry with matching type+id (for DH groups registered with keyBits).
	if keyBits == 0 {
		for k, t := range registry {
			if k.typ == typ && k.id == id {
				return t, true
			}
		}
	}
	return Transform{
		Type:    typ,
		ID:      id,
		KeyBits: keyBits,
		Name:    fmt.Sprintf("UNKNOWN(%s,%d)", typ, id),
		Family:  FamilyOther,
	}, false
}

// LookupDH is a convenience for DH group lookups.
func LookupDH(id uint16) (Transform, bool) {
	return Lookup(TypeDH, id, 0)
}

type registryKey struct {
	typ     TransformType
	id      uint16
	keyBits int
}

var registry = map[registryKey]Transform{}

func reg(t Transform) {
	key := registryKey{t.Type, t.ID, t.KeyBits}
	registry[key] = t
}

func init() {
	// ===== Encryption (Type 1) =====
	// RFC 8221, RFC 8247
	reg(Transform{Type: TypeEncryption, ID: 1, Name: "DES-IV64", Family: FamilyDES, Legacy: true, RFC: 2405})
	reg(Transform{Type: TypeEncryption, ID: 2, Name: "DES", Family: FamilyDES, Legacy: true, RFC: 2405})
	reg(Transform{Type: TypeEncryption, ID: 3, Name: "3DES", Family: Family3DES, Legacy: true, RFC: 2451})
	reg(Transform{Type: TypeEncryption, ID: 4, Name: "RC5", Family: FamilyOther, Legacy: true, RFC: 2451})
	reg(Transform{Type: TypeEncryption, ID: 5, Name: "IDEA", Family: FamilyIDEA, Legacy: true, RFC: 2451})
	reg(Transform{Type: TypeEncryption, ID: 6, Name: "CAST", Family: FamilyCAST, Legacy: true, RFC: 2451})
	reg(Transform{Type: TypeEncryption, ID: 7, Name: "Blowfish", Family: FamilyBlowfish, Legacy: true, RFC: 2451})
	reg(Transform{Type: TypeEncryption, ID: 8, Name: "3IDEA", Family: FamilyIDEA, Legacy: true})
	reg(Transform{Type: TypeEncryption, ID: 9, Name: "DES-IV32", Family: FamilyDES, Legacy: true})
	reg(Transform{Type: TypeEncryption, ID: 11, Name: "NULL", Family: FamilyNull, RFC: 2410})
	reg(Transform{Type: TypeEncryption, ID: 12, KeyBits: 128, Name: "AES-CBC-128", Family: FamilyAES, RFC: 3602})
	reg(Transform{Type: TypeEncryption, ID: 12, KeyBits: 192, Name: "AES-CBC-192", Family: FamilyAES, RFC: 3602})
	reg(Transform{Type: TypeEncryption, ID: 12, KeyBits: 256, Name: "AES-CBC-256", Family: FamilyAES, RFC: 3602})
	reg(Transform{Type: TypeEncryption, ID: 13, KeyBits: 128, Name: "AES-CTR-128", Family: FamilyAES, RFC: 3686})
	reg(Transform{Type: TypeEncryption, ID: 13, KeyBits: 192, Name: "AES-CTR-192", Family: FamilyAES, RFC: 3686})
	reg(Transform{Type: TypeEncryption, ID: 13, KeyBits: 256, Name: "AES-CTR-256", Family: FamilyAES, RFC: 3686})
	reg(Transform{Type: TypeEncryption, ID: 14, Name: "AES-CCM-8", Family: FamilyAES, AEAD: true, ICVBits: 64, RFC: 4309})
	reg(Transform{Type: TypeEncryption, ID: 15, Name: "AES-CCM-12", Family: FamilyAES, AEAD: true, ICVBits: 96, RFC: 4309})
	reg(Transform{Type: TypeEncryption, ID: 16, Name: "AES-CCM-16", Family: FamilyAES, AEAD: true, ICVBits: 128, RFC: 4309})
	reg(Transform{Type: TypeEncryption, ID: 18, KeyBits: 128, Name: "AES-GCM-8-128", Family: FamilyAES, AEAD: true, ICVBits: 64, RFC: 4106})
	reg(Transform{Type: TypeEncryption, ID: 18, KeyBits: 256, Name: "AES-GCM-8-256", Family: FamilyAES, AEAD: true, ICVBits: 64, RFC: 4106})
	reg(Transform{Type: TypeEncryption, ID: 19, KeyBits: 128, Name: "AES-GCM-12-128", Family: FamilyAES, AEAD: true, ICVBits: 96, RFC: 4106})
	reg(Transform{Type: TypeEncryption, ID: 19, KeyBits: 256, Name: "AES-GCM-12-256", Family: FamilyAES, AEAD: true, ICVBits: 96, RFC: 4106})
	reg(Transform{Type: TypeEncryption, ID: 20, KeyBits: 128, Name: "AES-GCM-16-128", Family: FamilyAES, AEAD: true, ICVBits: 128, RFC: 4106})
	reg(Transform{Type: TypeEncryption, ID: 20, KeyBits: 192, Name: "AES-GCM-16-192", Family: FamilyAES, AEAD: true, ICVBits: 128, RFC: 4106})
	reg(Transform{Type: TypeEncryption, ID: 20, KeyBits: 256, Name: "AES-GCM-16-256", Family: FamilyAES, AEAD: true, ICVBits: 128, RFC: 4106})
	reg(Transform{Type: TypeEncryption, ID: 23, KeyBits: 128, Name: "Camellia-CBC-128", Family: FamilyCamellia, RFC: 4312})
	reg(Transform{Type: TypeEncryption, ID: 23, KeyBits: 256, Name: "Camellia-CBC-256", Family: FamilyCamellia, RFC: 4312})
	reg(Transform{Type: TypeEncryption, ID: 28, Name: "ChaCha20-Poly1305", Family: FamilyAES, AEAD: true, ICVBits: 128, KeyBits: 256, RFC: 7634})

	// ===== PRF (Type 2) =====
	reg(Transform{Type: TypePRF, ID: 1, Name: "PRF-HMAC-MD5", Family: FamilyMD5, Legacy: true, RFC: 2104})
	reg(Transform{Type: TypePRF, ID: 2, Name: "PRF-HMAC-SHA1", Family: FamilySHA, RFC: 2104})
	reg(Transform{Type: TypePRF, ID: 3, Name: "PRF-HMAC-TIGER", Family: FamilyTiger, Legacy: true})
	reg(Transform{Type: TypePRF, ID: 4, Name: "PRF-AES128-XCBC", Family: FamilyAES, RFC: 4434})
	reg(Transform{Type: TypePRF, ID: 5, Name: "PRF-HMAC-SHA2-256", Family: FamilySHA, RFC: 4868})
	reg(Transform{Type: TypePRF, ID: 6, Name: "PRF-HMAC-SHA2-384", Family: FamilySHA, RFC: 4868})
	reg(Transform{Type: TypePRF, ID: 7, Name: "PRF-HMAC-SHA2-512", Family: FamilySHA, RFC: 4868})
	reg(Transform{Type: TypePRF, ID: 8, Name: "PRF-AES128-CMAC", Family: FamilyAES, RFC: 4615})

	// ===== Integrity (Type 3) =====
	reg(Transform{Type: TypeIntegrity, ID: 0, Name: "NONE", Family: FamilyNull})
	reg(Transform{Type: TypeIntegrity, ID: 1, Name: "HMAC-MD5-96", Family: FamilyMD5, Legacy: true, ICVBits: 96, RFC: 2403})
	reg(Transform{Type: TypeIntegrity, ID: 2, Name: "HMAC-SHA1-96", Family: FamilySHA, ICVBits: 96, RFC: 2404})
	reg(Transform{Type: TypeIntegrity, ID: 3, Name: "DES-MAC", Family: FamilyDES, Legacy: true, ICVBits: 96})
	reg(Transform{Type: TypeIntegrity, ID: 4, Name: "KPDK-MD5", Family: FamilyMD5, Legacy: true})
	reg(Transform{Type: TypeIntegrity, ID: 5, Name: "AES-XCBC-96", Family: FamilyAES, ICVBits: 96, RFC: 3566})
	reg(Transform{Type: TypeIntegrity, ID: 6, Name: "HMAC-MD5-128", Family: FamilyMD5, Legacy: true, ICVBits: 128})
	reg(Transform{Type: TypeIntegrity, ID: 7, Name: "HMAC-SHA1-160", Family: FamilySHA, ICVBits: 160})
	reg(Transform{Type: TypeIntegrity, ID: 8, Name: "AES-CMAC-96", Family: FamilyAES, ICVBits: 96, RFC: 4494})
	reg(Transform{Type: TypeIntegrity, ID: 9, Name: "AES-128-GMAC", Family: FamilyAES, ICVBits: 128, RFC: 4543})
	reg(Transform{Type: TypeIntegrity, ID: 10, Name: "AES-192-GMAC", Family: FamilyAES, ICVBits: 128, RFC: 4543})
	reg(Transform{Type: TypeIntegrity, ID: 11, Name: "AES-256-GMAC", Family: FamilyAES, ICVBits: 128, RFC: 4543})
	reg(Transform{Type: TypeIntegrity, ID: 12, Name: "HMAC-SHA2-256-128", Family: FamilySHA, ICVBits: 128, RFC: 4868})
	reg(Transform{Type: TypeIntegrity, ID: 13, Name: "HMAC-SHA2-384-192", Family: FamilySHA, ICVBits: 192, RFC: 4868})
	reg(Transform{Type: TypeIntegrity, ID: 14, Name: "HMAC-SHA2-512-256", Family: FamilySHA, ICVBits: 256, RFC: 4868})

	// ===== DH Groups (Type 4) =====
	reg(Transform{Type: TypeDH, ID: 0, Name: "NONE", Family: FamilyNull})
	reg(Transform{Type: TypeDH, ID: 1, Name: "MODP-768", Family: FamilyModp, KeyBits: 768, Legacy: true, RFC: 2409})
	reg(Transform{Type: TypeDH, ID: 2, Name: "MODP-1024", Family: FamilyModp, KeyBits: 1024, Legacy: true, RFC: 2409})
	reg(Transform{Type: TypeDH, ID: 5, Name: "MODP-1536", Family: FamilyModp, KeyBits: 1536, Legacy: true, RFC: 3526})
	reg(Transform{Type: TypeDH, ID: 14, Name: "MODP-2048", Family: FamilyModp, KeyBits: 2048, RFC: 3526})
	reg(Transform{Type: TypeDH, ID: 15, Name: "MODP-3072", Family: FamilyModp, KeyBits: 3072, RFC: 3526})
	reg(Transform{Type: TypeDH, ID: 16, Name: "MODP-4096", Family: FamilyModp, KeyBits: 4096, RFC: 3526})
	reg(Transform{Type: TypeDH, ID: 17, Name: "MODP-6144", Family: FamilyModp, KeyBits: 6144, RFC: 3526})
	reg(Transform{Type: TypeDH, ID: 18, Name: "MODP-8192", Family: FamilyModp, KeyBits: 8192, RFC: 3526})
	reg(Transform{Type: TypeDH, ID: 19, Name: "ECP-256", Family: FamilyECP, KeyBits: 256, RFC: 5903})
	reg(Transform{Type: TypeDH, ID: 20, Name: "ECP-384", Family: FamilyECP, KeyBits: 384, RFC: 5903})
	reg(Transform{Type: TypeDH, ID: 21, Name: "ECP-521", Family: FamilyECP, KeyBits: 521, RFC: 5903})
	reg(Transform{Type: TypeDH, ID: 22, Name: "MODP-1024-160", Family: FamilyModp, KeyBits: 1024, Legacy: true, RFC: 5114})
	reg(Transform{Type: TypeDH, ID: 23, Name: "MODP-2048-224", Family: FamilyModp, KeyBits: 2048, RFC: 5114})
	reg(Transform{Type: TypeDH, ID: 24, Name: "MODP-2048-256", Family: FamilyModp, KeyBits: 2048, RFC: 5114})
	reg(Transform{Type: TypeDH, ID: 25, Name: "ECP-192", Family: FamilyECP, KeyBits: 192, Legacy: true, RFC: 5114})
	reg(Transform{Type: TypeDH, ID: 26, Name: "ECP-224", Family: FamilyECP, KeyBits: 224, Legacy: true, RFC: 5114})
	reg(Transform{Type: TypeDH, ID: 27, Name: "Brainpool-P224r1", Family: FamilyECP, KeyBits: 224, RFC: 6954})
	reg(Transform{Type: TypeDH, ID: 28, Name: "Brainpool-P256r1", Family: FamilyECP, KeyBits: 256, RFC: 6954})
	reg(Transform{Type: TypeDH, ID: 29, Name: "Brainpool-P384r1", Family: FamilyECP, KeyBits: 384, RFC: 6954})
	reg(Transform{Type: TypeDH, ID: 30, Name: "Brainpool-P512r1", Family: FamilyECP, KeyBits: 512, RFC: 6954})
	reg(Transform{Type: TypeDH, ID: 31, Name: "Curve25519", Family: FamilyCurve, KeyBits: 256, RFC: 8031})
	reg(Transform{Type: TypeDH, ID: 32, Name: "Curve448", Family: FamilyCurve, KeyBits: 448, RFC: 8031})

	// ===== ESN (Type 5) =====
	reg(Transform{Type: TypeESN, ID: 0, Name: "No-ESN", Family: FamilyOther, RFC: 7296})
	reg(Transform{Type: TypeESN, ID: 1, Name: "ESN", Family: FamilyOther, RFC: 7296})
}

// All returns all registered transforms. Used by contract tests.
func All() []Transform {
	result := make([]Transform, 0, len(registry))
	for _, t := range registry {
		result = append(result, t)
	}
	return result
}

// IKEv2 Exchange Types
type ExchangeType uint8

const (
	ExchIKE_SA_INIT        ExchangeType = 34
	ExchIKE_AUTH           ExchangeType = 35
	ExchCREATE_CHILD_SA    ExchangeType = 36
	ExchINFORMATIONAL      ExchangeType = 37
	ExchIKE_SESSION_RESUME ExchangeType = 38
	ExchIKE_INTERMEDIATE   ExchangeType = 43
	ExchIKE_FOLLOWUP_KE    ExchangeType = 44
)

// IKEv1 Exchange Types
const (
	ExchV1None          ExchangeType = 0
	ExchV1Main          ExchangeType = 2
	ExchV1Aggressive    ExchangeType = 4
	ExchV1Informational ExchangeType = 5
	ExchV1Quick         ExchangeType = 32
)

func (e ExchangeType) String() string {
	switch e {
	case ExchIKE_SA_INIT:
		return "IKE_SA_INIT"
	case ExchIKE_AUTH:
		return "IKE_AUTH"
	case ExchCREATE_CHILD_SA:
		return "CREATE_CHILD_SA"
	case ExchINFORMATIONAL:
		return "INFORMATIONAL"
	case ExchIKE_SESSION_RESUME:
		return "IKE_SESSION_RESUME"
	case ExchIKE_INTERMEDIATE:
		return "IKE_INTERMEDIATE"
	case ExchIKE_FOLLOWUP_KE:
		return "IKE_FOLLOWUP_KE"
	case ExchV1Main:
		return "Main"
	case ExchV1Aggressive:
		return "Aggressive"
	case ExchV1Informational:
		return "Informational"
	case ExchV1Quick:
		return "Quick"
	default:
		return fmt.Sprintf("Exchange(%d)", e)
	}
}

// IsValidExchange checks if an exchange type is valid for the given IKE major version.
func IsValidExchange(version uint8, exch ExchangeType) bool {
	switch version {
	case 2:
		switch exch {
		case ExchIKE_SA_INIT, ExchIKE_AUTH, ExchCREATE_CHILD_SA,
			ExchINFORMATIONAL, ExchIKE_SESSION_RESUME,
			ExchIKE_INTERMEDIATE, ExchIKE_FOLLOWUP_KE:
			return true
		}
	case 1:
		switch exch {
		case ExchV1None, ExchV1Main, ExchV1Aggressive,
			ExchV1Informational, ExchV1Quick:
			return true
		}
	}
	return false
}

// IKEv2 Payload Types
type PayloadType uint8

const (
	PayloadNone     PayloadType = 0
	PayloadSA       PayloadType = 33
	PayloadKE       PayloadType = 34
	PayloadIDi      PayloadType = 35
	PayloadIDr      PayloadType = 36
	PayloadCERT     PayloadType = 37
	PayloadCERTREQ  PayloadType = 38
	PayloadAUTH     PayloadType = 39
	PayloadNonce    PayloadType = 40
	PayloadNotify   PayloadType = 41
	PayloadDelete   PayloadType = 42
	PayloadVendorID PayloadType = 43
	PayloadTSi      PayloadType = 44
	PayloadTSr      PayloadType = 45
	PayloadSK       PayloadType = 46
	PayloadCP       PayloadType = 47
	PayloadEAP      PayloadType = 48
	PayloadSKF      PayloadType = 53 // IKE fragment
)

func (p PayloadType) String() string {
	switch p {
	case PayloadNone:
		return "None"
	case PayloadSA:
		return "SA"
	case PayloadKE:
		return "KE"
	case PayloadIDi:
		return "IDi"
	case PayloadIDr:
		return "IDr"
	case PayloadCERT:
		return "CERT"
	case PayloadCERTREQ:
		return "CERTREQ"
	case PayloadAUTH:
		return "AUTH"
	case PayloadNonce:
		return "Nonce"
	case PayloadNotify:
		return "Notify"
	case PayloadDelete:
		return "Delete"
	case PayloadVendorID:
		return "VID"
	case PayloadTSi:
		return "TSi"
	case PayloadTSr:
		return "TSr"
	case PayloadSK:
		return "SK"
	case PayloadCP:
		return "CP"
	case PayloadEAP:
		return "EAP"
	case PayloadSKF:
		return "SKF"
	default:
		return fmt.Sprintf("Payload(%d)", p)
	}
}

// IKEv2 Notify Types
type NotifyType uint16

const (
	NotifyINVALID_KE_PAYLOAD            NotifyType = 17
	NotifyNO_PROPOSAL_CHOSEN            NotifyType = 14
	NotifyNAT_DETECTION_SOURCE_IP       NotifyType = 16388
	NotifyNAT_DETECTION_DESTINATION_IP  NotifyType = 16389
	NotifyCOOKIE                        NotifyType = 16390
	NotifyIKEV2_FRAGMENTATION_SUPPORTED NotifyType = 16430
	NotifySIGNATURE_HASH_ALGORITHMS     NotifyType = 16431
)

func (n NotifyType) String() string {
	switch n {
	case NotifyINVALID_KE_PAYLOAD:
		return "INVALID_KE_PAYLOAD"
	case NotifyNO_PROPOSAL_CHOSEN:
		return "NO_PROPOSAL_CHOSEN"
	case NotifyNAT_DETECTION_SOURCE_IP:
		return "NAT_DETECTION_SOURCE_IP"
	case NotifyNAT_DETECTION_DESTINATION_IP:
		return "NAT_DETECTION_DESTINATION_IP"
	case NotifyCOOKIE:
		return "COOKIE"
	case NotifyIKEV2_FRAGMENTATION_SUPPORTED:
		return "IKEV2_FRAGMENTATION_SUPPORTED"
	case NotifySIGNATURE_HASH_ALGORITHMS:
		return "SIGNATURE_HASH_ALGORITHMS"
	default:
		return fmt.Sprintf("Notify(%d)", n)
	}
}

// AuthMethod is an IKEv2 authentication method.
type AuthMethod uint8

const (
	AuthRSASig     AuthMethod = 1
	AuthSharedKey  AuthMethod = 2
	AuthDSSSig     AuthMethod = 3
	AuthECDSA256   AuthMethod = 9
	AuthECDSA384   AuthMethod = 10
	AuthECDSA512   AuthMethod = 11
	AuthDigitalSig AuthMethod = 14 // RFC 7427
)

func (a AuthMethod) String() string {
	switch a {
	case AuthRSASig:
		return "RSA-Sig"
	case AuthSharedKey:
		return "Shared-Key"
	case AuthDSSSig:
		return "DSS-Sig"
	case AuthECDSA256:
		return "ECDSA-256"
	case AuthECDSA384:
		return "ECDSA-384"
	case AuthECDSA512:
		return "ECDSA-512"
	case AuthDigitalSig:
		return "Digital-Sig"
	default:
		return fmt.Sprintf("Auth(%d)", a)
	}
}

// IKEv1 Attribute Types
const (
	V1AttrEncryption   uint16 = 1
	V1AttrHash         uint16 = 2
	V1AttrAuthMethod   uint16 = 3
	V1AttrGroup        uint16 = 4
	V1AttrLifeType     uint16 = 11
	V1AttrLifeDuration uint16 = 12
	V1AttrPRF          uint16 = 13
	V1AttrKeyLength    uint16 = 14
)

// IKEv1 Encryption Algorithm IDs
const (
	V1EncrDES      uint16 = 1
	V1Encr3DES     uint16 = 5
	V1EncrBlowfish uint16 = 3
	V1EncrCAST     uint16 = 6
	V1EncrAESCBC   uint16 = 7
	V1EncrCamellia uint16 = 8
)

// IKEv1 Hash Algorithm IDs
const (
	V1HashMD5    uint16 = 1
	V1HashSHA1   uint16 = 2
	V1HashSHA256 uint16 = 4
	V1HashSHA384 uint16 = 5
	V1HashSHA512 uint16 = 6
)

// IKEv1 Auth Method IDs
const (
	V1AuthPSK      uint16 = 1
	V1AuthDSSSig   uint16 = 2
	V1AuthRSASig   uint16 = 3
	V1AuthRSAEncr  uint16 = 4
	V1AuthECDSA256 uint16 = 9
	V1AuthECDSA384 uint16 = 10
	V1AuthECDSA512 uint16 = 11
)

// V1EncryptionName returns the name for an IKEv1 encryption algorithm ID.
func V1EncryptionName(id, keyBits uint16) string {
	switch id {
	case V1EncrDES:
		return "DES"
	case V1Encr3DES:
		return "3DES"
	case V1EncrBlowfish:
		return "Blowfish"
	case V1EncrCAST:
		return "CAST"
	case V1EncrAESCBC:
		if keyBits > 0 {
			return fmt.Sprintf("AES-CBC-%d", keyBits)
		}
		return "AES-CBC"
	case V1EncrCamellia:
		return "Camellia"
	default:
		return fmt.Sprintf("V1-ENCR(%d)", id)
	}
}

// V1HashName returns the name for an IKEv1 hash algorithm ID.
func V1HashName(id uint16) string {
	switch id {
	case V1HashMD5:
		return "MD5"
	case V1HashSHA1:
		return "SHA-1"
	case V1HashSHA256:
		return "SHA-256"
	case V1HashSHA384:
		return "SHA-384"
	case V1HashSHA512:
		return "SHA-512"
	default:
		return fmt.Sprintf("V1-HASH(%d)", id)
	}
}

// V1AuthName returns the name for an IKEv1 auth method ID.
func V1AuthName(id uint16) string {
	switch id {
	case V1AuthPSK:
		return "PSK"
	case V1AuthDSSSig:
		return "DSS-Sig"
	case V1AuthRSASig:
		return "RSA-Sig"
	case V1AuthRSAEncr:
		return "RSA-Encr"
	case V1AuthECDSA256:
		return "ECDSA-256"
	case V1AuthECDSA384:
		return "ECDSA-384"
	case V1AuthECDSA512:
		return "ECDSA-512"
	default:
		return fmt.Sprintf("V1-AUTH(%d)", id)
	}
}
