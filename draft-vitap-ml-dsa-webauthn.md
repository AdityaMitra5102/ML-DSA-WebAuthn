---
title: "ML-DSA for Web Authentication"
abbrev: "ml-dsa-webauthn"
category: std

docname: draft-vitap-ml-dsa-webauthn-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
# area: "Security"
# workgroup: "Independent Author"
keyword:
 - PQC
 - COSE
 - WebAuthn
 - ML-DSA
 - CBOR
 - Passwordless
 - Phishing-resistant

author:
 -
    fullname: Aditya Mitra
    organization: VIT-AP University
    email: adityamitra5102@gmail.com
 -
    fullname: Sibi S. Chakkaravarthy
    organization: VIT-AP University
    email: chakkaravarthy.sibi@vitap.ac.in
 -
    fullname: Anisha Ghosh
    organization: VIT-AP University
    email: ghoshanisha2002@gmail.com
 -
    fullname: Devi Priya VS
    organization: VIT-AP University
    email: priya.21phd7042@vitap.ac.in

normative:
  IANA.cose: IANA.cose
  RFC9053: COSE
  RFC9679: CBOR
  I-D.draft-ietf-cose-dilithium-05: ML-DSA-COSE

informative:
  I-D.draft-ietf-cose-key-thumbprint: COSE-KID
  I-D.draft-ietf-lamps-dilithium-certificates:  ML-DSA-CERTS

  FIPS-186-5:
    title: "Digital Signature Standard (DSS)"
    target: https://doi.org/10.6028/NIST.FIPS.186-5

  FIPS-204:
    title: "Module-Lattice-Based Digital Signature Standard"
    target: https://doi.org/10.6028/NIST.FIPS.204

  WebAuthn:
    title: "Web Authentication: An API for accessing Public Key Credentials"
    target: https://www.w3.org/TR/webauthn-2

  CTAP:
    title: "Client To Authenticator Protocol (CTAP)"
    target: https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html

  SP-500-57:
    title: "Audit and Evaluation of Computer Security II: System Vulnerabilities and Controls"
    target: https://doi.org/10.6028/NBS.SP.500-57

---

--- abstract
This document describes implementation of Passwordless authentication in Web Authentication (WebAuthn) using Module-Lattice-Based Digital Signature Standard (ML-DSA), a Post-Quantum Cryptography (PQC) digital signature scheme defined in FIPS 204.

--- middle

# Introduction

This document describes how to use ML-DSA keys and signature as described in {{FIPS-204}} with {{WebAuthn}}.


# Terminology

{::boilerplate bcp14-tagged}

Some examples in this specification are truncated with "..." for readability.

# Background on Post-Quantum Cryptography

This section describes a generic backround of Post-Quantum Cryptography, Web Authentication and Phishing Resistance.
Post-Quantum Cryptography is defined to be a set of cryptographic algorithms that are not vulnerable against a malicious actor in possession of a large scale Quantum Computer. {{FIPS-204}} has described Module-Lattice-Based Digital Signature Algorithm which is not vulnerable to attacks involving a large-scale quantum computer.

## Motivation for ML-DSA in WebAuthn

With the wide range adoption of phishing-resistant passwordless authentication standard like Security Keys, Passkeys and Device attestation following the FIDO2 Specifications, the adopted cryptographic standards for authentication have been primarily ES256 (Elliptic Curve Digital Signature Algorithm with SHA-256) and RS256 (RSA with SHA-256) as defined in {{FIPS-186-5}}. Though most authenticators support other algorithms as well, the widely used default algorithms- ES256 and RS256 are deemed to be insecure against adversaries employing large-scale quantum computers.

Hence, the adoption of ML-DSA for WebAuthn would be necessary to secure digital identities and accounts from such adversaries.

# ML-DSA Integration in WebAuthn

This section describes the implementation of WebAuthn with ML-DSA.

## ML-DSA Key Representation in COSE

{{-ML-DSA-COSE}} describes CBOR Object Signing and Encryption (COSE) Serialization for ML-DSA. It is to be noted that the COSE representation of only 'Public key' or 'Verifying key' is used in WebAuthn. Hence, the COSE Representation of private keys are beyond the scope of this document.

ML-DSA Signature Scheme is parameterized to support different security levels. In this document, the abbreviations of ML-DSA-44, ML-DSA-65 and ML-DSA-87 are used to refer to ML-DSA with the parameter choices given in Table 1 of FIPS-204.

Along with {{-ML-DSA-COSE}}, this document requests the registration of the following algorithms in {{-IANA.cose}}:

| Name       | value                              |                 Description
|---
| ML-DSA-44  | TBD (requested assignment -48)     | CBOR Object Signing Algorithm for ML-DSA-44
| ML-DSA-65  | TBD (requested assignment -49)     | CBOR Object Signing Algorithm for ML-DSA-65
| ML-DSA-87  | TBD (requested assignment -50)     | CBOR Object Signing Algorithm for ML-DSA-87
{: #cose-algorithms align="left" title="COSE algorithms for ML-DSA"}

In accordance with the Algorithm Key Paid Type section of {{-ML-DSA-COSE}}, when present in AKP Keys, the "pub" parameter has the following constraints:

The "pub" parameter is the ML-DSA public key, as described in Section 5.3 of FIPS-204.

The size of "pub", and the associated signature for each of these algorithms is defined in Table 2 of FIPS-204, and repeated here for convenience:

| Algorithm | Private Key | Public Key | Signature Size
|---
| ML-DSA-44  | 2560       | 1312       | 2420
| ML-DSA-65  | 4032       | 1952       | 3309
| ML-DSA-87  | 4896       | 2592       | 4627
{: #fips-204-table-2 align="left" title="Sizes (in bytes) of keys and signatures of ML-DSA"}

These algorithms are used to produce signatures as described in Algorithm 2 of FIPS-204.

Signatures are encoded as bytestrings using the algorithms defined in Section 7.2 of FIPS-204.

## Signature Generation and Verification

Signature generation is done in accordance with Section 5.2 of FIPS-204. Signature Verification is done in accordance with Section 5.3 of FIPS-204.

If small keys or signature is needed, ML-DSA might not be the ideal option. Furthermore, in usage scenarios expecting swifter processing, ML-DSA-87 might not be the best option. Therefore, using ML-DSA-44 and ML-DSA-65 with WebAuthn is advised.

# Authenticator Behavior

This section describes how an authenticator, roaming or platform would implement ML-DSA.

The authenticator MUST have a secure storage for storing cryptographic secrets which SHOULD NOT be able to export the secrets in an unauthorized manner.

## Credential Creation

~~~
         +---------------+                    +--------+                                   +-----------+
         |               |                    |        |                                   |           |
         | Authenticator |                    | Client |                                   | RP Server |
         |               |                    |        |                                   |           |
         +-------+-------+                    +---+----+                                   +-----+-----+
                 |                                |                                              |
                 |                                |                                              |
                 |                                |                                              |
                 |                                |                                              |
                 |                                |      Get Challenge                           |
                 |                                +--------------------------------------------->|
                 |                                |                                              |
                 |                                |                                              |
                 |                                |                                              |
                 |                                |                   Challenge                  |
                 |                                |<---------------------------------------------+
                 |                                |                                              |
                 |                                |                                              |
                 |                                |                                              |
                 |                                |                                              |
                 |                                |                                              |
                 |                                |                                              |
                 |                                |                                              |
                 |                                |                                              |
                 |                                |                                              |
                 |  Credential Creation Request   |                                              |
                 |<-------------------------------+                                              |
+----------------+   (Challenge)                  |                                              |
| Generate       |                                |                                              |
| Keypair        |                                |                                              |
|                |                                |                                              |
|                |                                |                                              |
|                |                                |                                              |
+--------------->|                                |                                              |
                 |                                |                                              |
+----------------+                                |                                              |
| Sign challenge |                                |                                              |
|                |                                |                                              |
|                |                                |                                              |
|                |                                |                                              |
|                |                                |                                              |
+--------------->|                                |                                              |
                 |                                |                                              |
                 |  Assertion Response            |                                              |
                 +------------------------------->|                                              |
                 |  (Signed Challenge)            |     Assertion                                |
                 |                                +--------------------------------------------->|
                 |                                |                                              |
                 |                                |                                              +--------------------+
                 |                                |                                              |  Verify            |
                 |                                |                                              |                    |
                 |                                |                                              |                    |
                 |                                |                                              |                    |
                 |                                |                                              |                    |
                 |                                |                                              |<-------------------+
                 |                                |                                              |
                 |                                |                                              +--------------------+
                 |                                |                                              |   Save public key  |
                 |                                |                                              |                    |
                 |                                |                                              |                    |
                 |                                |                                              |                    |
                 |                                |                                              |                    |
                 |                                |                                              |                    |
                 |                                |                                              |<-------------------+
                 |                                |     Authentication response                  |
                 |                                |<---------------------------------------------+
                 |                                |                                              |
                 |                                |                                              |
                 |                                |                                              |
                 |                                |                                              |
                 |                                |                                              |
                 |                                |                                              |
                 |                                |                                              |
~~~

{{WebAuthn}} defines the credential creation API. This API takes a public key credential creation object, containing a cryptographic challenge, the Relying Party ID (RP ID), User details, and public key credential parameters. The public key credential parameters define the accepted algorithms.

An example of public key credential creation object is:

~~~
{
  challenge: new Uint8Array([215, 150, 119, 213, 215, 247, 188, 15, 142, 10, 53, 135, 17, 205, 130, 133, 158, 32, 113, 0, 62, 67, 112, 191, 123, 180, 224, 151, 233, 114, 68, 225]),
  rp: { id: "example.com", name: "Example Corporation" },
  user: {
    id: new Uint8Array([79, 252, 83, 72, 214, 7, 89, 26]),
    name: "johndoe",
    displayName: "John Doe",
  },
  pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -49 }],
}
~~~

The web application invokes the `Navigator.credentials.create()` function with the Public Key Credential Creation Object. The client web browser, or an application invokes the authenticator API defined in {{CTAP}}. The public key credential creation object is CBOR encoded and sent to the authenticator device over a chosen transport method which includes but is not limited to USB HID, BLE and NFC.

An example of CBOR Encoded Public Key Credential Creation object is:

~~~
h'A50158201637B26333915747DBDC6C630C0165405A64939AE8F6E4FC39414F853F702F1602A2626964696C6F63616C686F7374646E616D656B44656D6F2073657276657203A3626964504EC1D4219F294FB4A0BC0CD29D485AFC646E616D6566615F757365726B646973706C61794E616D6567412E20557365720481A263616C67382F64747970656A7075626C69632D6B657907A1627576F5'
~~~

The authenticator MUST verify whether any credential mentioned in the list of "excludeCredentials" in the public key credential creation object is already present on the authenticator, and in such cases it will return the error code in accordance with {{CTAP}}. Further authenticator MUST perform all additional checks involving authenticator PIN, User presence, user verification etc in accordance with Section 5.1 of CTAP.

The authenticator SHALL use ML-DSA-65 or ML-DSA-44 if included in `alg` -49 or -48 respectively are available in the public key credential parameters. If the parameters are not present, the authenticator SHALL behave in accordance with the "Backward Compatibility Considerations" section of this document.

The authenticator generates ML-DSA keypair in accordance with Section 5.1 of FIPS 204 and unique Key ID. The public key is COSE encoded following {{-ML-DSA-COSE}} and is a part of the attestedCredentialData.

After passing all checks in accordance with section 5.1 of CTAP, the authenticator SHOULD create the attestation statement. The authData is created in accordance with WebAuthn and CTAP specifications and the clientDataHash is appended to it. This is signed with the private key of the generated keypair. The attestation statement is generated in accordance with CTAP and WebAuthn.

The ML-DSA private key is to be stored in accordance with the "Storage security and Key management" section of this document.

The attestation statement is encoded in CBOR and returned to the client application via the same transport method.

## Authentication Flow

~~~
      +---------------+                    +--------+                                   +-----------+
      |               |                    |        |                                   |           |
      | Authenticator |                    | Client |                                   | RP Server |
      |               |                    |        |                                   |           |
      +-------+-------+                    +---+----+                                   +-----+-----+
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |      Get Challenge                           |
              |                                +--------------------------------------------->|
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                   Challenge                  |
              |                                |<---------------------------------------------+
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |   Assertion Request            |                                              |
              |<-------------------------------+                                              |
              |   (Challenge)                  |                                              |
+-------------+                                |                                              |
|Sign         |                                |                                              |
|Challenge    |                                |                                              |
|             |                                |                                              |
|             |                                |                                              |
+------------>|                                |                                              |
              |  Assertion Response            |                                              |
              +------------------------------->|                                              |
              |  (Signed Challenge)            |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |     Assertion                                |
              |                                +--------------------------------------------->|
              |                                |                                              |
              |                                |                                              +--------------------+
              |                                |                                              |     Verify         |
              |                                |                                              |                    |
              |                                |                                              |                    |
              |                                |                                              |                    |
              |                                |                                              |                    |
              |                                |                                              |<-------------------+
              |                                |     Authentication response                  |
              |                                |<---------------------------------------------+
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
              |                                |                                              |
~~~

{{WebAuthn}} defines the credential request API. This API takes a public key credential request object, containing a cryptographic challenge, the Relying Party ID (RP ID) and optionally a list of allowed credentials.

An example of public key credential request object is:

~~~
{
  challenge: new Uint8Array([215, 150, 119, 213, 215, 247, 188, 15, 142, 10, 53, 135, 17, 205, 130, 133, 158, 32, 113, 0, 62, 67, 112, 191, 123, 180, 224, 151, 233, 114, 68, 225]),
  rpId: "example.com",
}
~~~

The web application invokes the `Navigator.credentials.get()` function with the Public Key Credential Request Object. The client web browser, or an application invokes the authenticator API defined in {{CTAP}}. The public key credential request object is CBOR encoded and sent to the authenticator device over a chosen transport method which includes but is not limited to USB HID, BLE and NFC.

If a list of `allowedCredentials` is present, the authenticator must discover credentials bound to the same RP ID which is present in the list. If no such credential is present, it will return the error code in accordance with {{CTAP}}. Further authenticator MUST perform all additional checks involving authenticator PIN, User presence, user verification etc in accordance with Section 5.2 of CTAP.

The authenticator, on discovering a suitable credential for authentication SHOULD verify the algorithm. If it is not ML-DSA, the authenticator SHALL behave in accordance with the "Backward Compatibility Considerations" section of this document.

The credential is retrieved in accordance with the "Storage security and Key management" section of this document.

After passing all checks in accordance with section 5.2 of CTAP, the authenticator SHOULD create the assertion statement. The authData is created in accordance with WebAuthn and CTAP specifications and the clientDataHash is appended to it. This is signed with the decrypted ML-DSA private key. The assertion response is generated in accordance with CTAP and WebAuthn.

The assertion response is encoded in CBOR and returned to the client application via the same transport method.

All memory addresses used to handle the ML-DSA private key is immediately zeroized.

The authenticator `getNextAssertion()` function specification is to be similarly implemented in accordance with {{CTAP}}.

## Backward Compatibility Consideration

The authenticator SHOULD default to using RS256 and ES256 algorithms following FIPS-186-5 if the Relying Party (RP) does not support ML-DSA, which can be verified by inpecting the Public Key Credential Parameters field during credential creation.

# Client and Platform Considerations

This section describes the considerations about the Client and Platform.

## COSE Algorithm Support in WebAuthn Clients

The CTAP implementations on client, for example Windows Hello for Microsoft Windows based systems, iCloud Keychain for Apple systems, Google Password Manager, Dashlane, OnePassword and other browser based implementations for Linux SHOULD have support for ML-DSA Algorithms in accordance with COSE. Further, Platform Authenticators for such devices are RECOMMENDED to have support for ML-DSA Key Generation and signing in accordance with this document.

## Handling large signatures and keys

It is considered that the chosen transport methods including but not limited to USB HID, BLE and NFC are able to perform exchanges of the CBOR encoded data which may be often over 2000 bytes. The use of attestion certificates may increase the length even more.

## Error Handling and Fallback mechanisms

In case of errors involving ML-DSA key generation and signing, the authenticator may fallback to using ES256 or RS256 algoritms. In case of errors involving communication with the client, the authenticator may handle it in accordance with {{CTAP}}.

# Security Considerations

The security considerations of {{-COSE}} applies to this specification as well.

A detailed security analysis of ML-DSA is beyond the scope of this specification, see {{FIPS-204}} for additional details.

## Resistance to Quantum Attacks

See {{FIPS-204}} for details on resistance to quantum attacks.

## Storage security and Key management

It is to be noted that at the time of writing this draft, there is no suitable hardware security module (HSM), trusted platform module (TPM), Secure Element (SE), Trusted Execution Environment (TEE) with native support for ML-DSA. Hence, secure credential storage is a challenge. To overcome the same, the ML-DSA keys, also referred to as credentials, MUST be encrypted with Advanced Ecnryption Standard (AES), which is a Post Quantum Symmetric encryption algorithm in Galosis Counter Mode (GCM) with 256-bit keys.

The AES Keys MUST be generated and stored in secure storage, which may include a HSM, TPM, SE or TEE. The ML-DSA Keys may be generated on the standard computing environment, outside the secure storage. The ML-DSA Credential MUST be encrypted by AES as described above before being written to the Flash memory or Disk. Conversely, the same MUST be decrypted by AES in the secure storage before being used.

Any memory location, pointer or heap that has been used to handle the ML-DSA Credentials MUST be zeroized immediately after the operation is performed.

This section is to be updated when suitable secure storage modules supporting ML-DSA becomes widely available.

## Implementation Best Practices

If the amount of space in the secure storage permits, each ML-DSA Private key is RECOMMENDED to be encrypted with unique AES keys.
*	Prior to storage, each ML-DSA private key is to be encrypted independently using a distinct AES encryption key.
*	To guarantee robust encryption, the AES key size must be at least AES-256.
*	To avoid unwanted access, encrypted keys ought to be kept in Hardware Security Modules (HSMs), Secure Elements (SEs), or Trusted Platform Modules (TPMs).
*	NIST SP 800-57 recommendations should be followed by key management to provide secure AES key lifecycle management (creation, storage, rotation, and disposal).
*	Only in a trusted execution environment (TEE) or secure enclave should the private key be decrypted in order to avoid memory leakage.

# IANA Considerations

## Additions to Existing Registries

Along with {{-ML-DSA-COSE}}, this document requests the registration of the following entries to the COSE Algorithm Registry.
The following completed registration templates are provided as described in RFC9053 and RFC9054.

### Algorithms to be added

#### ML-DSA-44

* Name: ML-DSA-44
* Value: TBD (requested assignment -48)
* Description: CBOR Object Signing Algorithm for ML-DSA-44
* Capabilities: `[kty]`
* Reference: RFC XXXX
* Recommended: Yes

#### ML-DSA-65

* Name: ML-DSA-65
* Value: TBD (requested assignment -49)
* Description: CBOR Object Signing Algorithm for ML-DSA-65
* Capabilities: `[kty]`
* Reference: RFC XXXX
* Recommended: Yes


#### ML-DSA-87

* Name: ML-DSA-87
* Value: TBD (requested assignment -50)
* Description: CBOR Object Signing Algorithm for ML-DSA-87
* Capabilities: `[kty]`
* Reference: RFC XXXX
* Recommended: Yes

### New COSE Key Types

IANA is requested to add the following entries to the COSE Key Types Registry.
The following completed registration templates are provided as described in RFC9053.

#### AKP

* Name: AKP
* Value: TBD (requested assignment 7)
* Description: COSE Key Type for Algorithm Key Pairs
* Capabilities: `[kty(7)]`
* Reference: RFC XXXX

### New COSE Key Type Parameters

IANA is requested to add the following entries to the COSE Key Type Parameters.
The following completed registration templates are provided as described in RFC9053.

#### ML-DSA Public Key

* Key Type: TBD (requested assignment 7)
* Name: pub
* Label: -1
* CBOR Type: bstr
* Description: Public key
* Reference: RFC XXXX

--- back

# Acknowledgments
{:numbered="false"}

We express our sincere gratitude to Dr. S. V. Kota Reddy, Vice Chancellor, VIT-AP University, for his unwavering support and encouragement throughout this research. We also extend our heartfelt thanks to Dr. Jagadish Chandra Mudiganti, Registrar, VIT-AP University, for facilitating a conducive research environment. Our appreciation goes to Dr. Hari Seetha, Director, Centre of Excellence, Artificial Intelligence and Robotics (AIR), VIT-AP University, for her invaluable guidance and insightful discussions that significantly contributed to this work.

We also acknowledge Indominus Labs Private Limited and Digital Fortress Private Limited for their generous support, which played a crucial role in the successful execution of this research.
