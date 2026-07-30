# Certificate Path Validation — Analysis and Corrected Implementation

**Component:** `DCCvalidation.py` (Digital Calibration Certificate validation)
**Scope:** Trust-anchor handling and X.509 certification-path validation
**Normative basis:** RFC 5280, BSI TR-02103, DAkkS-TSPS Chapter 8 / 8.1 / 8.4
**Status:** Fixed. Covered by `tests/test_certificate_path_validation.py`.

---

## 1. Summary

Earlier revisions of `DCCvalidation.py` established a DCC's accreditation in part
by **comparing certificate names as strings** and by validating the certificate
chain against a **root certificate obtained at runtime from the certificate under
test**.

It matters where this comes from: **the implementation faithfully followed the
DAkkS-TSPS.** TSPS v1.5 (Chapter 8 / 8.4) defines the relevant trust anchor *by
name* — the certificate must have been "issued by the CA 'D-TRUST CA 5-22-2 2022'
and the certification path must refer to the Root-CA 'D-TRUST Root CA 5 2022'",
which "applies as the trust anchor for the purposes of the DAkkS". The TSPS gives
**no cryptographic identifier** (certificate, public key, or fingerprint) for that
anchor. A name string is therefore the only anchor description an implementer is
handed.

The difficulty is that the **same TSPS** (Chapter 8.1) simultaneously requires
conformance to **BSI TR-02103 and RFC 5280**, which define a trust anchor as a
specific certificate / public key — *not* a name. The specification is thus
internally inconsistent: a literal, TSPS-compliant reading of Chapter 8 / 8.4
produces exactly the name-based check that Chapter 8.1 forbids. The BAM
demonstrator complied with the letter of Chapter 8 / 8.4 while, as a direct
consequence of that wording, not conforming to the RFC 5280 / BSI TR-02103
requirement of the same document. **The root cause is the specification, not the
implementation.**

This document explains, constructively, the two resulting patterns, why they do
not satisfy RFC 5280 / BSI TR-02103, and how the corrected implementation resolves
the inconsistency by anchoring trust cryptographically — which also fulfils the
*intent* of the TSPS. The aim is to turn the demonstrator into a *correct
reference* for trust-anchor handling in the DCC ecosystem and to support the
requested TSPS clarification.

The corrected design follows the principle that RFC 5280 and BSI TR-02103 already
state, and that the TSPS should adopt explicitly: **a trust anchor is a specific
certificate / public key, not a name.**

---

## 2. The two patterns — and why a TSPS-compliant reading produces them

Both patterns below follow directly from the TSPS describing the trust anchor only
by name. Because no certificate or fingerprint is given, an implementer has nothing
to pin to; matching the *name* of the CA and root — and obtaining those
certificates dynamically in order to read their names — is the path of least
resistance the specification leaves open.

### Pattern A — The trust anchor was not pinned (obtained from the certificate itself)

The original flow obtained both the issuing intermediate **and the root** by
following the Authority Information Access (AIA) URLs found *inside the very
certificate being validated*:

```
seal certificate --AIA--> intermediate certificate --AIA--> "root" certificate
```

The downloaded "root" was then passed straight to `openssl verify -CAfile <root>`
as the trust anchor. Concretely (original code):

```python
download_cert(root_url, "D-TRUST Root CA 5 2022.crt")          # root taken from AIA
convert_der_to_pem("D-TRUST Root CA 5 2022.crt", "D-TRUST Root CA 5 2022.pem")
...
verify_certificate_signature("seal_cert.pem",
                             "D-TRUST CA 5-22-2 2022.pem",
                             "D-TRUST Root CA 5 2022.pem",       # <-- downloaded anchor
                             signing_date)
```

Because the AIA URLs are attacker-controllable fields of an attacker-supplied
certificate, a forged certificate can nominate **its own** root. `openssl verify`
then correctly reports that the forged chain is internally consistent — it is, but
only with respect to a trust anchor the attacker chose. **No step bound the
validation to the *genuine* D-TRUST Root CA 5 2022.** A path validation is only as
meaningful as the anchor it terminates at, and the anchor was not fixed.

This dynamic fetching is not itself demanded by the TSPS — but the TSPS leaves it
as the natural option: having defined the anchor only by a name, it provides no
certificate to pin, so the root is sourced at runtime and recognised by its name.
Fix the specification gap (give a cryptographic anchor) and this pattern has no
reason to exist.

### Pattern B — Certificate *names* were used as a security criterion (as Chapter 8 / 8.4 describes the anchor)

After the chain check, the decision used string comparisons of Common Names:

```python
issuer = dict(cert.get_issuer().get_components())[b'CN'].decode("utf-8")
if issuer == ca_issuer:                 # ca_issuer   = "D-TRUST CA 5-22-2 2022"
    correct_issuer = True

# Stringvergleich ist hier eigentlich nicht ausreichend   <-- already noted in code
root_subject = find_root_cert("seal_cert.pem")             # walked the chain by CN
if root_subject == root_ca_file:        # root_ca_file = "D-TRUST Root CA 5 2022"
    correct_root = True
```

This mirrors the TSPS wording one-to-one: the constants `ca_issuer =
"D-TRUST CA 5-22-2 2022"` and `root_ca_file = "D-TRUST Root CA 5 2022"` are exactly
the names Chapter 8 / 8.4 uses to describe the anchor. A Common Name / Subject DN /
Issuer DN is, however, a freely chosen attribute: anyone can generate a self-signed
certificate whose CN is exactly `D-TRUST Root CA 5 2022`, so these comparisons can
be satisfied by a certificate that has nothing to do with D-Trust. Notably, the
in-code comment `# Stringvergleich ist hier eigentlich nicht ausreichend` shows the
implementers were **themselves aware** that a string comparison is insufficient —
consistent with conscientiously following a specification that prescribed a name
while also referencing RFC 5280.

### Why this matters under RFC 5280 / BSI TR-02103 (which TSPS Chapter 8.1 mandates)

TSPS Chapter 8.1 explicitly requires conformance to BSI TR-02103 and RFC 5280.
RFC 5280 §6 ("Certification Path Validation") defines validation as a cryptographic
procedure that terminates at a **trust anchor**, where a trust anchor is a *trusted
public key* (with associated name and constraints) — not a name used as a lookup
key. BSI TR-02103 follows the same model. A name match is, at most, a consistency
check on top of a completed cryptographic validation; it is never a substitute for
it. Patterns A and B together meant the decisive trust step relied on
attacker-influenceable data — which is why Chapter 8 / 8.4 and Chapter 8.1 of the
TSPS cannot both be satisfied by a name-based reading.

---

## 3. The corrected implementation

The fix replaces both patterns with a single, cryptographically grounded path
validation against a **pinned** trust anchor. Key elements:

### 3.1 The trust anchor is pinned by fingerprint and embedded in the source

The genuine root is embedded directly in `DCCvalidation.py` as a single in-source
PEM constant (`TRUST_ANCHOR_PEM`) — there is no separate `.pem` file on disk to
lose, swap or let drift. It is verified on load against a hard-coded SHA-256
fingerprint:

```python
TRUST_ANCHOR_SHA256 = "d839672f984dca7cd480ce201627a4de61c5c1855f450e5b706200e73a23f047"
TRUST_ANCHOR_PEM    = """-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"""

def load_trust_anchor():
    anchor = x509.load_pem_x509_certificate(TRUST_ANCHOR_PEM.encode())
    if anchor.fingerprint(hashes.SHA256()).hex().lower() != TRUST_ANCHOR_SHA256.lower():
        raise RuntimeError("Embedded trust anchor fingerprint mismatch — refusing to trust it.")
    return anchor
```

The embedded certificate carries no trust of its own: it is accepted only if its
fingerprint equals the pin, so the sole unrecoverable failure is source-code
tampering (certificate and pin disagreeing). Where an external tool needs the
anchor as a real file (the `openssl ocsp -CAfile` subprocess), the pin-verified
PEM is materialised to a temporary file via `write_trust_anchor_file()`. Anyone can
reproduce and verify that file on Linux:

```bash
python3 - <<'PY' > D-TRUST_Root_CA_5_2022.pem
import DCCvalidation; print(DCCvalidation.TRUST_ANCHOR_PEM, end="")
PY
openssl x509 -in D-TRUST_Root_CA_5_2022.pem -noout -fingerprint -sha256 \
  | sed 's/.*=//' | tr -d ':' | tr 'A-Z' 'a-z'
# -> d839672f984dca7cd480ce201627a4de61c5c1855f450e5b706200e73a23f047
```

The validator **never downloads its trust anchor.** The root is no longer fetched
from AIA; only the issuing intermediate is fetched, and it is then cryptographically
required to chain to the pinned root.

The pinned values were cross-checked against the published certificate data of
D-Trust GmbH and against the identifiers cited in the related formal complaint:

| Field   | Value |
|---------|-------|
| Subject | `C=DE, O=D-Trust GmbH, CN=D-TRUST Root CA 5 2022` (self-signed) |
| Serial  | `71 CB 7A 9F A5 12 3C 25 35 AD EE 75 0B C0 80 6A` |
| SHA-1   | `64 32 11 33 21 69 B4 83 B5 5F 70 46 E5 6C BF C6 C1 1D C5 F8` |
| SHA-256 (pin) | `d839672f…3a23f047` |

### 3.2 Real path validation, name-independent

`validate_certificate_chain()` verifies the path `seal -> intermediate -> pinned
root` using cryptographic and temporal properties only:

* **Signature links** — each certificate's signature is verified under its
  issuer's public key (`_signature_is_valid`). This proves possession of the
  issuer's private key, which a chosen name cannot.
* **Termination at the pinned anchor** — the decisive condition
  (`anchored_to_pinned_root`) is that the intermediate is signed by the pinned
  root. The anchor is fixed by fingerprint, so a self-nominated root cannot be
  substituted.
* **Name chaining** — `seal.issuer == intermediate.subject` and
  `intermediate.issuer == anchor.subject` are checked, but only as a *consistency*
  check layered on top of the verified signatures, never as the trust decision.
* **Basic Constraints** — issuing certificates must assert `CA=TRUE`.
* **Temporal validity** — every certificate must be valid at the signing time.
* **Defense in depth** — the issuing intermediate is additionally compared to an
  expected pinned fingerprint (`intermediate_pin_ok`).

### 3.3 Mapping of the old decision variables

| Old (name-based) | New (cryptographic) |
|---|---|
| `verify_certificate_signature(..., downloaded_root, ...)` | `validate_certificate_chain(...)["chain_ok"]` — full path to the **pinned** anchor |
| `if issuer == ca_issuer` (CN string) | `intermediate_pin_ok` — issuing CA matches the expected pinned fingerprint |
| `find_root_cert()` + `if root_subject == root_ca_file` (CN string) | `anchored_to_pinned_root` — path provably ends at the SHA-256-pinned root |
| OCSP `-CAfile <downloaded root>` | OCSP `-CAfile <pinned trust anchor>` |

The CN walk (`find_root_cert`) has been removed; the string constants `ca_issuer`
and `root_ca_file` are retained **only** as human-readable log labels and are
explicitly documented as non-security.

---

## 4. Evidence that the fix is effective

`tests/test_certificate_path_validation.py` (runs fully offline) asserts:

1. **Genuine chain validates.** A real seal certificate (from `DCCs/`) plus the
   genuine intermediate validate to the pinned root.
2. **Name-spoofing is defeated.** A complete attacker-built chain whose
   certificates name themselves `D-TRUST Root CA 5 2022` and
   `D-TRUST CA 5-22-2 2022` — which *satisfied the former string checks* — is
   rejected with reason *"intermediate is not signed by the pinned trust anchor."*
3. **Pin integrity is enforced.** Tampering with the expected fingerprint makes
   `load_trust_anchor()` refuse; there is no fallback to an unverified certificate.

```
  PASS  test_genuine_chain_validates
  PASS  test_name_spoofing_attacker_chain_rejected
  PASS  test_tampered_pin_refuses
```

---

## 5. Relationship to the DAkkS-TSPS and the clarification request

To be explicit about responsibility: the root cause is the **specification**, not
the implementation. TSPS v1.5 Chapter 8 / 8.4 defines the trust anchor by name,
while Chapter 8.1 requires RFC 5280 / BSI TR-02103, which require a *cryptographic*
anchor. Those two cannot both be satisfied literally. The BAM demonstrator followed
Chapter 8 / 8.4 and is, in that sense, **TSPS-compliant**; what it could not also be
— given the same wording — is conformant to Chapter 8.1. This change additionally
satisfies Chapter 8.1 by identifying the anchor cryptographically.

This is exactly the clarification requested of the DAkkS: that the TSPS define the
trust anchor by **cryptographic identifiers**, and state that certificate names
(CN / Subject DN / Issuer DN) must not be used as a substitute for RFC 5280 /
BSI TR-02103 certification-path validation. Until the TSPS is amended, this
implementation resolves the inconsistency in favour of the higher-ranking normative
references (RFC 5280 / BSI TR-02103) while still honouring the TSPS *intent* of
anchoring on the genuine D-TRUST Root CA 5 2022. Where the TSPS text and the
RFC/BSI requirement conflict, an implementation that aims to be secure should follow
the latter and document the deviation — as done here. The demonstrator thereby
becomes a concrete, testable example of the recommended approach rather than of the
pitfall the specification currently invites.

---

## 6. Operational notes

* The trust anchor is the embedded `TRUST_ANCHOR_PEM` constant in `DCCvalidation.py`
  — it is part of the trusted code base and should be reviewed like source. Its
  SHA-256 is pinned in the same file.
* If D-Trust rotates the root, update **both** `TRUST_ANCHOR_PEM` and
  `TRUST_ANCHOR_SHA256` (and, if applicable, `EXPECTED_INTERMEDIATE_SHA256`) in the
  same change, and record the new identifiers here. The
  `test_embedded_anchor_loads_and_matches_pin` test fails if the certificate and the
  pin disagree, so a half-completed rotation is caught automatically.
* The intermediate continues to be fetched at runtime via AIA but is now only
  trusted if it cryptographically chains to the pinned root.