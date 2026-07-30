"""Regression tests for the corrected certification-path validation.

These tests guard against a reintroduction of the name-based trust decision that
was present in earlier revisions. They run fully offline.

Run with either:
    python3 tests/test_certificate_path_validation.py
    pytest tests/test_certificate_path_validation.py

What is proven here:
  1. A genuine seal certificate + genuine intermediate validate to the
     cryptographically pinned root.
  2. A complete ATTACKER-BUILT chain whose certificates merely *name themselves*
     "D-TRUST Root CA 5 2022" / "D-TRUST CA 5-22-2 2022" is REJECTED. Such a chain
     satisfied the former string comparisons (`issuer == ca_issuer`,
     `root_subject == root_ca_file`) but must never be trusted.
  2b. The signature-link check itself is truly cryptographic: it verifies genuine
     RSA and ECDSA signatures and rejects a same-name / wrong-key issuer.
  3. Tampering with the pinned anchor (wrong fingerprint) makes the anchor refuse
     to load — there is no fallback to an unverified certificate.
  4. The sole in-source anchor (TRUST_ANCHOR_PEM) loads and matches the pin.
  5. The in-process OCSP evaluation is fail-closed: only a GOOD, in-window response
     signed by the issuer (or an issuer-delegated responder) is accepted; revoked,
     untrusted-signer, stale and wrong-certificate responses are all rejected.
"""
import os
import sys
import types
import datetime

# The path-validation functions do not use these heavy modules, but the module
# imports them at top level (and the project venv is Windows-only), so we stub
# them to keep the test self-contained on any platform.
for _m in ("xmlschema", "xmlsec", "requests"):
    sys.modules.setdefault(_m, types.ModuleType(_m))
_ossl = types.ModuleType("OpenSSL")
_crypto = types.ModuleType("OpenSSL.crypto")
_ossl.crypto = _crypto
sys.modules.setdefault("OpenSSL", _ossl)
sys.modules.setdefault("OpenSSL.crypto", _crypto)
# tkinter may be absent on headless CI runners; the validation code only imports
# messagebox at module load and never calls it here, so a stub keeps CI hermetic.
_tk = types.ModuleType("tkinter")
_msgbox = types.ModuleType("tkinter.messagebox")
_tk.messagebox = _msgbox
sys.modules.setdefault("tkinter", _tk)
sys.modules.setdefault("tkinter.messagebox", _msgbox)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
sys.path.insert(0, REPO_ROOT)

from lxml import etree  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.x509 import ocsp  # noqa: E402
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa, ec  # noqa: E402

# Register lightweight stand-ins for the runtime singletons before import.
from Instance_Manager import IM  # noqa: E402


class _Dummy:
    def info(self, *a, **k): pass
    def warning(self, *a, **k): pass
    def error(self, *a, **k): pass


for _k in ("EB", "CC", "MD", "logger"):
    try:
        IM.set_instance(_k, _Dummy())
    except ValueError:
        pass

import DCCvalidation as V  # noqa: E402

DSIG = {"dsig": "http://www.w3.org/2000/09/xmldsig#"}
SAMPLE_DCC = os.path.join(REPO_ROOT, "DCCs", "8.1I1496A-SEALED.xml")
INTERMEDIATE = os.path.join(FIXTURES, "D-TRUST_CA_5-22-2_2022.pem")


def _write_seal(tmp_path):
    """Extract the REAL BAM seal certificate from a sample DCC and write it as PEM.

    Pulls the base64 X509Certificate out of the DCC's XML signature and wraps it in
    PEM armor exactly as the production get_signature_details() does, so the tests
    run against a genuine, in-the-wild certificate rather than a synthetic one.
    Returns (path_to_pem, parsed_certificate).
    """
    root = etree.parse(SAMPLE_DCC).getroot()
    b64 = root.xpath("//dsig:X509Certificate", namespaces=DSIG)[0].text.strip()
    pem = f"-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----".encode()
    path = os.path.join(tmp_path, "seal_cert.pem")
    with open(path, "wb") as fh:
        fh.write(pem)
    return path, x509.load_pem_x509_certificate(pem)


def _self_signed(cn, key, issuer_key, issuer_name, ca):
    """Tiny certificate factory used to forge attacker certificates.

    Builds a cert with subject "C=DE, O=D-Trust GmbH, CN=<cn>", a fixed 2023-2035
    validity window, the requested BasicConstraints(ca=...), signed with issuer_key.
    Passing issuer_key == key and issuer_name == its own name yields a self-signed
    root; otherwise an issued (chained) certificate. Returns (cert, name).
    """
    nb = datetime.datetime(2023, 1, 1, tzinfo=datetime.timezone.utc)
    na = datetime.datetime(2035, 1, 1, tzinfo=datetime.timezone.utc)
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "D-Trust GmbH"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    return (x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(issuer_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(nb).not_valid_after(na)
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
            .sign(issuer_key, hashes.SHA256())), name


def test_genuine_chain_validates(tmp_path_factory=None):
    """POSITIVE case: a genuine DCC must still validate end-to-end.

    A real seal certificate + the genuine intermediate must validate to the pinned
    root. The validation time is set inside every certificate's validity window.
    This guards against a "fix" that merely rejects everything: it proves the new
    code does not produce false negatives on legitimate, correctly-issued DCCs.

    Asserts:
      * chain_ok                -> full path seal->intermediate->pinned root verifies
      * anchored_to_pinned_root -> the path terminates at the SHA-256-pinned root
      * intermediate_pin_ok     -> the issuer matches the expected pinned intermediate
    """
    tmp = _mk_tmp(tmp_path_factory, "genuine")
    seal_path, seal = _write_seal(tmp)
    at = seal.not_valid_before_utc + datetime.timedelta(days=1)
    res = V.validate_certificate_chain(seal_path, INTERMEDIATE, at)
    assert res["chain_ok"] is True, res["reason"]
    assert res["anchored_to_pinned_root"] is True
    assert res["intermediate_pin_ok"] is True


def test_name_spoofing_attacker_chain_rejected(tmp_path_factory=None):
    """SECURITY case: a chain that only *names itself* D-TRUST must be rejected.

    Reconstructs the exact attack the previous (name-based) logic was vulnerable to.
    A complete, internally-consistent attacker chain is built from fresh keys:
        evil self-signed root  CN="D-TRUST Root CA 5 2022"
          -> evil intermediate CN="D-TRUST CA 5-22-2 2022"
            -> evil seal        (named after the BAM laboratory)
    Every certificate carries the genuine *names* but none of the genuine *keys*.

    The assertions are deliberately two-part:
      1. Prove the OLD checks WOULD have accepted it — the leaf issuer CN equals
         V.ca_issuer and the fake root subject CN equals V.root_ca_file. This makes
         the test a faithful proof of the real vulnerability, not a strawman.
      2. Prove the NEW validation REJECTS it (chain_ok / anchored_to_pinned_root are
         False) — because the fake intermediate is not signed by the SHA-256-pinned
         genuine root. Names match; cryptography does not.

    This is the permanent regression guard: if a CN-based shortcut is ever
    reintroduced, this test fails.
    """
    tmp = _mk_tmp(tmp_path_factory, "attacker")
    rk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root, root_name = _self_signed("D-TRUST Root CA 5 2022", rk, rk,
                                   _name("D-TRUST Root CA 5 2022"), True)
    ik = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    inter, inter_name = _self_signed("D-TRUST CA 5-22-2 2022", ik, rk, root.subject, True)
    sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    seal, _ = _self_signed("Bundesanstalt für Materialforschung und -prüfung", sk, ik,
                           inter.subject, False)

    seal_path = os.path.join(tmp, "evil_seal.pem")
    inter_path = os.path.join(tmp, "evil_inter.pem")
    with open(seal_path, "wb") as fh:
        fh.write(seal.public_bytes(serialization.Encoding.PEM))
    with open(inter_path, "wb") as fh:
        fh.write(inter.public_bytes(serialization.Encoding.PEM))

    # Part 1 — the former string checks WOULD have accepted this chain:
    assert seal.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == V.ca_issuer
    assert root.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == V.root_ca_file

    # Part 2 — the cryptographic validation rejects it: the fake intermediate is
    # not signed by the pinned genuine root, so the path is not anchored.
    at = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    res = V.validate_certificate_chain(seal_path, inter_path, at)
    assert res["chain_ok"] is False
    assert res["anchored_to_pinned_root"] is False


def test_signature_link_verifies_across_algorithms():
    """SIGNATURE-LINK case: _signature_is_valid() works across RSA and ECDSA.

    Direct regression test for the Copilot review point about how the signature
    link is verified. It exercises _signature_is_valid() with genuinely-issued
    child certificates under both an RSA issuer (PKCS#1 v1.5) and an EC issuer
    (ECDSA), and proves the check is truly cryptographic:

      * a correctly-issued child verifies under its real issuer (both algorithms);
      * a child whose issuer has the SAME name but a DIFFERENT key does NOT verify
        (so it is the signature, not the Common Name, that decides);
      * an unrelated issuer does not verify.

    The genuine BAM chain is RSA-PSS and is additionally covered end-to-end by
    test_genuine_chain_validates.
    """
    # RSA issuer -> RSA child (PKCS#1 v1.5)
    rsa_root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_root, _ = _self_signed("Test RSA Root", rsa_root_key, rsa_root_key,
                               _name("Test RSA Root"), True)
    rsa_child_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_child, _ = _self_signed("Test RSA Child", rsa_child_key, rsa_root_key,
                                rsa_root.subject, False)

    # EC issuer -> EC child (ECDSA)
    ec_root_key = ec.generate_private_key(ec.SECP256R1())
    ec_root, _ = _self_signed("Test EC Root", ec_root_key, ec_root_key,
                              _name("Test EC Root"), True)
    ec_child_key = ec.generate_private_key(ec.SECP256R1())
    ec_child, _ = _self_signed("Test EC Child", ec_child_key, ec_root_key,
                               ec_root.subject, False)

    # Correctly-issued children verify under their real issuers.
    assert V._signature_is_valid(rsa_child, rsa_root) is True
    assert V._signature_is_valid(ec_child, ec_root) is True

    # Same issuer NAME, different KEY -> must fail on the signature, not the name.
    imposter_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    imposter_root, _ = _self_signed("Test RSA Root", imposter_key, imposter_key,
                                    _name("Test RSA Root"), True)
    assert V._signature_is_valid(rsa_child, imposter_root) is False

    # Unrelated issuer (also cross-algorithm) -> must fail.
    assert V._signature_is_valid(rsa_child, ec_root) is False
    assert V._signature_is_valid(ec_child, rsa_root) is False


def test_tampered_pin_refuses():
    """INTEGRITY case: a mismatching pin must hard-fail, with no silent fallback.

    Temporarily replaces the expected fingerprint with an all-zero value and checks
    that load_trust_anchor() raises RuntimeError instead of trusting the embedded
    certificate. The original constant is restored in `finally` so the mutation
    cannot leak into the other tests. This protects the single piece of trusted
    material the whole scheme rests on: the embedded root is rejected on mismatch.
    """
    original = V.TRUST_ANCHOR_SHA256
    try:
        V.TRUST_ANCHOR_SHA256 = "00" * 32
        raised = False
        try:
            V.load_trust_anchor()
        except RuntimeError:
            raised = True
        assert raised, "load_trust_anchor must refuse a mismatching pin"
    finally:
        V.TRUST_ANCHOR_SHA256 = original


def test_embedded_anchor_loads_and_matches_pin():
    """SOURCE-OF-TRUTH case: the sole in-source anchor must load and match the pin.

    The certificate lives only in TRUST_ANCHOR_PEM (no file on disk). load_trust_anchor()
    must parse it and return a certificate whose SHA-256 equals TRUST_ANCHOR_SHA256,
    proving the embedded string is a valid certificate and is the genuine root.
    """
    anchor = V.load_trust_anchor()
    fp = anchor.fingerprint(hashes.SHA256()).hex().lower()
    assert fp == V.TRUST_ANCHOR_SHA256.lower(), "embedded anchor must match the pin"


# --- OCSP (in-process revocation check) -------------------------------------
# These exercise the fail-closed OCSP response evaluation V._ocsp_response_is_good()
# with synthetic, signed OCSP responses (no network). They pin down the security
# contract: only an explicitly GOOD, in-window response signed by the issuer (or an
# issuer-delegated responder) is accepted; everything else is rejected.

_OCSP_AT = datetime.datetime(2024, 6, 1, tzinfo=datetime.timezone.utc)
_OCSP_THIS = datetime.datetime(2024, 5, 31, tzinfo=datetime.timezone.utc)
_OCSP_NEXT = datetime.datetime(2024, 6, 2, tzinfo=datetime.timezone.utc)


def _issuer_and_child():
    """Build a self-signed issuer CA (RSA) and a child certificate it issues."""
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer, _ = _self_signed("OCSP Test Issuer", issuer_key, issuer_key,
                             _name("OCSP Test Issuer"), True)
    child_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    child, _ = _self_signed("OCSP Test Leaf", child_key, issuer_key, issuer.subject, False)
    return issuer, issuer_key, child


def _ocsp_response(child, issuer, signer_cert, signer_key, status,
                   this_update=_OCSP_THIS, next_update=_OCSP_NEXT,
                   revocation_time=None, embed_certs=None):
    """Build and re-parse a signed OCSP response (as the responder would return)."""
    builder = ocsp.OCSPResponseBuilder().add_response(
        cert=child, issuer=issuer, algorithm=hashes.SHA1(),
        cert_status=status, this_update=this_update, next_update=next_update,
        revocation_time=revocation_time, revocation_reason=None)
    builder = builder.responder_id(ocsp.OCSPResponderEncoding.NAME, signer_cert)
    if embed_certs:
        builder = builder.certificates(embed_certs)
    signed = builder.sign(signer_key, hashes.SHA256())
    return ocsp.load_der_ocsp_response(signed.public_bytes(serialization.Encoding.DER))


def test_ocsp_good_response_accepted():
    """OCSP: a GOOD, in-window, issuer-signed response is accepted."""
    issuer, issuer_key, child = _issuer_and_child()
    resp = _ocsp_response(child, issuer, issuer, issuer_key, ocsp.OCSPCertStatus.GOOD)
    assert V._ocsp_response_is_good(resp, child, issuer, _OCSP_AT) is True


def test_ocsp_revoked_response_rejected():
    """OCSP: a REVOKED response must never be accepted."""
    issuer, issuer_key, child = _issuer_and_child()
    resp = _ocsp_response(child, issuer, issuer, issuer_key, ocsp.OCSPCertStatus.REVOKED,
                          revocation_time=datetime.datetime(2024, 5, 15,
                                                            tzinfo=datetime.timezone.utc))
    assert V._ocsp_response_is_good(resp, child, issuer, _OCSP_AT) is False


def test_ocsp_untrusted_signer_rejected():
    """OCSP: a response signed by a party the issuer did not authorise is rejected.

    The response says GOOD, but it is signed by an unrelated CA that the issuer never
    delegated (no responder certificate is included that chains to the issuer). It
    must not be trusted — otherwise anyone could forge a 'good' status.
    """
    issuer, issuer_key, child = _issuer_and_child()
    rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rogue, _ = _self_signed("Rogue Responder", rogue_key, rogue_key,
                            _name("Rogue Responder"), True)
    resp = _ocsp_response(child, issuer, rogue, rogue_key, ocsp.OCSPCertStatus.GOOD)
    assert V._ocsp_response_is_good(resp, child, issuer, _OCSP_AT) is False


def test_ocsp_delegated_responder_accepted():
    """OCSP: a GOOD response from an issuer-delegated responder is accepted (RFC 6960).

    The responder certificate is issued by the CA and carries the id-kp-OCSPSigning
    EKU, and is embedded in the response. This guards against over-rejecting the
    legitimate delegated-responder case that real OCSP deployments use.
    """
    issuer, issuer_key, child = _issuer_and_child()
    resp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nb = datetime.datetime(2023, 1, 1, tzinfo=datetime.timezone.utc)
    na = datetime.datetime(2035, 1, 1, tzinfo=datetime.timezone.utc)
    responder = (x509.CertificateBuilder()
                 .subject_name(_name("Delegated OCSP Responder"))
                 .issuer_name(issuer.subject)
                 .public_key(resp_key.public_key())
                 .serial_number(x509.random_serial_number())
                 .not_valid_before(nb).not_valid_after(na)
                 .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                 .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), False)
                 .sign(issuer_key, hashes.SHA256()))
    resp = _ocsp_response(child, issuer, responder, resp_key, ocsp.OCSPCertStatus.GOOD,
                          embed_certs=[responder])
    assert V._ocsp_response_is_good(resp, child, issuer, _OCSP_AT) is True


def test_ocsp_stale_response_rejected():
    """OCSP: a response whose validity window does not cover the signing time is rejected."""
    issuer, issuer_key, child = _issuer_and_child()
    resp = _ocsp_response(child, issuer, issuer, issuer_key, ocsp.OCSPCertStatus.GOOD)
    too_late = datetime.datetime(2024, 6, 10, tzinfo=datetime.timezone.utc)  # after next_update
    assert V._ocsp_response_is_good(resp, child, issuer, too_late) is False


def test_ocsp_serial_mismatch_rejected():
    """OCSP: a response about a DIFFERENT certificate is rejected."""
    issuer, issuer_key, child = _issuer_and_child()
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other, _ = _self_signed("OCSP Other Leaf", other_key, issuer_key, issuer.subject, False)
    resp = _ocsp_response(child, issuer, issuer, issuer_key, ocsp.OCSPCertStatus.GOOD)
    # Response is about `child`, but we evaluate it as the status of `other`.
    assert V._ocsp_response_is_good(resp, other, issuer, _OCSP_AT) is False


def _name(cn):
    """Build a "C=DE, O=D-Trust GmbH, CN=<cn>" X.509 name (used where only a name,
    not a full certificate, is required)."""
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "D-Trust GmbH"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def _mk_tmp(factory, label):
    """Return a temp directory. Under pytest the tmp_path_factory fixture is passed
    and used; when the file is run directly (factory is None) it falls back to
    tempfile.mkdtemp. This is why each test takes `tmp_path_factory=None`."""
    if factory is not None:
        return str(factory.mktemp(label))
    import tempfile
    return tempfile.mkdtemp(prefix=f"dcc_{label}_")


# Allow running without pytest: execute each test, print PASS/FAIL, exit non-zero
# on any failure (so it doubles as a standalone, CI-friendly check).
if __name__ == "__main__":
    failures = 0
    for fn in (test_genuine_chain_validates,
               test_name_spoofing_attacker_chain_rejected,
               test_signature_link_verifies_across_algorithms,
               test_tampered_pin_refuses,
               test_embedded_anchor_loads_and_matches_pin,
               test_ocsp_good_response_accepted,
               test_ocsp_revoked_response_rejected,
               test_ocsp_untrusted_signer_rejected,
               test_ocsp_delegated_responder_accepted,
               test_ocsp_stale_response_rejected,
               test_ocsp_serial_mismatch_rejected):
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
        except AssertionError as exc:
            failures += 1
            print(f"  FAIL  {fn.__name__}: {exc}")
    print("=" * 60)
    print("ALL TESTS PASSED" if failures == 0 else f"{failures} TEST(S) FAILED")
    sys.exit(1 if failures else 0)