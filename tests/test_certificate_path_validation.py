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
  3. Tampering with the pinned anchor (wrong fingerprint) makes the anchor refuse
     to load — there is no fallback to an unverified certificate.
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

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
sys.path.insert(0, REPO_ROOT)

from lxml import etree  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

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
    root = etree.parse(SAMPLE_DCC).getroot()
    b64 = root.xpath("//dsig:X509Certificate", namespaces=DSIG)[0].text.strip()
    pem = f"-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----".encode()
    path = os.path.join(tmp_path, "seal_cert.pem")
    with open(path, "wb") as fh:
        fh.write(pem)
    return path, x509.load_pem_x509_certificate(pem)


def _self_signed(cn, key, issuer_key, issuer_name, ca):
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
    tmp = _mk_tmp(tmp_path_factory, "genuine")
    seal_path, seal = _write_seal(tmp)
    at = seal.not_valid_before_utc + datetime.timedelta(days=1)
    res = V.validate_certificate_chain(seal_path, INTERMEDIATE, at)
    assert res["chain_ok"] is True, res["reason"]
    assert res["anchored_to_pinned_root"] is True
    assert res["intermediate_pin_ok"] is True


def test_name_spoofing_attacker_chain_rejected(tmp_path_factory=None):
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

    # The former string checks WOULD have accepted this chain:
    assert seal.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == V.ca_issuer
    assert root.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == V.root_ca_file

    at = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    res = V.validate_certificate_chain(seal_path, inter_path, at)
    assert res["chain_ok"] is False
    assert res["anchored_to_pinned_root"] is False


def test_tampered_pin_refuses():
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


def _name(cn):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "D-Trust GmbH"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def _mk_tmp(factory, label):
    if factory is not None:
        return str(factory.mktemp(label))
    import tempfile
    return tempfile.mkdtemp(prefix=f"dcc_{label}_")


if __name__ == "__main__":
    failures = 0
    for fn in (test_genuine_chain_validates,
               test_name_spoofing_attacker_chain_rejected,
               test_tampered_pin_refuses):
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
        except AssertionError as exc:
            failures += 1
            print(f"  FAIL  {fn.__name__}: {exc}")
    print("=" * 60)
    print("ALL TESTS PASSED" if failures == 0 else f"{failures} TEST(S) FAILED")
    sys.exit(1 if failures else 0)