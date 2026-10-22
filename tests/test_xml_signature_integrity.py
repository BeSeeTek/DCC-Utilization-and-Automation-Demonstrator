"""Integrity tests for the XMLDSig seal verification (real xmlsec, real DCCs).

Unlike test_certificate_path_validation.py (which stubs xmlsec because it only
exercises the certificate-chain logic), this module drives the ACTUAL XML digital
signature verification with a real `xmlsec` against genuine sealed DCCs shipped in
the repository. It proves the tamper-detection half of validation:

  1. An intact sealed DCC verifies (the seal signs the document as-is).
  2. The SAME DCC with a broken seal is rejected (any post-sealing modification is
     detected).

Both use the production code path get_signature_details() -> validate_xml_signature().

Run with either:
    python3 tests/test_xml_signature_integrity.py
    pytest tests/test_xml_signature_integrity.py

Requires: xmlsec, lxml, cryptography, pytz (see the ci "xml-signature-integrity" job).
"""
import os
import sys
import types

# Stub only the modules the XMLDSig path does not touch; xmlsec stays REAL so the
# signature is genuinely verified. (The certificate-chain suite stubs xmlsec too;
# here we must not.)
for _m in ("xmlschema", "requests"):
    sys.modules.setdefault(_m, types.ModuleType(_m))
_ossl = types.ModuleType("OpenSSL")
_crypto = types.ModuleType("OpenSSL.crypto")
_ossl.crypto = _crypto
sys.modules.setdefault("OpenSSL", _ossl)
sys.modules.setdefault("OpenSSL.crypto", _crypto)
_tk = types.ModuleType("tkinter")
_msgbox = types.ModuleType("tkinter.messagebox")
_tk.messagebox = _msgbox
sys.modules.setdefault("tkinter", _tk)
sys.modules.setdefault("tkinter.messagebox", _msgbox)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import xmlsec  # noqa: E402,F401  (import for real — a missing xmlsec must fail loudly)
from cryptography import x509  # noqa: E402

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

DCC_DIR = os.path.join(REPO_ROOT, "DCCs")
INTACT_DCC = os.path.join(DCC_DIR, "8.1I1539A_SEALED.xml")
BROKEN_DCC = os.path.join(DCC_DIR, "8.1I1539A_SEALED_seal_broken.xml")


def test_intact_seal_verifies():
    """INTEGRITY (positive): an unmodified sealed DCC must verify.

    Runs the production path get_signature_details() -> validate_xml_signature() on
    a genuine sealed DCC. A True result means the XML digital signature checks out,
    i.e. the document is byte-for-byte what was sealed. Also sanity-checks that the
    embedded seal certificate is a parseable X.509 certificate.
    """
    details = V.get_signature_details(INTACT_DCC)
    assert details is not None, "no signature details extracted from the intact DCC"
    seal_cert_pem, signing_date, signature_node = details
    # The extracted certificate must be a real, parseable X.509 certificate.
    x509.load_pem_x509_certificate(seal_cert_pem.encode())
    assert V.validate_xml_signature(signature_node, seal_cert_pem) is True, \
        "an intact sealed DCC must verify"


def test_broken_seal_is_rejected():
    """INTEGRITY (negative): a tampered DCC must be rejected.

    Same DCC, but with a deliberately broken seal (8.1I1539A_SEALED_seal_broken.xml).
    validate_xml_signature() must return False: any modification after sealing breaks
    the signature digest, which is exactly the post-sealing-tamper detection the DCC
    workflow relies on. This is the guard that the signature check is real and not a
    no-op.
    """
    details = V.get_signature_details(BROKEN_DCC)
    assert details is not None, "no signature details extracted from the broken DCC"
    seal_cert_pem, signing_date, signature_node = details
    assert V.validate_xml_signature(signature_node, seal_cert_pem) is False, \
        "a DCC with a broken seal must be rejected"


# Allow running without pytest: execute each test, print PASS/FAIL, exit non-zero
# on any failure (so it doubles as a standalone, CI-friendly check).
if __name__ == "__main__":
    failures = 0
    for fn in (test_intact_seal_verifies,
               test_broken_seal_is_rejected):
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
        except AssertionError as exc:
            failures += 1
            print(f"  FAIL  {fn.__name__}: {exc}")
    print("=" * 60)
    print("ALL TESTS PASSED" if failures == 0 else f"{failures} TEST(S) FAILED")
    sys.exit(1 if failures else 0)
