"""
crypto_utils.py — Secure Ethereum address derivation and memory management.

This module handles all cryptographic operations for EthRecover:
  1. Deriving an Ethereum public address from a raw private key hex string.
  2. Checking candidates against a target address set.
  3. Secure memory wiping for sensitive data.

SECURITY NOTES:
  - No data is logged to disk or transmitted over the network.
  - Use `secure_wipe()` on any mutable buffer holding key material after use.
  - Python's garbage collector may retain copies; bytearray + memset is best-effort.
"""

import ctypes
import os
from typing import Optional, Set

from eth_account import Account


# ---------------------------------------------------------------------------
# Address derivation
# ---------------------------------------------------------------------------

def derive_address(private_key_hex: str) -> Optional[str]:
    """
    Derive the checksummed Ethereum address from a 64-character hex private key.

    Parameters
    ----------
    private_key_hex : str
        A 64-character hexadecimal string (no '0x' prefix, no whitespace).

    Returns
    -------
    str or None
        The checksummed Ethereum address (e.g. '0xABC...'), or None if the
        input is not a valid secp256k1 private key.
    """
    try:
        acct = Account.from_key(private_key_hex)
        return acct.address  # checksummed, e.g. '0x71C...'
    except Exception:
        return None


def check_candidate(candidate_hex: str, targets: Set[str]) -> bool:
    """
    Derive an address from *candidate_hex* and return True if it matches
    any address in *targets*.

    Both the derived address and every element in *targets* are compared
    in **lowercase** to avoid checksum-related false negatives.

    Parameters
    ----------
    candidate_hex : str
        64-character hex string representing a potential private key.
    targets : set of str
        Set of Ethereum addresses to match (stored lowercase internally).

    Returns
    -------
    bool
        True if the derived address matches a target, False otherwise.
    """
    addr = derive_address(candidate_hex)
    if addr is None:
        return False
    return addr.lower() in targets


def fast_check_candidate(candidate_hex: str, targets: Set[str]):
    """
    Like check_candidate but returns the (candidate, address) tuple on match,
    or None on miss. Used by the multiprocessing workers to return the result
    in a single call.

    Parameters
    ----------
    candidate_hex : str
        64-character hex string representing a potential private key.
    targets : set of str
        Set of Ethereum addresses to match (stored lowercase internally).

    Returns
    -------
    tuple(str, str) or None
        (private_key_hex, derived_address) if match found, else None.
    """
    addr = derive_address(candidate_hex)
    if addr is None:
        return None
    if addr.lower() in targets:
        return (candidate_hex, addr)
    return None


# ---------------------------------------------------------------------------
# Secure memory wiping
# ---------------------------------------------------------------------------

def secure_wipe(data: bytearray) -> None:
    """
    Overwrite the contents of a mutable byte buffer with zeros.

    This is a **best-effort** defence against memory forensics.  Python's
    garbage collector and string interning make it impossible to guarantee
    that no copies of sensitive data remain in the process address space.

    Parameters
    ----------
    data : bytearray
        The mutable buffer to wipe.  Passing an immutable ``bytes`` object
        will raise a TypeError.
    """
    if not isinstance(data, bytearray):
        return  # silently skip immutable types (cannot wipe str/bytes)

    length = len(data)
    if length == 0:
        return

    # Use ctypes.memset for a single low-level operation.
    ctypes.memset(
        (ctypes.c_char * length).from_buffer(data),
        0,
        length,
    )


def encrypt_and_save(private_key_hex: str, address: str, filepath: str,
                     password: str) -> None:
    """
    Encrypt the recovered private key with a user-supplied password and save
    it to *filepath* as a Fernet-encrypted blob.

    The key derivation uses PBKDF2-HMAC-SHA256 with a random 16-byte salt
    and 480 000 iterations.

    Parameters
    ----------
    private_key_hex : str
        The recovered private key in hex.
    address : str
        The corresponding Ethereum address.
    password : str
        User-supplied encryption password.
    filepath : str
        Output file path.
    """
    import base64
    import json as _json
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    fernet_key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    f = Fernet(fernet_key)

    payload = _json.dumps({
        "private_key": private_key_hex,
        "address": address,
    }).encode("utf-8")

    encrypted = f.encrypt(payload)

    with open(filepath, "wb") as fh:
        # Write salt (16 bytes) + encrypted blob
        fh.write(salt + encrypted)

    print(f"  [+] Encrypted key saved to: {filepath}")
    print(f"      (salt: {salt.hex()[:16]}...)")
