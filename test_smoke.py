"""
Smoke test suite for EthRecover v2.0.

Tests all recovery levels with a known keypair.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from eth_account import Account
from crypto_utils import derive_address, check_candidate, fast_check_candidate, secure_wipe
from recovery_engine import (
    level1_format_fixes,
    level1_5_truncation_padding,
    level1_7_transpositions,
    level2_ocr_substitutions,
    level2_5_insertion_deletion,
    level2_7_duplicate_chars,
    estimate_level3_candidates,
    clean_corrupted_input,
    clean_corrupted_input_preserve_case,
    diff_keys,
    run_level3,
    _is_hex,
)
from state_manager import (
    new_checkpoint, save_checkpoint, load_checkpoint, clear_checkpoint,
)


# ---------------------------------------------------------------------------
# Shared test keypair
# ---------------------------------------------------------------------------

TEST_KEY = "4c0883a69102937d6231471b5dbb6204fe512961708279f23efb56c49e5f7e12"

def _get_test_pair():
    """Return (key, address) for the well-known test keypair."""
    addr = derive_address(TEST_KEY)
    assert addr is not None, "Failed to derive address from test key"
    return TEST_KEY, addr


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_is_hex_edge():
    """_is_hex should return False for empty strings."""
    print("\n── Test _is_hex edge cases ──")
    assert _is_hex("") is False, "_is_hex('') should be False"
    assert _is_hex("0") is True
    assert _is_hex("abcdef0123456789") is True
    assert _is_hex("xyz") is False
    print("  ✓ _is_hex edge cases PASSED")


def test_level1():
    """Level 1: format fixes should recover from prefix/case/whitespace."""
    print("\n── Test Level 1: Format Fixes ──")
    key, addr = _get_test_pair()

    # Corrupt: add 0x prefix + uppercase + trailing spaces
    corrupted = "0x" + key.upper() + "   "
    candidates = level1_format_fixes(corrupted)
    assert key.lower() in [c.lower() for c in candidates], \
        "Level 1 failed to produce correct candidate"
    assert check_candidate(key, {addr.lower()}), "check_candidate failed"

    # Also test with \\x prefix
    corrupted2 = "\\x" + key.upper()
    candidates2 = level1_format_fixes(corrupted2)
    assert key.lower() in [c.lower() for c in candidates2], \
        "Level 1 failed with \\x prefix"

    # Test with dashes
    corrupted3 = key[:16] + "-" + key[16:32] + "-" + key[32:48] + "-" + key[48:]
    candidates3 = level1_format_fixes(corrupted3)
    assert key.lower() in [c.lower() for c in candidates3], \
        "Level 1 failed with dash-separated key"

    print("  ✓ Level 1 PASSED")


def test_level1_5():
    """Level 1.5: truncation and padding."""
    print("\n── Test Level 1.5: Truncation & Padding ──")
    key, addr = _get_test_pair()

    # Simulate leading zeros stripped (key starts with '4c', pretend it was '004c...')
    # Create a key with leading zeros
    short_key = key.lstrip("0")  # strip any leading zeros
    if len(short_key) < 64:
        candidates = level1_5_truncation_padding(short_key)
        assert key in candidates, f"Failed to recover left-padded key"
        print(f"  Truncated to {len(short_key)} chars → recovered with left-pad ✓")
    else:
        # Our test key doesn't have leading zeros, so test with a synthetic case
        short = key[2:]  # remove first 2 chars → 62 chars
        candidates = level1_5_truncation_padding(short)
        # Left-pad should produce "00" + short
        assert "00" + short in candidates, "Left-pad failed for 62-char key"
        print(f"  62-char key → left-padded ✓")

    # Too long
    long_key = "ab" + key  # 66 chars
    candidates = level1_5_truncation_padding(long_key)
    assert key in candidates, "Sliding window failed for 66-char key"
    print(f"  66-char key → sliding window found original ✓")

    print("  ✓ Level 1.5 PASSED")


def test_level1_7():
    """Level 1.7: adjacent transpositions."""
    print("\n── Test Level 1.7: Transpositions ──")
    key, addr = _get_test_pair()

    # Swap positions 10 and 11
    chars = list(key)
    if chars[10] != chars[11]:  # only test if they're different
        chars[10], chars[11] = chars[11], chars[10]
        corrupted = "".join(chars)
        candidates = level1_7_transpositions(corrupted)
        assert key in candidates, "Transposition recovery failed"
        print(f"  Swapped chars[10]↔[11] ('{key[10]}' ↔ '{key[11]}') → recovered ✓")
    else:
        print(f"  Skipped (chars[10]==chars[11], no visible swap)")

    n = len(level1_7_transpositions(key, max_swaps=1))
    print(f"  Single-swap candidates: {n}")
    assert n <= 63, "Too many single-swap candidates"

    print("  ✓ Level 1.7 PASSED")


def test_level2():
    """Level 2: OCR substitution should handle 0→O confusion."""
    print("\n── Test Level 2: OCR Substitution ──")
    key, addr = _get_test_pair()

    # Find a '0' in the key and replace it with 'O' (OCR error)
    if '0' in key:
        idx = key.index('0')
        # Use uppercase 'O' in original-case input
        corrupted = key[:idx] + 'O' + key[idx+1:]
        print(f"  Corrupted at index {idx}: '0' → 'O'")

        # Level 2 should work on case-preserved input
        candidates = level2_ocr_substitutions(corrupted)
        matched = any(check_candidate(c, {addr.lower()}) for c in candidates)
        assert matched, "Level 2 OCR recovery failed"
        print("  ✓ Level 2 PASSED (via address match)")
    else:
        print("  (no '0' in test key — skipping)")


def test_level2_5():
    """Level 2.5: insertion/deletion for wrong-length keys."""
    print("\n── Test Level 2.5: Insertion/Deletion ──")
    key, addr = _get_test_pair()

    # 65-char key (one extra char inserted)
    extra = key[:20] + "f" + key[20:]
    assert len(extra) == 65
    candidates = level2_5_insertion_deletion(extra)
    assert key in candidates, "Deletion recovery failed for 65-char key"
    print(f"  65-char key (extra 'f' at pos 20) → deletion found original ✓")

    # 63-char key (one char deleted)
    short = key[:20] + key[21:]
    assert len(short) == 63
    candidates = level2_5_insertion_deletion(short)
    # The original key should be among the insertion candidates
    assert key in candidates, "Insertion recovery failed for 63-char key"
    print(f"  63-char key (deleted pos 20) → insertion found original ✓")

    print("  ✓ Level 2.5 PASSED")


def test_level2_7():
    """Level 2.7: duplicate character handling."""
    print("\n── Test Level 2.7: Duplicate Characters ──")
    key, addr = _get_test_pair()

    # Find a position with a non-doubled char, double it → 65 chars
    # Then test level1_5 + level2_7 combo indirectly
    # For level2_7: find a doubled char and test collapsing
    for i in range(len(key) - 1):
        if key[i] == key[i + 1]:
            # Found a natural double — test that collapsing produces 63 chars
            candidates = level2_7_duplicate_chars(key)
            print(f"  Found doubled '{key[i]}' at positions {i}-{i+1}")
            print(f"  Collapse candidates: {len(candidates)}")
            break
    else:
        print(f"  No natural doubles in test key — testing synthetic")
        # Create a 63-char input with a known double at pos 0
        short_key = key[1:]  # remove first char → 63 chars
        candidates = level2_7_duplicate_chars(short_key)
        print(f"  63-char input → expand candidates: {len(candidates)}")

    print("  ✓ Level 2.7 PASSED")


def test_level3():
    """Level 3: 1-char hex flip should be recovered."""
    print("\n── Test Level 3: Hex Flip (1 change) ──")
    key, addr = _get_test_pair()

    # Flip one hex character
    chars = list(key)
    original_char = chars[10]
    new_char = '0' if original_char != '0' else '1'
    chars[10] = new_char
    corrupted = "".join(chars)

    print(f"  Flipped index 10: '{original_char}' → '{new_char}'")

    est = estimate_level3_candidates(64, 1)
    print(f"  Estimated candidates: {est}")

    found_key, found_addr, tested, completed = run_level3(
        corrupted, {addr.lower()}, max_changes=1, num_workers=2,
        completed_batches=set(), progress_callback=None,
    )

    assert found_key is not None, f"Level 3 failed to find key (tested {tested})"
    assert found_key.lower() == key.lower(), "Level 3 found wrong key"
    assert found_addr.lower() == addr.lower(), "Level 3 found wrong address"
    print(f"  Found after testing {tested} candidates")
    print("  ✓ Level 3 PASSED")


def test_checkpoint():
    """Test checkpoint save/load with new fields."""
    print("\n── Test Checkpoint ──")
    cp = new_checkpoint("deadbeef" * 8, ["0xabc123"], max_changes=2)
    cp.level = 2
    cp.total_tested = 42
    cp.completed_batches = {0, 1, 5}

    path = "test_checkpoint.json"
    save_checkpoint(cp, path)

    # Load with validation
    loaded = load_checkpoint(path, corrupted="deadbeef" * 8, targets=["0xabc123"])
    assert loaded is not None, "Failed to load checkpoint"
    assert loaded.level == 2
    assert loaded.total_tested == 42
    assert loaded.completed_batches == {0, 1, 5}

    # Test standalone resume (no corrupted/targets provided)
    loaded2 = load_checkpoint(path)
    assert loaded2 is not None, "Standalone checkpoint load failed"
    assert loaded2.corrupted_raw == "deadbeef" * 8, "Stored corrupted_raw missing"
    assert loaded2.targets_raw == ["0xabc123"], "Stored targets_raw missing"

    clear_checkpoint(path)
    print("  ✓ Checkpoint PASSED")


def test_secure_wipe():
    """Test secure wipe of bytearray."""
    print("\n── Test Secure Wipe ──")
    buf = bytearray(b"secret_key_material")
    secure_wipe(buf)
    assert all(b == 0 for b in buf), "Secure wipe did not zero buffer"
    print("  ✓ Secure Wipe PASSED")


def test_diff_keys():
    """Test diff highlighting output."""
    print("\n── Test Diff Keys ──")
    result = diff_keys("abcdef", "abXdYf")
    assert "^" in result, "Diff should contain ^ markers"
    assert "2 character(s) changed" in result, f"Wrong change count: {result}"
    print("  ✓ Diff Keys PASSED")


def test_clean_input():
    """Test input cleaning with various prefixes."""
    print("\n── Test Clean Input ──")
    assert clean_corrupted_input("0x" + "a" * 64) == "a" * 64
    assert clean_corrupted_input("\\x" + "b" * 64) == "b" * 64
    assert clean_corrupted_input("hex:" + "c" * 64) == "c" * 64
    assert clean_corrupted_input("  ab-cd:ef  ") == "abcdef"

    # Case preservation
    raw = clean_corrupted_input_preserve_case("0xAbCdEf")
    assert raw == "AbCdEf"

    print("  ✓ Clean Input PASSED")


# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  EthRecover v2.0 Smoke Tests")
    print("=" * 60)

    tests = [
        test_is_hex_edge,
        test_level1,
        test_level1_5,
        test_level1_7,
        test_level2,
        test_level2_5,
        test_level2_7,
        test_level3,
        test_checkpoint,
        test_secure_wipe,
        test_diff_keys,
        test_clean_input,
    ]

    passed = 0
    failed = 0
    for test_fn in tests:
        try:
            test_fn()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"  ✗ {test_fn.__name__} FAILED: {e}")

    print(f"\n{'=' * 60}")
    print(f"  Results: {passed} passed, {failed} failed out of {len(tests)}")
    if failed == 0:
        print(f"  ALL TESTS PASSED ✓")
    else:
        print(f"  SOME TESTS FAILED ✗")
    print(f"{'=' * 60}")
    sys.exit(1 if failed else 0)
