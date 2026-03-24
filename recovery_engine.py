# pyre-unsafe
"""
recovery_engine.py — Core recovery logic for EthRecover v2.0.

Implements eight recovery levels in ascending order of computational cost.
Each level generates "candidate" private key hex strings from the corrupted
input, derives the Ethereum address, and checks it against target addresses.

RECOVERY LEVELS:
  Level 1    — Format / encoding fixes (instant)
  Level 1.5  — Truncation & padding (instant)
  Level 1.7  — Adjacent character transpositions (~2K candidates)
  Level 2    — OCR / character substitution (<1K candidates)
  Level 2.5  — Single insertion / deletion (for 63/65-char keys)
  Level 2.7  — Duplicate character collapse / expansion
  Level 2.9  — Known-prefix brute force (user-specified)
  Level 3    — Hex-flip / Hamming distance (combinatorial, multiprocessed)

PERFORMANCE NOTES:
  - The inner loop (Level 3) is the bottleneck.  We minimise object creation
    by working with lists of characters and ''.join() only when testing.
  - Multiprocessing is used for Level 3 to spread position-combinations
    across all available CPU cores.
  - Each worker receives a *batch* of position-combinations (not individual
    candidates) so IPC overhead is amortised.

CRYPTOGRAPHIC LIMITS:
  A 64-character hex private key has 16^64 ≈ 1.16 × 10^77 possible values.
  Even with all the world's computers running for millennia, you cannot
  brute-force more than a handful of character changes.

  max_changes | candidates          | ~time @ 50 000 keys/s
  ------------|---------------------|----------------------
  1           |              960    |  < 1 second
  2           |           28 560    |  < 1 second
  3           |          537 920    |  ~11 seconds
  4           |        7 418 880    |  ~2.5 minutes
  5           |       78 348 288    |  ~26 minutes
  6           |      649 671 168    |  ~3.6 hours
  7           |    4 329 587 712    |  ~24 hours
  8           |   23 464 857 600    |  ~5.4 days

  Beyond 5 changes the search is impractical on consumer hardware.
"""

import itertools
import json
import os
import re
from math import comb
from multiprocessing import Pool
from typing import Dict, List, Optional, Set, Tuple

from crypto_utils import derive_address, fast_check_candidate

# ---------------------------------------------------------------------------
# Constants & Globals
# ---------------------------------------------------------------------------

HEX_CHARS = "0123456789abcdef"

# Globals for multiprocessing to avoid IPC overhead
_w_key_chars: List[str] = []
_w_targets: Set[str] = set()


# OCR / copy-paste confusion map — covers both upper and lowercase keys.
# Each entry maps a character that might appear in a corrupted key to the
# list of hex-valid characters it could have been confused with.
OCR_MAP: Dict[str, List[str]] = {
    # Digit confusions
    "0": ["o", "d"],
    "1": ["l", "i", "7"],
    "2": ["z"],
    "5": ["s"],
    "6": ["g", "b"],
    "8": ["b"],
    # Lowercase letter confusions (input is lowercased before Level 2)
    "o": ["0"],
    "l": ["1"],
    "i": ["1"],
    "z": ["2"],
    "s": ["5"],
    "g": ["6", "9"],
    "b": ["6", "8"],
    "d": ["0"],
    "q": ["9"],
    "t": ["7"],
    # Uppercase originals (in case raw input is used for Level 2)
    "O": ["0"],
    "I": ["1"],
    "L": ["1"],
    "Z": ["2"],
    "S": ["5"],
    "G": ["6", "9"],
    "B": ["8", "6"],
    "D": ["0"],
    "Q": ["9"],
    "T": ["7"],
}


# ---------------------------------------------------------------------------
# Level 1: Format / encoding fixes   (instant)
# ---------------------------------------------------------------------------

def level1_format_fixes(corrupted: str) -> List[str]:
    """
    Generate candidate keys by fixing common formatting issues.

    Handles:  0x/0X/\\x/hex: prefixes, whitespace, newlines, tabs,
              dash separators, case normalisation.

    Returns a *deduplicated* list of candidate 64-char lowercase hex strings.
    """
    candidates: Set[str] = set()
    raw = corrupted

    # Variations to try
    variations = [
        raw,
        raw.strip(),
        raw.replace(" ", ""),
        raw.replace("\n", "").replace("\r", ""),
        raw.replace("\t", ""),
        raw.replace("-", ""),            # dash-separated hex
        raw.replace(":", ""),            # colon-separated hex
        raw.replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", ""),
        raw.replace(" ", "").replace("-", "").replace(":", ""),
    ]

    prefixes_to_strip = ["0x", "0X", "\\x", "\\X", "x", "X", "hex:", "HEX:", "Hex:"]

    for v in variations:
        for prefix in [""] + prefixes_to_strip:
            stripped = v
            plen: int = len(prefix)
            if prefix and stripped.startswith(prefix):
                stripped = stripped[plen:]
            elif prefix and stripped.lower().startswith(prefix.lower()):
                stripped = stripped[plen:]

            # Try original case, lowercase, and uppercase
            for case_variant in (stripped, stripped.lower(), stripped.upper()):
                cleaned = case_variant.strip()
                if len(cleaned) == 64 and _is_hex(cleaned):
                    candidates.add(cleaned.lower())

    return list(candidates)


# ---------------------------------------------------------------------------
# Level 1.5: Truncation & padding   (instant)
# ---------------------------------------------------------------------------

def level1_5_truncation_padding(corrupted_clean: str) -> List[str]:
    """
    Generate candidates for keys that are the wrong length.

    Handles:
      - Key too short  → left-pad or right-pad with '0'
      - Key too long   → try all 64-char windows (sliding)
      - Key too long   → truncate from left or right

    Returns a deduplicated list of 64-char lowercase hex candidates.
    """
    candidates: Set[str] = set()
    key = corrupted_clean.lower()
    klen = len(key)

    if klen == 64:
        return []  # nothing to fix

    if not _is_hex(key):
        # Try stripping non-hex chars from ends
        stripped = key.lstrip("x").rstrip(" \n\r\t")
        if _is_hex(stripped):
            key = stripped
            klen = len(key)

    if klen < 64 and _is_hex(key):
        # Left-pad with zeros (most common — leading zeros dropped)
        candidates.add(key.zfill(64))
        # Right-pad with zeros
        candidates.add(key.ljust(64, "0"))
        # Center-pad (less likely but covers it)
        diff = 64 - klen
        candidates.add("0" * (diff // 2) + key + "0" * (diff - diff // 2))

    if klen > 64 and _is_hex(key):
        # Truncate from left
        candidates.add(key[klen - 64:])
        # Truncate from right
        candidates.add(key[:64])
        # Sliding window — try every 64-char substring
        for i in range(klen - 64 + 1):
            window = key[i:i + 64]
            candidates.add(window)

    # Remove anything that isn't exactly 64 valid hex chars
    return [c for c in candidates if len(c) == 64 and _is_hex(c)]


# ---------------------------------------------------------------------------
# Level 1.7: Adjacent character transposition   (~2K candidates)
# ---------------------------------------------------------------------------

def level1_7_transpositions(corrupted_clean: str, max_swaps: int = 2) -> List[str]:
    """
    Generate candidates by swapping adjacent characters.

    A single-swap pass produces 63 candidates (for a 64-char key).
    With max_swaps=2 it produces ~63*62/2 ≈ 1953 candidates.

    Only valid hex results are returned.
    """
    if len(corrupted_clean) != 64 or not _is_hex(corrupted_clean):
        return []

    candidates: Set[str] = set()
    chars = list(corrupted_clean)

    # Single swaps
    for i in range(len(chars) - 1):
        swapped = chars.copy()
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
        c = "".join(swapped)
        if c != corrupted_clean:
            candidates.add(c)

    # Double swaps (two non-overlapping adjacent pairs)
    if max_swaps >= 2:
        for i in range(len(chars) - 1):
            for j in range(i + 2, len(chars) - 1):
                swapped = chars.copy()
                swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
                swapped[j], swapped[j + 1] = swapped[j + 1], swapped[j]
                c = "".join(swapped)
                if c != corrupted_clean:
                    candidates.add(c)

    candidates.discard(corrupted_clean)
    return list(candidates)


# ---------------------------------------------------------------------------
# Level 2: OCR / character-substitution   (<1K candidates)
# ---------------------------------------------------------------------------

def level2_ocr_substitutions(corrupted_clean: str) -> List[str]:
    """
    Generate candidates by replacing OCR-ambiguous characters.

    Works on both lowercased and original-case input to catch all mappings.

    Parameters
    ----------
    corrupted_clean : str
        The 64-char string after basic cleaning (may still contain non-hex
        chars from OCR corruption like 'O', 'I', 'l', etc.).

    Returns
    -------
    list of str
        All unique candidate hex strings produced by OCR substitution.
    """
    chars = list(corrupted_clean)
    ambiguous_positions: List[Tuple[int, List[str]]] = []

    for i, ch in enumerate(chars):
        if ch in OCR_MAP:
            # Build list of valid hex replacements from the OCR map
            valid_subs = []
            seen = set()
            for r in OCR_MAP[ch]:
                rl = r.lower()
                if rl in HEX_CHARS and rl not in seen:
                    seen.add(rl)
                    valid_subs.append(rl)
            if valid_subs:
                ambiguous_positions.append((i, valid_subs))

    if not ambiguous_positions:
        return []

    # Build per-position replacement options
    candidates: Set[str] = set()
    replacement_options: List[List[str]] = []
    for pos, replacements in ambiguous_positions:
        original = chars[pos].lower() if chars[pos].lower() in HEX_CHARS else None
        options_set: Set[str] = set(replacements)
        if original:
            options_set.add(original)
        replacement_options.append(sorted(options_set))

    # --- Guard against combinatorial explosion ---
    # With N ambiguous positions each having ~2 options, the product is 2^N.
    # Cap at 12 simultaneous positions (~4096 combos max per group).
    MAX_SIMULTANEOUS = 12

    if len(ambiguous_positions) <= MAX_SIMULTANEOUS:
        # Small enough to enumerate all combos
        for combo in itertools.product(*replacement_options):
            result = list(corrupted_clean.lower())
            for idx, (pos, _) in enumerate(ambiguous_positions):
                result[pos] = combo[idx]
            key = "".join(result)
            if len(key) == 64 and _is_hex(key):
                candidates.add(key)
    else:
        # Too many ambiguous positions — use a tiered strategy:
        # 1) Try each position independently (linear)
        base = list(corrupted_clean.lower())
        for (pos, _), opts in zip(ambiguous_positions, replacement_options):
            for opt in opts:
                trial = base.copy()
                trial[pos] = opt
                key = "".join(trial)
                if len(key) == 64 and _is_hex(key):
                    candidates.add(key)

        # 2) Try all pairs of positions
        for i in range(len(ambiguous_positions)):
            for j in range(i + 1, min(len(ambiguous_positions), i + 20)):
                pi, oi = ambiguous_positions[i][0], replacement_options[i]
                pj, oj = ambiguous_positions[j][0], replacement_options[j]
                for a in oi:
                    for b in oj:
                        trial = base.copy()
                        trial[pi] = a
                        trial[pj] = b
                        key = "".join(trial)
                        if len(key) == 64 and _is_hex(key):
                            candidates.add(key)

    # Remove the obvious original
    candidates.discard(corrupted_clean.lower())
    return list(candidates)


# ---------------------------------------------------------------------------
# Level 2.5: Single insertion / deletion   (for 63/65-char keys)
# ---------------------------------------------------------------------------

def level2_5_insertion_deletion(corrupted_clean: str) -> List[str]:
    """
    Handle keys that are off by exactly one character.

    - 65-char key → try deleting each character (65 candidates)
    - 63-char key → try inserting each hex char at each position (64×16 = 1024)

    Returns only valid 64-char hex candidates.
    """
    candidates: Set[str] = set()
    key = corrupted_clean.lower()

    if len(key) == 65 and _is_hex(key):
        # Try deleting each character
        for i in range(65):
            c = key[:i] + key[i + 1:]
            if len(c) == 64:
                candidates.add(c)

    elif len(key) == 63 and _is_hex(key):
        # Try inserting each hex char at each position
        for i in range(64):
            for h in HEX_CHARS:
                c = key[:i] + h + key[i:]
                if len(c) == 64:
                    candidates.add(c)

    elif len(key) == 66 and _is_hex(key):
        # Two extra chars — try deleting every pair
        for i in range(66):
            for j in range(i + 1, 66):
                c = key[:i] + key[i + 1:j] + key[j + 1:]
                if len(c) == 64:
                    candidates.add(c)

    elif len(key) == 62 and _is_hex(key):
        # Two missing chars — try inserting at same position (doubled char)
        for i in range(63):
            for h in HEX_CHARS:
                c = key[:i] + h + h + key[i:]
                if len(c) == 64:
                    candidates.add(c)

    return list(candidates)


# ---------------------------------------------------------------------------
# Level 2.7: Duplicate character collapse / expansion
# ---------------------------------------------------------------------------

def level2_7_duplicate_chars(corrupted_clean: str) -> List[str]:
    """
    Fix doubled or missing-doubled characters.

    - Find consecutive duplicate chars and try collapsing them (removing one).
    - Find single chars surrounded by different chars and try doubling them.

    Only returns candidates of exactly 64 hex chars.
    """
    candidates: Set[str] = set()
    key = corrupted_clean.lower()

    if not _is_hex(key):
        return []

    # Collapse: find doubled chars, remove one copy
    for i in range(len(key) - 1):
        if key[i] == key[i + 1]:
            collapsed = key[:i] + key[i + 1:]
            # Now it's len-1 chars; left-pad to 64 if needed
            if len(collapsed) == 64 and _is_hex(collapsed):
                candidates.add(collapsed)
            elif len(collapsed) == 63:
                # Pad with 0 on left (leading zero dropped scenario)
                padded = "0" + collapsed
                if _is_hex(padded):
                    candidates.add(padded)

    # Expand: try doubling each character
    if len(key) == 63:
        for i in range(len(key)):
            expanded = key[:i] + key[i] + key[i:]
            if len(expanded) == 64 and _is_hex(expanded):
                candidates.add(expanded)

    # For 64-char keys: try collapsing one double then expanding another spot
    if len(key) == 64:
        for i in range(len(key) - 1):
            if key[i] == key[i + 1]:
                # Remove one of the doubles → 63 chars
                short = key[:i] + key[i + 1:]
                # This 63-char string might be the real key that was
                # corrupted by a missing char elsewhere.  We already handle
                # that case with level2_5, so skip to avoid explosion.
                pass

    candidates.discard(corrupted_clean.lower())
    return list(candidates)


# ---------------------------------------------------------------------------
# Level 2.9: Known-prefix brute force
# ---------------------------------------------------------------------------

def level2_9_known_prefix_bruteforce(
    known_prefix: str, targets: Set[str], progress_callback=None,
) -> Tuple[Optional[str], Optional[str], int]:
    """
    Brute-force the suffix of a key when the user knows the first N chars.

    WARNING: This is only practical when the unknown suffix is ≤4 hex chars
    (65 536 candidates for 4 chars, ~1M for 5).

    Parameters
    ----------
    known_prefix : str
        The known portion of the private key (lowercase hex, no 0x).
    targets : set of str
        Lowercase target addresses.
    progress_callback : callable or None
        Called with (num_tested,) periodically.

    Returns
    -------
    (found_key, found_address, total_tested)
    """
    prefix = known_prefix.lower().strip()
    if not _is_hex(prefix) or len(prefix) >= 64:
        return (None, None, 0)

    suffix_len = 64 - len(prefix)
    total = 16 ** suffix_len
    tested = 0

    for i in range(total):
        suffix = format(i, f"0{suffix_len}x")
        candidate = prefix + suffix
        tested += 1

        result = fast_check_candidate(candidate, targets)
        if result is not None:
            return (result[0], result[1], tested)

        if progress_callback and tested % 10000 == 0:
            progress_callback(10000)

    return (None, None, tested)


# ---------------------------------------------------------------------------
# Level 3: Hex-flip / Hamming distance   (combinatorial, multiprocessed)
# ---------------------------------------------------------------------------

def estimate_level3_candidates(key_length: int, max_changes: int) -> int:
    """
    Estimate the total number of candidates for Level 3.

    For each subset of `k` positions (out of `key_length`) and each position
    changed to one of 15 alternative hex chars:
        total = Σ_{k=1}^{max_changes}  C(key_length, k) × 15^k
    """
    total = 0
    for k in range(1, max_changes + 1):
        total += comb(key_length, k) * (15 ** k)
    return total


def _generate_batches(key_length: int, max_changes: int):
    """
    Split the Level-3 search space into batches.

    Each batch is a *position-combination* (a tuple of indices into the key
    where characters will be flipped). For each batch the worker iterates
    all 15^len(positions) substitution values.
    """
    for k in range(1, max_changes + 1):
        for positions in itertools.combinations(range(key_length), k):
            yield positions


def _worker_init(corrupted_key: str, target_set_list: list):
    """
    Initializer for each pool worker.  Stores shared data in global
    variables that persist for the lifetime of the worker process,
    avoiding repeated IPC for large data.
    """
    global _w_key_chars, _w_targets
    _w_key_chars = list(corrupted_key)
    _w_targets = set(target_set_list)


def _worker_process_batch(args: Tuple[int, Tuple[int, ...]]):
    """
    Worker function: for a given set of positions, try all hex substitutions.

    Parameters
    ----------
    args : (batch_index, position_tuple)
        The batch_index is returned as-is so the caller can track progress
        correctly even with imap_unordered.

    Returns
    -------
    (batch_index, found_key_or_None, found_addr_or_None, num_tested)
    """
    global _w_key_chars, _w_targets

    batch_index, positions = args
    chars = _w_key_chars.copy()  # local copy (list of chars)
    original_chars = [chars[p] for p in positions]
    n_positions = len(positions)
    tested = 0

    # For each position, the alternatives are all hex chars except the original.
    alternatives = []
    for p in positions:
        alts = [h for h in HEX_CHARS if h != chars[p]]
        alternatives.append(alts)

    for combo in itertools.product(*alternatives):
        # Apply substitutions
        for i in range(n_positions):
            chars[positions[i]] = combo[i]

        candidate = "".join(chars)
        tested += 1

        result = fast_check_candidate(candidate, _w_targets)
        if result is not None:
            # Restore original chars before returning
            for i in range(n_positions):
                chars[positions[i]] = original_chars[i]
            return (batch_index, result[0], result[1], tested)

        # Restore for next iteration
        for i in range(n_positions):
            chars[positions[i]] = original_chars[i]

    return (batch_index, None, None, tested)


def run_level3(
    corrupted_clean: str,
    targets: Set[str],
    max_changes: int,
    num_workers: int,
    completed_batches: Set[int],
    progress_callback=None,
) -> Tuple[Optional[str], Optional[str], int, Set[int]]:
    """
    Run the Level-3 hex-flip search with multiprocessing.

    Parameters
    ----------
    corrupted_clean : str
        64-char lowercase hex key.
    targets : set of str
        Lowercase target addresses.
    max_changes : int
        Maximum number of characters to change simultaneously.
    num_workers : int
        Number of worker processes.
    completed_batches : set of int
        Batch indices already completed (from a checkpoint).
    progress_callback : callable or None
        Called with (num_tested_in_batch, batch_index) after each batch.

    Returns
    -------
    (found_key, found_address, total_tested, new_completed_batches)
    """
    total_batches = sum(comb(len(corrupted_clean), k) for k in range(1, max_changes + 1))
    remaining_count = total_batches - len(completed_batches)

    if remaining_count <= 0:
        return (None, None, 0, completed_batches)

    all_batches = _generate_batches(len(corrupted_clean), max_changes)

    def generate_remaining():
        for idx, batch in enumerate(all_batches):
            if idx not in completed_batches:
                yield (idx, batch)

    total_tested = 0
    new_completed = set(completed_batches)
    found_key = None
    found_address = None

    target_list = list(targets)

    with Pool(
        processes=num_workers,
        initializer=_worker_init,
        initargs=(corrupted_clean, target_list),
    ) as pool:
        if total_batches > 100_000:
            chunksize = 1
        else:
            chunksize = max(1, remaining_count // (num_workers * 4))

        for result in pool.imap_unordered(
            _worker_process_batch, generate_remaining(), chunksize=chunksize
        ):
            batch_idx, key, addr, tested = result
            total_tested += tested
            new_completed.add(batch_idx)

            if progress_callback:
                progress_callback(tested, batch_idx)

            if key is not None:
                found_key = key
                found_address = addr
                pool.terminate()
                break

    return (found_key, found_address, total_tested, new_completed)


# ---------------------------------------------------------------------------
# Level 4: Wallet / keystore file repair
# ---------------------------------------------------------------------------

def level4_wallet_repair(file_path: str) -> List[str]:
    """
    Attempt to repair common JSON corruption in an Ethereum keystore
    (UTC / JSON) file and extract the encrypted private key blob.

    This does NOT decrypt the keystore — it only repairs the JSON structure
    so that the file can be parsed.  The extracted key would still need a
    password to decrypt.
    """
    if not os.path.isfile(file_path):
        return []

    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError:
        return []

    candidates = []

    # --- Repair strategies ---
    repairs = [
        raw,                                    # original
        raw.strip(),                            # trim whitespace
        "{" + raw.strip().strip("{}") + "}",    # ensure outer braces
        raw.replace("'", '"'),                  # single → double quotes
        raw.replace('\\"', '"'),                # unescape quotes
        re.sub(r',\s*}', '}', raw),             # trailing comma before }
        re.sub(r',\s*]', ']', raw),             # trailing comma before ]
        re.sub(r'}\s*{', '},{', raw),           # missing comma between objects
    ]

    for attempt in repairs:
        try:
            data = json.loads(attempt)
        except json.JSONDecodeError:
            continue

        ciphertext = _extract_ciphertext(data)
        if ciphertext:
            candidates.append(ciphertext)

    return list(set(candidates))


def _extract_ciphertext(data: dict) -> Optional[str]:
    """Pull the ciphertext hex from a parsed keystore JSON."""
    try:
        crypto = data.get("crypto") or data.get("Crypto") or {}
        ct = crypto.get("ciphertext", "")
        if ct and _is_hex(ct):
            return ct.lower()
    except (AttributeError, TypeError):
        pass
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_hex(s: str) -> bool:
    """Return True if *s* is a non-empty string of hexadecimal characters."""
    if not s or not isinstance(s, str):
        return False
    try:
        int(s, 16)
        return True
    except (ValueError, TypeError):
        return False


def clean_corrupted_input(corrupted: str) -> str:
    """
    Apply basic normalisation to the corrupted input:
      - Strip whitespace / newlines / tabs
      - Remove common prefixes: 0x, 0X, \\x, hex:
      - Lowercase

    Returns the cleaned string (may not be valid hex or 64 chars).
    """
    cleaned = corrupted.strip()
    # Strip known prefixes (order matters — longest first)
    prefixes = ["hex:", "HEX:", "Hex:", "0x", "0X", "\\x", "\\X"]
    for p in prefixes:
        if cleaned.startswith(p):
            cleaned = cleaned[len(p):]
            break
        elif cleaned.lower().startswith(p.lower()):
            cleaned = cleaned[len(p):]
            break

    # Remove separator characters
    cleaned = cleaned.replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", "")
    cleaned = cleaned.replace("-", "").replace(":", "")

    return cleaned.lower()


def clean_corrupted_input_preserve_case(corrupted: str) -> str:
    """
    Like clean_corrupted_input but preserves the original case.
    Used for Level 2 (OCR) where case matters for the substitution map.
    """
    cleaned = corrupted.strip()

    prefixes = ["hex:", "HEX:", "Hex:", "0x", "0X", "\\x", "\\X"]
    for p in prefixes:
        if cleaned.startswith(p):
            cleaned = cleaned[len(p):]
            break
        elif cleaned.lower().startswith(p.lower()):
            cleaned = cleaned[len(p):]
            break

    cleaned = cleaned.replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", "")
    cleaned = cleaned.replace("-", "").replace(":", "")

    return cleaned


def diff_keys(original: str, recovered: str) -> str:
    """
    Produce a visual diff between the corrupted and recovered key.

    Returns a multi-line string showing:
      - The corrupted key with '^' markers under changed positions.
      - The recovered key.
    """
    orig = original.lower()
    recov = recovered.lower()

    # Pad to same length for comparison
    max_len = max(len(orig), len(recov))
    orig_padded = orig.ljust(max_len)
    recov_padded = recov.ljust(max_len)

    markers = []
    for i in range(max_len):
        if i < len(orig) and i < len(recov) and orig_padded[i] == recov_padded[i]:
            markers.append(" ")
        else:
            markers.append("^")

    changes = markers.count("^")
    lines = [
        f"  Corrupted:  {orig}",
        f"  Recovered:  {recov}",
        f"              {''.join(markers)}",
        f"  ({changes} character(s) changed)",
    ]
    return "\n".join(lines)
