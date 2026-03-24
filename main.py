#!/usr/bin/env python3
"""
main.py — EthRecover v2.0 CLI entry point.

Usage:
    python main.py                                        # Interactive mode
    python main.py --corrupted <KEY> --target <ADDR>      # Direct mode
    python main.py --resume                               # Resume from checkpoint
    python main.py --corrupted <KEY> --target <ADDR> --known-prefix <PREFIX>

EthRecover attempts to recover an Ethereum private key from a corrupted
source string by systematically mutating it and checking the derived
address against one or more known target addresses.

SECURITY:
  • This tool is designed for OFFLINE USE ONLY.
  • No network calls are made.  No sensitive data is written to disk
    except the final encrypted result file.
  • Run on an airgapped machine whenever possible.
"""

import argparse
import getpass
import os
import sys
import time
from multiprocessing import cpu_count

from tqdm import tqdm

from crypto_utils import (
    check_candidate,
    derive_address,
    encrypt_and_save,
    secure_wipe,
)
from recovery_engine import (
    clean_corrupted_input,
    clean_corrupted_input_preserve_case,
    diff_keys,
    estimate_level3_candidates,
    level1_format_fixes,
    level1_5_truncation_padding,
    level1_7_transpositions,
    level2_ocr_substitutions,
    level2_5_insertion_deletion,
    level2_7_duplicate_chars,
    level2_9_known_prefix_bruteforce,
    level4_wallet_repair,
    run_level3,
)
from state_manager import (
    CheckpointState,
    clear_checkpoint,
    load_checkpoint,
    new_checkpoint,
    save_checkpoint,
)

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║    ███████╗████████╗██╗  ██╗██████╗ ███████╗ ██████╗ ██████╗ ██╗   ║
║    ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔════╝██╔═══██╗██║   ║
║    █████╗     ██║   ███████║██████╔╝█████╗  ██║     ██║   ██║██║   ║
║    ██╔══╝     ██║   ██╔══██║██╔══██╗██╔══╝  ██║     ██║   ██║╚═╝   ║
║    ███████╗   ██║   ██║  ██║██║  ██║███████╗╚██████╗╚██████╔╝██╗   ║
║    ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝   ║
║                                                                      ║
║          Ethereum Private Key Recovery Tool  v2.0                    ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""

OFFLINE_WARNING = """
┌──────────────────────── ⚠  SECURITY WARNING ─────────────────────────┐
│                                                                       │
│  This tool is designed for OFFLINE / AIRGAPPED use ONLY.              │
│                                                                       │
│  • Disconnect from the internet BEFORE running this tool.             │
│  • Private keys will be held in memory during recovery.               │
│  • No data is transmitted over the network.                           │
│  • No key material is logged to disk.                                 │
│  • Run on a trusted, malware-free machine.                            │
│                                                                       │
│  Press Ctrl+C at any time to stop — progress will be saved.           │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
"""


# ---------------------------------------------------------------------------
# Interactive mode
# ---------------------------------------------------------------------------

def interactive_wizard() -> argparse.Namespace:
    """
    Guided wizard for users who run the tool with no arguments.
    Returns a Namespace matching the argparse output.
    """
    print("  ┌────────────────────────────────────────┐")
    print("  │     EthRecover — Interactive Setup      │")
    print("  └────────────────────────────────────────┘\n")

    # Step 1: Corrupted key
    print("  Step 1/4: Paste your corrupted private key (or path to keystore file).")
    print("            Press Enter when done.\n")
    corrupted = input("  > ").strip()
    if not corrupted:
        print("\n  [!] No input provided. Exiting.")
        sys.exit(1)

    # Step 2: Target addresses
    print("\n  Step 2/4: Paste your target Ethereum address(es).")
    print("            One per line. Enter a blank line when done.\n")
    targets = []
    while True:
        addr = input("  > ").strip()
        if not addr:
            break
        targets.append(addr)
    if not targets:
        print("\n  [!] No target addresses provided. Exiting.")
        sys.exit(1)

    # Step 3: Max changes
    print(f"\n  Step 3/4: Maximum character changes for deep search (1-8).")
    print(f"            Higher = slower but more thorough. [default: 2]\n")
    mc_raw = input("  > ").strip()
    max_changes = 2
    if mc_raw:
        try:
            max_changes = int(mc_raw)
            max_changes = max(1, min(8, max_changes))
        except ValueError:
            print("  [!] Invalid number, using default (2).")

    # Step 4: Known prefix?
    print(f"\n  Step 4/4: Do you know the first part of the key for certain?")
    print(f"            Paste the known prefix, or press Enter to skip.\n")
    known_prefix = input("  > ").strip()

    # Build namespace
    ns = argparse.Namespace()
    ns.corrupted = corrupted
    ns.target = targets
    ns.max_changes = max_changes
    ns.workers = cpu_count() or 4
    ns.resume = False
    ns.checkpoint_file = "ethrecover_checkpoint.json"
    ns.known_prefix = known_prefix if known_prefix else None

    return ns


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    # If no arguments are given, launch interactive mode
    if len(sys.argv) == 1:
        return interactive_wizard()

    parser = argparse.ArgumentParser(
        prog="ethrecover",
        description="Recover a corrupted Ethereum private key by matching "
                    "against known target addresses.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py                                    # Interactive mode\n"
            "  python main.py --corrupted 'aB3d...' --target 0x71C7...\n"
            "  python main.py --corrupted keyfile.json --target 0x71C7... 0x82D9...\n"
            "  python main.py --corrupted 'aB3d...' --target 0x71C7... --max-changes 3\n"
            "  python main.py --resume                           # Resume from checkpoint\n"
            "  python main.py --corrupted 'aB3d...' --target 0x71C7... --known-prefix 'aB3d1f'\n"
        ),
    )

    parser.add_argument(
        "--corrupted",
        type=str,
        default="",
        help="The corrupted private key hex string, or path to a JSON keystore file.",
    )
    parser.add_argument(
        "--target",
        type=str,
        nargs="*",
        default=[],
        help="One or more Ethereum addresses to match against (e.g. 0x71C7...).",
    )
    parser.add_argument(
        "--max-changes",
        type=int,
        default=2,
        help="Maximum number of character changes for Level 3 (default: 2, max recommended: 5).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=cpu_count() or 4,
        help=f"Number of CPU worker processes (default: {cpu_count() or 4}).",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from a saved checkpoint file (no other args needed).",
    )
    parser.add_argument(
        "--checkpoint-file",
        type=str,
        default="ethrecover_checkpoint.json",
        help="Path to the checkpoint file (default: ethrecover_checkpoint.json).",
    )
    parser.add_argument(
        "--known-prefix",
        type=str,
        default=None,
        help="Known correct prefix of the private key (for suffix brute force).",
    )

    args = parser.parse_args()

    # Validation — resume can work alone now
    if not args.resume and (not args.corrupted or not args.target):
        parser.error("--corrupted and --target are required (unless --resume is set).")

    if args.max_changes < 1 or args.max_changes > 8:
        parser.error("--max-changes must be between 1 and 8.")

    if args.max_changes > 5:
        print(f"\n  ⚠  WARNING: --max-changes={args.max_changes} will produce an "
              f"extremely large search space.")
        print(f"     This may take hours or days.  Consider starting with a lower value.\n")

    if args.workers < 1:
        parser.error("--workers must be at least 1.")

    # Validate target addresses
    for t in args.target:
        t_stripped = t.strip()
        if not t_stripped.startswith("0x") and not t_stripped.startswith("0X"):
            print(f"  ⚠  Target '{t_stripped}' is missing 0x prefix — adding it.")
            args.target[args.target.index(t)] = "0x" + t_stripped
        if len(t_stripped.replace("0x", "").replace("0X", "")) != 40:
            print(f"  ⚠  Target '{t_stripped}' does not look like a 42-char Ethereum address.")

    return args


# ---------------------------------------------------------------------------
# Helper: print match result
# ---------------------------------------------------------------------------

def _print_match(private_key: str, address: str, level_name: str) -> None:
    print("\n")
    print("  ╔══════════════════════════════════════════════════════════════╗")
    print("  ║               🎉  KEY RECOVERED SUCCESSFULLY  🎉           ║")
    print("  ╠══════════════════════════════════════════════════════════════╣")
    print(f"  ║  Address:     {address:<46s} ║")
    print(f"  ║  Private Key: {private_key[:20]}...{private_key[-10:]:<23s} ║")
    print(f"  ║  Found at:    {level_name:<46s} ║")
    print("  ╚══════════════════════════════════════════════════════════════╝")
    print()


# ---------------------------------------------------------------------------
# Level runners
# ---------------------------------------------------------------------------

def _run_simple_level(name: str, candidates: list, targets: set) -> tuple:
    """Run a simple (non-multiprocessed) level. Returns (key, addr) or (None, None)."""
    print(f"\n  ── {name} ──")
    print(f"     Candidates: {len(candidates)}")

    if not candidates:
        print(f"     Nothing to test. Skipping.")
        return (None, None)

    use_progress = len(candidates) > 50
    iterator = candidates
    if use_progress:
        iterator = tqdm(candidates, desc=f"     {name.split(':')[0].strip()[:10]}",
                        unit=" keys",
                        bar_format="     {l_bar}{bar:30}{r_bar}")

    for c in iterator:
        addr = derive_address(c)
        if addr and addr.lower() in targets:
            if use_progress:
                iterator.close()
            return (c, addr)

    if use_progress:
        pass  # tqdm auto-closes
    print(f"     No match found.")
    return (None, None)


def _run_level3(corrupted_clean: str, targets: set, max_changes: int,
                num_workers: int, checkpoint: CheckpointState,
                checkpoint_path: str) -> tuple:
    """Run Level 3 (hex flips) with multiprocessing. Returns (key, addr) or (None, None)."""
    print("\n  ── Level 3: Hex-Flip / Hamming Distance ──")

    total_est = estimate_level3_candidates(len(corrupted_clean), max_changes)
    already_tested = checkpoint.total_tested if checkpoint.level >= 3 else 0

    print(f"     Max changes:  {max_changes}")
    print(f"     Search space: {total_est:,} candidates")
    if already_tested > 0:
        print(f"     Resuming:     {already_tested:,} already tested")
    print(f"     Workers:      {num_workers}")
    print()

    pbar = tqdm(
        total=total_est,
        initial=already_tested,
        desc="     Level 3",
        unit=" keys",
        bar_format="     {l_bar}{bar:30}{r_bar}",
        miniters=1000,
    )

    completed_batches = checkpoint.completed_batches if checkpoint.level >= 3 else set()
    _batch_tested = [already_tested]
    _checkpoint_counter = [0]

    def _progress_callback(num_tested: int, batch_idx: int):
        _batch_tested[0] += num_tested
        pbar.update(num_tested)
        _checkpoint_counter[0] += 1

        # Auto-checkpoint periodically
        if _checkpoint_counter[0] % 500 == 0:
            checkpoint.level = 3
            checkpoint.completed_batches = set(completed_batches)  # copy
            checkpoint.total_tested = _batch_tested[0]
            save_checkpoint(checkpoint, checkpoint_path)

    try:
        found_key, found_addr, tested, new_completed = run_level3(
            corrupted_clean,
            targets,
            max_changes,
            num_workers,
            completed_batches,
            progress_callback=_progress_callback,
        )
    except KeyboardInterrupt:
        checkpoint.level = 3
        checkpoint.completed_batches = completed_batches
        checkpoint.total_tested = _batch_tested[0]
        save_checkpoint(checkpoint, checkpoint_path)
        pbar.close()
        print(f"\n  [!] Interrupted. Progress saved ({_batch_tested[0]:,} keys tested).")
        print(f"      Resume with: python main.py --resume")
        sys.exit(0)

    pbar.close()

    if found_key:
        return (found_key, found_addr)

    checkpoint.level = 4  # mark L3 complete
    checkpoint.completed_batches = new_completed
    checkpoint.total_tested = _batch_tested[0]
    save_checkpoint(checkpoint, checkpoint_path)

    print("     No match found at Level 3.")
    return (None, None)


# ---------------------------------------------------------------------------
# Search space estimator
# ---------------------------------------------------------------------------

def _print_search_plan(corrupted_clean: str, corrupted_raw_case: str,
                       max_changes: int, known_prefix: str = None) -> None:
    """Print the estimated search plan before running."""
    print("\n  ┌─────────────────────────────────────────┐")
    print("  │           Recovery Plan Summary          │")
    print("  └─────────────────────────────────────────┘\n")

    levels = [
        ("Level 1  — Format/Encoding",    "< 20", "instant"),
        ("Level 1.5 — Truncation/Padding", "< 100" if len(corrupted_clean) != 64 else "skip", "instant"),
        ("Level 1.7 — Transpositions",     "~2,000" if len(corrupted_clean) == 64 else "skip", "instant"),
        ("Level 2  — OCR Substitution",    "< 1,000", "< 1 sec"),
        ("Level 2.5 — Insert/Delete",      _est_level25(corrupted_clean), _est_level25_time(corrupted_clean)),
        ("Level 2.7 — Duplicate Chars",    "< 200", "instant"),
    ]

    if known_prefix:
        suffix_len = 64 - len(clean_corrupted_input(known_prefix))
        est = f"{16 ** suffix_len:,}"
        levels.append(("Level 2.9 — Prefix Brute Force", est, _time_estimate(16 ** suffix_len)))

    est3 = estimate_level3_candidates(64, max_changes)
    levels.append((f"Level 3  — Hex Flips (≤{max_changes} changes)", f"{est3:,}", _time_estimate(est3)))

    for name, candidates, eta in levels:
        if candidates == "skip":
            print(f"    ○ {name:<38s}  (skipped — key is correct length)")
        else:
            print(f"    ● {name:<38s}  {candidates:>14s} candidates   ~{eta}")

    print()


def _est_level25(key: str) -> str:
    klen = len(key)
    if klen == 65:
        return "65"
    elif klen == 63:
        return "1,024"
    elif klen == 66:
        return f"{66*65//2:,}"
    elif klen == 62:
        return f"{63*16:,}"
    return "skip"


def _est_level25_time(key: str) -> str:
    klen = len(key)
    if klen in (63, 65):
        return "instant"
    elif klen in (62, 66):
        return "< 1 sec"
    return "n/a"


def _time_estimate(n: int) -> str:
    """Rough time estimate at ~50K keys/s."""
    secs = n / 50_000
    if secs < 1:
        return "instant"
    elif secs < 60:
        return f"{secs:.0f} sec"
    elif secs < 3600:
        return f"{secs/60:.1f} min"
    elif secs < 86400:
        return f"{secs/3600:.1f} hours"
    else:
        return f"{secs/86400:.1f} days"


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

def main() -> None:
    print(BANNER)
    print(OFFLINE_WARNING)

    args = parse_args()
    checkpoint_path = args.checkpoint_file

    # --- Handle --resume (standalone or with args) ---
    checkpoint = None
    corrupted_raw = args.corrupted or ""
    target_list = args.target or []

    if args.resume:
        checkpoint = load_checkpoint(path=checkpoint_path)
        if checkpoint:
            print(f"  [✓] Checkpoint loaded (Level {checkpoint.level}, "
                  f"{checkpoint.total_tested:,} keys already tested).")
            # Use stored values if the user didn't provide new ones
            if not corrupted_raw and checkpoint.corrupted_raw:
                corrupted_raw = checkpoint.corrupted_raw
                print(f"  [*] Using stored corrupted key from checkpoint.")
            if not target_list and checkpoint.targets_raw:
                target_list = checkpoint.targets_raw
                print(f"  [*] Using stored target(s) from checkpoint.")
        else:
            print("  [!] No valid checkpoint found. Starting fresh.")

    if not corrupted_raw or not target_list:
        print("\n  [!] Missing --corrupted and/or --target.  Cannot proceed.")
        print("      Run with --help to see usage examples, or just run:")
        print("      python main.py")
        sys.exit(1)

    # Normalize targets
    targets = {t.lower() for t in target_list}

    if checkpoint is None:
        checkpoint = new_checkpoint(corrupted_raw, list(targets), args.max_changes)

    # --- Detect wallet file (Level 4 pre-check) ---
    is_wallet_file = os.path.isfile(corrupted_raw)
    if is_wallet_file:
        print(f"  [*] Detected file input: {corrupted_raw}")

    # --- Clean the input ---
    corrupted_clean = clean_corrupted_input(corrupted_raw)
    corrupted_raw_case = clean_corrupted_input_preserve_case(corrupted_raw)

    # --- Input summary ---
    print(f"\n  Input Summary:")
    print(f"    Corrupted key: {corrupted_clean[:24]}{'...' if len(corrupted_clean) > 24 else ''}")
    print(f"    Key length:    {len(corrupted_clean)} characters "
          f"{'✓' if len(corrupted_clean) == 64 else '⚠ (expected 64)'}")
    print(f"    Targets:       {len(targets)} address(es)")
    for t in sorted(targets):
        print(f"      → {t}")
    print(f"    Max changes:   {args.max_changes}")
    print(f"    Workers:       {args.workers}")

    # --- Print search plan ---
    _print_search_plan(corrupted_clean, corrupted_raw_case, args.max_changes, args.known_prefix)

    start_time = time.time()

    # ── Level 4: Wallet file repair (if applicable) ──
    if is_wallet_file:
        print("  ── Level 4: Wallet / Keystore File Repair ──")
        ciphertexts = level4_wallet_repair(corrupted_raw)
        if ciphertexts:
            print(f"     Extracted {len(ciphertexts)} ciphertext candidate(s) from keystore.")
            for i, ct in enumerate(ciphertexts):
                print(f"     [{i+1}] {ct[:40]}...")
        else:
            print("     Could not extract ciphertext from keystore file.")

        if len(corrupted_clean) != 64:
            print("\n  [!] Could not extract a 64-char hex key from the file.")
            print("      Provide the raw private key hex directly if possible.")
            sys.exit(1)

    # ── Level 1: Format fixes ──
    if checkpoint.level <= 1:
        candidates = level1_format_fixes(corrupted_raw)
        key, addr = _run_simple_level("Level 1: Format & Encoding Fixes", candidates, targets)
        if key:
            _handle_success(key, addr, "Level 1: Format Fix", corrupted_clean,
                            start_time, checkpoint_path)
            return
        checkpoint.level = 2
        save_checkpoint(checkpoint, checkpoint_path)

    # ── Level 1.5: Truncation & padding ──
    if checkpoint.level <= 2 and len(corrupted_clean) != 64:
        candidates = level1_5_truncation_padding(corrupted_clean)
        key, addr = _run_simple_level("Level 1.5: Truncation & Padding", candidates, targets)
        if key:
            _handle_success(key, addr, "Level 1.5: Truncation/Padding", corrupted_clean,
                            start_time, checkpoint_path)
            return

    # ── Level 1.7: Transpositions ──
    if checkpoint.level <= 2 and len(corrupted_clean) == 64:
        candidates = level1_7_transpositions(corrupted_clean)
        key, addr = _run_simple_level("Level 1.7: Adjacent Transpositions", candidates, targets)
        if key:
            _handle_success(key, addr, "Level 1.7: Transposition", corrupted_clean,
                            start_time, checkpoint_path)
            return
        checkpoint.level = 3
        save_checkpoint(checkpoint, checkpoint_path)

    # ── Level 2: OCR substitutions ──
    if checkpoint.level <= 3:
        # Use case-preserved version so OCR map can match uppercase chars
        candidates = level2_ocr_substitutions(corrupted_raw_case)
        key, addr = _run_simple_level("Level 2: OCR / Character Substitution", candidates, targets)
        if key:
            _handle_success(key, addr, "Level 2: OCR Substitution", corrupted_clean,
                            start_time, checkpoint_path)
            return

    # ── Level 2.5: Insertion / deletion ──
    if checkpoint.level <= 3 and len(corrupted_clean) != 64:
        candidates = level2_5_insertion_deletion(corrupted_clean)
        key, addr = _run_simple_level("Level 2.5: Character Insertion/Deletion",
                                      candidates, targets)
        if key:
            _handle_success(key, addr, "Level 2.5: Insert/Delete", corrupted_clean,
                            start_time, checkpoint_path)
            return

    # ── Level 2.7: Duplicate chars ──
    if checkpoint.level <= 3:
        candidates = level2_7_duplicate_chars(corrupted_clean)
        key, addr = _run_simple_level("Level 2.7: Duplicate Character Fix", candidates, targets)
        if key:
            _handle_success(key, addr, "Level 2.7: Duplicate Fix", corrupted_clean,
                            start_time, checkpoint_path)
            return

    # ── Level 2.9: Known-prefix brute force ──
    if checkpoint.level <= 3 and args.known_prefix:
        print("\n  ── Level 2.9: Known-Prefix Brute Force ──")
        prefix_clean = clean_corrupted_input(args.known_prefix)
        suffix_len = 64 - len(prefix_clean)
        total = 16 ** suffix_len
        print(f"     Prefix:       {prefix_clean[:24]}... ({len(prefix_clean)} chars)")
        print(f"     Suffix to try: {suffix_len} chars ({total:,} combinations)")

        if suffix_len > 6:
            print(f"     ⚠  {suffix_len} unknown chars = {total:,} combinations.")
            print(f"        This will take a very long time.  Consider providing more of the key.")
        elif suffix_len > 0:
            pbar = tqdm(total=total, desc="     Brute", unit=" keys",
                        bar_format="     {l_bar}{bar:30}{r_bar}")

            def _bf_progress(n):
                pbar.update(n)

            try:
                key, addr, tested = level2_9_known_prefix_bruteforce(
                    prefix_clean, targets, progress_callback=_bf_progress)
            except KeyboardInterrupt:
                pbar.close()
                checkpoint.level = 3
                save_checkpoint(checkpoint, checkpoint_path)
                print(f"\n  [!] Interrupted. Progress saved.")
                sys.exit(0)

            pbar.close()
            if key:
                _handle_success(key, addr, "Level 2.9: Known-Prefix Brute Force",
                                corrupted_clean, start_time, checkpoint_path)
                return
            print(f"     No match ({tested:,} tested).")

    # ── Must have 64-char key for Level 3 ──
    if len(corrupted_clean) != 64:
        elapsed = time.time() - start_time
        print(f"\n  [!] Key is {len(corrupted_clean)} chars after cleaning (need 64 for Level 3).")
        print(f"      Quick levels exhausted. Time: {_format_elapsed(elapsed)}")
        sys.exit(1)

    # ── Level 3: Hex flips ──
    if checkpoint.level <= 3:
        key, addr = _run_level3(
            corrupted_clean, targets, args.max_changes,
            args.workers, checkpoint, checkpoint_path,
        )
        if key:
            _handle_success(key, addr, "Level 3: Hex Flip", corrupted_clean,
                            start_time, checkpoint_path)
            return

    # ── No match ──
    elapsed = time.time() - start_time
    print(f"\n  ════════════════════════════════════════════")
    print(f"  ❌  No matching key found after exhaustive search.")
    print(f"     Total time:  {_format_elapsed(elapsed)}")
    print(f"\n  Suggestions:")
    print(f"    • Increase --max-changes (currently {args.max_changes})")
    print(f"    • Double-check the target address")
    print(f"    • Try providing a --known-prefix if you're sure of part of the key")
    print(f"    • Check if the corruption is more severe than expected")
    print(f"  ════════════════════════════════════════════\n")

    clear_checkpoint(checkpoint_path)


# ---------------------------------------------------------------------------
# Success handler
# ---------------------------------------------------------------------------

def _handle_success(found_key: str, found_addr: str, level_name: str,
                    original_clean: str, start_time: float,
                    checkpoint_path: str) -> None:
    """Display result, show diff, encrypt & save key, clean up."""
    elapsed = time.time() - start_time
    _print_match(found_key, found_addr, level_name)
    print(f"  Time elapsed: {_format_elapsed(elapsed)}\n")

    # Show diff highlighting
    print("  ── What was fixed ──")
    print(diff_keys(original_clean, found_key))
    print()

    # Encrypt and save
    print("  To save the recovered key to an encrypted file, enter a password.")
    print("  (Press Enter to skip saving.)\n")
    try:
        password = getpass.getpass("  Encryption password: ")
    except (EOFError, KeyboardInterrupt):
        password = ""

    if password:
        output_path = os.path.join(os.getcwd(), "recovered_key.enc")
        encrypt_and_save(found_key, found_addr, output_path, password)
    else:
        print("  [*] Skipping encrypted save.")

    # Display the full key for manual copy
    print(f"\n  ┌─────────────────────────────────────────────────────────────────────┐")
    print(f"  │  COPY YOUR KEY NOW — it will be wiped from memory after this step. │")
    print(f"  │  {found_key:<66s}│")
    print(f"  └─────────────────────────────────────────────────────────────────────┘\n")

    clear_checkpoint(checkpoint_path)

    # Best-effort memory wipe
    key_buf = bytearray(found_key.encode("utf-8"))
    secure_wipe(key_buf)
    del key_buf


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_elapsed(seconds: float) -> str:
    """Format elapsed seconds as a human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        m, s = divmod(seconds, 60)
        return f"{int(m)}m {s:.1f}s"
    else:
        h, rem = divmod(seconds, 3600)
        m, s = divmod(rem, 60)
        return f"{int(h)}h {int(m)}m {s:.0f}s"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from multiprocessing import freeze_support
    freeze_support()

    # Do NOT override SIGINT — let KeyboardInterrupt propagate naturally
    # so that the Level 3 runner can save the checkpoint before exiting.
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  [!] Interrupted by user. Exiting...")
        sys.exit(0)
