# EthRecover - Instructions

EthRecover is a powerful offline tool designed to recover corrupted Ethereum private keys by systematically generating permutations and verifying them against a known target Ethereum address. 

## 🔒 Security First: Offline Usage
**This tool is built for offline/airgapped environments.** Given the sensitive nature of private keys:
1. Download or clone this repository to a secure machine.
2. **Disconnect the machine from the internet entirely.**
3. Run the recovery process.
4. Wipe the machine's memory or restart it after you have successfully recovered your key.
5. EthRecover does not make any network calls or save unencrypted sensitive data to the disk.

---

## 🚀 Easy Quick Run (Windows)
For standard Windows users, the easiest way to run EthRecover is by utilizing the built-in batch script:

1. Double click the **`run.bat`** file.
2. The script will automatically:
   - Check your Python installation.
   - Create an isolated virtual environment (`.venv`).
   - Install all required dependencies from `requirements.txt`.
   - Launch the **Interactive Wizard**.
3. Follow the on-screen prompts to paste your corrupted private key and target Ethereum address.

---

## 🛠 Advanced Command Line Usage (Cross-Platform)

If you prefer using the command line manually, open your terminal (Command Prompt, PowerShell, bash, etc.) and follow these steps:

### 1. Setup Environment
First, create your virtual environment and install the requirements:
```bash
python -m venv .venv

# On Windows:
.venv\Scripts\activate
# On Linux / macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Run the Tool
You can invoke `main.py` with custom arguments for more targeted recoveries.

**Interactive Mode:**
```bash
python main.py
```

**Direct Mode:**
Provide the corrupted key and target address directly:
```bash
python main.py --corrupted "your_corrupted_key_here" --target "0xYourEthereumAddressHere"
```
*(You can also pass a path to a corrupted `.json` keystore file to `--corrupted`)*

**Change Maximum Search Depth (Level 3):**
The hex-flip brute force level checks permutations. A higher number checks deeper but drastically increases search time. Maximum recommended is `5`.
```bash
python main.py --corrupted "key" --target "0xAddress" --max-changes 3
```

**Brute Force with Known Prefix (Level 2.9):**
If you know for a fact that the first few characters of your corrupted key are 100% correct, you can supply them. The tool will brute force the final missing characters.
```bash
python main.py --corrupted "key" --target "0xAddress" --known-prefix "aB3d1f"
```

**Resume from a Checkpoint:**
If you closed the application mid-run (like during a long Level 3 search), EthRecover saves your progress to a `ethrecover_checkpoint.json` file. You can resume exactly where it left off:
```bash
python main.py --resume
```

---

## 🧠 Recovery Levels Explained

EthRecover operates in tiers, progressing from instant format fixes to heavy computational brute-forcing:
*   **Level 1 & 1.5:** Quickly fixes padding, formatting, trailing spaces, and `0x`/`\x` prefixes.
*   **Level 1.7:** Swaps adjacent characters to fix "fat-finger" typos. 
*   **Level 2:** Substitutes visually ambiguous characters often caused by OCR apps or copying errors (e.g. `0` vs `O`, `1` vs `l`).
*   **Level 2.5 & 2.7:** Inserts/Deletes single missing or duplicate characters.
*   **Level 2.9:** Prefix brute forcing (Optional).
*   **Level 3:** Full Hex-Flip Hamming distance checking using your machine's multiprocessing power.
*   **Level 4:** Extracts target ciphertext hashes from `.json` keystore files for raw checking.

## 💾 Saving the Recovered Key
Once EthRecover finds a match, it will present the correct private key in the console terminal. You will also be prompted to save it securely to an encrypted file (`recovered_key.enc`). You will need to provide an encryption password to save it.
