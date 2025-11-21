


# 🔱 PassPloit: Metasploit-Style Password Analysis Framework

![PassPloit Logo - A Metasploit-inspired console with security icons]
(Note: Replace this with an actual screenshot or logo image link)

**PassPloit** is a Python-based, command-line utility designed as a conceptual framework for simulating and analyzing password security. Inspired by the command structure and interface of Metasploit, this tool allows security professionals and students to assess password strength, simulate hash cracking scenarios, and practice with basic encryption/decryption techniques.

⚠️ **DISCLAIMER:** This tool is created for **educational purposes only** (e.g., learning about password hashing, key strength, and cryptographic concepts). Use it responsibly and ethically. The author is not responsible for any misuse.

---

## ✨ Features

PassPloit uses a familiar module-based architecture, categorized primarily under **auxiliary** modules for security analysis.

| Module Category | Path | Description |
| :--- | :--- | :--- |
| **Analysis** | `auxiliary/analyze/password_strength` | Calculates password length, character types, keyspace size, and provides detailed estimates for online, offline, and massive brute-force crack times (using realistic modern attack rates). |
| **Cracking** | `auxiliary/crack/hash` | Simulates a dictionary attack against MD5, SHA1, and SHA256 hashes using a user-provided wordlist. Features a progress bar for a realistic experience. |
| **Encryption** | `auxiliary/encrypt/encrypt` | Encrypts text using various algorithms (AES-256-CBC, Caesar Cipher, Base64, and RSA). |
| **Decryption** | `auxiliary/encrypt/decrypt` | Decrypts text using the corresponding algorithm, requiring necessary keys, passwords, or salts. |
| **Key Management** | `auxiliary/encrypt/key_manager` | Generates RSA key pairs (Public/Private) and offers easy clipboard copy functionality. |

---

## 🛠️ Installation

PassPloit requires **Python 3.x** and a few standard libraries.

### 1. Clone the Repository


git clone [https://github.com/YourUsername/PassPloit.git](https://github.com/YourUsername/PassPloit.git)
cd PassPloit


### 2\. Install Dependencies

You will need the `cryptography` library for AES/RSA and `pyperclip` for key copying.


# Using the requirements file (Recommended)
pip install -r requirements.txt

# Manually installing
pip install pyperclip cryptography


### 3\. Setup Wordlist (Optional but Recommended)

For the `auxiliary/crack/hash` module to work effectively, you need a wordlist file named **`wordlist.txt`** in the same directory. You can download common wordlists like `rockyou.txt` and place it here, or use a small custom list for testing.

-----

## 🚀 Usage Guide (Metasploit Style)

Run the console using the following command:

```bash
python pspconsole.py
```

### Basic Commands

| Command | Purpose |
| :--- | :--- |
| `use <module_path>` | Select a specific module for use. |
| `show options` | Display the required and optional settings for the current module. |
| `set <OPTION> <value>` | Assign a value to a module option. |
| `run` or `exploit` | Execute the selected module. |
| `back` | Exit the current module context. |
| `help` | Display the full list of console commands. |

### Example 1: Password Strength Analysis

Let's check the security of a weak password.

```bash
passploit > use auxiliary/analyze/password_strength
passploit (auxiliary/analyze/password_strength) > set PASSWORD password123
[*] PASSWORD => password123
passploit (auxiliary/analyze/password_strength) > run

# ... Output will show:
# Strength Category: Weak
# Time to Crack (Offline Attack): Seconds to Minutes (Likely found in a common wordlist or via simple rules.)
# 🚨 ACTION REQUIRED: This password is NOT SAFE and can be cracked quickly! Use a new one.
```

### Example 2: Simulating Hash Cracking

We will try to crack the SHA256 hash of a common word.

```bash
passploit > use auxiliary/crack/hash
passploit (auxiliary/crack/hash) > show options

Module options (HashCracker):
  Name               Current Setting       Required    Description
  ----               ---------------       --------    -----------
  HASH                                     yes         Hash to crack
  WORDLIST           wordlist.txt          no          Wordlist file path

passploit (auxiliary/crack/hash) > set HASH 5baa61e4c9b93f3f0682250b6910606d288d6c1b  # This is SHA1 of 'password'
passploit (auxiliary/crack/hash) > run

# ... Output will show:
# [+] Hash Successfully Cracked!
# [*] Plaintext: **password**
# [*] Hash Type: SHA1
```

-----

## 🔐 Cryptography Simulation

PassPloit includes modules to demonstrate modern and classic encryption schemes:

### Example: Generating RSA Keys

The `key_manager` module generates the public/private key pair needed for the RSA encryption module.

```bash
passploit > use auxiliary/encrypt/key_manager
passploit (auxiliary/encrypt/key_manager) > run

# ... Output will show:
# --- PUBLIC KEY ---
# -----BEGIN PUBLIC KEY-----
# MIIBIjANBg...
# --- PRIVATE KEY ---
# -----BEGIN PRIVATE KEY-----
# MIIEvAIBAD...
```

-----

## 📝 License

This project is licensed under the **MIT License** - see the `LICENSE` file for details.

## 🤝 Contribution

Contributions are welcome\! If you find a bug or have a suggestion for a new module (e.g., a simulation for salting or other hashing algorithms), please open an issue or submit a pull request.

-----

Created with ❤️ by **Aegis Dynamics** (Muhammad Hamza/Handle)

```
