# PassPloit-Metasploit-Style.py
import string
import time
import math
import hashlib
import sys
import os
import random
import base64
import re
import platform
import subprocess
import json
import pyperclip  # For clipboard functionality
from typing import List, Optional, Tuple, Dict
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# --- Configuration & Realistic Simulation Parameters ---

# Supported hash algorithms for the simulation and cracking
SUPPORTED_ALGORITHMS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
}
HASH_TYPES = { # For cracking hash length detection
    32: 'md5',
    40: 'sha1',
    64: 'sha256'
}
WORDLIST_FILE = "wordlist.txt"
BAR_LENGTH = 100 # Progress bar length
HISTORY_FILE = "passploit_history.json" # File to store command history

# *** CHANGE 1: More Realistic Cracking Speeds ***
# Ye values ab zyada realistic hain, ek powerful attacker ke liye.
OFFLINE_ATTACK_RATE = {
    "md5": 50_000_000,      # 50 million/sec (high-end GPU)
    "sha1": 30_000_000,     # 30 million/sec
    "sha256": 10_000_000,   # 10 million/sec
}

# Character sets defined for complexity calculation
CHARSETS = {
    "lower": string.ascii_lowercase,  
    "upper": string.ascii_uppercase,  
    "digits": string.digits,          
    "symbols": string.punctuation,    
}

# ANSI Color Codes - Metasploit Style
ColorReset  = "\033[0m"
ColorRed    = "\033[91m"
ColorGreen  = "\033[92m" 
ColorYellow = "\033[93m" 
ColorBlue   = "\033[94m"
ColorCyan   = "\033[96m"
ColorOrange = "\033[33m"
ColorWhite  = "\033[97m"
ColorDim    = "\033[2m"
ColorBold   = "\033[1m"

# --- PassPloit Logo Definition ---

PASSPLOIT_LOGO = r"""  
|     ________                                  _______    ___                    ___
     /   ___  \                                /   ___  \ /  /           __      /  /  
    /  /___/  / __________  _______  _______  /  /___/  //  / _________ /__/    /  /
   /  ______ //  _____   //  _____//  _____/ /  ______ //  / /   ___   /__  ___/  /__
  /  /       /  /     /  /\______  \______  /  /       /  / /  /   /  //  //__   __ /
 /  /       \  \_____/  / ____  \  ____  \ /  /       /  /__\  \___\  \/  /  /  /___
/__/         \ _____/\_//_______//_______//__/       /______/\_______//__/   \____ /                                                                                                      
>> PASSPLOIT << [SYSTEM READY]
---------------------------------------------
                          Build by: Aegis Dynamics
"""

# --- Dangerous Art Drawings ---
DANGEROUS_ARTS = [
r"""
    ⚠️  WARNING: SYSTEM BREACH DETECTED  ⚠️
    
    ╔════════════════════════════════════════╗
    ║                                        ║
    ║  UNAUTHORIZED ACCESS PROTOCOL ACTIVE   ║
    ║                                        ║
    ╚════════════════════════════════════════╝
""",
r"""
    ☠️  CYBER THREAT IMMINENT  ☠️
    
    ╔════════════════════════════════════════╗
    ║                                        ║
    ║    ENCRYPTION BYPASS INITIATED         ║
    ║                                        ║
    ╚════════════════════════════════════════╝
""",
r"""
    🔥 FIREWALL COMPROMISED 🔥
    
    ╔════════════════════════════════════════╗
    ║                                        ║
    ║   INTRUSION DETECTION SYSTEM OFFLINE   ║
    ║                                        ║
    ╚════════════════════════════════════════╝
""",
r"""
    💀 DATA EXFILTRATION IN PROGRESS 💀
    
    ╔════════════════════════════════════════╗
    ║                                        ║
    ║     SECURITY PROTOCOLS DISABLED        ║
    ║                                        ║
    ╚════════════════════════════════════════╝
""",
r"""
    ⚡ KERNEL EXPLOIT LOADED ⚡
    
    ╔════════════════════════════════════════╗
    ║                                        ║
    ║    ROOT ACCESS OBTAINED                 ║
    ║                                        ║
    ╚════════════════════════════════════════╝
"""
]

# --- Metasploit Style Loading Animation ---

def metasploit_loading():
    """Metasploit"""
    loading_messages = [
        "Loading core modules...",
        "Loading auxiliary modules...",
        "Loading exploit modules...",
        "Loading post-exploitation modules...",
        "Loading payload modules...",
        "Loading encoder modules...",
        "Loading plugin modules...",
        "Loading database plugins...",
        "Loading encryption modules...",
        "Loading asymmetric crypto modules...",
    ]
    
    print(f"{ColorDim}", end="")
    for message in loading_messages:
        print(f"\r[*] {message}", end="", flush=True)
        time.sleep(0.2)
        for _ in range(3):
            sys.stdout.write(".")
            sys.stdout.flush()
            time.sleep(0.1)
        print("\r" + " " * 60 + "\r", end="", flush=True)
    
    print(f"{ColorGreen}[+]{ColorReset} PassPloit console initialized\n")

# ----------------------------------------------------
#               Hash Cracking Functions
# ----------------------------------------------------

def get_wordlist_size(filepath):
    """Calculates the total number of lines (words) in the wordlist file."""
    try:
        with open(filepath, 'r', encoding='latin-1') as f:
            return sum(1 for line in f)
    except FileNotFoundError:
        return 0

def update_progress_bar(progress, total_words):
    """Prints the custom loading bar on a single line."""
    percent = (progress / total_words)
    filled_len = int(BAR_LENGTH * percent)
    bar = '=' * filled_len + ' ' * (BAR_LENGTH - filled_len)
    
    sys.stdout.write(f"\r[*] |{bar}| {int(percent * 100):3d}%")
    sys.stdout.flush()

def crack_hash_mode(target_hash, hash_type):
    """Core function to crack a hash using wordlist with progress bar."""
    
    if not os.path.exists(WORDLIST_FILE):
        return f"\n{ColorRed}[-]{ColorReset} Error: Wordlist file '{WORDLIST_FILE}' not found. Ensure the file is in the same folder."

    total_words = get_wordlist_size(WORDLIST_FILE)
    if total_words == 0:
        return f"\n{ColorRed}[-]{ColorReset} Error: Wordlist is empty or an error occurred while counting lines."
    
    print(f"\n{ColorGreen}[+]{ColorReset} Starting crack: Hash Type = {hash_type.upper()}")
    
    try:
        update_progress_bar(0, total_words)
        
        update_frequency = total_words // BAR_LENGTH
        if update_frequency == 0:
            update_frequency = 1

        with open(WORDLIST_FILE, 'r', encoding='latin-1') as f:
            for i, line in enumerate(f):
                word = line.strip()
                encoded_word = word.encode('utf-8')
                
                hasher_func = SUPPORTED_ALGORITHMS.get(hash_type)
                if not hasher_func:
                     return f"{ColorRed}[-]{ColorReset} Error: Hash type '{hash_type}' is not supported."
                     
                calculated_hash = hasher_func(encoded_word).hexdigest()

                if calculated_hash == target_hash:
                    # HASH CRACKED: Clear the progress bar line
                    sys.stdout.write('\r' + ' ' * (BAR_LENGTH + 10) + '\r')
                    sys.stdout.flush()
                    return f"\n{ColorGreen}[+]{ColorReset} Hash Successfully Cracked!\n{ColorCyan}[*]{ColorReset} Plaintext: **{word}**\n{ColorCyan}[*]{ColorReset} Hash Type: {hash_type.upper()}"
                
                if (i + 1) % update_frequency == 0 or i == total_words - 1:
                    update_progress_bar(i + 1, total_words)

        # HASH FAILED: Clear the progress bar line which is currently showing 100%
        sys.stdout.write('\r' + ' ' * (BAR_LENGTH + 10) + '\r')
        sys.stdout.flush()
        return f"\n{ColorRed}[-]{ColorReset} Sorry, Plaintext was not found in the wordlist."

    except Exception as e:
        # ERROR: Clear the progress bar line
        sys.stdout.write('\r' + ' ' * (BAR_LENGTH + 10) + '\r')
        sys.stdout.flush()
        return f"\n{ColorRed}[-]{ColorReset} An unexpected error occurred during cracking: {e}"

# ----------------------------------------------------
#               PassPloit Core Functions
# ----------------------------------------------------

def save_to_wordlist(password: str, filename: str = "wordlist.txt"):
    """Saves the plaintext password to the wordlist file silently."""
    try:
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(password + '\n')
    except Exception as e:
        print(f"\n{ColorRed}[ERROR]{ColorReset} Could not save password to wordlist: {e}")

def get_password_stats(password: str, algo_name: str) -> dict:
    stats = {
        "length": len(password),
        "has_lower": any(c in CHARSETS["lower"] for c in password),
        "has_upper": any(c in CHARSETS["upper"] for c in password),
        "has_digits": any(c in CHARSETS["digits"] for c in password),
        "has_symbols": any(c in CHARSETS["symbols"] for c in password),
    }
    
    stats["keyspace_size"] = sum([
        len(CHARSETS["lower"]) if stats["has_lower"] else 0,
        len(CHARSETS["upper"]) if stats["has_upper"] else 0,
        len(CHARSETS["digits"]) if stats["has_digits"] else 0,
        len(CHARSETS["symbols"]) if stats["has_symbols"] else 0,
    ])
    
    stats["unique_types"] = sum([stats["has_lower"], stats["has_upper"], stats["has_digits"], stats["has_symbols"]])
    
    try:
        hasher = SUPPORTED_ALGORITHMS[algo_name]()
        hasher.update(password.encode('utf-8'))
        stats["simulated_hash"] = hasher.hexdigest()
    except Exception:
        stats["simulated_hash"] = "Error generating hash."

    return stats

def get_strength_category(stats: dict) -> Tuple[str, str]:
    length = stats["length"]
    unique_types = stats["unique_types"]
    category = "Weak"
    color = ColorRed 
    if length >= 8 and unique_types >= 2:
        category = "Medium"
        color = ColorYellow
    if length >= 12 and unique_types >= 3:
        category = "Good"
        color = ColorBlue
    if length >= 16 and unique_types == 4:
        category = "Excellent"
        color = ColorGreen
    return color + category + ColorReset, category

# *** CHANGE 2: Improved and New Time Calculation Functions ***
# Yahan par maine time calculation ko improve kiya aur nayi functions add kiye hain.

def calculate_time_to_crack(stats: dict, category: str, algo_name: str) -> str:
    """Calculate time to crack for a standard offline attack."""
    # Realistic attack speed for a single dedicated machine
    attack_rate = OFFLINE_ATTACK_RATE.get(algo_name, OFFLINE_ATTACK_RATE["sha256"])
    
    # For weak passwords, it's likely in a wordlist, so it's very fast.
    if category in ["Weak", "Medium"] and stats["length"] <= 8:
        return ColorRed + "Seconds to Minutes" + ColorReset + " (Likely found in a common wordlist or via simple rules.)"

    keyspace = stats["keyspace_size"]
    length = stats["length"]
    
    if keyspace == 0:
        return "Not Calculable"
        
    try:
        # Average time to crack is trying half of all combinations
        total_attempts = keyspace ** length
    except OverflowError:
        return "Over 1000 Years"

    crack_time_seconds = (total_attempts / 2) / attack_rate
    
    # If it's an excellent password and would take centuries, say it's practically impossible.
    if category == "Excellent" and crack_time_seconds > 3153600000: # 100 years
        return ColorGreen + "Practically Impossible" + ColorReset + " (Requires centuries with current technology)"

    # Convert seconds to a more readable format
    if crack_time_seconds < 60:
        return f"{crack_time_seconds:.2f} seconds"
    elif crack_time_seconds < 3600:
        return f"{crack_time_seconds / 60:.2f} minutes"
    elif crack_time_seconds < 86400:
        return f"{crack_time_seconds / 3600:.2f} hours"
    elif crack_time_seconds < 31536000:
        return f"{crack_time_seconds / 86400:.2f} days"
    elif crack_time_seconds < 3153600000: # 100 years
        years = crack_time_seconds / 31536000
        return f"Approx. {years:.2f} years"
    else:
        return "Over 100 Years"

def calculate_online_attack_time(stats: dict, category: str) -> str:
    """Calculate time for an online attack (e.g., on a website login)."""
    # Online attacks are heavily rate-limited, maybe 10 tries per second max.
    attack_rate = 10 
    
    keyspace = stats["keyspace_size"]
    length = stats["length"]
    
    if keyspace == 0:
        return "Not Calculable"
        
    try:
        total_attempts = keyspace ** length
    except OverflowError:
        return "Millions of Years"
    
    crack_time_seconds = (total_attempts / 2) / attack_rate
    
    if crack_time_seconds < 60:
        return f"{crack_time_seconds:.2f} seconds"
    elif crack_time_seconds < 3600:
        return f"{crack_time_seconds / 60:.2f} minutes"
    elif crack_time_seconds < 86400:
        return f"{crack_time_seconds / 3600:.2f} hours"
    elif crack_time_seconds < 2592000:  # 30 days
        return f"{crack_time_seconds / 86400:.2f} days"
    else:
        months = crack_time_seconds / 2592000
        return f"Approx. {months:.2f} months"

def calculate_offline_attack_time(stats: dict, category: str, algo_name: str) -> str:
    """Calculate time for a standard offline attack (single PC)."""
    # This is the same as the main calculate_time_to_crack function for consistency
    return calculate_time_to_crack(stats, category, algo_name)

def calculate_massive_attack_time(stats: dict, category: str, algo_name: str) -> str:
    """Calculate time for a massive attack (botnet or supercomputer)."""
    # A massive attack could be thousands of times faster
    attack_rate = OFFLINE_ATTACK_RATE.get(algo_name, OFFLINE_ATTACK_RATE["sha256"]) * 1000
    
    keyspace = stats["keyspace_size"]
    length = stats["length"]
    
    if keyspace == 0:
        return "Not Calculable"
        
    try:
        total_attempts = keyspace ** length
    except OverflowError:
        return "Thousands of Years"
    
    crack_time_seconds = (total_attempts / 2) / attack_rate
    
    if crack_time_seconds < 60:
        return f"{crack_time_seconds:.2f} seconds"
    elif crack_time_seconds < 3600:
        return f"{crack_time_seconds / 60:.2f} minutes"
    elif crack_time_seconds < 86400:
        return f"{crack_time_seconds / 3600:.2f} hours"
    elif crack_time_seconds < 31536000:
        return f"{crack_time_seconds / 86400:.2f} days"
    else:
        years = crack_time_seconds / 31536000
        return f"Approx. {years:.2f} years"


def get_suggestions(stats: dict) -> List[str]:
    suggestions = []
    if stats["length"] < 16:
        suggestions.append(f"Increase the length! Current: {stats['length']}. Target: 16+ characters.")
    if not stats["has_upper"]:
        suggestions.append("Add Upper case letters (A-Z).")
    if not stats["has_lower"]:
        suggestions.append("Add Lower case letters (a-z).")
    if not stats["has_digits"]:
        suggestions.append("Add Numbers (0-9).")
    if not stats["has_symbols"]:
        suggestions.append("Add Symbols (!@#$%).")
    if not suggestions:
        suggestions.append("Your password is **Excellent!** Use a password manager to store it.")
    return suggestions

def animate_text(text: str, delay: float = 0.005):
    if len(text) > 100:
        delay = 0.003 
    
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)

# ----------------------------------------------------
#               Module Classes
# ----------------------------------------------------

class Module(object):
    """Base class for all modules"""
    def __init__(self):
        self.options = {}
        self.description = ""
        self.author = "Aegis Dynamics"
        self.license = "MSF_LICENSE"
        self.references = []
        self.msf_handler = None
        
    def info(self):
        """Display module information in Metasploit format"""
        print(f"\n{ColorCyan}       Name: {ColorReset}{self.__class__.__name__}")
        print(f"{ColorCyan}     Module: {ColorReset}{self.__class__.__module__}")
        print(f"{ColorCyan}    License: {ColorReset}{self.license}")
        print(f"{ColorCyan}       Rank: {ColorReset}Normal")
        print(f"{ColorCyan}  Provided by: {ColorReset}{self.author}")
        print(f"\n{ColorCyan}Basic options:{ColorReset}")
        print(f"{ColorCyan}================{ColorReset}")
        print(f"{ColorCyan}  Name     Current Setting     Required    Description{ColorReset}")
        print(f"{ColorCyan}  ----     ---------------     --------    -----------{ColorReset}")
        
        for name, option in self.options.items():
            required = "yes" if option['required'] else "no"
            current = option['value'] if option['value'] else ""
            print(f"  {name:<9} {current:<19} {required:<11} {option['description']}")
        
        if self.references:
            print(f"\n{ColorCyan}References:{ColorReset}")
            print(f"{ColorCyan}=========== {ColorReset}")
            for ref in self.references:
                print(f"  {ref}")
                
    def run(self):
        """Run the module - to be implemented by subclasses"""
        print(f"{ColorRed}[-]{ColorReset} Module run method not implemented")
        
    def set_option(self, name, value):
        """Set an option value"""
        if name in self.options:
            self.options[name]['value'] = value
            return True
        return False
        
    def get_option(self, name):
        """Get an option value"""
        if name in self.options:
            return self.options[name]['value']
        return None

class Auxiliary(Module):
    """Base class for auxiliary modules"""
    def __init__(self):
        super(Auxiliary, self).__init__()
        self.type = "auxiliary"

class Exploit(Module):
    """Base class for exploit modules"""
    def __init__(self):
        super(Exploit, self).__init__()
        self.type = "exploit"
        self.targets = []
        self.payloads = []
        self.default_target = 0
        self.default_port = 0
        self.arch = []
        self.platform = []
        self.privileged = False
        self.disclosure_date = ""
        self.default_target = 0

class Post(Module):
    """Base class for post-exploitation modules"""
    def __init__(self):
        super(Post, self).__init__()
        self.type = "post"

class Payload(Module):
    """Base class for payload modules"""
    def __init__(self):
        super(Payload, self).__init__()
        self.type = "payload"

class Encoder(Module):
    """Base class for encoder modules"""
    def __init__(self):
        super(Encoder, self).__init__()
        self.type = "encoder"

class Nop(Module):
    """Base class for NOP modules"""
    def __init__(self):
        super(Nop, self).__init__()
        self.type = "nop"

class Evasion(Module):
    """Base class for evasion modules"""
    def __init__(self):
        super(Evasion, self).__init__()
        self.type = "evasion"

# ----------------------------------------------------
#               Concrete Module Implementations
# ----------------------------------------------------

class PasswordStrengthAnalyzer(Auxiliary):
    """Analyze password strength"""
    def __init__(self):
        super(PasswordStrengthAnalyzer, self).__init__()
        self.description = "Analyze password strength"
        self.options = {
            'PASSWORD': {'value': '', 'required': True, 'description': 'Password to analyze'},
            'ALGORITHM': {'value': 'sha256', 'required': True, 'description': 'Hash algorithm (md5, sha1, sha256)'},
        }
        self.references = [
            "URL:https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet"
        ]
        
    def run(self):
        password = self.get_option('PASSWORD')
        algorithm = self.get_option('ALGORITHM')
        
        if not password:
            print(f"{ColorRed}[-]{ColorReset} PASSWORD option is required")
            return
            
        if algorithm not in SUPPORTED_ALGORITHMS:
            print(f"{ColorRed}[-]{ColorReset} Invalid algorithm. Supported: {', '.join(SUPPORTED_ALGORITHMS.keys())}")
            return
        
        # Display the analysis
        print("\n" + "-"*70)
        
        # Get Stats, Hash, Strength, and Crack Time
        stats = get_password_stats(password, algorithm)
        colored_category, category_str = get_strength_category(stats)
        time_to_crack = calculate_time_to_crack(stats, category_str, algorithm)
        suggestions = get_suggestions(stats)
        
        # --- Display Results ---
        print("\n--- SIMULATION TARGET ---")
        print(f"Plaintext (The Cracked Password): {ColorCyan}{password}{ColorReset}")
        print(f"Simulated Hash ({algorithm.upper()}): {ColorOrange}{stats['simulated_hash']}{ColorReset}")
        
        print("\n--- Strength Analysis ---")
        print(f"Password Length: {stats['length']} characters")
        print(f"Strength Category: {colored_category}")
        
        # *** CHANGE 3: Updated Crack Simulation Display ***
        # Yahan par maine output ko update kiya hai nayi functions ke saath.
        print("\n--- Crack Simulation ---")
        print(f"Time to Crack (Offline Attack): {time_to_crack}")
        print("\n--- Detailed Crack Time Estimates ---")
        print(f"Online Attack (e.g., website login): {calculate_online_attack_time(stats, category_str)}")
        print(f"Offline Attack (fast hash, single PC): {calculate_offline_attack_time(stats, category_str, algorithm)}")
        print(f"Massive Attack (botnet/supercomputer): {calculate_massive_attack_time(stats, category_str, algorithm)}")

        # Check if the crack time is low, and advise the user
        if category_str in ["Weak", "Medium"] or "seconds" in time_to_crack or "minutes" in time_to_crack:
            print(f"\n🚨 {ColorRed}ACTION REQUIRED:{ColorReset} This password is **NOT SAFE** and can be cracked quickly! Use a new one.")
        else:
            print(f"\n✅ {ColorGreen}VERDICT:{ColorReset} This password is SAFE against common brute-force attacks.")
        
        print("\n--- Improvement Suggestions ---")
        for i, suggestion in enumerate(suggestions):
            print(f"  {i+1}. {suggestion}")
            
        print("-"*70)
        
        # wordlist
        save_to_wordlist(password)

class HashCracker(Auxiliary):
    """Crack hash using wordlist"""
    def __init__(self):
        super(HashCracker, self).__init__()
        self.description = "Crack hash using wordlist"
        self.options = {
            'HASH': {'value': '', 'required': True, 'description': 'Hash to crack'},
            'WORDLIST': {'value': 'wordlist.txt', 'required': False, 'description': 'Wordlist file path'},
        }
        self.references = [
            "URL:https://hashcat.net/hashcat/"
        ]
        
    def run(self):
        target_hash = self.get_option('HASH')
        wordlist = self.get_option('WORDLIST')
        
        if not target_hash:
            print(f"{ColorRed}[-]{ColorReset} HASH option is required")
            return
            
        # Detect hash type
        hash_length = len(target_hash)
        hash_type = HASH_TYPES.get(hash_length)
        
        if not hash_type:
            print(f"{ColorRed}[-]{ColorReset} Unknown hash type. Supported hash lengths: {', '.join([f'{length} ({algo})' for length, algo in HASH_TYPES.items()])}")
            return
        
        result = crack_hash_mode(target_hash, hash_type)
        print(result)

class EncryptText(Auxiliary):
    """Encrypt text using various algorithms"""
    def __init__(self):
        super(EncryptText, self).__init__()
        self.description = "Encrypt text using various algorithms"
        self.options = {
            'ALGORITHM': {'value': 'aes', 'required': True, 'description': 'Encryption algorithm (aes, caesar, base64, rsa)'},
            'TEXT': {'value': '', 'required': True, 'description': 'Text to encrypt'},
            'PASSWORD': {'value': '', 'required': False, 'description': 'Password for AES encryption'},
            'SHIFT': {'value': '3', 'required': False, 'description': 'Shift value for Caesar cipher'},
            'PUBLIC_KEY': {'value': '', 'required': False, 'description': 'Public key for RSA encryption'},
        }
        
    def run(self):
        algo = self.get_option('ALGORITHM')
        text = self.get_option('TEXT')
        
        if not algo or not text:
            print(f"{ColorRed}[-]{ColorReset} ALGORITHM and TEXT options are required")
            return
            
        if algo == 'aes':
            password = self.get_option('PASSWORD')
            if not password:
                print(f"{ColorRed}[-]{ColorReset} PASSWORD option is required for AES encryption")
                return
            
            ciphertext, iv_salt = encrypt_aes(text, password)
            
            if not ciphertext.startswith("Error:"):
                print(f"\n{ColorCyan}[*]{ColorReset} Encryption Results:")
                print(f"{ColorCyan}[*]{ColorReset} =================")
                print(f"\n{ColorGreen}[+]{ColorReset} Algorithm: AES-256-CBC")
                print(f"{ColorGreen}[+]{ColorReset} Ciphertext (Base64):\n{ColorWhite}{ciphertext}{ColorReset}")
                print(f"\n{ColorYellow}[!]{ColorReset} IV:Salt (Base64): {iv_salt}")
                print(f"{ColorYellow}[!]{ColorReset} Save this IV:Salt value for decryption")
            else:
                print(f"\n{ColorRed}[-]{ColorReset} Encryption failed: {ciphertext}")
        
        elif algo == 'caesar':
            shift = int(self.get_option('SHIFT'))
            ciphertext = encrypt_caesar(text, shift)
            
            print(f"\n{ColorCyan}[*]{ColorReset} Encryption Results:")
            print(f"{ColorCyan}[*]{ColorReset} =================")
            print(f"\n{ColorGreen}[+]{ColorReset} Algorithm: Caesar Cipher")
            print(f"{ColorGreen}[+]{ColorReset} Shift: {shift}")
            print(f"{ColorGreen}[+]{ColorReset} Ciphertext: {ColorWhite}{ciphertext}{ColorReset}")
        
        elif algo == 'base64':
            ciphertext = encrypt_base64(text)
            
            print(f"\n{ColorCyan}[*]{ColorReset} Encryption Results:")
            print(f"{ColorCyan}[*]{ColorReset} =================")
            print(f"\n{ColorGreen}[+]{ColorReset} Algorithm: Base64")
            print(f"{ColorGreen}[+]{ColorReset} Ciphertext: {ColorWhite}{ciphertext}{ColorReset}")
        
        elif algo == 'rsa':
            public_key = self.get_option('PUBLIC_KEY')
            if not public_key:
                print(f"{ColorRed}[-]{ColorReset} PUBLIC_KEY option is required for RSA encryption")
                return
            
            ciphertext = encrypt_rsa(text, public_key)
            
            if not ciphertext.startswith("Error:"):
                print(f"\n{ColorCyan}[*]{ColorReset} Encryption Results:")
                print(f"{ColorCyan}[*]{ColorReset} =================")
                print(f"\n{ColorGreen}[+]{ColorReset} Algorithm: RSA")
                print(f"{ColorGreen}[+]{ColorReset} Ciphertext (Base64):\n{ColorWhite}{ciphertext}{ColorReset}")
            else:
                print(f"\n{ColorRed}[-]{ColorReset} Encryption failed: {ciphertext}")
        
        else:
            print(f"{ColorRed}[-]{ColorReset} Unknown algorithm. Supported: aes, caesar, base64, rsa")

class DecryptText(Auxiliary):
    """Decrypt text using various algorithms"""
    def __init__(self):
        super(DecryptText, self).__init__()
        self.description = "Decrypt text using various algorithms"
        self.options = {
            'ALGORITHM': {'value': 'aes', 'required': True, 'description': 'Decryption algorithm (aes, caesar, base64, rsa)'},
            'CIPHERTEXT': {'value': '', 'required': True, 'description': 'Text to decrypt'},
            'PASSWORD': {'value': '', 'required': False, 'description': 'Password for AES decryption'},
            'SHIFT': {'value': '3', 'required': False, 'description': 'Shift value for Caesar cipher'},
            'IV_SALT': {'value': '', 'required': False, 'description': 'IV and salt for AES (format: iv:salt)'},
            'PRIVATE_KEY': {'value': '', 'required': False, 'description': 'Private key for RSA decryption'},
        }
        
    def run(self):
        algo = self.get_option('ALGORITHM')
        ciphertext = self.get_option('CIPHERTEXT')
        
        if not algo or not ciphertext:
            print(f"{ColorRed}[-]{ColorReset} ALGORITHM and CIPHERTEXT options are required")
            return
            
        if algo == 'aes':
            password = self.get_option('PASSWORD')
            iv_salt = self.get_option('IV_SALT')
            if not password or not iv_salt:
                print(f"{ColorRed}[-]{ColorReset} PASSWORD and IV_SALT options are required for AES decryption")
                return
            
            plaintext = decrypt_aes(ciphertext, password, iv_salt)
            
            if not plaintext.startswith("Error:"):
                print(f"\n{ColorCyan}[*]{ColorReset} Decryption Results:")
                print(f"{ColorCyan}[*]{ColorReset} =================")
                print(f"\n{ColorGreen}[+]{ColorReset} Algorithm: AES-256-CBC")
                print(f"{ColorGreen}[+]{ColorReset} Plaintext: {ColorWhite}{plaintext}{ColorReset}")
            else:
                print(f"\n{ColorRed}[-]{ColorReset} Decryption failed: {plaintext}")
        
        elif algo == 'caesar':
            shift = int(self.get_option('SHIFT'))
            plaintext = decrypt_caesar(ciphertext, shift)
            
            print(f"\n{ColorCyan}[*]{ColorReset} Decryption Results:")
            print(f"{ColorCyan}[*]{ColorReset} =================")
            print(f"\n{ColorGreen}[+]{ColorReset} Algorithm: Caesar Cipher")
            print(f"{ColorGreen}[+]{ColorReset} Shift: {shift}")
            print(f"{ColorGreen}[+]{ColorReset} Plaintext: {ColorWhite}{plaintext}{ColorReset}")
        
        elif algo == 'base64':
            plaintext = decrypt_base64(ciphertext)
            
            if not plaintext.startswith("Error:"):
                print(f"\n{ColorCyan}[*]{ColorReset} Decryption Results:")
                print(f"{ColorCyan}[*]{ColorReset} =================")
                print(f"\n{ColorGreen}[+]{ColorReset} Algorithm: Base64")
                print(f"{ColorGreen}[+]{ColorReset} Plaintext: {ColorWhite}{plaintext}{ColorReset}")
            else:
                print(f"\n{ColorRed}[-]{ColorReset} Decryption failed: {plaintext}")
        
        elif algo == 'rsa':
            private_key = self.get_option('PRIVATE_KEY')
            if not private_key:
                print(f"{ColorRed}[-]{ColorReset} PRIVATE_KEY option is required for RSA decryption")
                return
            
            plaintext = decrypt_rsa(ciphertext, private_key)

            if not plaintext.startswith("Error:"):
                print(f"\n{ColorCyan}[*]{ColorReset} Decryption Results:")
                print(f"{ColorCyan}[*]{ColorReset} =================")
                print(f"\n{ColorGreen}[+]{ColorReset} Algorithm: RSA")
                print(f"{ColorGreen}[+]{ColorReset} Plaintext: {ColorWhite}{plaintext}{ColorReset}")
            else:
                print(f"\n{ColorRed}[-]{ColorReset} Decryption failed: {plaintext}")
        
        else:
            print(f"{ColorRed}[-]{ColorReset} Unknown algorithm. Supported: aes, caesar, base64, rsa")

class KeyManager(Auxiliary):
    """Generate RSA key pairs"""
    def __init__(self):
        super(KeyManager, self).__init__()
        self.description = "Generate RSA key pairs"
        self.options = {
            'KEY_SIZE': {'value': '2048', 'required': False, 'description': 'Size of the RSA key to generate (e.g., 2048, 4096)'},
            'ACTION': {'value': 'generate', 'required': False, 'description': 'Action to perform (generate, copy_public, copy_private)'},
            'PUBLIC_KEY': {'value': '', 'required': False, 'description': 'Public key to copy (for copy_public action)'},
            'PRIVATE_KEY': {'value': '', 'required': False, 'description': 'Private key to copy (for copy_private action)'},
        }
        self.last_generated_keys = {'public': '', 'private': ''}
        
    def run(self):
        action = self.get_option('ACTION').lower()
        
        if action == 'generate':
            key_size = int(self.get_option('KEY_SIZE'))
            print(f"\n{ColorGreen}[*]{ColorReset} Generating {key_size}-bit RSA key pair...")
            
            private_key, public_key = generate_rsa_keys(key_size)
            
            # Store the generated keys for potential copying later
            self.last_generated_keys['public'] = public_key
            self.last_generated_keys['private'] = private_key
            
            print(f"\n{ColorCyan}[*]{ColorReset} Key Generation Complete:")
            print(f"{ColorCyan}[*]{ColorReset} =======================")
            print(f"\n{ColorYellow}--- PUBLIC KEY ---{ColorReset}")
            print(f"{ColorWhite}{public_key}{ColorReset}")
            print(f"\n{ColorYellow}--- PRIVATE KEY ---{ColorReset}")
            print(f"{ColorWhite}{private_key}{ColorReset}")
            print(f"\n{ColorOrange}[!]{ColorReset} {ColorBold}IMPORTANT:{ColorReset} Keep your private key secret! Share the public key for others to encrypt messages for you.")
            print(f"\n{ColorGreen}[+]{ColorReset} Use 'set ACTION copy_public' to copy the public key to clipboard")
            print(f"{ColorGreen}[+]{ColorReset} Use 'set ACTION copy_private' to copy the private key to clipboard")
            
        elif action == 'copy_public':
            public_key = self.get_option('PUBLIC_KEY') or self.last_generated_keys['public']
            
            if not public_key:
                print(f"{ColorRed}[-]{ColorReset} No public key available. Generate a key pair first or provide a PUBLIC_KEY.")
                return
                
            try:
                pyperclip.copy(public_key)
                print(f"{ColorGreen}[+]{ColorReset} Public key copied to clipboard successfully!")
            except Exception as e:
                print(f"{ColorRed}[-]{ColorReset} Failed to copy public key: {e}")
                print(f"{ColorYellow}[!]{ColorReset} Try installing the pyperclip package: pip install pyperclip")
                
        elif action == 'copy_private':
            private_key = self.get_option('PRIVATE_KEY') or self.last_generated_keys['private']
            
            if not private_key:
                print(f"{ColorRed}[-]{ColorReset} No private key available. Generate a key pair first or provide a PRIVATE_KEY.")
                return
                
            try:
                pyperclip.copy(private_key)
                print(f"{ColorGreen}[+]{ColorReset} Private key copied to clipboard successfully!")
                print(f"{ColorOrange}[!]{ColorReset} {ColorBold}WARNING:{ColorReset} Be careful with your private key!")
            except Exception as e:
                print(f"{ColorRed}[-]{ColorReset} Failed to copy private key: {e}")
                print(f"{ColorYellow}[!]{ColorReset} Try installing the pyperclip package: pip install pyperclip")
                
        else:
            print(f"{ColorRed}[-]{ColorReset} Unknown action: {action}")
            print(f"{ColorGreen}[*]{ColorReset} Available actions: generate, copy_public, copy_private")

# ----------------------------------------------------
#               Encryption/Decryption Functions
# ----------------------------------------------------

def generate_key(password: str, salt: bytes = None) -> bytes:
    """Generate a key from password using PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt

def encrypt_aes(plaintext: str, password: str) -> Tuple[str, str]:
    """Encrypt text using AES-256-CBC"""
    try:
        key, salt = generate_key(password)
        iv = os.urandom(16)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        padding_length = 16 - (len(plaintext) % 16)
        padded_plaintext = plaintext + chr(padding_length) * padding_length
        
        ciphertext = encryptor.update(padded_plaintext.encode()) + encryptor.finalize()
        
        encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
        encoded_iv = base64.b64encode(iv).decode('utf-8')
        encoded_salt = base64.b64encode(salt).decode('utf-8')
        
        return encoded_ciphertext, f"{encoded_iv}:{encoded_salt}"
    except Exception as e:
        return f"Error: {str(e)}", ""

def decrypt_aes(ciphertext: str, password: str, iv_salt: str) -> str:
    """Decrypt text using AES-256-CBC"""
    try:
        decoded_ciphertext = base64.b64decode(ciphertext)
        parts = iv_salt.split(':')
        iv = base64.b64decode(parts[0])
        salt = base64.b64decode(parts[1])
        
        key, _ = generate_key(password, salt)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        padded_plaintext = decryptor.update(decoded_ciphertext) + decryptor.finalize()
        
        padding_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_length].decode('utf-8')
        
        return plaintext
    except Exception as e:
        return f"Error: {str(e)}"

def encrypt_caesar(plaintext: str, shift: int) -> str:
    """Encrypt text using Caesar cipher"""
    result = ""
    for char in plaintext:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result

def decrypt_caesar(ciphertext: str, shift: int) -> str:
    """Decrypt text using Caesar cipher"""
    return encrypt_caesar(ciphertext, -shift)

def encrypt_base64(plaintext: str) -> str:
    """Encode text using Base64"""
    return base64.b64encode(plaintext.encode('utf-8')).decode('utf-8')

def decrypt_base64(ciphertext: str) -> str:
    """Decode text using Base64"""
    try:
        return base64.b64decode(ciphertext).decode('utf-8')
    except Exception as e:
        return f"Error: {str(e)}"

# --- RSA Functions ---

def generate_rsa_keys(key_size: int = 2048) -> Tuple[str, str]:
    """Generate a new RSA key pair and return them as PEM formatted strings."""
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem.decode('utf-8'), public_pem.decode('utf-8')
    except Exception as e:
        return f"Error generating RSA keys: {str(e)}", f"Error generating RSA keys: {str(e)}"

def encrypt_rsa(plaintext: str, public_key_pem: str) -> str:
    """Encrypt plaintext using a public key."""
    try:
        # Clean up the public key PEM format
        public_key_pem = public_key_pem.strip()
        
        # Ensure the public key has proper PEM formatting
        if not public_key_pem.startswith('-----BEGIN PUBLIC KEY-----'):
            public_key_pem = '-----BEGIN PUBLIC KEY-----\n' + public_key_pem
        if not public_key_pem.endswith('-----END PUBLIC KEY-----'):
            public_key_pem = public_key_pem + '\n-----END PUBLIC KEY-----'
            
        # Remove any extra whitespace within the key
        lines = public_key_pem.split('\n')
        cleaned_lines = []
        for line in lines:
            if line.startswith('-----'):
                cleaned_lines.append(line)
            else:
                # Remove all whitespace from Base64 content
                cleaned_lines.append(''.join(line.split()))
        
        public_key_pem = '\n'.join(cleaned_lines)
        
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )
        
        ciphertext = public_key.encrypt(
            plaintext.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode('utf-8')
    except Exception as e:
        return f"Error: {str(e)}\nPlease ensure the public key is in valid PEM format with '-----BEGIN PUBLIC KEY-----' and '-----END PUBLIC KEY-----' headers."

def decrypt_rsa(ciphertext_b64: str, private_key_pem: str) -> str:
    """Decrypt ciphertext using a private key."""
    try:
        # Clean up the private key PEM format
        private_key_pem = private_key_pem.strip()
        
        # Ensure the private key has proper PEM formatting
        if not private_key_pem.startswith('-----BEGIN PRIVATE KEY-----'):
            private_key_pem = '-----BEGIN PRIVATE KEY-----\n' + private_key_pem
        if not private_key_pem.endswith('-----END PRIVATE KEY-----'):
            private_key_pem = private_key_pem + '\n-----END PRIVATE KEY-----'
            
        # Remove any extra whitespace within the key
        lines = private_key_pem.split('\n')
        cleaned_lines = []
        for line in lines:
            if line.startswith('-----'):
                cleaned_lines.append(line)
            else:
                # Remove all whitespace from Base64 content
                cleaned_lines.append(''.join(line.split()))
        
        private_key_pem = '\n'.join(cleaned_lines)
        
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        
        ciphertext = base64.b64decode(ciphertext_b64)
        
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"Error: {str(e)}\nPlease ensure the private key is in valid PEM format with '-----BEGIN PRIVATE KEY-----' and '-----END PRIVATE KEY-----' headers."

# ----------------------------------------------------
#               Module Manager
# ----------------------------------------------------

class ModuleManager(object):
    """Manages all modules in the framework"""
    def __init__(self):
        self.modules = {}
        self.current_module = None
        self.load_modules()
        
    def load_modules(self):
        """Load all available modules"""
        # Load auxiliary modules
        self.modules['auxiliary/analyze/password_strength'] = PasswordStrengthAnalyzer()
        self.modules['auxiliary/crack/hash'] = HashCracker()
        self.modules['auxiliary/encrypt/encrypt'] = EncryptText()
        self.modules['auxiliary/encrypt/decrypt'] = DecryptText()
        self.modules['auxiliary/encrypt/key_manager'] = KeyManager()
        
    def get_module(self, path):
        """Get a module by path"""
        return self.modules.get(path)
        
    def use_module(self, path):
        """Set the current module"""
        module = self.get_module(path)
        if module:
            self.current_module = module
            return True
        return False
        
    def get_current_module(self):
        """Get the current module"""
        return self.current_module
        
    def list_modules(self, module_type=None):
        """List all modules, optionally filtered by type"""
        if module_type:
            print(f"\n{ColorCyan}{module_type.capitalize()} modules:{ColorReset}")
            print(f"{ColorGreen}{'=' * (len(module_type) + 9)}{ColorReset}")
        else:
            print(f"\n{ColorCyan}All modules:{ColorReset}")
            print(f"{ColorGreen}{'=' * 12}{ColorReset}")
            
        for path, module in self.modules.items():
            if not module_type or module.type == module_type:
                print(f"  {path:<40} {module.description}")

# ----------------------------------------------------
#               Console Interface
# ----------------------------------------------------

class Console(object):
    """Main console interface"""
    def __init__(self):
        self.module_manager = ModuleManager()
        self.global_options = {
            'WORKSPACE': {'value': 'default', 'description': 'Current workspace'},
            'LogLevel': {'value': 'info', 'description': 'Logging level'},
            'PromptChar': {'value': '>', 'description': 'Prompt character'},
            'PromptColor': {'value': 'red', 'description': 'Prompt color'},
        }
        self.running = True
        self.history = []
        self.load_history()
        
    def load_history(self):
        """Load command history from file"""
        try:
            if os.path.exists(HISTORY_FILE):
                with open(HISTORY_FILE, 'r') as f:
                    self.history = json.load(f)
        except Exception as e:
            print(f"{ColorYellow}[!]{ColorReset} Could not load history file: {e}")
            self.history = []
            
    def save_history(self):
        """Save command history to file"""
        try:
            with open(HISTORY_FILE, 'w') as f:
                json.dump(self.history, f)
        except Exception as e:
            print(f"{ColorYellow}[!]{ColorReset} Could not save history file: {e}")
            
    def add_to_history(self, command):
        """Add a command to history"""
        # Don't add empty commands or duplicate the last command
        if not command or (self.history and command == self.history[-1]):
            return
            
        self.history.append(command)
        
        # Keep only the last 100 commands
        if len(self.history) > 100:
            self.history = self.history[-100:]
            
        self.save_history()
        
    def display_history(self, count=None):
        """Display command history"""
        if not self.history:
            print(f"{ColorYellow}[!]{ColorReset} No command history available")
            return
            
        if count is None:
            # Show all history
            start_index = 0
        else:
            # Show last 'count' commands
            start_index = max(0, len(self.history) - count)
            
        print(f"\n{ColorCyan}Command History:{ColorReset}")
        print(f"{ColorGreen}==============={ColorReset}")
        
        for i in range(start_index, len(self.history)):
            print(f"  {i+1:3d}: {self.history[i]}")
        
    def display_banner(self):
        """Display the PassPloit banner with Metasploit-style loading"""
        metasploit_loading()
        
        print(f"{ColorGreen}", end="")
        for line in PASSPLOIT_LOGO.strip().split('\n'):
            animate_text(line, delay=0.003)
            print()
        print(f"{ColorReset}")
        
        # Display random dangerous art
        random_art = random.choice(DANGEROUS_ARTS)
        print(f"{ColorRed}{random_art}{ColorReset}")
        time.sleep(1)
        
        print(f"{ColorCyan}       =[ passploit v4.1-dev                          ]{ColorReset}")
        print(f"{ColorCyan}+ -- --=[ 3 exploits - 4 auxiliary - 0 post            ]{ColorReset}")
        print(f"{ColorCyan}+ -- --=[ 0 payloads - 0 encoders - 0 nops             ]{ColorReset}")
        print(f"{ColorCyan}+ -- --=[ 0 evasion                                    ]{ColorReset}")
        print(f"{ColorYellow}\nPassPloit tip: Use 'use auxiliary/encrypt/key_manager' to generate RSA keys.{ColorReset}\n")
        
    # *** CHANGE 4: Fixed get_prompt method to show full module path ***
    # Yahan par maine prompt ko fix kiya hai.
    def get_prompt(self):
        """Get the current prompt string"""
        prompt_color = ColorRed
        if self.global_options['PromptColor']['value'].lower() == 'green':
            prompt_color = ColorGreen
        elif self.global_options['PromptColor']['value'].lower() == 'blue':
            prompt_color = ColorBlue
        elif self.global_options['PromptColor']['value'].lower() == 'yellow':
            prompt_color = ColorYellow
            
        prompt_char = self.global_options['PromptChar']['value']
        
        if self.module_manager.get_current_module():
            # Find the module path by iterating through the loaded modules
            module_path = "unknown"
            for path, module_obj in self.module_manager.modules.items():
                if module_obj == self.module_manager.get_current_module():
                    module_path = path
                    break
            
            return f"{prompt_color}passploit{ColorReset} {ColorYellow}({module_path}){ColorReset} {prompt_char} "
        else:
            return f"{prompt_color}passploit{ColorReset} {prompt_char} "
            
    def handle_command(self, command_str):
        """Handle a command string"""
        parts = command_str.strip().split()
        if not parts:
            return
            
        command = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        # Add command to history (except for history command itself)
        if command != 'history':
            self.add_to_history(command_str)
        
        if command in ['exit', 'quit']:
            self.running = False
            print(f"{ColorGreen}[*]{ColorReset} Exiting PassPloit...")
            
        elif command in ['?', 'help']:
            self.display_help()
            
        elif command == 'clear':
            self.clear_screen()
            
        elif command == 'history':
            if args:
                try:
                    count = int(args[0])
                    self.display_history(count)
                except ValueError:
                    print(f"{ColorRed}[-]{ColorReset} Invalid number. Usage: history [count]")
            else:
                self.display_history()
                
        elif command == 'back':
            if self.module_manager.get_current_module():
                print(f"{ColorGreen}[*]{ColorReset} Backing out from module context")
                self.module_manager.current_module = None
            else:
                print(f"{ColorRed}[-]{ColorReset} You are not in a module context")
                
        elif command == 'show':
            if not args:
                print(f"{ColorRed}[-]{ColorReset} Usage: show <options|targets|modules|info>")
                return
                
            show_type = args[0].lower()
            if show_type == 'modules':
                self.module_manager.list_modules()
            elif show_type == 'options':
                self.show_options()
            elif show_type == 'info' and self.module_manager.get_current_module():
                self.module_manager.get_current_module().info()
            elif show_type == 'targets' and self.module_manager.get_current_module():
                if hasattr(self.module_manager.get_current_module(), 'targets'):
                    targets = self.module_manager.get_current_module().targets
                    if targets:
                        print(f"\n{ColorCyan}Available targets:{ColorReset}")
                        print(f"{ColorGreen}=================={ColorReset}")
                        for i, target in enumerate(targets):
                            print(f"  {i}  {target}")
                    else:
                        print(f"{ColorRed}[-]{ColorReset} No targets available for this module")
                else:
                    print(f"{ColorRed}[-]{ColorReset} This module does not have targets")
            else:
                print(f"{ColorRed}[-]{ColorReset} Invalid show command")
                
        elif command == 'use':
            if not args:
                print(f"{ColorRed}[-]{ColorReset} Usage: use <module_name>")
                return
                
            module_name = args[0].lower()
            if self.module_manager.use_module(module_name):
                print(f"{ColorGreen}[*]{ColorReset} Using module {module_name}")
                print(f"{ColorGreen}[*]{ColorReset} Type 'show options' to see available options")
            else:
                print(f"{ColorRed}[-]{ColorReset} Unknown module: {module_name}")
                print(f"{ColorYellow}[!]{ColorReset} Use 'show modules' to see available modules")
                
        elif command == 'set':
            if not args or len(args) < 2:
                print(f"{ColorRed}[-]{ColorReset} Usage: set <option> <value>")
                return
                
            option_name = args[0].upper()
            option_value = ' '.join(args[1:])
            
            if self.module_manager.get_current_module():
                if self.module_manager.get_current_module().set_option(option_name, option_value):
                    print(f"{ColorGreen}[*]{ColorReset} {option_name} => {option_value}")
                else:
                    print(f"{ColorRed}[-]{ColorReset} Unknown option: {option_name}")
            else:
                if option_name in self.global_options:
                    self.global_options[option_name]['value'] = option_value
                    print(f"{ColorGreen}[*]{ColorReset} {option_name} => {option_value}")
                else:
                    print(f"{ColorRed}[-]{ColorReset} Unknown global option: {option_name}")
                    
        elif command == 'unset':
            if not args:
                print(f"{ColorRed}[-]{ColorReset} Usage: unset <option>")
                return
                
            option_name = args[0].upper()
            
            if self.module_manager.get_current_module():
                if self.module_manager.get_current_module().set_option(option_name, ''):
                    print(f"{ColorGreen}[*]{ColorReset} {option_name} => ")
                else:
                    print(f"{ColorRed}[-]{ColorReset} Unknown option: {option_name}")
            else:
                if option_name in self.global_options:
                    self.global_options[option_name]['value'] = ''
                    print(f"{ColorGreen}[*]{ColorReset} {option_name} => ")
                else:
                    print(f"{ColorRed}[-]{ColorReset} Unknown global option: {option_name}")
                    
        elif command == 'run':
            if self.module_manager.get_current_module():
                self.module_manager.get_current_module().run()
            else:
                print(f"{ColorRed}[-]{ColorReset} You must select a module before running it")
                
        elif command == 'exploit':
            if self.module_manager.get_current_module():
                self.module_manager.get_current_module().run()
            else:
                print(f"{ColorRed}[-]{ColorReset} You must select a module before running it")
                
        else:
            print(f"{ColorRed}[-]{ColorReset} Unknown command: {command}")
            print(f"{ColorYellow}[!]{ColorReset} Type 'help' for a list of commands")
            
    def show_options(self):
        """Show options for the current module or global options"""
        if self.module_manager.get_current_module():
            print(f"\n{ColorCyan}Module options ({self.module_manager.get_current_module().__class__.__name__}):{ColorReset}")
            print(f"{ColorGreen}{'=' * (len(self.module_manager.get_current_module().__class__.__name__) + 16)}{ColorReset}")
            
            for name, option in self.module_manager.get_current_module().options.items():
                required = "yes" if option['required'] else "no"
                current = option['value'] if option['value'] else ""
                print(f"  {name:<15} {current:<20} {required:<10} {option['description']}")
        else:
            print(f"\n{ColorCyan}Global options:{ColorReset}")
            print(f"{ColorGreen}================{ColorReset}")
            
            for name, option in self.global_options.items():
                current = option['value'] if option['value'] else ""
                print(f"  {name:<15} {current:<20} {option['description']}")
                
    def display_help(self):
        """Display help information"""
        print(f"\n{ColorCyan}PassPloit Console Commands:{ColorReset}")
        print(f"{ColorGreen}=========================={ColorReset}")
        print(f"  {ColorYellow}?{ColorReset}         Help menu")
        print(f"  {ColorYellow}clear{ColorReset}      Clear the terminal screen")
        print(f"  {ColorYellow}exit{ColorReset}       Exit the console")
        print(f"  {ColorYellow}help{ColorReset}       Help menu")
        print(f"  {ColorYellow}history{ColorReset}    Show command history")
        print(f"  {ColorYellow}quit{ColorReset}       Exit the console")
        print(f"  {ColorYellow}back{ColorReset}       Move back from the current context")
        print(f"  {ColorYellow}use{ColorReset} <mod>  Select a module by name")
        print(f"  {ColorYellow}info{ColorReset}       Display information about a module")
        print(f"  {ColorYellow}show{ColorReset} <opt> Show available modules, options, or targets")
        print(f"  {ColorYellow}set{ColorReset} <opt>  Set a context-specific option")
        print(f"  {ColorYellow}unset{ColorReset} <opt> Unset a context-specific option")
        print(f"  {ColorYellow}run{ColorReset}        Run the selected module")
        print(f"  {ColorYellow}exploit{ColorReset}    Run the selected module (alias for run)")
        
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if platform.system() == 'Windows' else 'clear')
        
    def run(self):
        """Run the main console loop"""
        self.display_banner()
        
        while self.running:
            try:
                print() # <-- Har naye prompt se pehle distance
                command = input(self.get_prompt())
                self.handle_command(command)
            except KeyboardInterrupt:
                print(f"\n{ColorYellow}[!]{ColorReset} Use 'exit' or 'quit' to exit")
            except EOFError:
                print(f"\n{ColorGreen}[*]{ColorReset} Exiting PassPloit...")
                break

# ----------------------------------------------------
#               Main Entry Point
# ----------------------------------------------------

if __name__ == "__main__":
    console = Console()
    console.run()