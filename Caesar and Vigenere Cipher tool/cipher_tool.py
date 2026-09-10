#!/usr/bin/env python3
"""
=============================================================================
CLASSICAL CIPHER & CRYPTANALYSIS SUITE
Caesar and Vigenère Cipher Encryption, Decryption, and Automated Breaking Tool
=============================================================================
Features:
  - Caesar Cipher: Encrypt, Decrypt, Brute-force & Chi-Squared Frequency Analysis Auto-Crack
  - Vigenère Cipher: Encrypt, Decrypt, Index of Coincidence (IoC) Key Length Detection & Auto-Crack
  - Frequency Distribution Analyzer & Chi-Square Goodness-of-Fit
  - Standalone CLI interface + Programmatic Python API
=============================================================================
"""

import sys
import math
import string
import argparse
from collections import Counter
from typing import Dict, List, Tuple, Optional

# Standard English Letter Frequencies (normalized percentages summing to ~1.0)
# Derived from extensive corpora (ETAOIN SHRDLCUMWFGYPBVKJXQZ)
ENGLISH_FREQ: Dict[str, float] = {
    'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253, 'E': 0.12702,
    'F': 0.02228, 'G': 0.02015, 'H': 0.06094, 'I': 0.06966, 'J': 0.00153,
    'K': 0.00772, 'L': 0.04025, 'M': 0.02406, 'N': 0.06749, 'O': 0.07507,
    'P': 0.01929, 'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
    'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150, 'Y': 0.01974,
    'Z': 0.00074
}

# Expected Index of Coincidence for standard English text
ENGLISH_IOC = 0.0667
# Theoretical IoC for uniformly random distribution over 26 letters (1/26)
RANDOM_IOC = 0.0385


# =============================================================================
# 1. CORE CAESAR CIPHER IMPLEMENTATION
# =============================================================================

def caesar_encrypt(plaintext: str, shift: int) -> str:
    """
    Encrypts plaintext using the Caesar cipher with a specified shift.
    Preserves letter casing and leaves non-alphabetic characters untouched.
    
    Formula: C_i = (P_i + k) mod 26
    """
    shift = shift % 26
    encrypted_chars = []
    
    for char in plaintext:
        if char.isupper():
            shifted = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            encrypted_chars.append(shifted)
        elif char.islower():
            shifted = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            encrypted_chars.append(shifted)
        else:
            encrypted_chars.append(char)
            
    return "".join(encrypted_chars)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """
    Decrypts ciphertext using the Caesar cipher by shifting backwards.
    
    Formula: P_i = (C_i - k) mod 26
    """
    return caesar_encrypt(ciphertext, -shift)


# =============================================================================
# 2. CORE VIGENÈRE CIPHER IMPLEMENTATION
# =============================================================================

def clean_key(key: str) -> str:
    """Extracts alphabetic characters from key and returns uppercase string."""
    cleaned = "".join(c for c in key if c.isalpha()).upper()
    if not cleaned:
        raise ValueError("Key must contain at least one alphabetic character.")
    return cleaned


def vigenere_encrypt(plaintext: str, key: str) -> str:
    """
    Encrypts plaintext using the Vigenère polyalphabetic substitution cipher.
    Non-alphabetic characters are preserved and do not advance the key index.
    
    Formula: C_i = (P_i + K_(j mod L)) mod 26
    """
    key_upper = clean_key(key)
    key_len = len(key_upper)
    encrypted_chars = []
    key_idx = 0
    
    for char in plaintext:
        if char.isalpha():
            shift = ord(key_upper[key_idx % key_len]) - ord('A')
            if char.isupper():
                shifted = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                shifted = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            encrypted_chars.append(shifted)
            key_idx += 1
        else:
            encrypted_chars.append(char)
            
    return "".join(encrypted_chars)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """
    Decrypts ciphertext encrypted with Vigenère cipher.
    
    Formula: P_i = (C_i - K_(j mod L)) mod 26
    """
    key_upper = clean_key(key)
    key_len = len(key_upper)
    decrypted_chars = []
    key_idx = 0
    
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key_upper[key_idx % key_len]) - ord('A')
            if char.isupper():
                shifted = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                shifted = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            decrypted_chars.append(shifted)
            key_idx += 1
        else:
            decrypted_chars.append(char)
            
    return "".join(decrypted_chars)


# =============================================================================
# 3. FREQUENCY ANALYSIS & STATISTICAL CRYPTANALYSIS
# =============================================================================

def get_letter_counts(text: str) -> Counter:
    """Counts frequencies of uppercase letters A-Z."""
    letters = [c.upper() for c in text if c.isalpha()]
    return Counter(letters)


def chi_squared_score(text: str) -> float:
    """
    Calculates Chi-Squared (χ²) statistic of text against standard English frequencies.
    Lower score indicates a distribution closer to natural English.
    
    Formula: χ² = Σ ((Observed_i - Expected_i)² / Expected_i)
    """
    counts = get_letter_counts(text)
    total_letters = sum(counts.values())
    if total_letters == 0:
        return float('inf')
        
    chi_sq = 0.0
    for char, expected_prop in ENGLISH_FREQ.items():
        expected_count = total_letters * expected_prop
        observed_count = counts.get(char, 0)
        chi_sq += ((observed_count - expected_count) ** 2) / expected_count
        
    return chi_sq


def calculate_ioc(text: str) -> float:
    """
    Calculates the Index of Coincidence (IoC) of a given text.
    Measures the probability that two randomly selected letters from the text are identical.
    
    Formula: IoC = Σ (f_i * (f_i - 1)) / (N * (N - 1))
    Where N is the total number of letters and f_i is the frequency of letter i.
    English monograph IoC is typically ~0.065 to 0.068.
    Random text IoC is ~0.0385.
    """
    counts = get_letter_counts(text)
    n = sum(counts.values())
    if n <= 1:
        return 0.0
        
    numerator = sum(count * (count - 1) for count in counts.values())
    denominator = n * (n - 1)
    return numerator / denominator


# =============================================================================
# 4. CIPHER BREAKING ENGINES
# =============================================================================

def break_caesar(ciphertext: str) -> Dict:
    """
    Breaks Caesar cipher automatically using Chi-Squared goodness-of-fit.
    Evaluates all 26 possible shift keys and selects the one producing the minimum χ².
    """
    best_shift = 0
    min_chi = float('inf')
    all_scores = []
    
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        score = chi_squared_score(decrypted)
        all_scores.append((shift, score, decrypted[:60]))
        if score < min_chi:
            min_chi = score
            best_shift = shift
            
    best_plaintext = caesar_decrypt(ciphertext, best_shift)
    
    return {
        "best_shift": best_shift,
        "chi_squared": min_chi,
        "plaintext": best_plaintext,
        "ranked_candidates": sorted(all_scores, key=lambda x: x[1])
    }


def find_vigenere_key_length(ciphertext: str, max_key_len: int = 16) -> List[Tuple[int, float]]:
    """
    Estimates the most likely Vigenère key length using the Index of Coincidence.
    Splits the text into 'k' interleaved slices and calculates the average IoC for each candidate key length.
    When candidate length matches the true key length, slices exhibit monoalphabetic English IoC (~0.066).
    """
    only_letters = "".join(c.upper() for c in ciphertext if c.isalpha())
    if len(only_letters) < 10:
        return [(1, 0.0)]
        
    results = []
    max_test = min(max_key_len, len(only_letters) // 2)
    
    for k in range(1, max_test + 1):
        slice_iocs = []
        for i in range(k):
            sub_text = only_letters[i::k]
            slice_iocs.append(calculate_ioc(sub_text))
        avg_ioc = sum(slice_iocs) / len(slice_iocs)
        results.append((k, avg_ioc))
        
    # Sort by closeness to English IoC (0.0667)
    results.sort(key=lambda item: abs(item[1] - ENGLISH_IOC))
    return results


def break_vigenere(ciphertext: str, key_length: Optional[int] = None, max_key_len: int = 16) -> Dict:
    """
    Breaks Vigenère cipher automatically:
    1. If key_length is not provided, estimate it using Index of Coincidence.
    2. Partition ciphertext into 'key_length' independent Caesar ciphers.
    3. Solve each slice independently via Chi-Squared frequency analysis to recover each letter of the keyword.
    4. Reconstruct the full keyword and decrypt the entire ciphertext.
    """
    only_letters = "".join(c.upper() for c in ciphertext if c.isalpha())
    
    # 1. Determine key length
    length_candidates = find_vigenere_key_length(ciphertext, max_key_len=max_key_len)
    if key_length is None or key_length <= 0:
        detected_length = length_candidates[0][0]
    else:
        detected_length = key_length
        
    # 2. Recover each letter of the key by solving each slice as a Caesar cipher
    recovered_key_chars = []
    sub_scores = []
    
    for i in range(detected_length):
        slice_text = only_letters[i::detected_length]
        caesar_res = break_caesar(slice_text)
        shift = caesar_res["best_shift"]
        key_letter = chr(ord('A') + shift)
        recovered_key_chars.append(key_letter)
        sub_scores.append(caesar_res["chi_squared"])
        
    recovered_key = "".join(recovered_key_chars)
    decrypted_text = vigenere_decrypt(ciphertext, recovered_key)
    overall_chi = chi_squared_score(decrypted_text)
    
    return {
        "recovered_key": recovered_key,
        "key_length": detected_length,
        "key_length_candidates": length_candidates[:5],
        "decrypted_plaintext": decrypted_text,
        "average_chi_squared": sum(sub_scores) / len(sub_scores) if sub_scores else 0,
        "overall_chi_squared": overall_chi
    }


# =============================================================================
# 5. FORMATTING & REPORTING HELPERS
# =============================================================================

def print_banner():
    banner = r"""
========================================================================
   __  __ _____ ___ ___ ___   ___ ___ ___ _  _ ___ ___ 
  / _|/ /|_   _/ _ \ _ \_ _| / __|_ _| _ \ || | __| _ \
 | (_/ _ \ | || (_) |   /| | | (__ | ||  _/ __ | _||   /
  \__\___/ |_| \___/|_|_|___| \___|___|_| |_||_|___|_|_\
   Automated Classical Cipher & Cryptanalysis Engine
========================================================================
    """
    print(banner)


def display_frequency_table(text: str):
    """Displays an ASCII bar chart comparing text letter frequencies with English norms."""
    counts = get_letter_counts(text)
    total = sum(counts.values())
    if total == 0:
        print("[!] No alphabetic characters in text to analyze.")
        return
        
    print(f"\nLetter Frequency Analysis (Total Letters: {total})")
    print(f"{'Char':<5} {'Count':<7} {'Observed %':<12} {'English %':<12} {'Distribution Visual'}")
    print("-" * 65)
    
    for char in string.ascii_uppercase:
        obs_count = counts.get(char, 0)
        obs_pct = (obs_count / total) * 100
        eng_pct = ENGLISH_FREQ[char] * 100
        bars_obs = "█" * int(obs_pct)
        bars_eng = "░" * int(eng_pct)
        print(f" {char:<4} {obs_count:<7} {obs_pct:>6.2f}%      {eng_pct:>6.2f}%     {bars_obs}")


# =============================================================================
# 6. INTERACTIVE & CLI INTERACTION
# =============================================================================

def run_interactive_mode():
    """Runs a friendly, interactive menu for educational and live interview demos."""
    print_banner()
    while True:
        print("\n--- CIPHER & CRYPTANALYSIS CONTROL MENU ---")
        print("1. Caesar Cipher: Encrypt")
        print("2. Caesar Cipher: Decrypt (known shift)")
        print("3. Caesar Cipher: Auto-Crack (Frequency Analysis / Chi-Squared)")
        print("4. Vigenère Cipher: Encrypt")
        print("5. Vigenère Cipher: Decrypt (known key)")
        print("6. Vigenère Cipher: Auto-Crack (IoC + Slice Frequency Analysis)")
        print("7. Text Frequency Distribution & Index of Coincidence")
        print("8. Run Built-in Demonstration & Self-Test")
        print("9. Exit")
        
        choice = input("\nEnter selection (1-9): ").strip()
        
        if choice == '1':
            text = input("\nEnter Plaintext: ")
            shift_in = input("Enter Shift (0-25): ").strip()
            try:
                shift = int(shift_in)
                cipher = caesar_encrypt(text, shift)
                print("\n[+] Resulting Ciphertext:")
                print(cipher)
            except ValueError:
                print("[!] Invalid integer shift.")
                
        elif choice == '2':
            text = input("\nEnter Ciphertext: ")
            shift_in = input("Enter Shift (0-25): ").strip()
            try:
                shift = int(shift_in)
                plain = caesar_decrypt(text, shift)
                print("\n[+] Recovered Plaintext:")
                print(plain)
            except ValueError:
                print("[!] Invalid integer shift.")
                
        elif choice == '3':
            text = input("\nEnter Caesar Ciphertext to Crack: ")
            result = break_caesar(text)
            print("\n" + "="*50)
            print("  CAESAR CRYPTANALYSIS REPORT")
            print("="*50)
            print(f"Detected Shift Key : {result['best_shift']}")
            print(f"Chi-Squared (χ²)   : {result['chi_squared']:.4f}")
            print("\n[+] Recovered Plaintext:")
            print(result['plaintext'])
            print("\nTop 3 Candidate Shifts:")
            for s, score, sample in result['ranked_candidates'][:3]:
                print(f"  Shift {s:2d} | χ²: {score:8.2f} | Sample: {sample}...")
                
        elif choice == '4':
            text = input("\nEnter Plaintext: ")
            key = input("Enter Keyword (e.g. SECRET, CIPHER): ").strip()
            try:
                cipher = vigenere_encrypt(text, key)
                print("\n[+] Resulting Ciphertext:")
                print(cipher)
            except ValueError as e:
                print(f"[!] Error: {e}")
                
        elif choice == '5':
            text = input("\nEnter Ciphertext: ")
            key = input("Enter Keyword: ").strip()
            try:
                plain = vigenere_decrypt(text, key)
                print("\n[+] Recovered Plaintext:")
                print(plain)
            except ValueError as e:
                print(f"[!] Error: {e}")
                
        elif choice == '6':
            text = input("\nEnter Vigenère Ciphertext to Crack: ")
            k_len_in = input("Enter known key length (press Enter to auto-detect): ").strip()
            k_len = int(k_len_in) if k_len_in.isdigit() else None
            
            print("\n[i] Performing Index of Coincidence test & statistical slicing...")
            result = break_vigenere(text, key_length=k_len)
            print("\n" + "="*50)
            print("  VIGENÈRE CRYPTANALYSIS REPORT")
            print("="*50)
            print(f"Detected Key Length : {result['key_length']}")
            print(f"Recovered Keyword   : {result['recovered_key']}")
            print(f"Overall Chi-Squared : {result['overall_chi_squared']:.4f}")
            print("\nKey Length Candidates (IoC closest to English 0.0667):")
            for k, ioc in result['key_length_candidates']:
                print(f"  Length {k:2d} | Avg IoC: {ioc:.5f}")
            print("\n[+] Recovered Plaintext:")
            print(result['decrypted_plaintext'])
            
        elif choice == '7':
            text = input("\nEnter text to analyze: ")
            ioc = calculate_ioc(text)
            chi = chi_squared_score(text)
            print(f"\nIndex of Coincidence (IoC) : {ioc:.5f} (English ~0.0667, Random ~0.0385)")
            print(f"Chi-Squared vs English (χ²): {chi:.4f}")
            display_frequency_table(text)
            
        elif choice == '8':
            run_builtin_demonstration()
            
        elif choice == '9':
            print("\nExiting Cipher Tool. Happy Cryptanalyzing!\n")
            break
        else:
            print("[!] Invalid option, please choose 1-9.")


def run_builtin_demonstration():
    """Executes a full verification suite demonstrating cipher functionality and cracking."""
    print("\n" + "#"*70)
    print("  RUNNING AUTOMATED BUILT-IN VERIFICATION & DEMONSTRATION")
    print("#"*70)
    
    sample_text = (
        "Cryptography is the practice and study of techniques for secure communication "
        "in the presence of adversarial third parties. Classical ciphers such as Caesar "
        "and Vigenere are susceptible to statistical cryptanalysis using letter frequencies."
    )
    
    print(f"\n[1] Original Plaintext:\n\"{sample_text}\"")
    
    # --- Caesar Demo ---
    caesar_shift = 7
    caesar_cipher = caesar_encrypt(sample_text, caesar_shift)
    print(f"\n[2] Caesar Encrypted (Shift = {caesar_shift}):\n\"{caesar_cipher}\"")
    
    caesar_crack = break_caesar(caesar_cipher)
    print(f"[3] Caesar Auto-Cracker:")
    print(f"    - Identified Shift: {caesar_crack['best_shift']} (Expected: {caesar_shift})")
    print(f"    - Success: {caesar_crack['best_shift'] == caesar_shift}")
    print(f"    - Recovered Text: \"{caesar_crack['plaintext'][:60]}...\"")
    
    # --- Vigenère Demo ---
    vigenere_key = "KEYWORD"
    vigenere_cipher = vigenere_encrypt(sample_text, vigenere_key)
    print(f"\n[4] Vigenère Encrypted (Key = '{vigenere_key}'):\n\"{vigenere_cipher}\"")
    
    vigenere_crack = break_vigenere(vigenere_cipher)
    print(f"[5] Vigenère Auto-Cracker:")
    print(f"    - Detected Key Length: {vigenere_crack['key_length']} (Expected: {len(vigenere_key)})")
    print(f"    - Recovered Keyword: '{vigenere_crack['recovered_key']}' (Expected: '{vigenere_key}')")
    print(f"    - Success: {vigenere_crack['recovered_key'] == vigenere_key}")
    print(f"    - Recovered Text: \"{vigenere_crack['decrypted_plaintext'][:60]}...\"")
    print("\n" + "#"*70 + "\n")


# =============================================================================
# 7. MAIN ARGS ENTRY POINT
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Classical Cryptography & Cryptanalysis Suite (Caesar and Vigenère)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt with Caesar shift 5:
  python cipher_tool.py --cipher caesar --mode encrypt --text "HELLO WORLD" --shift 5

  # Auto-crack a Caesar ciphertext:
  python cipher_tool.py --cipher caesar --mode crack --text "MJQQT BTWQI"

  # Encrypt with Vigenère:
  python cipher_tool.py --cipher vigenere --mode encrypt --text "ATTACK AT DAWN" --key "LEMON"

  # Auto-crack Vigenère ciphertext:
  python cipher_tool.py --cipher vigenere --mode crack --text "LXFOPV EF RNHR"

  # Interactive Menu:
  python cipher_tool.py --interactive
        """
    )
    
    parser.add_argument("--interactive", action="store_true", help="Launch interactive terminal menu")
    parser.add_argument("--demo", action="store_true", help="Run automated demonstration & validation tests")
    parser.add_argument("--cipher", choices=["caesar", "vigenere"], help="Cipher algorithm")
    parser.add_argument("--mode", choices=["encrypt", "decrypt", "crack", "analyze"], help="Operation mode")
    parser.add_argument("--text", type=str, help="Input text or ciphertext")
    parser.add_argument("--shift", type=int, default=3, help="Shift integer for Caesar (default: 3)")
    parser.add_argument("--key", type=str, default="KEY", help="Keyword for Vigenère (default: 'KEY')")
    parser.add_argument("--key-len", type=int, help="Known key length for Vigenère crack (optional)")
    
    args = parser.parse_args()
    
    if args.demo:
        run_builtin_demonstration()
        return
        
    if args.interactive or len(sys.argv) == 1:
        run_interactive_mode()
        return
        
    if not args.text:
        print("[!] Error: --text argument is required when not in interactive or demo mode.")
        sys.exit(1)
        
    if args.mode == "analyze":
        ioc = calculate_ioc(args.text)
        chi = chi_squared_score(args.text)
        print(f"Index of Coincidence (IoC): {ioc:.5f}")
        print(f"Chi-Squared Statistic     : {chi:.4f}")
        display_frequency_table(args.text)
        return
        
    if args.cipher == "caesar":
        if args.mode == "encrypt":
            print(caesar_encrypt(args.text, args.shift))
        elif args.mode == "decrypt":
            print(caesar_decrypt(args.text, args.shift))
        elif args.mode == "crack":
            res = break_caesar(args.text)
            print(f"Detected Shift: {res['best_shift']}")
            print(f"Chi-Squared   : {res['chi_squared']:.4f}")
            print(f"Plaintext     :\n{res['plaintext']}")
            
    elif args.cipher == "vigenere":
        if args.mode == "encrypt":
            print(vigenere_encrypt(args.text, args.key))
        elif args.mode == "decrypt":
            print(vigenere_decrypt(args.text, args.key))
        elif args.mode == "crack":
            res = break_vigenere(args.text, key_length=args.key_len)
            print(f"Detected Key Length: {res['key_length']}")
            print(f"Recovered Keyword  : {res['recovered_key']}")
            print(f"Plaintext          :\n{res['decrypted_plaintext']}")


if __name__ == "__main__":
    main()
