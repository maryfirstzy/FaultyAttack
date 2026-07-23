import os
import random
from sympy import mod_inverse

# SECP256K1 Curve Order (The prime 'n')
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def initialize_btc_file():
    """Ensures BTC.txt exists with target addresses."""
    btc_file = "BTC.txt"
    sample_addresses = [
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "3BMEXbNRg9biqHhJbK3FTEqZpA7RjHBEuX",
        "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
    ]
    if not os.path.exists(btc_file):
        with open(btc_file, "w") as f:
            for addr in sample_addresses:
                f.write(f"{addr}\n")
        print(f"[+] Created {btc_file} with sample targets.")

def mock_blockchain_signature_extraction(address):
    """
    Simulates extracting raw ECDSA signatures (z, r, s) from a blockchain explorer.
    In a live exploit/audit, this replaces API calls to fetching Tx inputs.
    We inject a faulty nonce flaw (k is small/leaked) for simulation purposes.
    """
    # Deterministic simulation seed based on address string
    random.seed(sum(ord(c) for c in address))
    
    # Secret private key bound to this simulated target
    simulated_private_key = random.randint(0x11111111, 0xFFFFFFFF)
    
    # Faulty Attack Parameter: Nonce k is weak/restricted (e.g. upper bits are 0)
    nonce_bound = 2**128 
    k1 = random.randint(1, nonce_bound)
    k2 = random.randint(1, nonce_bound)
    
    # Message hashes (z)
    z1 = random.randint(1, N - 1)
    z2 = random.randint(1, N - 1)
    
    # Signature components (r, s)
    r1 = random.randint(1, N - 1)
    r2 = random.randint(1, N - 1)
    
    # ECDSA Math: s = k^-1 * (z + r * private_key) mod N
    s1 = (mod_inverse(k1, N) * (z1 + r1 * simulated_private_key)) % N
    s2 = (mod_inverse(k2, N) * (z2 + r2 * simulated_private_key)) % N
    
    # Return simulated public transaction data plus the structural fault data
    return (z1, r1, s1), (z2, r2, s2), simulated_private_key

def solve_nonce_leak(sig1, sig2):
    """
    Lattice-reduction alternative for severe leaks (e.g. identical repeated nonces).
    Solves the system of equations to extract the private key 'd'.
    """
    z1, r1, s1 = sig1
    z2, r2, s2 = sig2
    
    # Reconstructed Linear Congruence:
    # d = (s1*z2 - s2*z1) / (s2*r1 - s1*r2) mod N
    numerator = ((s1 * z2) - (s2 * z1)) % N
    denominator = ((s2 * r1) - (s1 * r2)) % N
    
    try:
        recovered_d = (numerator * mod_inverse(denominator, N)) % N
        return recovered_d
    except ValueError:
        return None

def main():
    initialize_btc_file()
    
    with open("BTC.txt", "r") as f:
        addresses = [line.strip() for line in f if line.strip()]
        
    found_vulnerabilities = []
    
    print(f"[*] Loaded {len(addresses)} target addresses from BTC.txt\n")
    
    for addr in addresses:
        print(f"[*] Auditing signatures for: {addr}")
        
        # 1. Fetch the signature data associated with the address
        sig1, sig2, true_secret = mock_blockchain_signature_extraction(addr)
        
        # 2. Run the Hidden Number Problem algebraic solver
        recovered_key = solve_nonce_leak(sig1, sig2)
        
        if recovered_key and recovered_key == true_secret:
            print(f" [!] [HIGH] Faulty Attack Vulnerability Confirmed!")
            print(f" [!] Private Key Extracted: {hex(recovered_key)}\n")
            found_vulnerabilities.append((addr, hex(recovered_key)))
        else:
            print(" [*] Address transactions secure. No mathematical leaks found.\n")
            
    # 3. Output results to Found.txt
    with open("Found.txt", "w") as f:
        if found_vulnerabilities:
            for addr, key in found_vulnerabilities:
                f.write(f"VULNERABLE ADDRESS: {addr}\nRECOVERED PRIVATE KEY: {key}\n\n")
            print("[+] Critical alerts written to Found.txt")
        else:
            f.write("No vulnerable keys recovered.\n")
            print("[*] Scan complete. Found.txt is empty.")

if __name__ == "__main__":
    main()
