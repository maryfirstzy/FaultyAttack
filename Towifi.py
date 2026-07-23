import hashlib
import os
import base58

def hex_to_wif(private_key_hex, compressed=True):
    """
    Converts a 64-character hexadecimal private key into Wallet Import Format (WIF).
    """
    # 1. Add Mainnet Prefix (0x80)
    prefix = "80"
    extended_key = prefix + private_key_hex

    # 2. Add Compression Flag (0x01) if modern compressed address format is used
    if compressed:
        extended_key += "01"

    # Convert hexadecimal string to raw bytes
    extended_bytes = bytes.fromhex(extended_key)

    # 3. Calculate SHA-256 Checksum (Double SHA-256)
    first_sha = hashlib.sha256(extended_bytes).digest()
    second_sha = hashlib.sha256(first_sha).digest()
    
    # Take the first 4 bytes of the second hash as the checksum
    checksum = second_sha[:4]

    # 4. Append Checksum to the extended key bytes
    final_bytes = extended_bytes + checksum

    # 5. Base58 Encode the final byte array
    wif_string = base58.b58encode(final_bytes).decode('utf-8')
    return wif_string

def process_found_keys():
    found_file = "Found.txt"
    output_file = "Spendable_WIF.txt"

    if not os.path.exists(found_file):
        print(f"[!] {found_file} not found. Please run the Lattice Attack script first.")
        return

    print(f"[*] Reading private keys from {found_file}...")
    
    wif_records = []
    
    with open(found_file, "r") as f:
        lines = f.readlines()

    current_address = "Unknown"
    for line in lines:
        line = line.strip()
        if "VULNERABLE ADDRESS:" in line:
            current_address = line.split("VULNERABLE ADDRESS:")[1].strip()
        elif "RECOVERED PRIVATE KEY:" in line:
            raw_hex = line.split("RECOVERED PRIVATE KEY:")[1].strip()
            
            # Clean up potential hex notation prefixes (0x)
            if raw_hex.lower().startswith("0x"):
                raw_hex = raw_hex[2:]
            
            # Pad with leading zeros if it's shorter than 64 characters (32 bytes)
            raw_hex = raw_hex.zfill(64)

            try:
                # Generate both formats for safety
                compressed_wif = hex_to_wif(raw_hex, compressed=True)
                uncompressed_wif = hex_to_wif(raw_hex, compressed=False)

                wif_records.append((current_address, raw_hex, compressed_wif, uncompressed_wif))
                print(f"[+] Successfully converted key for address: {current_address}")
            except Exception as e:
                print(f"[!] Error processing hex key '{raw_hex}': {e}")

    # Write the spendable WIF keys to the final output file
    if wif_records:
        with open(output_file, "w") as f:
            for addr, hex_key, comp_wif, uncomp_wif in wif_records:
                f.write(f"Bitcoin Address: {addr}\n")
                f.write(f"Raw Hex Key:     {hex_key}\n")
                f.write(f"WIF Compressed:  {comp_wif}  (Starts with K or L - Use this for standard wallets)\n")
                f.write(f"WIF Legacy:      {uncomp_wif}  (Starts with 5)\n")
                f.write("-" * 80 + "\n")
        print(f"\n[+] Conversion complete! Spendable strings saved to: {output_file}")
    else:
        print("[*] No private keys were found in the source file format to convert.")

if __name__ == "__main__":
    process_found_keys()
