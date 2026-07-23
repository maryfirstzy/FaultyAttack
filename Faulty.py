import os

def check_vulnerabilities():
    # Get the absolute path of the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Combine the script directory with the filenames
    btc_file = os.path.join(script_dir, "BTC.txt")
    found_file = os.path.join(script_dir, "Found.txt")
    
    # Pre-defined list of monitored/vulnerable addresses
    monitored_addresses = {
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 
        "3BMEXbNRg9biqHhJbK3FTEqZpA7RjHBEuX"
    }

    # Ensure BTC.txt exists before proceeding
    if not os.path.exists(btc_file):
        print(f"[!] {btc_file} not found. Please create it and add Bitcoin addresses.")
        return

    # Read addresses from BTC.txt
    with open(btc_file, "r") as f:
        target_addresses = [line.strip() for line in f if line.strip()]

    # Check for vulnerability matches
    found_matches = []
    for address in target_addresses:
        if address in monitored_addresses:
            found_matches.append(address)
            print(f"[!] [HIGH] Faulty Attack / Malicious Match Found: {address}")

    # Write found addresses to Found.txt
    if found_matches:
        with open(found_file, "w") as f:
            for match in found_matches:
                f.write(f"{match}\n")
        print(f"[+] Vulnerable addresses logged to {found_file}")
    else:
        print("[*] No matching vulnerabilities or faulty attacks detected in the provided addresses.")

if __name__ == "__main__":
    check_vulnerabilities()
