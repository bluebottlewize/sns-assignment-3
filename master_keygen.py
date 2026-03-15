import json
import os
from crypto_utils import generate_schnorr_keypair

def export_key(filename, data):
    """Helper to save keys to JSON."""
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def generate_system_keys():
    print("Generating Independent Schnorr Key Pairs for Distributed Authorities...")
    
    # 1. Define the Authority IDs 
    as_nodes = ["AS_1", "AS_2", "AS_3"]
    tgs_nodes = ["TGS_1", "TGS_2", "TGS_3"]
    all_nodes = as_nodes + tgs_nodes
    
    private_keys = {}
    public_keys = {}
    
    # 2. Generate and distribute keys independently [cite: 42]
    for node_id in all_nodes:
        print(f"Generating keys for {node_id}...")
        priv_key, pub_key = generate_schnorr_keypair()
        
        # Save private key securely (Simulating independent storage) 
        priv_filename = f"{node_id.lower()}_private.json"
        private_keys[node_id] = priv_key

        export_key(priv_filename, {
            "authority_id": node_id,
            "private_key": priv_key
        })
        
        # Collect public keys for global distribution [cite: 46]
        public_keys[node_id] = pub_key

    # 3. Publish Public Keys to a central directory accessible by clients/services
    export_key("public_keys.json", public_keys)
    
    print("\nKey generation complete!")
    print("Private keys saved to individual node files (e.g., as_1_private.json).")
    print("All public keys published to 'public_keys.json'.")

    return private_keys, public_keys

if __name__ == "__main__":
    private_keys, public_keys = generate_system_keys()