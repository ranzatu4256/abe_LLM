import modal
from modal import App, Image
import sys
import hashlib # ハッシュ関数(SHA256)のために追加
import os # os.urandom のために追加 (より良い対称鍵生成のため)
import traceback # For detailed error logging

# --- abe_image definition remains the same ---
abe_image = (
    Image.debian_slim(python_version="3.11")
    .apt_install(
        "wget",
        "git",
        "sudo",
        "subversion",
        "m4",
        "python3-setuptools",
        "python3-dev",
        "libgmp-dev",
        "flex", # flexを追加
        "bison", # bisonを追加
        "libssl-dev",
    )
    .run_commands(
        "git clone https://github.com/JHUISI/charm.git /charm",
        "cd charm && sudo ./configure.sh",
        # PBCのインストール手順を修正 (charmのconfigure.shが内部でPBCを処理する可能性もあるが、明示的に)
        "cd charm && wget http://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && tar -xzf pbc-0.5.14.tar.gz",
        "cd charm/pbc-0.5.14 && ./configure && make && sudo make install",
        # charm本体のビルドとインストール
        "cd charm && sudo make && sudo make install",
        # ライブラリパスの更新
        "sudo ldconfig",
        # テスト実行 (オプション)
        #"cd charm && sudo make test"
    )
    .run_commands(
        # ABEライブラリのクローンとインストール (makeが必要か、pipだけで良いかはリポジトリによる)
        # sagrawal87/ABE の README を見ると pip install . で良さそう
        "git clone https://github.com/sagrawal87/ABE.git /ABE",
        # pip install の前に charm が python path にないと失敗する可能性があるので site-packages にリンクを貼るか PYTHONPATH を設定
        # または、charmのインストール後にpip installを実行
        "cd /ABE && pip install .",
        # サンプル実行はここでは不要
        # "cd ABE && python samples/main.py"
    )
    # charmライブラリへのパスを通す必要があるかもしれない
    # .env({"PYTHONPATH": "/usr/local/lib/python3.11/site-packages:/charm"}) # 環境に合わせて調整
    .pip_install(
        "transformers"
    )
)
# ---------------------------------------------

stub = modal.Stub("abe-app", image=abe_image)

# バイト列をXORするためのヘルパー関数
def xor_bytes(key_stream, data):
    """Performs XOR operation between a key stream and data bytes."""
    key_len = len(key_stream)
    data_len = len(data)
    # Repeat key stream to match data length if necessary
    full_key = (key_stream * (data_len // key_len + 1))[:data_len]
    return bytes(b ^ k for b, k in zip(data, full_key))

# --- Key Generation Function ---
def _generate_keys(cpabe, pairing_group, attributes: list):
    """
    Generates Master Public Key (PK), Master Secret Key (MSK),
    and a User Secret Key (SK) for the given attributes.

    Args:
        cpabe: An initialized AC17CPABE instance.
        pairing_group: The PairingGroup instance.
        attributes: A list of strings representing the user's attributes.

    Returns:
        A tuple (pk, msk, user_key) or (None, None, None) on failure.
    """
    try:
        print("Generating Master Public Key (PK) and Master Secret Key (MSK)...")
        (pk, msk) = cpabe.setup()
        print("PK and MSK generated.")
        # print("PK:", pk) # Optional: Print for debugging
        # print("MSK:", msk) # Optional: Print for debugging

        print(f"Generating User Secret Key (SK) for attributes: {attributes}...")
        user_key = cpabe.keygen(pk, msk, attributes)
        print("User Secret Key generated.")
        # print("User Key:", user_key) # Optional: Print for debugging

        if pk is None or msk is None or user_key is None:
            print("Error: Key generation failed (setup or keygen returned None).")
            return None, None, None

        return pk, msk, user_key
    except Exception as e:
        print(f"An error occurred during key generation: {e}")
        traceback.print_exc()
        return None, None, None

# --- Encryption Function ---
def _encrypt_message(pk, cpabe, pairing_group, message_str: str, policy_str: str):
    """
    Encrypts a message string using ABE with a symmetric key (hybrid approach).

    Args:
        pk: The master public key.
        cpabe: An initialized AC17CPABE instance.
        pairing_group: The PairingGroup instance.
        message_str: The message string to encrypt.
        policy_str: The access policy string for the ABE encryption.

    Returns:
        A dictionary containing the ABE ciphertext ('abe_ctxt') and
        the symmetrically encrypted message ('sym_ctxt'), or None on failure.
    """
    try:
        from charm.toolbox.pairinggroup import GT # Import GT here

        print(f"Encrypting message with policy: '{policy_str}'")
        # 1. Generate a random symmetric key k (as a GT element)
        k = pairing_group.random(GT)
        print("Generated random symmetric key (k).")

        # 2. Encrypt the symmetric key k using ABE
        abe_ctxt = cpabe.encrypt(pk, k, policy_str)
        if abe_ctxt is None:
             print("Error: ABE encryption of symmetric key failed.")
             return None
        print("Symmetric key encrypted with ABE.")

        # 3. Derive a byte key from the symmetric key k using a hash function
        serialized_k = pairing_group.serialize(k)
        derived_key = hashlib.sha256(serialized_k).digest() # Use SHA256
        # print(f"Derived byte key hash (SHA256): {derived_key.hex()}") # Optional debug

        # 4. Encrypt the original message string using the derived byte key (XOR)
        message_bytes = message_str.encode('utf-8')
        encrypted_message_bytes = xor_bytes(derived_key, message_bytes)
        print("Original message encrypted with derived key (XOR).")

        # 5. Combine ABE ciphertext and symmetrically encrypted message
        ciphertext = {
            'policy': policy_str, # Include policy for context
            'abe_ctxt': abe_ctxt,
            'sym_ctxt': encrypted_message_bytes
        }
        print("Encryption successful.")
        return ciphertext
    except Exception as e:
        print(f"An error occurred during encryption: {e}")
        traceback.print_exc()
        return None

# --- Decryption Function ---
def _decrypt_message(pk, cpabe, pairing_group, user_key, ciphertext):
    """
    Decrypts a message encrypted using the hybrid ABE-symmetric scheme.

    Args:
        pk: The master public key.
        cpabe: An initialized AC17CPABE instance.
        pairing_group: The PairingGroup instance.
        user_key: The user's secret key corresponding to their attributes.
        ciphertext: The ciphertext dictionary containing 'abe_ctxt' and 'sym_ctxt'.

    Returns:
        The decrypted message string, or None on failure.
    """
    try:
        print("Attempting decryption...")
        # 1. Decrypt the ABE ciphertext to recover the symmetric key k'
        # This requires the user_key attributes to satisfy the ciphertext policy
        k_prime = cpabe.decrypt(pk, ciphertext['abe_ctxt'], user_key)

        if k_prime is None or k_prime is False:
            # charm versions might return None or False on failure
            print("Decryption failed: ABE could not recover the symmetric key.")
            print("Verify if the user key attributes satisfy the policy.")
            print(f"Policy required: {ciphertext.get('policy', 'N/A')}")
            # Consider logging user_key attributes here if possible/safe
            return None
        print("Symmetric key recovered via ABE decryption.")

        # 2. Derive the byte key again from the recovered symmetric key k'
        serialized_k_prime = pairing_group.serialize(k_prime)
        derived_key_prime = hashlib.sha256(serialized_k_prime).digest()
        # print(f"Derived byte key hash from k' (SHA256): {derived_key_prime.hex()}") # Optional debug

        # 3. Decrypt the symmetrically encrypted message using the derived byte key (XOR)
        decrypted_message_bytes = xor_bytes(derived_key_prime, ciphertext['sym_ctxt'])
        print("Symmetric ciphertext decrypted with derived key (XOR).")

        # 4. Decode the decrypted bytes back to a string
        decrypted_message_str = decrypted_message_bytes.decode('utf-8')
        print("Decryption successful.")
        return decrypted_message_str

    except UnicodeDecodeError as e:
        print(f"Decryption failed: Could not decode decrypted bytes to UTF-8. {e}")
        print(f"Raw decrypted bytes (may contain sensitive info): {decrypted_message_bytes!r}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during decryption: {e}")
        traceback.print_exc()
        return None

def _encrypt_tokenizer(pk, cpabe, pairing_group, message_str: str, policy_str: str):
    from transformers import AutoTokenizer
    os.system("git clone https://huggingface.co/llm-jp/llm-jp-3-3.7b-instruct") #モデルダウンロード
    import json

    with open('llm-jp-3-3.7b-instruct/tokenizer.json', encoding="utf-8", mode='r') as js:
        dict_json = json.load(js)

    model_id = "llm-jp-3-3.7b-instruct"
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    
    model = dict_json["model"]["vocab"]
    secrets_token = tokenizer.encode("東京都,調布市")

    access_policy = '((ONE or THREE) and (TWO))' # Example policy
    print("modelの29249")
    print(model[29249][0])

    model_size = len(model)
    for m in range(model_size):
        if m in secrets_token and m != 1:
            ciphertext = _encrypt_message(pk, cpabe, pairing_group, message_str, access_policy)
            model[m][0] = ciphertext['sym_ctxt'].hex()

    print("modelの29249")
    print(model[29249][0])
    dict_json["model"]["vocab"] = model

    with open("edited_tokenizer.json", encoding="utf-8", mode="w") as js:
        json.dump(dict_json, js, indent=2)
    return


@stub.function(timeout=600) # Extend timeout for potential build/setup time
def perform_abe_operations(message_str: str):
    """
    Orchestrates ABE setup, key generation, encryption, and decryption.
    """
    try:
        # Import necessary libraries within the Modal function environment
        from charm.toolbox.pairinggroup import PairingGroup
        from ABE.ac17 import AC17CPABE

        # --- Initialization ---
        print("Initializing Pairing Group and CPABE...")
        pairing_group = PairingGroup('MNT224') # Choose the curve
        cpabe = AC17CPABE(pairing_group, 2) # Initialize AC17 CP-ABE scheme (verbose=2)
        print("Initialization complete.")

        # --- Key Generation ---
        # Define user attributes for which to generate a key
        user_attributes = ['ONE', 'TWO']
        pk, msk, user_key = _generate_keys(cpabe, pairing_group, user_attributes)

        if pk is None or msk is None or user_key is None:
            print("Key generation failed. Aborting.")
            return False, None

        # --- Encryption ---
        # Define the access policy for the message
        access_policy = '((ONE or THREE) and (TWO))' # Example policy
        ciphertext = _encrypt_message(pk, cpabe, pairing_group, message_str, access_policy)

        _encrypt_tokenizer(pk, cpabe, pairing_group, message_str, access_policy)
        _encrypt_tokenizer(pk, cpabe, pairing_group, message_str, access_policy)

        if ciphertext is None:
            print("Encryption process failed. Aborting.")
            return False, None

        # --- Display Ciphertext Info (Optional) ---
        print("\n--- Ciphertext Information ---")
        print(f"Policy: {ciphertext['policy']}")
        # Displaying abe_ctxt is usually too verbose and complex
        # print(f"ABE Ciphertext (k): {ciphertext['abe_ctxt']}")
        try:
            # Attempt to decode sym_ctxt as UTF-8 for display (likely garbled)
            #decoded_sym_ctxt = ciphertext['sym_ctxt'].decode('utf-8', errors='replace')
            decoded_sym_ctxt = ciphertext['sym_ctxt'].hex()
            print(f"Symmetric Ciphertext (decoded as UTF-8, likely garbled): '{decoded_sym_ctxt}'")
        except Exception as e:
            print(f"Could not decode sym_ctxt for display: {e}")
            print(f"Symmetric Ciphertext (raw bytes): {ciphertext['sym_ctxt']}")
        print("----------------------------\n")

        # --- Decryption ---
        # Attempt decryption using the generated user_key
        print(f"Attempting decryption using key with attributes: {user_attributes}")
        decrypted_message = _decrypt_message(pk, cpabe, pairing_group, user_key, ciphertext)

        # --- Result Verification ---
        if decrypted_message is not None:
            print(f"\nOriginal message:    '{message_str}'")
            print(f"Decrypted message:   '{decrypted_message}'")
            if decrypted_message == message_str:
                print("\nSuccessful decryption and message match!")
                return True, decrypted_message # Success
            else:
                print("\nDecryption failed! (Message mismatch after successful ABE/XOR steps)")
                # This case indicates a potential issue in the logic if ABE/XOR didn't error
                return False, None # Failure
        else:
            # _decrypt_message already printed the failure reason
            print("\nDecryption process failed.")
            return False, None # Failure

    except ImportError as e:
        print(f"Import Error: {e}. Check library paths and installation in the Modal image.")
        print("Current sys.path:", sys.path)
        import site
        print("Site packages:", site.getsitepackages())
        return False, None
    except Exception as e:
        print(f"An unexpected error occurred in perform_abe_operations: {e}")
        traceback.print_exc()
        return False, None

@stub.local_entrypoint()
def main():
    message_to_encrypt = "市"
    print(f"Attempting to encrypt and decrypt: '{message_to_encrypt}'")
    # Call the orchestrator Modal function
    success, decrypted_msg = perform_abe_operations.remote(message_to_encrypt)

    print("-" * 20)
    if success:
        print(f"Operation completed successfully. Decrypted message: '{decrypted_msg}'")
    else:
        print("Operation failed.")
