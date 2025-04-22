import modal
from modal import App, Image
import sys
import hashlib # ハッシュ関数(SHA256)のために追加
import os # os.urandom のために追加 (より良い対称鍵生成のため)

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
        "libssl-dev"
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
)
# ---------------------------------------------

stub = modal.Stub("abe-app", image=abe_image)

# バイト列をXORするためのヘルパー関数
def xor_bytes(key_stream, data):
    key_len = len(key_stream)
    data_len = len(data)
    # 必要に応じてキーストリームを繰り返してデータ長に合わせる
    full_key = (key_stream * (data_len // key_len + 1))[:data_len]
    return bytes(b ^ k for b, k in zip(data, full_key))

def _decrypt_message(pk, cpabe, pairing_group, user_key, ciphertexts):
            # --- 文字列の復号 ---
        # 7. ABE暗号文から対称鍵 k' を復号
        # 復号者の秘密鍵 `key` が `ciphertext['policy']` を満たしている必要がある
        k_prime = cpabe.decrypt(pk, ciphertexts[0]['abe_ctxt'], user_key)

        if k_prime is None or k_prime is False:
             # charmのバージョンや実装によって失敗時の返り値が異なる場合がある
            print("Decryption failed: ABE decryption could not recover the symmetric key.")
            print("Check if the key attributes satisfy the policy.")
            print(f"Policy: {ciphertexts[0]['policy']}")
            #print(f"Attributes: {attr_list}")
            return False, None # 失敗を示す

        # 8. 復号した対称鍵 k' から再度バイト列の鍵を派生
        serialized_k_prime = pairing_group.serialize(k_prime)
        derived_key_prime = hashlib.sha256(serialized_k_prime).digest()

        # 9. XOR暗号化されたメッセージを派生鍵で復号 (XORは暗号化も復号も同じ操作)
        decrypted_message_bytes = xor_bytes(derived_key_prime, ciphertexts[0]['sym_ctxt'])

        # 10. バイト列を文字列にデコード
        decrypted_message_str = decrypted_message_bytes.decode('utf-8')
        return decrypted_message_str

@stub.function(timeout=600) # ビルドに時間がかかる場合があるのでタイムアウトを延長
def perform_abe_operations(message_str: str):
    try:
        # Modal環境内でライブラリをインポート
        from charm.toolbox.pairinggroup import PairingGroup, GT
        from ABE.ac17 import AC17CPABE

        # 1. セットアップ
        pairing_group = PairingGroup('MNT224') # 使用する曲線を選択
        cpabe = AC17CPABE(pairing_group, 2) # AC17CPABEを初期化

        # マスター公開鍵とマスター秘密鍵を生成
        (pk, msk) = cpabe.setup()
        print("pk:")
        print(pk)
        print(type(pk))

        # ユーザーの属性リストとそれに対応する秘密鍵を生成
        zaiko_attr_list = ['YASAI', 'HANYO'] #在庫担当の属性
        nikomi_attr_list = ['HANYO']

        zaiko_key = cpabe.keygen(pk, msk, zaiko_attr_list)
        nikomi_key = cpabe.keygen(pk, msk, nikomi_attr_list)

        # --- 文字列の暗号化 ---
        # 2. ランダムな対称鍵 k を生成 (GTの要素として)
        k = pairing_group.random(GT)

        # 3. 対称鍵 k をABEで暗号化
        # アクセスポリシー (このポリシーは上記の attr_list で満たされる必要がある)
        policy_str = '((ONE or THREE) and (TWO))' # 簡略化: ONE, TWO, THREE が必要
        policy_str = 'YASAI'
        
        yasai_ctxt_k = cpabe.encrypt(pk, k, policy_str)

        # 4. 対称鍵 k からバイト列の鍵を派生させる (ハッシュ関数を使用)
        # GT要素をバイト列にシリアライズし、それをハッシュ化する
        serialized_k = pairing_group.serialize(k)
        derived_key = hashlib.sha256(serialized_k).digest() # SHA256を使用

        # 5. 元のメッセージ文字列をバイト列に変換し、派生鍵でXOR暗号化
        message_bytes = message_str.encode('utf-8')
        encrypted_message_bytes = xor_bytes(derived_key, message_bytes)

        # 6. ABE暗号文とXOR暗号化されたメッセージを結合 (辞書など)
        ciphertext = {
            'policy': policy_str, # 復号時にどのポリシーか分かるように含めても良い
            'abe_ctxt': yasai_ctxt_k,
            'sym_ctxt': encrypted_message_bytes
        }
        ciphertexts = []
        ciphertexts.append(ciphertext)

        print("Encryption_successful.")
        # print(f"Ciphertext components: {ciphertext}") # デバッグ用

        # --- 文字列の復号 ---
        zaiko_dec_message = _decrypt_message(pk, cpabe, pairing_group, zaiko_key, ciphertexts)
        nikomi_dec_message = _decrypt_message(pk, cpabe, pairing_group, nikomi_key, ciphertexts)

        # 11. 結果の検証と表示
        print(f"Original message:    '{message_str}'")
        # --- 暗号文バイト列をUTF-8でデコードして表示 (文字化け想定) ---
        #try:
        #    # UTF-8でデコード試行。デコードできないバイトは置換文字''に置き換える
        #    decoded_sym_ctxt = ciphertext['sym_ctxt'].decode('utf-8', errors='strict')
        #    print(f"Ciphertext (sym_ctxt decoded as UTF-8, likely garbled): '{decoded_sym_ctxt}'")
        #except Exception as e:
        #    # 万が一デコード処理自体でエラーが出た場合 (通常は errors='replace' で回避されるはず)
        #    print(f"Could not decode sym_ctxt as UTF-8: {e}")
        #    # 元のバイト列表現も表示しておく
        #    print(f"Ciphertext (sym_ctxt raw bytes): {ciphertext['sym_ctxt']}")
        # -----------------------------------------------------------
        print(f"zaiko Decrypted message:   '{zaiko_dec_message}'")
        print(f"nikomi Decrypted message:   '{nikomi_dec_message}'")

        #if decrypted_message_str == message_str:
        #    print("Successful decryption!")
        #    return True, decrypted_message_str # 成功と復号結果を返す
        #else:
        #    print("Decryption failed! (Message mismatch)")
        #    # 元のkと復号したk'が一致するか確認するデバッグコード
        ##    if k == k_prime:
         #        print("Symmetric key k was recovered correctly, issue might be in XOR or hashing.")
         #   else:
         #        print("Symmetric key k was NOT recovered correctly.")
         #        print(f"Original k hash: {hashlib.sha256(serialized_k).hexdigest()}")
         #        print(f"Decrypted k' hash: {hashlib.sha256(serialized_k_prime).hexdigest()}")

            #return False, None # 失敗を示す

    except ImportError as e:
        print(f"Import Error: {e}. Check library paths and installation in the Modal image.")
        # PYTHONPATHの確認やcharm, ABEライブラリのインストール場所を確認
        # 例: sys.path を表示してみる
        print("Current sys.path:", sys.path)
        # site-packagesの場所を確認
        import site
        print("Site packages:", site.getsitepackages())
        return False, None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
        return False, None

@stub.local_entrypoint()
def main():
    message_to_encrypt = "これは秘密のメッセージです。"
    print(f"Attempting to encrypt and decrypt: '{message_to_encrypt}'")
    # Modal関数を呼び出し
    success, decrypted_msg = perform_abe_operations.remote(message_to_encrypt)

    print("-" * 20)
    if success:
        print(f"Operation completed successfully. Decrypted message: '{decrypted_msg}'")
    else:
        print("Operation failed.")

