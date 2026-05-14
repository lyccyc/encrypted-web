import os
import pandas as pd
import hashlib
from crypto import ff1_lib, ff3_lib
from ff3 import FF3Cipher
from dotenv import load_dotenv

load_dotenv()
ENCRYPTION_KEY = os.getenv('KEY') 
os.environ['KEY'] = ENCRYPTION_KEY

def encryption(input_file, output_dir, algo):
    """
    encryption task entry point
    """
    df = pd.read_csv(input_file, dtype=str, encoding='utf-8-sig')

    initial_cols = ["Numeric", "plaintext", "original_plaintext", "original_Ciphertext", 
                    "Encrypted_Numeric", "Encrypted_ID", "Status", "plus50", "Swap_Index"]
    for col in initial_cols:
        if col not in df.columns:
            df[col] = ""
    df["Swap_Index"] = -1
    df["plus50"] = False

    lib = ff1_lib if algo == 'FF1' else ff3_lib

    for idx in df.index:
        original_id = str(df.loc[idx, "ID"]).strip()
        numeric = lib.IDN_to_number(original_id)
        if numeric:
            df.loc[idx, "Numeric"] = numeric
            df.loc[idx, "plaintext"] = numeric[:9]
            df.loc[idx, "original_plaintext"] = numeric[:9]
        else:
            df.loc[idx, "Status"] = "INVALID_FORMAT"

    df = _process_encryption_loop(df, lib)
    
    base_name = os.path.splitext(os.path.basename(input_file))[0]
    
    algo_tag = "ff1" if algo == 'FF1' else "ff3"

    # Example A : include logs and metadata
    # meta_ff1_{filename}.csv
    metadata_filename = f"meta_{algo_tag}_{base_name}.csv"
    metadata_path = os.path.join(output_dir, metadata_filename)
    df.to_csv(metadata_path, index=False, encoding='utf-8-sig')

    # Example B : public results only
    # encrypt_ff1_{filename}.csv
    exclude_cols = ["Numeric", "plaintext", "original_plaintext", "original_Ciphertext", 
                    "Encrypted_Numeric", "Status", "plus50", "Swap_Index", 
                    "Decrypted_Numeric", "Decrypted_ID",
                    "First_Try_Before_Adjust", "First_Try_Before_Swap"]
    
    public_cols = [c for c in df.columns if c not in exclude_cols]
    public_df = df[public_cols]
    
    public_filename = f"encrypt_{algo_tag}_{base_name}.csv"
    public_path = os.path.join(output_dir, public_filename)
    public_df.to_csv(public_path, index=False, encoding='utf-8-sig')

    return public_path, metadata_path


def decryption(input_file, output_dir):
    """
    decryption task entry point
    """
    df = pd.read_csv(input_file, dtype=str)
    
    filename = os.path.basename(input_file).lower()
    
    if "ff1" in filename:
        algo = "FF1"
        lib = ff1_lib
        print(f"Detected Algorithm: FF1 from filename '{filename}'")
    elif "ff3" in filename:
        algo = "FF3-1" 
        lib = ff3_lib
        print(f"Detected Algorithm: FF3 from filename '{filename}'")
    else:
        print(f"Warning: Cannot detect algorithm from filename '{filename}', defaulting to FF3-1")
        algo = "FF3-1"
        lib = ff3_lib

    if "Decrypted_ID" not in df.columns:
        df["Decrypted_ID"] = ""

    for idx in df.index:
        status = df.loc[idx, "Status"]
        enc_numeric = df.loc[idx, "Encrypted_Numeric"]
        
        if pd.isna(status) or status in ["FAILED", "INVALID_FORMAT", ""]:
            df.loc[idx, "Decrypted_ID"] = "N/A"
            continue

        try:
            tweak = lib.generate_tweak(idx)
            
            if algo == 'FF1':
                tweak_bytes = tweak.encode('utf-8')
                key_bytes = os.getenv('KEY').encode('utf-8')
                decrypted_numeric = lib.FF1_decrypt(enc_numeric, 10, key_bytes, tweak_bytes)
            else:
                cipher = FF3Cipher(os.getenv('KEY'), tweak)
                decrypted_numeric = cipher.decrypt(enc_numeric)

            plus50 = str(df.loc[idx, "plus50"]).upper() == "TRUE"
            
            if status == "FIXED_50" or (status == "SWAPPED" and plus50):
                orig_plain = str(df.loc[idx, "original_plaintext"])
                is_local = int(orig_plain[:2]) < 50
                dec_prefix = int(decrypted_numeric[:2])
                
                if is_local:
                    final_prefix = dec_prefix - 50
                else:
                    final_prefix = dec_prefix + 50
                
                decrypted_numeric = str(final_prefix).zfill(2) + decrypted_numeric[2:]

            decrypted_id = lib.number_to_IDN(decrypted_numeric)
            df.loc[idx, "Decrypted_ID"] = decrypted_id

        except Exception as e:
            # print(f"Decryption error at index {idx}: {e}")
            df.loc[idx, "Decrypted_ID"] = "ERROR"

    wanted_columns = ["Encrypted_ID", "Decrypted_ID"]
    final_cols = [c for c in wanted_columns if c in df.columns]
    result_df = df[final_cols]

    output_filename = f"decrypted_{os.path.basename(input_file)}"
    output_path = os.path.join(output_dir, output_filename)
    result_df.to_csv(output_path, index=False, encoding='utf-8-sig')
    
    return output_path

def _process_encryption_loop(df, lib):
    """
    kernal encryption processing loop
    """
    for idx in df.index:
        if df.loc[idx, "Status"] in ["OK", "FIXED_50", "SWAPPED", "FAILED", "INVALID_FORMAT"]:
            continue

        plaintext = df.loc[idx, "plaintext"]
        if pd.isna(plaintext) or plaintext == "":
            continue

        # 判斷本國/外籍
        try:
            is_local = int(plaintext[:2]) < 50
        except ValueError:
            df.loc[idx, "Status"] = "INVALID_FORMAT"
            continue
        
        res = lib.encrypt_with_mod(plaintext, idx, is_local)
        
        processed_plain, encrypted, status, plus50, first_try = res

        if status == "FAILED":
            df.loc[idx, "original_Ciphertext"] = encrypted
            # swap 
            swap_success = lib.encrypt_with_swap(df, idx)

            if swap_success:
                new_numeric = df.loc[idx, "Encrypted_Numeric"]
                df.loc[idx, "Encrypted_ID"] = lib.number_to_IDN(new_numeric)
            else:
                df.loc[idx, "Status"] = "FAILED"
                df.loc[idx, "Encrypted_ID"] = "A000000000" # Fallback 
        else:
            # successful encryption
            df.loc[idx, "plaintext"] = processed_plain
            df.loc[idx, "Encrypted_Numeric"] = encrypted
            df.loc[idx, "Status"] = status
            df.loc[idx, "plus50"] = plus50
            
            # convert to  IDN
            enc_id = lib.number_to_IDN(df.loc[idx, "Encrypted_Numeric"])
            df.loc[idx, "Encrypted_ID"] = enc_id

    return df