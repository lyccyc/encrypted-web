"""
分開處理本國和外籍
對應主程式: ff3_main_v2.py
"""

import hashlib
from ff3 import FF3Cipher
import pandas as pd
import os
from dotenv import load_dotenv

load_dotenv()
KEY = os.getenv('KEY')

letter_map = {
    "A1": "00",
    "B1": "01",
    "C1": "02",
    "D1": "03",
    "E1": "04",
    "F1": "05",
    "G1": "06",
    "H1": "07",
    "I1": "08",
    "J1": "09",
    "K1": "10",
    "L1": "11",
    "M1": "12",
    "N1": "13",
    "O1": "14",
    "P1": "15",
    "Q1": "16",
    "R1": "17",
    "S1": "18",
    "T1": "19",
    "U1": "20",
    "V1": "21",
    "W1": "22",
    "X1": "23",
    "Z1": "24",
    "A2": "25",
    "B2": "26",
    "C2": "27",
    "D2": "28",
    "E2": "29",
    "F2": "30",
    "G2": "31",
    "H2": "32",
    "I2": "33",
    "J2": "34",
    "K2": "35",
    "L2": "36",
    "M2": "37",
    "N2": "38",
    "O2": "39",
    "P2": "40",
    "Q2": "41",
    "R2": "42",
    "S2": "43",
    "T2": "44",
    "U2": "45",
    "V2": "46",
    "W2": "47",
    "X2": "48",
    "Z2": "49",
    "A8": "50",
    "B8": "51",
    "C8": "52",
    "D8": "53",
    "E8": "54",
    "F8": "55",
    "G8": "56",
    "H8": "57",
    "I8": "58",
    "J8": "59",
    "K8": "60",
    "L8": "61",
    "M8": "62",
    "N8": "63",
    "O8": "64",
    "P8": "65",
    "Q8": "66",
    "R8": "67",
    "S8": "68",
    "T8": "69",
    "U8": "70",
    "V8": "71",
    "W8": "72",
    "X8": "73",
    "Z8": "74",
    "A9": "75",
    "B9": "76",
    "C9": "77",
    "D9": "78",
    "E9": "79",
    "F9": "80",
    "G9": "81",
    "H9": "82",
    "I9": "83",
    "J9": "84",
    "K9": "85",
    "L9": "86",
    "M9": "87",
    "N9": "88",
    "O9": "89",
    "P9": "90",
    "Q9": "91",
    "R9": "92",
    "S9": "93",
    "T9": "94",
    "U9": "95",
    "V9": "96",
    "W9": "97",
    "X9": "98",
    "Z9": "99",
}
translate_map = {
    "A": "10",
    "B": "11",
    "C": "12",
    "D": "13",
    "E": "14",
    "F": "15",
    "G": "16",
    "H": "17",
    "I": "34",
    "J": "18",
    "K": "19",
    "L": "20",
    "M": "21",
    "N": "22",
    "O": "35",
    "P": "23",
    "Q": "24",
    "R": "25",
    "S": "26",
    "T": "27",
    "U": "28",
    "V": "29",
    "W": "32",
    "X": "30",
    "Z": "33",
}

reverse_map = {v: k for k, v in letter_map.items()}
df = pd.DataFrame()
df["Numeric"] = ""
df["Invalid_Ciphertext"] = ""
df["Encrypted_Numeric"] = ""
df["Encrypted_ID"] = ""
df["Status"] = ""
df["Swap_Index"] = -1
df["Plus50"] = False
df["Decrypted_Numeric"] = ""
df["Decrypted_ID"] = ""


def calculate_check_digit(id9):
    weights = [1, 9, 8, 7, 6, 5, 4, 3, 2, 1]
    n0 = int(translate_map[id9[0]])
    nums = [n0 // 10, n0 % 10] + [int(ch) for ch in id9[1:]]
    weights = [1, 9, 8, 7, 6, 5, 4, 3, 2, 1]
    total = sum([a * b for a, b in zip(nums, weights)])
    check_digit = (10 - total % 10) % 10

    return str(check_digit)


def number_to_IDN(id_number):
    letter = reverse_map[id_number[:2]][0]
    gender = reverse_map[id_number[:2]][1]
    rest = id_number[2:9]
    id9 = letter + gender + rest
    check = calculate_check_digit(id9)
    return letter + gender + rest + check


def IDN_to_number(id_number):
    prefix = id_number[0:2]
    numeric_prefix = int(letter_map[prefix])
    return str(numeric_prefix).zfill(2) + id_number[2:10]


def generate_tweak(index):
    return hashlib.sha256(str(index).encode()).hexdigest()[:14].upper()


def decrypt_to_ID(decrypt):
    prefix = decrypt[:2]
    letter = reverse_map[prefix]
    rest = decrypt[2:]
    return letter + rest


def encrypt_fun(plaintext, idx):
    try:
        tweak = generate_tweak(idx)
        cipher = FF3Cipher(KEY, tweak)
        ciphertext = cipher.encrypt(plaintext)
        return ciphertext
    except Exception as e:
        print(f"[加密錯誤] idx={idx}, plaintext={plaintext}, 錯誤: {e}")
        return None

def encrypt_with_mod(plaintext, idx, is_local):
    """
    嘗試加密，如果失敗則嘗試 +/-50 修正。
    返回：處理後明文、密文、狀態、plus50、first_try（未調整前的第一次加密結果）
    """
    ciphertext = encrypt_fun(plaintext, idx)
    first_try = ciphertext  # <<< 新增：保留第一次嘗試結果（可能為 None）

    if ciphertext is not None:
        prefix = int(plaintext[:2])
        cipher_prefix = int(ciphertext[:2])

        if (is_local and cipher_prefix < 50) or (not is_local and cipher_prefix >= 50):
            return plaintext, ciphertext, "OK", False, first_try
        # else: 第一次有密文但分佈不符 → 繼續走 ±50

    # 第一次加密失敗或不符合條件，嘗試 +/-50 修正
    prefix = int(plaintext[:2])
    if is_local:
        adjusted_plaintext = str(prefix + 50) + plaintext[2:]
    else:
        adjusted_plaintext = str(prefix - 50).zfill(2) + plaintext[2:]

    adjusted_ciphertext = encrypt_fun(adjusted_plaintext, idx)

    if adjusted_ciphertext is not None:
        adjusted_cipher_prefix = int(adjusted_ciphertext[:2])
        if (is_local and adjusted_cipher_prefix < 50) or (
            not is_local and adjusted_cipher_prefix >= 50
        ):
            return adjusted_plaintext, adjusted_ciphertext, "FIXED_50", True, first_try

    # 兩種方式都失敗
    return plaintext, adjusted_ciphertext, "FAILED", False, first_try


def encrypt_with_swap(df, start_index):
    """
    當 df.loc[start_index] 無法成功加密時，嘗試透過交換找到一個解決方案，直接修改 df。
    """
    max_index = len(df) - 1

    # 遍歷從 start_index + 1 開始的後續索引，尋找可以交換的目標
    for j in range(start_index + 1, max_index + 1):
        # 進行交換：將 df.loc[start_index] 的內容與 df.loc[j] 的內容對調
        df.iloc[[start_index, j]] = df.iloc[[j, start_index]].copy()

        # 現在 df.loc[start_index] 包含了原 df.loc[j] 的資料
        # 嘗試對這筆新到位的資料進行加密
        plaintext_current = df.loc[df.index[start_index], "Numeric"][:9]
        is_local_current = int(plaintext_current[:2]) < 50

        # 調用 encrypt_with_mod 進行加密嘗試 (包含 +/-50 修正)
        plaintext_processed, encrypted, status, plus50, first_try = encrypt_with_mod(
            plaintext_current, start_index, is_local_current
        )

        if status in ["OK", "FIXED_50"]:
            df.loc[df.index[start_index], "plaintext"] = plaintext_processed
            df.loc[df.index[start_index], "Encrypted_Numeric"] = encrypted
            df.loc[df.index[start_index], "Status"] = "SWAPPED"
            df.loc[df.index[start_index], "Swap_Index"] = j
            df.loc[df.index[start_index], "plus50"] = plus50
            df.loc[df.index[start_index], "First_Try_Before_Adjust"] = first_try or ""
            return True
        else:
            # 如果交換後加密仍失敗，則還原本次交換，繼續嘗試與下一筆資料交換
            df.iloc[[start_index, j]] = df.iloc[[j, start_index]].copy()  # 還原
            # 如果還原後，你想要將原始的 start_index 的資料標記為 FAILED，則在循環結束後處理

    # === 若是最後一筆，嘗試與 index 0 對調 ===
    if start_index == max_index:
        df.iloc[[start_index, 0]] = df.iloc[[0, start_index]].copy()
        plaintext_current = df.loc[df.index[start_index], "Numeric"][:9]
        is_local_current = int(plaintext_current[:2]) < 50

        plaintext_processed, encrypted, status, plus50, first_try = encrypt_with_mod(
            plaintext_current, start_index, is_local_current
        )

        if status in ["OK", "FIXED_50"]:
            df.loc[df.index[start_index], "plaintext"] = plaintext_processed
            df.loc[df.index[start_index], "Encrypted_Numeric"] = encrypted
            df.loc[df.index[start_index], "Status"] = "SWAPPED"
            df.loc[df.index[start_index], "Swap_Index"] = 0
            df.loc[df.index[start_index], "plus50"] = plus50  # <<< 補上
            df.loc[df.index[start_index], "First_Try_Before_Adjust"] = first_try or ""
            return True
        else:
            df.iloc[[start_index, 0]] = df.iloc[[0, start_index]].copy()

    df.loc[df.index[start_index], "Encrypted_Numeric"] = "XXXXXXXXXX"
    df.loc[df.index[start_index], "Encrypted_ID"] = "A000000000"  # 確保有預設值
    df.loc[df.index[start_index], "Status"] = "FAILED"
    df.loc[df.index[start_index], "Swap_Index"] = -1
    return False  # 表示未能成功處理 start_index
