import math
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib
import os
from dotenv import load_dotenv

load_dotenv()
letter_map = {
    "A1": "00", "B1": "01", "C1": "02", "D1": "03", "E1": "04",
    "F1": "05", "G1": "06", "H1": "07", "I1": "08", "J1": "09",
    "K1": "10", "L1": "11", "M1": "12", "N1": "13", "O1": "14",
    "P1": "15", "Q1": "16", "R1": "17", "S1": "18", "T1": "19",
    "U1": "20", "V1": "21", "W1": "22", "X1": "23", "Z1": "24",

    "A2": "25", "B2": "26", "C2": "27", "D2": "28", "E2": "29",
    "F2": "30", "G2": "31", "H2": "32", "I2": "33", "J2": "34",
    "K2": "35", "L2": "36", "M2": "37", "N2": "38", "O2": "39",
    "P2": "40", "Q2": "41", "R2": "42", "S2": "43", "T2": "44",
    "U2": "45", "V2": "46", "W2": "47", "X2": "48", "Z2": "49",

    "A8": "50", "B8": "51", "C8": "52", "D8": "53", "E8": "54",
    "F8": "55", "G8": "56", "H8": "57", "I8": "58", "J8": "59",
    "K8": "60", "L8": "61", "M8": "62", "N8": "63", "O8": "64",
    "P8": "65", "Q8": "66", "R8": "67", "S8": "68", "T8": "69",
    "U8": "70", "V8": "71", "W8": "72", "X8": "73", "Z8": "74",

    "A9": "75", "B9": "76", "C9": "77", "D9": "78", "E9": "79",
    "F9": "80", "G9": "81", "H9": "82", "I9": "83", "J9": "84",
    "K9": "85", "L9": "86", "M9": "87", "N9": "88", "O9": "89",
    "P9": "90", "Q9": "91", "R9": "92", "S9": "93", "T9": "94",
    "U9": "95", "V9": "96", "W9": "97", "X9": "98", "Z9": "99"
}

translate_map = {
    "A": "10", "B": "11", "C": "12", "D": "13", "E": "14", "F": "15", "G": "16", "H": "17",
    "I": "34", "J": "18", "K": "19", "L": "20", "M": "21", "N": "22", "O": "35", "P": "23",
    "Q": "24", "R": "25", "S": "26", "T": "27", "U": "28", "V": "29", "W": "32", "X": "30", "Z": "33"
}

reverse_map = {v: k for k, v in letter_map.items()}

key = os.getenv("KEY").encode("utf-8")

def CIPH(key, X):
    """
    輸入:
    key: 加密密鑰，類型為bytes，長度應為16位元組。
    X: 要加密的資料，類型為bytes，長度應為16位元組。
    輸出:
    返回加密後的資料，類型為bytes。
    """
    # 選擇 AES-ECB 模式，因為這是 FF1 PRF 的常見底層函式
    cipher = AES.new(key, AES.MODE_ECB) 
    # 加密 X
    ciphertext = cipher.encrypt(X)
    return ciphertext

def PRF(key, X):
    """
    輸入:
    key: 加密密鑰，類型為bytes，長度應為16位元組。
    X: 要進行處理的數據，類型為bytes，長度應為16位元組的整數倍。
    輸出:
    返回偽隨機函式計算後的結果，類型為bytes。
    """
    # 計算 X 可以分成多少個 16 位元組的塊
    m = int(len(X) / 16)
    
    # 初始化 Y 為 16 個位元組的 0 值
    Y = bytes(16)
    
    # 將 X 分解為多個 16 位元組的塊
    X_list = [X[i*16 : (i+1)*16] for i in range(m)]

    # 執行 CBC 鏈結邏輯
    for i in range(m):
        # 將 Y 和當前塊 X 進行 XOR 運算
        # 由於兩個都是 bytes 物件，我們需要先轉換成 int 再運算
        Y_int = int.from_bytes(Y, 'big')
        X_int = int.from_bytes(X_list[i], 'big')
        xor_result_int = Y_int ^ X_int
        
        # 將 XOR 結果轉換回 bytes
        data = xor_result_int.to_bytes(16, 'big')
        
        # 使用 CIPH 進行加密，並將結果賦值給 Y
        Y = CIPH(key, data)
        
    return Y

def NUM_radix(n, radix):
    """
    將數字n轉換成給定基數radix的字串表示形式。
    """
    if n == 0:
        return 0
    a = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    b = []
    while n > 0:
        b.append(a[n % radix])
        n = n // radix
    b.reverse()
    return int(''.join(map(str, b)))

def str_radix_m(n, m, radix):
    """
    給定一個數字n和長度m，將數字轉換為基數radix的字串表示，確保字串長度為m。
    """
    X = [0] * m
    for i in range(m - 1, -1, -1):
        X[i] = n % radix
        n = n // radix
    return ''.join(map(str, X))

def FF1(plaintext, radix, key, tweak):
    n = len(plaintext)
    u = math.floor(n / 2)
    v = n - u
    A = plaintext[:u]
    B = plaintext[u:]

    b = math.ceil((math.ceil(math.log2(radix) * v)) / 8)
    t = len(tweak)

    P = bytes([1, 2, 1]) + radix.to_bytes(3, 'big') + bytes([10, u%256]) + n.to_bytes(4, 'big') + t.to_bytes(4, 'big')

    for i in range(10):
        # Q = tweak || [0]^(-t-b-1) mod 16 || [i]^1 ||[NUM_radix(B)]^b
        Q = tweak + (0).to_bytes((-t - b - 1) % 16, 'big') + i.to_bytes(1, 'big') + int(NUM_radix(int(B), radix)).to_bytes(b, 'big')
        R = PRF(key, P + Q)
        y = int.from_bytes(R, 'big')

        if i % 2 == 0:
            m = u
        else:
            m = v

        c = (NUM_radix(int(A), radix) + y) % radix ** m
        C = str_radix_m(c, m, radix)
        A = B
        B = C

    return str(A) + str(B)

def FF1_decrypt(ciphertext, radix, key, tweak):
    n = len(ciphertext)
    u = math.floor(n / 2)
    v = n - u
    A = ciphertext[:u]
    B = ciphertext[u:]

    b = math.ceil((math.ceil(math.log2(radix) * v)) / 8)
    t = len(tweak)
    P = bytes([1, 2, 1]) + radix.to_bytes(3, 'big') + bytes([10, u%256]) + n.to_bytes(4, 'big') + t.to_bytes(4, 'big')

    for i in range(9, -1, -1):
        if i % 2 == 0:
            m = u
        else:
            m = v

        C = A
        A = B
        B = C
        
        Q = tweak + (0).to_bytes((-t - b - 1) % 16, 'big') + i.to_bytes(1, 'big') + int(NUM_radix(int(B), radix)).to_bytes(b, 'big')
        R = PRF(key, P + Q)
        y = int.from_bytes(R, 'big')

        c = (NUM_radix(int(A), radix) - y) % radix ** m
        A = str_radix_m(c, m, radix)

    return A + B

def calculate_check_digit(id9):
    weights = [1, 9, 8, 7, 6, 5, 4, 3, 2, 1]
    n0 = int(translate_map[id9[0]])
    nums = [n0 // 10, n0 % 10] + [int(ch) for ch in id9[1:]]
    weights = [1, 9, 8, 7, 6, 5, 4, 3, 2, 1]
    total = sum([a * b for a, b in zip(nums, weights)])
    check_digit = (10 - total % 10) % 10

    return str(check_digit)

def number_to_IDN(id_number_str):
    """
    將數字字串轉換回身分證字號格式，並加上驗證碼。
    """
    # 從數字字串中提取前兩位，轉換回字母和性別碼
    prefix_num = id_number_str[:2]
    # 這裡的邏輯需要修正，因為 reverse_map 不包含數字開頭
    # 這裡需要一個反向查找的邏輯，根據數字轉換回字母和性別碼
    
    # 假設我們能夠正確地反向查找
    id_prefix = reverse_map[prefix_num]
    letter = id_prefix[0]
    gender = id_prefix[1]
    
    # 提取後面的數字
    rest = id_number_str[2:9]
    id9 = letter + gender + rest
    check_digit = calculate_check_digit(id9)

    return f"{letter}{gender}{rest}{check_digit}"

def IDN_to_number(id_number):
    """
    將身分證字號轉換為純數字字串，移除驗證碼。
    """
    prefix = id_number[0:2]
    # 使用 letter_map 進行轉換
    if prefix in letter_map:
        numeric_prefix = letter_map[prefix]
        return numeric_prefix + id_number[2:9]
    else:
        # 處理無法轉換的情況，例如無效的身分證字號
        return None

def generate_tweak(index):
    return hashlib.sha256(str(index).encode()).hexdigest()[:14].upper()

def encrypt_with_mod(plaintext, idx, is_local):
    """
    嘗試加密，如果失敗則嘗試 +/-50 修正。
    返回處理後的明文、密文和狀態。
    """
    tweak = generate_tweak(idx).encode('utf-8')
    ciphertext = FF1(plaintext, 10, key, tweak)
    first_try = ciphertext

    if ciphertext is not None:
        prefix = int(plaintext[:2])
        cipher_prefix = int(ciphertext[:2])

        if (is_local and cipher_prefix < 50) or (not is_local and cipher_prefix >= 50):
            return plaintext, ciphertext, "OK", False, first_try
            invalid_ciphertext = ciphertext
    # 第一次加密失敗或不符合條件，嘗試 +/-50 修正
    prefix = int(plaintext[:2]) # 再次獲取原始明文前綴

    if is_local:
        adjusted_plaintext = str(prefix + 50) + plaintext[2:]
    else:
        adjusted_plaintext = str(prefix - 50).zfill(2) + plaintext[2:]
    
    adjusted_ciphertext = FF1(adjusted_plaintext, 10, key, tweak)

    if adjusted_ciphertext is not None:
        adjusted_cipher_prefix = int(adjusted_ciphertext[:2])
        if (is_local and adjusted_cipher_prefix < 50) or (not is_local and adjusted_cipher_prefix >= 50):
            return adjusted_plaintext, adjusted_ciphertext, "FIXED_50",True, first_try
    
    # 兩種方式都失敗
    return plaintext, adjusted_ciphertext, "FAILED", False, first_try # 返回原始明文和 FAILED 狀態

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
        plaintext_current = df.loc[df.index[start_index], 'Numeric'][:9]
        is_local_current = int(plaintext_current[:2]) < 50

        # 調用 encrypt_with_mod 進行加密嘗試 (包含 +/-50 修正)
        plaintext_processed, encrypted, status, plus50, first_try = encrypt_with_mod(plaintext_current, start_index, is_local_current)

        if status in ["OK", "FIXED_50"]:
            # 如果成功加密了 df.loc[start_index] (原 df.loc[j] 的資料)
            df.loc[df.index[start_index], 'plaintext'] = plaintext_processed # 更新明文為處理後的
            df.loc[df.index[start_index], 'Encrypted_Numeric'] = encrypted
            df.loc[df.index[start_index], 'Status'] = "SWAPPED" # 因為發生了交換
            df.loc[df.index[start_index], 'Swap_Index'] = j # 記錄和哪一筆交換了
            df.loc[df.index[start_index], 'plus50'] = plus50
            df.loc[df.index[start_index], "First_Try_Before_Adjust"] = first_try or ""
            # 這裡的關鍵是：原始 start_index 的資料現在在 j 位置，它會在主迴圈中被處理到
            # 由於我們已經處理了 start_index，可以立即返回，表示這個位置的加密已完成
            return True # 表示成功處理了 start_index
        else:
            # 如果交換後加密仍失敗，則還原本次交換，繼續嘗試與下一筆資料交換
            df.iloc[[start_index, j]] = df.iloc[[j, start_index]].copy() # 還原
            # 如果還原後，你想要將原始的 start_index 的資料標記為 FAILED，則在循環結束後處理
            
    # === 若是最後一筆，嘗試與 index 0 對調 ===
    if start_index == max_index:
        df.iloc[[start_index, 0]] = df.iloc[[0, start_index]].copy()

        plaintext_current = df.loc[df.index[start_index], 'Numeric'][:9]
        is_local_current = int(plaintext_current[:2]) < 50

        plaintext_processed, encrypted, status, plus50, first_try = encrypt_with_mod(plaintext_current, start_index, is_local_current)

        if status in ["OK", "FIXED_50"]:
            df.loc[df.index[start_index], 'plaintext'] = plaintext_processed
            df.loc[df.index[start_index], 'Encrypted_Numeric'] = encrypted
            df.loc[df.index[start_index], 'Status'] = "SWAPPED"
            df.loc[df.index[start_index], 'Swap_Index'] = 0
            df.loc[df.index[start_index], "First_Try_Before_Adjust"] = first_try or ""
            return True
        else:
            # 還原
            df.iloc[[start_index, 0]] = df.iloc[[0, start_index]].copy()
            
    df.loc[df.index[start_index], 'Encrypted_Numeric'] = "XXXXXXXXXX"
    df.loc[df.index[start_index], 'Encrypted_ID'] = "A000000000" # 確保有預設值
    df.loc[df.index[start_index], 'Status'] = "FAILED"
    df.loc[df.index[start_index], 'Swap_Index'] = -1
    return False # 表示未能成功處理 start_index
