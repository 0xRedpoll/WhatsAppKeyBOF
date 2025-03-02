import os
import struct
import argparse
from Crypto.Cipher import AES

def decrypt_page(cipher, key, page_number, page_data):
    iv = bytearray(16)
    struct.pack_into('<I', iv, 0, page_number)
    iv[4:16] = page_data[-12:]
    
    cipher = AES.new(key, AES.MODE_OFB, iv)
    decrypted_page = cipher.decrypt(page_data)
    return decrypted_page

def decrypt_db_file(db_key, input_file, output_file):
    page_size = 4096
    
    with open(input_file, 'rb') as f:
        input_bytes = f.read()
    
    copied_bytes = input_bytes[0x10:0x18]
    
    with open(output_file, 'wb') as f:
        for i in range(0, len(input_bytes), page_size):
            page_data = input_bytes[i:i + page_size]
            decrypted_page = decrypt_page(AES, db_key, (i // page_size) + 1, page_data)
            f.write(decrypted_page)
    
    with open(output_file, 'r+b') as f:
        f.seek(0x10)
        f.write(copied_bytes)
    
    print(f"DB file successfully decrypted: {output_file}")

def decrypt_dbwal_file(db_key, input_file, output_file):
    page_size = 4096
    header_size = 32
    page_header_size = 24
    
    with open(input_file, 'rb') as f:
        input_bytes = f.read()
    
    file_header = input_bytes[:header_size]
    
    with open(output_file, 'wb') as f:
        f.write(file_header)
    
        for i in range(header_size, len(input_bytes), page_size + page_header_size):
            page_header_data = input_bytes[i:i + page_header_size]
            page_data = input_bytes[i + page_header_size:i + page_header_size + page_size]
            
            page_index = struct.unpack('>I', page_header_data[:4])[0]
            iv = bytearray(16)
            struct.pack_into('<I', iv, 0, page_index)
            iv[4:16] = page_data[-12:]
            
            decrypted_page = decrypt_page(AES, db_key, page_index, page_data)
            f.write(page_header_data)
            f.write(decrypted_page)
    
    print(f"DBWAL file successfully decrypted: {output_file}")

def decrypt_all_files(db_key, target_directory):
    for file in os.listdir(target_directory):
        if file.endswith('.db') or file.endswith('.db-wal'):
            input_path = os.path.join(target_directory, file)
            output_path = input_path.replace(file, f"dec_{file}")
            
            try:
                if file.endswith('.db'):
                    print(f"Decrypting DB: {file}")
                    decrypt_db_file(db_key, input_path, output_path)
                elif file.endswith('.db-wal'):
                    print(f"Decrypting DB-WAL: {file}")
                    decrypt_dbwal_file(db_key, input_path, output_path)
            except Exception as e:
                print(f"Error decrypting {file}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Decrypt messages.db and messages.db-wal files.")
    parser.add_argument("-k", "--key", required=True, help="Decryption key (hex format)")
    parser.add_argument("-d", "--directory", required=True, help="Target directory containing database files")
    
    args = parser.parse_args()
    db_key = bytes.fromhex(args.key)
    decrypt_all_files(db_key, args.directory)

if __name__ == "__main__":
    main()