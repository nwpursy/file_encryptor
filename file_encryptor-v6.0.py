''' 
将代码打包生成.exe可执行文件
pyinstaller --onefile --clean --name FileEncryptor --hidden-import="cryptography.hazmat.backends.openssl" file_encryptor-v6.0.py

--onefile: 打包成单个可执行文件。
--clean: 在打包前清理旧的缓存文件，非常重要。
--name FileEncryptor: 给你的程序起一个好听的名字，最终生成 FileEncryptor.exe。
--icon=lock.ico: （可选）给程序一个图标，需要一个 .ico 文件在同目录下。
--hidden-import="...": 这是解决问题的关键！ 我们在这里手动告诉 PyInstaller 要把哪些它可能找不到的模块也打包进去。
cryptography.hazmat.backends.openssl: cryptography 库的核心后端。
openpyxl.cell._writer: openpyxl 有时会隐藏这个模块。
file_encryptor_cli.py: 您的脚本文件。

找到你的可执行文件:
PyInstaller执行完毕后，会在当前目录下生成几个文件夹，包括 build 和 dist。你的最终成果——那个独立的 .exe 文件——就在 dist 文件夹里，文件名通常是 file_encryptor_cli.exe。
分发和使用:
现在，你只需要将 dist 文件夹里的那个 .exe 文件（例如 file_encryptor_cli.exe）复制给任何人。他们就可以在任何Windows电脑上直接使用它了，无需安装Python或任何库。
'''
import os
import sys
import argparse
import configparser
import shutil
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# (所有辅助函数和核心加解密函数均保持不变)
def get_application_path():
    if getattr(sys, 'frozen', False):
        application_path = os.path.dirname(sys.executable)
    else:
        application_path = os.path.dirname(os.path.abspath(__file__))
    return application_path

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def save_key(key, filename):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    is_private = isinstance(key, rsa.RSAPrivateKey)
    pem = key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption()) if is_private else key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

def load_rsa_key(filename, is_private=True):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    key = serialization.load_pem_private_key(pemlines, password=None) if is_private else serialization.load_pem_public_key(pemlines)
    return key

def encrypt_file(input_file, rsa_public_key):
    # [+] 详细日志: 开始读取文件
    print(f"    - (1/4) 正在读取源文件 '{os.path.basename(input_file)}'...", end='', flush=True)
    with open(input_file, 'rb') as f: file_data = f.read()
    print(" 完成。")
    
    original_filename = os.path.basename(input_file)
    packed_data = original_filename.encode('utf-8') + b'::METADATA_SEPARATOR::' + file_data
    
    # [+] 详细日志: 生成AES密钥
    print("    - (2/4) 正在生成一次性AES会话密钥...", end='', flush=True)
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    print(" 完成。")

    # [+] 详细日志: 使用AES加密
    print("    - (3/4) 正在使用AES加密文件数据 (处理大文件时可能需要一些时间)...", end='', flush=True)
    encrypted_file_data = aesgcm.encrypt(nonce, packed_data, None)
    print(" 完成。")

    # [+] 详细日志: 使用RSA加密AES密钥
    print("    - (4/4) 正在使用RSA公钥加密会话密钥...", end='', flush=True)
    encrypted_aes_key = rsa_public_key.encrypt(aes_key,rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    print(" 完成。")
    
    return encrypted_aes_key + nonce + encrypted_file_data

def decrypt_file(input_file, rsa_private_key):
    print(f"    - (1/4) 正在读取加密文件 '{os.path.basename(input_file)}'...", end='', flush=True)
    with open(input_file, 'rb') as f:
        encrypted_aes_key = f.read(256)
        nonce = f.read(12)
        encrypted_file_data = f.read()
    print(" 完成。")

    print("    - (2/4) 正在使用RSA私钥解密会话密钥...", end='', flush=True)
    aes_key = rsa_private_key.decrypt(encrypted_aes_key,rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    print(" 完成。")

    print("    - (3/4) 正在使用AES解密文件数据 (处理大文件时可能需要一些时间)...", end='', flush=True)
    aesgcm = AESGCM(aes_key)
    decrypted_packed_data = aesgcm.decrypt(nonce, encrypted_file_data, None)
    print(" 完成。")

    print("    - (4/4) 正在解析原始文件名和数据...", end='', flush=True)
    separator = b'::METADATA_SEPARATOR::'
    if separator not in decrypted_packed_data:
        raise ValueError("数据完整性校验失败，文件可能已损坏或密钥不正确。")
    original_filename_bytes, original_file_data = decrypted_packed_data.split(separator, 1)
    original_filename = original_filename_bytes.decode('utf-8')
    output_path = f"decrypted_{original_filename}"
    with open(output_path, 'wb') as f:
        f.write(original_file_data)
    print(" 完成。")
    
    return output_path

# --- 主函数 (增加详细日志和鲁棒性检查) ---
def main():
    APP_PATH = get_application_path()
    DEFAULT_CONFIG_PATH = os.path.join(APP_PATH, 'config.ini')
    
    # (命令行解析部分无变化)
    parser = argparse.ArgumentParser(description="文件混合加密解密工具 (V6 - 专业版)。")
    subparsers = parser.add_subparsers(dest='command', required=True, help="可执行的命令")
    p_encrypt = subparsers.add_parser('encrypt', help="加密一个文件并生成唯一标识的密钥对。")
    p_encrypt.add_argument('-i', '--input', help="需要加密的原始文件路径。")
    p_encrypt.add_argument('-o', '--output-dir', help="加密后的.bin文件输出目录。")
    p_encrypt.add_argument('--keys-dir', help="密钥存放目录。")
    p_decrypt = subparsers.add_parser('decrypt', help="解密一个文件，可自动推断密钥。")
    p_decrypt.add_argument('-f', '--filename', required=True, help="需要解密的.bin文件的【文件名】。")
    p_decrypt.add_argument('-k', '--key', help="【可选】手动指定私钥文件路径。")
    p_decrypt.add_argument('-s', '--source-dir', help="【可选】手动指定加密文件所在目录。")
    p_decrypt.add_argument('-o', '--output-dir', help="【可选】手动指定解密后文件的存放目录。")
    
    args = parser.parse_args()
    
    print("--- 初始化 ---")
    config = configparser.ConfigParser()
    if os.path.exists(DEFAULT_CONFIG_PATH):
        print(f"[✓] 成功从 '{DEFAULT_CONFIG_PATH}' 加载配置。")
        config.read(DEFAULT_CONFIG_PATH, encoding='utf-8')
    else:
        print(f"[!] 提示: 未找到默认配置文件 'config.ini'，将仅使用命令行参数。")

    try:
        if args.command == 'encrypt':
            print("\n--- 开始加密任务 ---")
            # 1. 解析配置
            input_file = args.input or config.get('Encrypt', 'source_file_path', fallback=None)
            output_dir = args.output_dir or config.get('Encrypt', 'encrypted_output_dir', fallback=os.path.join(APP_PATH, 'output_encrypted'))
            keys_dir = args.keys_dir or config.get('Keys', 'storage_dir', fallback=os.path.join(APP_PATH, 'keys'))
            
            # [+] 鲁棒性检查
            if not input_file: raise ValueError("必须通过 -i 参数或在 config.ini 中提供源文件。")
            if not os.path.exists(input_file): raise FileNotFoundError(f"源文件不存在: {input_file}")
            os.makedirs(output_dir, exist_ok=True)
            os.makedirs(keys_dir, exist_ok=True)
            print(f"[✓] 配置检查通过。源文件: {input_file}")

            # 2. 生成唯一标识和密钥
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            base_filename = os.path.splitext(os.path.basename(input_file))[0]
            unique_id = f"{base_filename}_{timestamp}"
            print(f"[+] 为本次任务创建唯一标识: {unique_id}")

            print("-> 正在生成RSA密钥对...")
            private_key, public_key = generate_rsa_keys()
            privkey_path = os.path.join(keys_dir, f"{unique_id}_private.pem")
            pubkey_path = os.path.join(keys_dir, f"{unique_id}_public.pem")
            save_key(private_key, privkey_path)
            save_key(public_key, pubkey_path)
            
            # 3. 执行加密
            print(f"-> 正在加密核心流程...")
            encrypted_data = encrypt_file(input_file, public_key)
            
            # 4. 保存文件
            encrypted_file_path = os.path.join(output_dir, f"{unique_id}.bin")
            print(f"-> 正在将加密数据写入磁盘...")
            with open(encrypted_file_path, 'wb') as f: f.write(encrypted_data)
            
            print("\n--- [SUCCESS] 加密任务完成 ---")
            print(f"  加密文件: {encrypted_file_path}")
            print(f"  公钥文件: {pubkey_path}")
            print(f"  私钥文件: {privkey_path}  (请务必妥善保管并发送给解密方!)")
            print("--------------------------------\n")

        elif args.command == 'decrypt':
            print("\n--- 开始解密任务 ---")
            # 1. 解析配置
            encrypted_filename = args.filename
            source_dir = args.source_dir or config.get('Decrypt', 'encrypted_source_dir', fallback=None)
            output_dir = args.output_dir or config.get('Decrypt', 'decrypted_output_dir', fallback=os.path.join(APP_PATH, 'output_decrypted'))
            keys_dir = config.get('Keys', 'storage_dir', fallback=os.path.join(APP_PATH, 'keys'))

            # [+] 鲁棒性检查
            if not source_dir: raise ValueError("必须通过 -s 参数或在 config.ini 中提供加密文件所在的目录。")
            input_file_full_path = os.path.join(source_dir, encrypted_filename)
            if not os.path.exists(input_file_full_path): raise FileNotFoundError(f"加密文件不存在: {input_file_full_path}")
            os.makedirs(output_dir, exist_ok=True)
            print(f"[✓] 配置检查通过。加密文件: {input_file_full_path}")
            
            # 2. 推断或获取私钥路径
            if args.key:
                private_key_file = args.key
                print(f"[+] 使用手动指定的私钥: {private_key_file}")
            else:
                base_name = os.path.splitext(encrypted_filename)[0]
                key_filename = f"{base_name}_private.pem"
                private_key_file = os.path.join(keys_dir, key_filename)
                print(f"[+] 自动推断私钥为: {private_key_file}")
            if not os.path.exists(private_key_file): raise FileNotFoundError(f"私钥文件不存在: {private_key_file}")

            # 3. 执行解密
            print("-> 正在加载私钥...")
            private_key = load_rsa_key(private_key_file, is_private=True)
            print(f"-> 正在解密核心流程...")
            temp_path = decrypt_file(input_file_full_path, private_key)
            
            # 4. 移动文件
            final_path = os.path.join(output_dir, os.path.basename(temp_path))
            print(f"-> 正在将解密后的文件移动到最终目录...")
            shutil.move(temp_path, final_path)

            print("\n--- [SUCCESS] 解密任务完成 ---")
            print(f"  文件已成功恢复至: {final_path}")
            print("--------------------------------\n")

    except Exception as e:
        print(f"\n--- [ERROR] 操作失败 ---")
        print(f"  错误类型: {e.__class__.__name__}")
        print(f"  错误信息: {e}")
        print("--------------------------\n")

if __name__ == "__main__":
    main()