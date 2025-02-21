# -*- coding: utf-8 -*-
__author__ = '7w1st22'
__date__ = '2024/12/20 10:18'

import binascii
import struct
import base64
import json
import os
import hashlib
import tempfile
import shutil  # 引入shutil模块
from Crypto.Cipher import AES


def calculate_file_hash(file_path, block_size=65536):
    """计算文件的 MD5 哈希值，用于唯一性校验"""
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(block_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def dump(file_path, temp_output_path):
    """解密 NCM 文件并写入临时文件"""
    # 十六进制转字符串
    core_key = binascii.a2b_hex("687A4852416D736F356B496E62617857")
    meta_key = binascii.a2b_hex("2331346C6A6B5F215C5D2630553C2728")
    unpad = lambda s: s[0:-(s[-1] if isinstance(s[-1], int) else ord(s[-1]))]

    with open(file_path, 'rb') as f:
        header = f.read(8)
        # 校验文件头是否为 NCM 格式
        assert binascii.b2a_hex(header) == b'4354454e4644414d', f"非 NCM 文件: {file_path}"
        f.seek(2, 1)
        key_length = struct.unpack('<I', f.read(4))[0]
        key_data = f.read(key_length)
        key_data_array = bytearray(key_data)
        for i in range(len(key_data_array)):
            key_data_array[i] ^= 0x64
        key_data = bytes(key_data_array)
        cryptor = AES.new(core_key, AES.MODE_ECB)
        key_data = unpad(cryptor.decrypt(key_data))[17:]
        key_length = len(key_data)
        key_data = bytearray(key_data)
        key_box = bytearray(range(256))
        c = 0
        last_byte = 0
        key_offset = 0
        for i in range(256):
            swap = key_box[i]
            c = (swap + last_byte + key_data[key_offset]) & 0xff
            key_offset = (key_offset + 1) % key_length
            key_box[i] = key_box[c]
            key_box[c] = swap
            last_byte = c
        meta_length = struct.unpack('<I', f.read(4))[0]
        meta_data = f.read(meta_length)
        meta_data_array = bytearray(meta_data)
        for i in range(len(meta_data_array)):
            meta_data_array[i] ^= 0x63
        meta_data = bytes(meta_data_array)
        meta_data = base64.b64decode(meta_data[22:])
        cryptor = AES.new(meta_key, AES.MODE_ECB)
        meta_data = unpad(cryptor.decrypt(meta_data)).decode('utf-8')[6:]
        meta_data = json.loads(meta_data)
        f.seek(9, 1)  # Skip CRC32 and other reserved bytes
        image_size = struct.unpack('<I', f.read(4))[0]
        image_data = f.read(image_size)

        # 生成解密后的文件名
        file_name = os.path.splitext(os.path.basename(file_path))[0] + '.' + meta_data['format']

        # 解密并写入临时文件
        with open(temp_output_path, 'wb') as m:
            while True:
                chunk = bytearray(f.read(0x8000))
                if not chunk:
                    break
                chunk_length = len(chunk)
                for i in range(1, chunk_length + 1):
                    j = i & 0xff
                    chunk[i - 1] ^= key_box[(key_box[j] + key_box[(key_box[j] + j) & 0xff]) & 0xff]
                m.write(chunk)
    return file_name  # 返回解密后的文件名


if __name__ == '__main__':
    input_dir = r"G:\cloudmusic\VipSongsDownload"  # 输入文件夹路径
    output_dir = r"F:\网易云音乐"  # 输出文件夹路径

    # 如果输出文件夹不存在，则创建
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 获取目标文件夹中已有文件的哈希值
    existing_hashes = {}
    for existing_file in os.listdir(output_dir):
        existing_file_path = os.path.join(output_dir, existing_file)
        if os.path.isfile(existing_file_path):
            try:
                file_hash = calculate_file_hash(existing_file_path)
                existing_hashes[file_hash] = existing_file_path
            except Exception as e:
                print(f"无法计算哈希值的文件：{existing_file_path}，错误：{e}")

    # 获取输入目录中的所有文件
    all_files = [file_name for file_name in os.listdir(input_dir) if os.path.isfile(os.path.join(input_dir, file_name))]
    total_files = len(all_files)
    processed_count = 0

    # 创建临时目录
    with tempfile.TemporaryDirectory() as temp_dir:
        # 遍历输入文件夹中的所有文件
        for file_name in all_files:
            input_file_path = os.path.join(input_dir, file_name)
            print(f"------------------------------------------------")
            # 跳过非 NCM 文件
            if not file_name.lower().endswith('.ncm'):
                print(f"跳过非 NCM 文件：{file_name}")
                continue

            # 解密并检查文件是否重复
            try:
                # 生成临时输出路径
                temp_output_path = os.path.join(temp_dir, f"temp_{file_name}")
                decrypted_file_name = dump(input_file_path, temp_output_path)
                final_output_path = os.path.join(output_dir, decrypted_file_name)
                temp_hash = calculate_file_hash(temp_output_path)

                # 检查哈希值是否已存在
                if temp_hash in existing_hashes:
                    print(f"文件已存在，跳过：{final_output_path}")
                    # 删除临时文件，不覆盖已有文件
                    os.remove(temp_output_path)
                else:
                    # 检查最终输出路径是否已存在（防止文件名冲突）
                    if os.path.exists(final_output_path):
                        existing_file_hash = calculate_file_hash(final_output_path)
                        if existing_file_hash == temp_hash:
                            print(f"文件已存在，跳过：{final_output_path}")
                            os.remove(temp_output_path)
                            continue
                        else:
                            # 文件名冲突，但内容不同，生成唯一文件名
                            base_name, ext = os.path.splitext(decrypted_file_name)
                            counter = 1
                            new_file_name = f"{base_name}_{counter}{ext}"
                            new_output_path = os.path.join(output_dir, new_file_name)
                            while os.path.exists(new_output_path):
                                existing_file_hash = calculate_file_hash(new_output_path)
                                if existing_file_hash == temp_hash:
                                    print(f"文件已存在，跳过：{new_output_path}")
                                    os.remove(temp_output_path)
                                    break
                                counter += 1
                                new_file_name = f"{base_name}_{counter}{ext}"
                                new_output_path = os.path.join(output_dir, new_file_name)
                            else:
                                # 移动临时文件到最终路径
                                shutil.move(temp_output_path, new_output_path)  # 使用shutil.move
                                existing_hashes[temp_hash] = new_output_path
                                print(f"文件生成成功：{new_output_path}")
                    else:
                        # 移动临时文件到最终路径
                        shutil.move(temp_output_path, final_output_path)  # 使用shutil.move
                        existing_hashes[temp_hash] = final_output_path
                        print(f"文件生成成功：{final_output_path}")
            except Exception as e:
                print(f"文件生成失败：{input_file_path}，错误：{e}")

            # 更新进度
            processed_count += 1
            remaining_files = total_files - processed_count
            print(f"进度：已处理 {processed_count}/{total_files}，剩余 {remaining_files} 个文件")
