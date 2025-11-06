#include "VEHinj.h"

// 左旋转宏
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
// 对齐宏（向上取整到对齐边界）
#define ALIGN_UP(x, a) (((x) + ((a) - 1)) & ~((a) - 1))

#undef RtlCopyMemory // 傻逼C标准库给WinAPI定义到C运行时函数 这是什么行为

// ChaCha20轮函数
void chacha20_quarter_round(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
	*a += *b; *d = ROTL32(*d ^ *a, 16);
	*c += *d; *b = ROTL32(*b ^ *c, 12);
	*a += *b; *d = ROTL32(*d ^ *a, 8);
	*c += *d; *b = ROTL32(*b ^ *c, 7);
}

// ChaCha20块函数
void chacha20_block(uint32_t* state, uint8_t* keystream) {
	uint32_t x[16];
	RtlCopyMemory(x, state, 16 * sizeof(uint32_t));
	for (int i = 0; i < 10; i++) {
		chacha20_quarter_round(&x[0], &x[4], &x[8], &x[12]);
		chacha20_quarter_round(&x[1], &x[5], &x[9], &x[13]);
		chacha20_quarter_round(&x[2], &x[6], &x[10], &x[14]);
		chacha20_quarter_round(&x[3], &x[7], &x[11], &x[15]);
		chacha20_quarter_round(&x[0], &x[5], &x[10], &x[15]);
		chacha20_quarter_round(&x[1], &x[6], &x[11], &x[12]);
		chacha20_quarter_round(&x[2], &x[7], &x[8], &x[13]);
		chacha20_quarter_round(&x[3], &x[4], &x[9], &x[14]);
	}
	for (int i = 0; i < 16; i++) {
		x[i] += state[i];
	}
	for (int i = 0; i < 16; i++) {
		keystream[i * 4 + 0] = (x[i] >> 0) & 0xFF;
		keystream[i * 4 + 1] = (x[i] >> 8) & 0xFF;
		keystream[i * 4 + 2] = (x[i] >> 16) & 0xFF;
		keystream[i * 4 + 3] = (x[i] >> 24) & 0xFF;
	}
}

// ChaCha20解密
void chacha20_decrypt(const unsigned char* encrypted, size_t len,
	const unsigned char* key, const unsigned char* nonce,
	unsigned char* decrypted) {
	uint32_t state[16];

	// 自定义常量
	state[0] = 0xA4757138;
	state[1] = 0xCAB5636C;
	state[2] = 0xA3D14186;
	state[3] = 0xFD06C16F;

	// 密钥（32 字节）
	for (int i = 0; i < 8; i++) {
		state[4 + i] = ((uint32_t)key[4 * i]) |
			((uint32_t)key[4 * i + 1] << 8) |
			((uint32_t)key[4 * i + 2] << 16) |
			((uint32_t)key[4 * i + 3] << 24);
	}

	// 随机数（nonce[4:16] -> state[13-15]）
	state[13] = ((uint32_t)nonce[4]) | ((uint32_t)nonce[5] << 8) |
		((uint32_t)nonce[6]) << 16 | ((uint32_t)nonce[7] << 24);
	state[14] = ((uint32_t)nonce[8]) | ((uint32_t)nonce[9] << 8) |
		((uint32_t)nonce[10]) << 16 | ((uint32_t)nonce[11] << 24);
	state[15] = ((uint32_t)nonce[12]) | ((uint32_t)nonce[13] << 8) |
		((uint32_t)nonce[14]) << 16 | ((uint32_t)nonce[15] << 24);

	// 初始计数器（nonce[0:4]）
	uint32_t initial_counter = ((uint32_t)nonce[0]) | ((uint32_t)nonce[1] << 8) |
		((uint32_t)nonce[2] << 16) | ((uint32_t)nonce[3] << 24);

	uint8_t keystream[64];
	size_t num_blocks = (len + 63) / 64; // 64字节块的数量

	for (size_t block = 0; block < num_blocks; block++) {
		state[12] = initial_counter + block; // 每个块计数器自增
		chacha20_block(state, keystream);

		size_t start = block * 64;
		size_t end = (start + 64 < len) ? start + 64 : len;
		for (size_t i = start; i < end; i++) {
			decrypted[i] = encrypted[i] ^ keystream[i - start];
		}
	}
}

