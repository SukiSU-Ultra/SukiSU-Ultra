#ifndef __KSU_H_MANAGER_SIGN
#define __KSU_H_MANAGER_SIGN

#include <linux/types.h>

// rsuntk/KernelSU
#define EXPECTED_SIZE_RSUNTK 0x396
#define EXPECTED_HASH_RSUNTK                                                   \
	"f415f4ed9435427e1fdf7f1fccd4dbc07b3d6b8751e4dbcec6f19671f427870b"

// 5ec1cff/KernelSU
#define EXPECTED_SIZE_5EC1CFF 384
#define EXPECTED_HASH_5EC1CFF                                                  \
	"7e0c6d7278a3bb8e364e0fcba95afaf3666cf5ff3c245a3b63c8833bd0445cc4"

// tiann/KernelSU
#define EXPECTED_SIZE_OFFICIAL 0x033b
#define EXPECTED_HASH_OFFICIAL                                                 \
	"c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6"

// KOWX712/KernelSU
#define EXPECTED_SIZE_KOWX712 0x375
#define EXPECTED_HASH_KOWX712                                                  \
	"484fcba6e6c43b1fb09700633bf2fb4758f13cb0b2f4457b80d075084b26c588"

// ShirkNeko/KernelSU
#define EXPECTED_SIZE_SHIRKNEKO   0x35c
#define EXPECTED_HASH_SHIRKNEKO   											   \
	"947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef"

// Neko/KernelSU
#define EXPECTED_SIZE_NEKO   0x29c
#define EXPECTED_HASH_NEKO      											   \
	"946b0557e450a6430a0ba6b6bccee5bc12953ec8735d55e26139b0ec12303b21"

// Dynamic Sign
#define EXPECTED_SIZE_OTHER   0x300
#define EXPECTED_HASH_OTHER      											   \
	"0000000000000000000000000000000000000000000000000000000000000000"

typedef struct {
	u32 size;
	const char *sha256;
} apk_sign_key_t;

#endif /* MANAGER_SIGN_H */
