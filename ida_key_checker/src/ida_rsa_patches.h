/*
* Known rsa mod patches
* 
* RnD, 2021
*/

#ifdef _MSC_VER
#pragma once
#endif

#ifndef _IDA_KNOWN_RSA_PATCHES_
#define _IDA_KNOWN_RSA_PATCHES_

#include <stdint.h>

namespace ida
{
	// known keygen patches mod
	const uint8_t rsa_mod_patch_1[] = {
		0xED, 0xFD, 0x42, 0xCB, 0xF9, 0x78, 0x54, 0x6E, 0x89, 0x11, 0x22, 0x58, 0x84, 0x43, 0x6C, 0x57,
		0x14, 0x05, 0x25, 0x65, 0x0B, 0xCF, 0x6E, 0xBF, 0xE8, 0x0E, 0xDB, 0xC5, 0xFB, 0x1D, 0xE6, 0x8F,
		0x4C, 0x66, 0xC2, 0x9C, 0xB2, 0x2E, 0xB6, 0x68, 0x78, 0x8A, 0xFC, 0xB0, 0xAB, 0xBB, 0x71, 0x80,
		0x44, 0x58, 0x4B, 0x81, 0x0F, 0x89, 0x70, 0xCD, 0xDF, 0x22, 0x73, 0x85, 0xF7, 0x5D, 0x5D, 0xDD,
		0xD9, 0x1D, 0x4F, 0x18, 0x93, 0x7A, 0x08, 0xAA, 0x83, 0xB2, 0x8C, 0x49, 0xD1, 0x2D, 0xC9, 0x2E,
		0x75, 0x05, 0xBB, 0x38, 0x80, 0x9E, 0x91, 0xBD, 0x0F, 0xBD, 0x2F, 0x2E, 0x6A, 0xB1, 0xD2, 0xE3,
		0x3C, 0x0C, 0x55, 0xD5, 0xBD, 0xDD, 0x47, 0x8E, 0xE8, 0xBF, 0x84, 0x5F, 0xCE, 0xF3, 0xC8, 0x2B,
		0x9D, 0x29, 0x29, 0xEC, 0xB7, 0x1F, 0x4D, 0x1B, 0x3D, 0xB9, 0x6E, 0x3A, 0x8E, 0x7A, 0xAF, 0x93
	};

	// china patch
	const uint8_t rsa_mod_patch_2[] = {
		0xED, 0xFD, 0x42, 0x5C, 0xF9, 0x78, 0x54, 0x6E, 0x89, 0x11, 0x22, 0x58, 0x84, 0x43, 0x6C, 0x57,
		0x14, 0x05, 0x25, 0x65, 0x0B, 0xCF, 0x6E, 0xBF, 0xE8, 0x0E, 0xDB, 0xC5, 0xFB, 0x1D, 0xE6, 0x8F,
		0x86, 0x66, 0xC2, 0x9C, 0xB2, 0x2E, 0xB6, 0x68, 0x78, 0x8A, 0xFC, 0xB0, 0xAB, 0xBB, 0x71, 0x80,
		0x44, 0x58, 0x4B, 0x81, 0x0F, 0x89, 0x70, 0xCD, 0xDF, 0x22, 0x73, 0x85, 0xF7, 0x5D, 0x5D, 0xDD,
		0xD9, 0x1D, 0x4F, 0x18, 0x93, 0x7A, 0x08, 0xAA, 0x83, 0xB2, 0x8C, 0x49, 0xD1, 0x2D, 0xC9, 0x2E,
		0x75, 0x05, 0xBB, 0x38, 0x80, 0x9E, 0x91, 0xBD, 0x0F, 0xBD, 0x2F, 0x2E, 0x6A, 0xB1, 0xD2, 0xE3,
		0x3C, 0x0C, 0x55, 0xD5, 0xBD, 0xDD, 0x47, 0x8E, 0xE8, 0xBF, 0x84, 0x5F, 0xCE, 0xF3, 0xC8, 0x2B,
		0x9D, 0x29, 0x29, 0xEC, 0xB7, 0x1F, 0x4D, 0x1B, 0x3D, 0xB9, 0x6E, 0x3A, 0x8E, 0x7A, 0xAF, 0x93
	};

	// china big changes
	const uint8_t rsa_mod_patch_3[] = {
		0xED, 0xFD, 0x42, 0xDC, 0x21, 0x16, 0xFE, 0xBE, 0x2F, 0x6B, 0x22, 0xB3, 0x9D, 0x3E, 0xEE, 0xB5,
		0x8D, 0x49, 0x10, 0x6A, 0xAD, 0x35, 0x7A, 0x0C, 0x0B, 0x1C, 0xB1, 0x34, 0xC1, 0x1D, 0x53, 0x80,
		0xE1, 0x6F, 0xCD, 0x7E, 0x08, 0x62, 0xDC, 0x1D, 0xA4, 0x0F, 0xFF, 0x46, 0xE9, 0x6D, 0x02, 0xF5,
		0xC6, 0xE2, 0x59, 0x54, 0x7C, 0x2E, 0x47, 0xCB, 0x84, 0xD2, 0xBF, 0x93, 0x38, 0x21, 0xB7, 0xC3,
		0xD5, 0xA9, 0x00, 0x9A, 0x66, 0x75, 0x84, 0x0E, 0x9F, 0x43, 0x18, 0x47, 0x3B, 0x02, 0xD2, 0x4F,
		0x86, 0x64, 0x69, 0x28, 0x86, 0x0C, 0x2E, 0xD0, 0xBB, 0x98, 0x6D, 0x9D, 0xC9, 0x10, 0x4C, 0xE5,
		0x51, 0x31, 0xA7, 0xD7, 0xBD, 0xDD, 0x47, 0x8E, 0xE8, 0xBF, 0x84, 0x5F, 0xCE, 0xF3, 0xC8, 0x2B,
		0x9D, 0x29, 0x29, 0xEC, 0xB7, 0x1F, 0x4D, 0x1B, 0x3D, 0xB9, 0x6E, 0x3A, 0x8E, 0x7A, 0xAF, 0x93
	};

	const uint8_t* k_patch_mods[] = {
		rsa_mod_patch_1,
		rsa_mod_patch_2,
		rsa_mod_patch_3
	};
}

#endif // _IDA_KNOWN_RSA_PATCHES_