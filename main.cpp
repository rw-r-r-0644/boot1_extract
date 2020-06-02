/*
	CDecrypt - Decrypt Wii U NUS content files [https://code.google.com/p/cdecrypt/]

	Copyright (c) 2013-2015 crediar

	CDecrypt is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#define _CRT_SECURE_NO_WARNINGS

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <time.h>
#include <vector>
#include <ctype.h>
#include <cstdint>
#include <sys/stat.h>

#pragma comment(lib,"libeay32.lib")

typedef uint64_t u64;
typedef int64_t s64;

typedef uint32_t u32;
typedef int32_t s32;

typedef uint16_t u16;
typedef int16_t s16;

typedef uint8_t u8;
typedef int8_t s8;

AES_KEY key;
u8 enc_title_key[16];
u8 dec_title_key[16];
u8 title_id[16];
u8 dkey[16];

u64 H0Count = 0;
u64 H0Fail  = 0;

// Uncomment the following line and replace 0x00 with the correct wiiu common key bytes
//#define WIIU_COMMON_KEY {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,}

#ifndef WIIU_COMMON_KEY
#error Please fill in the common key in main.cpp!
#else

const u8 CKey[16] = WIIU_COMMON_KEY;

#pragma pack(1)

enum ContentType
{
	CONTENT_REQUIRED=	(1<< 0),	// not sure
	CONTENT_SHARED	=	(1<<15),
	CONTENT_OPTIONAL=	(1<<14),
};

typedef struct
{
	u16 IndexOffset;	//	0	 0x204
	u16 CommandCount;	//	2	 0x206
	u8	SHA2[32];			//  12 0x208
} ContentInfo;

typedef struct
{
	u32 ID;					//	0	 0xB04
	u16 Index;			//	4  0xB08
	u16 Type;				//	6	 0xB0A
	u64 Size;				//	8	 0xB0C
	u8	SHA2[32];		//  16 0xB14
} Content;

typedef struct
{
	u32 SignatureType;		// 0x000
	u8	Signature[0x100];	// 0x004

	u8	Padding0[0x3C];		// 0x104
	u8	Issuer[0x40];			// 0x140

	u8	Version;					// 0x180
	u8	CACRLVersion;			// 0x181
	u8	SignerCRLVersion;	// 0x182
	u8	Padding1;					// 0x183

	u64	SystemVersion;		// 0x184
	u64	TitleID;					// 0x18C 
	u32	TitleType;				// 0x194 
	u16	GroupID;					// 0x198 
	u8	Reserved[62];			// 0x19A 
	u32	AccessRights;			// 0x1D8
	u16	TitleVersion;			// 0x1DC 
	u16	ContentCount;			// 0x1DE 
	u16 BootIndex;				// 0x1E0
	u8	Padding3[2];			// 0x1E2 
	u8	SHA2[32];					// 0x1E4
	
	ContentInfo ContentInfos[64];

	Content Contents[];		// 0x1E4 

} TitleMetaData;

#define bs16(s) (unsigned short)( ((s)>>8) | ((s)<<8) )
#define bs32(s) (u32)( (((s)&0xFF0000)>>8) | (((s)&0xFF00)<<8) | ((s)>>24) | ((s)<<24) )

u32 bs24( u32 i )
{
	return ((i&0xFF0000)>>16) | ((i&0xFF)<<16) | (i&0x00FF00);
}
u64 bs64( u64 i )
{
	return ((u64)(bs32(i&0xFFFFFFFF))<<32) | (bs32(i>>32));
}
char *ReadFile( const char *Name, u32 *Length )
{
	FILE *in = fopen(Name,"rb");
	if( in == NULL )
	{
		//perror("");
		return NULL;
	}

	fseek( in, 0, SEEK_END );
	*Length = ftell(in);
	
	fseek( in, 0, 0 );

	char *Data = new char[*Length];

	u32 read = fread( Data, 1, *Length, in );

	fclose( in );

	return Data;
}
void FileDump( const char *Name, void *Data, u32 Length )
{
	if( Data == NULL )
	{
		printf("zero ptr");
		return;
	}
	if( Length == 0 )
	{
		printf("zero sz");
		return;
	}
	FILE *Out = fopen( Name, "wb" );
	if( Out == NULL )
	{
		perror("");
		return;
	}

	if( fwrite( Data, 1, Length, Out ) != Length )
  {
		perror("");
  }

	fclose( Out );
}
s32 main( s32 argc, char*argv[])
{
	char str[1024];
	
	printf("boot1_extract\n");
	printf("Built: %s %s\n", __TIME__, __DATE__ );

	if( argc != 3 )
	{
		printf("Usage:\n");
		printf(" boot1_extract tmd tik\n\n");
		return EXIT_SUCCESS;
	}

	u32 TMDLen;
	char *TMD = ReadFile( argv[1], &TMDLen );
	if( TMD == nullptr )
	{
		perror("Failed to open tmd\n");
		return EXIT_FAILURE;
	}
	
	u32 TIKLen;
	char *TIK = ReadFile( argv[2], &TIKLen );
	if( TIK == nullptr )
	{
		perror("Failed to open tik\n");
		return EXIT_FAILURE;
	}

	TitleMetaData *tmd = (TitleMetaData*)TMD;

	if( tmd->Version != 1 )
	{
		printf("Unsupported TMD Version:%u\n", tmd->Version );
		return EXIT_FAILURE;
	}
	
	printf("Title version:%u\n", bs16(tmd->TitleVersion) );
	printf("Content Count:%u\n", bs16(tmd->ContentCount) );

	AES_set_decrypt_key( CKey, sizeof(CKey)*8, &key );

	memset( title_id, 0, sizeof(title_id) );
	
	memcpy( title_id, TMD + 0x18C, 8 );
	memcpy( enc_title_key, TIK + 0x1BF, 16 );
	
	printf("Encrypted Title KEY:\n\t");
	for(s32 i=0; i< sizeof(enc_title_key); ++i)
		printf("%02X", enc_title_key[i]);
	printf("\n");
		
	printf("Title ID:\n\t");
	for(s32 i=0; i< sizeof(title_id); ++i)
		printf("%02X", title_id[i]);
	printf("\n");
	
	AES_cbc_encrypt(enc_title_key, dec_title_key, sizeof(dec_title_key), &key, title_id, AES_DECRYPT);
	
	printf("Decrypted Title KEY:\n\t");
	for(s32 i=0; i< sizeof(dec_title_key); ++i)
		printf("%02X", dec_title_key[i]);
	printf("\n");

	AES_set_decrypt_key( dec_title_key, sizeof(dec_title_key)*8, &key);
		
	char iv[16];
	memset( iv, 0, sizeof(iv) );
	
	sprintf( str, "%08x.app", bs32(tmd->Contents[0].ID) );
	
	u32 CNTLen;
	char *CNT = ReadFile( str, &CNTLen );
	if( CNT == (char*)NULL )
	{
		sprintf( str, "%08x", bs32(tmd->Contents[0].ID) );
		CNT = ReadFile( str, &CNTLen );
		if( CNT == (char*)NULL )
		{
			printf("Failed to open content:%02X\n", bs32(tmd->Contents[0].ID) );
			return EXIT_FAILURE;
		}
	}

	if( bs64(tmd->Contents[0].Size) != (u64)CNTLen )
	{
		printf("Size of content:%u is wrong: %u:%I64u\n", bs32(tmd->Contents[0].ID), CNTLen, bs64(tmd->Contents[0].Size) );
		return EXIT_FAILURE;
	}

	AES_cbc_encrypt( (const u8 *)(CNT), (u8 *)(CNT), CNTLen, &key, (u8*)(iv), AES_DECRYPT );	

	FileDump("boot1_enc.bin", CNT, CNTLen);

	return EXIT_SUCCESS;
}

#endif
