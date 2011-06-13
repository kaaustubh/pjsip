/******************************************************************************
 *
 *	Copyright (c) 2004 Geodesic Information Systems Ltd
 *	All rights reserved.
 *
 *	File: 
 *		MunduRC4.h
 *
 *	Description: 
 *		This file implements the RC4 Encryption Algorithm
 *
 *	History:
 *		2004 April, 07	Created by mukesh sharma
 *
 *****************************************************************************/

#ifndef	_MUNDURC4_H_
#define	_MUNDURC4_H_
//#define _NEW_METHOD_
#define _ENCRIPT_PORT_ 9065
#define _NO_HEX_      1
#define CONST_DIGIT 5
#define MUNDU_DATA_ENUM MunduSecureData
//#define teststr "67e0cfec91bdf3dc26e363e170ed093f986245405571ef8e655560259ba63874078083ca5caf0a57f589b97d2b38d9b5e44a682f72bd7fa57a16bd0ce347fd3fb2e59607836ac139e53fef461b52eb6a70fd3bfece645b4f8802e95895845529306ab0002c7e30e1053d2db21e9c36d7095448fb51906cbc91e124512b56cbb39c07ff91127bad75c369984db0171e0254b9cb880fc5a1e524516cb49b638bd0725ce03a94118ddf97226a044a5508fd71f4c91236282fa5270cbcc6b2d43e4c8cfd8f77f9d35fef7c23a7da0504a4b38513f662f88977b45a0ff27364c138808d1020d6748e0f6f9e130cb3ff5d3f28e4a0bb2201dfae6d149a1c79ea721dfc0c779ec0b00357aa8225dace428329feb468a9641e35b76788c68b7aa88ffe9f0e41b0e72296f82f6d731888d82cdea97c17dccb7610a2201d7fe7606e193be54a7c9ec29b4f6b97e517229c97dbcd64c023"
//#define MUNDU_DATA_ENUM  MunduNewIncription
//#define MUNDU_DATA_ENUM MunduRC4New
/***********************************************************************
 *
 *	Include Palm OS Headers
 *
 ***********************************************************************/
#ifndef Int32
typedef long Int32;
#endif
typedef unsigned long UInt32;
#ifndef Boolean
typedef unsigned char Boolean;
#endif
#ifndef UInt8
typedef unsigned char UInt8;
#endif
#define true 1
#define false 0
typedef char Char;
#define StrPrintF sprintf
#define MemPtrNew(x) malloc(x)
#define MemPtrFree(x) free(x) 
#define MemSet(x,y,z) memset(x,z,y)
typedef unsigned short int UINT2;
typedef unsigned short                  UInt16;
/* UINT4 defines a four byte word */
typedef unsigned int UINT4;
#ifndef PROTOTYPES
#define PROTOTYPES 1
#endif

/* POINTER defines a generic pointer type */
typedef unsigned char *POINTER;

/* UINT2 defines a two byte word */


/* UINT4 defines a four byte word */


#define StrCopy strcpy
#define StrLen strlen
#define MemMove memmove
#define SysRandom(x) rand()
typedef struct RC4VarType
{
	Int32	iLong;
	Int32	aLong;
	Int32	jLong;
	Int32	totalLong;
	UInt8*	keyDataCharP;
	UInt8*	boxDataCharP;
}RC4VarType;
typedef enum 
{
	MunduPlaneData=0,//use to send Plain text
	MunduSslData,//use to send text through ssl socket
	MunduSecureData,//use to send text through mundu securite algorithum
	MunduLicenseEncryption,
	MunduSpeakEncryption,
	MunduNewIncription,
	MunduRC4New
	
	
} MunduSecuriteEnum;
typedef enum  Rc4TypeEnum
{
	RC4WholeData=0,
	RC4ChunkInit,
	RC4ChunkContinue,
	RC4ChunkEnd
	
	
}Rc4TypeEnum;

typedef struct ShareLibMNLGlobalsType
{
	RC4VarType rc4Var;
	
}ShareLibMNLGlobalsType;
typedef struct {
	UINT4 state[4];                                   /* state (ABCD) */
	UINT4 count[2];        /* number of bits, modulo 2^64 (lsb first) */
	unsigned char buffer[64];                         /* input buffer */
} MD5_CTX;

void MyMD5Init (MD5_CTX *);
void MyMD5Update
(MD5_CTX *, unsigned char *, unsigned int);
void MyMD5Final  (unsigned char [16], MD5_CTX *);
 void MyMD5Transform (UINT4 state[4],unsigned  char block[64]);
//static Char* MemToHexString(MemPtr memP, Int32 bytesLong);
char* MemToHexString(void* memP, int bytesLong);

int decode_base64(unsigned char *dest, unsigned char *src);

unsigned char *encode_base64(int size, unsigned char *src);

/***********************************************************************
 *
 *	Global function prototypes
 *
 ***********************************************************************/

//	This function encrypts data using the rc4 algo 
UInt8* MunduRC4Encrypt(UInt8* keyByteP, Int32 keyLenLong, UInt8* inputByteP, Int32 inputLenLong, Boolean old, Rc4TypeEnum rc4Enum);

//	This function decrypt data using the rc4 algo 
UInt8* MunduRC4Decrypt(UInt8* keyByteP, Int32 keyLenLong, UInt8* inputByteP, Int32 inputLenLong,Boolean oldB);

//	This function converts binary data to hex
Char* MunduRC4Bin2Hex(UInt8* inputByteP, Int32 inputLenLong);

//	This function converts hex data to binary format
UInt8* MunduRC4Hex2Bin(UInt8* inputByteP, Int32 inputLenLong);

//	Internal function used for conversion from hex to bin
static	Int32 HexValue(UInt8 cByte);
void MunduMD5Hash(UInt8* challengeStrCharP,UInt32 lenUShort, UInt8* authResponseCharP);
UInt8* EncryptInfo(MunduSecuriteEnum secureEnum,UInt8* inputDataCharP,UInt32 lenULong,UInt32 *outlenULongP,Boolean urlEncode,Boolean noHex);
UInt8* DecryptInfo(MunduSecuriteEnum secureEnum,UInt8* hexDataCharP,UInt32 lenULong,UInt32 *outlenULongP,Boolean noHex);
void MakeMD5Hash(Char* challengeStrCharP, Char** authResponseCharP);
void testEncription(char *testP);

 void UnlockMNLGlobal(ShareLibMNLGlobalsType *shareLibMNLGlobalsPtr);
ShareLibMNLGlobalsType * LockMNLGlobal(void);
void testHash(char *testP);


#endif	//	_MUNDURC4_H_
