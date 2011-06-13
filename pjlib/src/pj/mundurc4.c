/******************************************************************************
 *
 *	Copyright (c) 2004 Geodesic Information Systems Ltd
 *	All rights reserved.
 *
 *	File: 
 *		MunduRC4.c
 *
 *	Description: 
 *		This file implements the RC4 Encryption Algorithm
 *
 *	History:
 *		2004 April, 07	Created by Mukesh sharma
 *
 *****************************************************************************/

/***********************************************************************
 *
 *	Include Palm OS Headers
 *
 ***********************************************************************/

/***********************************************************************
 *
 *	Include Application Specific Headers
 *
 ***********************************************************************/
#include "mundurc4.h"

//#define MYHASHKEY "shankarjaikishan"
#define MYHASHKEY  "a92538a309f9d9164a82917e31ef0026dca328ac3f12c87ff138e0a1d561f79e39dec82ae96ab2e1ceeefea6222bd65ff39d2956e831a9fff0eb41605a9363b1"
#define  MUNDULICENSEKEY "MUNDU"  
#include "stdlib.h"
#include "string.h"
#include "time.h"
#include "stdio.h"
char* StrIToA(char *result,int a)
{
	int c;
	int rno = 0;
	int r;
	int i = 0;
	c = a;
	while(c!=0)
	{
		r = c%10;
		rno = rno*10 + r;
		c = c/10;
		
		
	}
	c = rno;
	while(c!=0)
	{
		r = c%10;
		//rno = rno*10 + r;
		result[i] = 48 + r;
		c = c/10;
		
		++i;
	}
	result[i]=0;
	return result;

}

/* MD5C.C - RSA Data Security, Inc., MD5 message-digest algorithm
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
 rights reserved.
 
 License to copy and use this software is granted provided that it
 is identified as the "RSA Data Security, Inc. MD5 Message-Digest
 Algorithm" in all material mentioning or referencing this software
 or this function.
 
 License is also granted to make and use derivative works provided
 that such works are identified as "derived from the RSA Data
 Security, Inc. MD5 Message-Digest Algorithm" in all material
 mentioning or referencing the derived work.
 
 RSA Data Security, Inc. makes no representations concerning either
 the merchantability of this software or the suitability of this
 software for any particular purpose. It is provided "as is"
 without express or implied warranty of any kind.
 
 These notices must be retained in any copies of any part of this
 documentation and/or software.
 */

/* Constants for MD5Transform routine.
 */


#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

void MD5Transform (UINT4 [4],  unsigned char [64]);
void EncodeMundu 
(unsigned char *, UINT4 *, unsigned int);
void DecodeMundu 
(UINT4 *,  unsigned char *, unsigned int);
void MD5_memcpy (POINTER, POINTER, unsigned int);
void MD5_memset (POINTER, int, unsigned int);


/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
 Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
(a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
(a) = ROTATE_LEFT ((a), (s)); \
(a) += (b); \
}
#define GG(a, b, c, d, x, s, ac) { \
(a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
(a) = ROTATE_LEFT ((a), (s)); \
(a) += (b); \
}
#define HH(a, b, c, d, x, s, ac) { \
(a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
(a) = ROTATE_LEFT ((a), (s)); \
(a) += (b); \
}
#define II(a, b, c, d, x, s, ac) { \
(a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
(a) = ROTATE_LEFT ((a), (s)); \
(a) += (b); \
}

/* MD5 initialization. Begins an MD5 operation, writing a new context.
 */
void MyMD5Init (MD5_CTX *context)                                        /* context */
{
	context->count[0] = context->count[1] = 0;
	/* Load magic initialization constants.
	 */
	context->state[0] = 0x67452301;
	context->state[1] = 0xefcdab89;
	context->state[2] = 0x98badcfe;
	context->state[3] = 0x10325476;
}

/* MD5 block update operation. Continues an MD5 message-digest
 operation, processing another message block, and updating the
 context.
 */
void MyMD5Update (MD5_CTX *context /* context */,unsigned char *input /* input block */,unsigned int inputLen                     /* length of input block */)
{
	unsigned int i, index, partLen;
	
	/* Compute number of bytes mod 64 */
	index = (unsigned int)((context->count[0] >> 3) & 0x3F);
	
	/* Update number of bits */
	if ((context->count[0] += ((UINT4)inputLen << 3))
		< ((UINT4)inputLen << 3))
		context->count[1]++;
	context->count[1] += ((UINT4)inputLen >> 29);
	
	partLen = 64 - index;
	
	/* Transform as many times as possible.
	 */
	if (inputLen >= partLen) {
		MD5_memcpy
		((POINTER)&context->buffer[index], (POINTER)input, partLen);
		MyMD5Transform (context->state, context->buffer);
		
		for (i = partLen; i + 63 < inputLen; i += 64)
		MyMD5Transform (context->state, &input[i]);
		
		index = 0;
	}
	else
		i = 0;
	
	/* Buffer remaining input */
	MD5_memcpy
	((POINTER)&context->buffer[index], (POINTER)&input[i],
	 inputLen-i);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
 the message digest and zeroizing the context.
 */
void MyMD5Final (
unsigned  char digest[16],                         /* message digest */
MD5_CTX *context)                                      /* context */
{
	unsigned   char bits[8];
	unsigned int index, padLen;
	unsigned char *PADDING = MemPtrNew(70);
	//unsigned char PADDING[64] = {
	//0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	// 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	// 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	//};
	MemSet(PADDING,70,0);
	PADDING[0] = 0x80;
	/* Save number of bits */
	EncodeMundu (bits, context->count, 8);
	
	/* Pad out to 56 mod 64.
	 */
	index = (unsigned int)((context->count[0] >> 3) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	MyMD5Update (context, PADDING, padLen);
	
	/* Append length (before padding) */
	MyMD5Update (context, bits, 8);
	
	/* Store state in digest */
	EncodeMundu (digest, context->state, 16);
	
	/* Zeroize sensitive information.
	 */
	MD5_memset ((POINTER)context, 0, sizeof (*context));
	MemPtrFree(PADDING);
}

/* MD5 basic transformation. Transforms state based on block.
 */
void MyMD5Transform (UINT4 state[4],unsigned  char block[64])
{
	UINT4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];
	
	DecodeMundu (x, block, 64);
	
	/* Round 1 */
	FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
	FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
	FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
	FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
	FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
	FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
	FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
	FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
	FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
	FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
	FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
	FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
	FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
	FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
	FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
	FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */
	
	/* Round 2 */
	GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
	GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
	GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
	GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
	GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
	GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
	GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
	GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
	GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
	GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
	GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
	GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
	GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
	GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
	GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
	GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */
	
	/* Round 3 */
	HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
	HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
	HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
	HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
	HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
	HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
	HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
	HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
	HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
	HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
	HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
	HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
	HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
	HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
	HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
	HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */
	
	/* Round 4 */
	II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
	II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
	II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
	II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
	II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
	II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
	II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
	II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
	II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
	II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
	II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
	II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
	II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
	II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
	II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
	II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */
	
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	
	/* Zeroize sensitive information.
	 */
	MD5_memset ((POINTER)x, 0, sizeof (x));
}

/* Encodes input (UINT4) into output (unsigned char). Assumes len is
 a multiple of 4.
 */
void EncodeMundu (
unsigned char *output,
UINT4 *input,
unsigned int len)
{
	unsigned int i, j;
	
	for (i = 0, j = 0; j < len; i++, j += 4) {
		output[j] = (unsigned  char)(input[i] & 0xff);
		output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);
		output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
		output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);
	}
}

/* Decodes input (unsigned char) into output (UINT4). Assumes len is
 a multiple of 4.
 */
void DecodeMundu (
UINT4 *output,
unsigned char *input,
unsigned int len)
{
	unsigned int i, j;
	
	for (i = 0, j = 0; j < len; i++, j += 4)
		output[i] = ((UINT4)input[j]) | (((UINT4)input[j+1]) << 8) |
		(((UINT4)input[j+2]) << 16) | (((UINT4)input[j+3]) << 24);
}

/* Note: Replace "for loop" with standard memcpy if possible.
 */

void MD5_memcpy (POINTER output,POINTER input,unsigned int len)
{
	unsigned int i;
	
	for (i = 0; i < len; i++)
		output[i] = input[i];
}

/* Note: Replace "for loop" with standard memset if possible.
 */
void MD5_memset (
POINTER output,
int value,
unsigned int len)
{
	unsigned int i;
	
	for (i = 0; i < len; i++)
		((char *)output)[i] = (char)value;
}
/*
 static Char* MemToHexString(MemPtr memP, Int32 bytesLong)
 {
 Char* ptrCharP = (Char*)memP;
 Int32 i = 0;
 
 Char* retStrCharP = (Char*)MemPtrNew((bytesLong*2)+1);
 
 for (i=0; i<bytesLong; i++)
 {
 retStrCharP [i*2] = (ptrCharP [i] >> 4) & 0xf;
 retStrCharP [i*2] += (retStrCharP [i*2] <= 0x9) ? '0' : ('a'-0xa);
 
 retStrCharP [(i*2)+1] = ptrCharP [i] & 0xf;
 retStrCharP [(i*2)+1] += (retStrCharP [(i*2)+1] <= 0x9) ? '0' : ('a'-0xa);
 }
 retStrCharP [bytesLong*2] = 0;
 
 return retStrCharP ;
 }
 */
char* MemToHexString(void* pMem, int nBytes)
{
	const char* ptr = (char*)pMem;
	int i = 0;
	
	char* retStr = (char*)MemPtrNew((nBytes*2)+5);
	MemSet(retStr,(nBytes*2)+5,'\0');
	
	for (i=0; i<nBytes; i++)
	{
		retStr[i*2] = (ptr[i] >> 4) & 0xf;
		retStr[i*2] += (retStr[i*2] <= 0x9) ? '0' : ('a'-0xa);
		retStr[(i*2)+1] = ptr[i] & 0xf;
		retStr[(i*2)+1] += (retStr[(i*2)+1] <= 0x9) ? '0' : ('a'-0xa);
	}
	retStr[nBytes*2] = 0;
	
	return retStr;
}



static unsigned char DecodeMunduL(unsigned char c) 
{
	if(c >= 'A' && c <= 'Z') return(c - 'A');
	if(c >= 'a' && c <= 'z') return(c - 'a' + 26);
	if(c >= '0' && c <= '9') return(c - '0' + 52);
	if(c == '+')             return 62;
	// WinDrawChars("Mukesh",6,10,50);
	
	return 63;
}

static int is_base64(unsigned char c) 
{
	if((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
	   (c >= '0' && c <= '9') || (c == '+')             ||
	   (c == '/')             || (c == '=')) 
	{
		return true;
	}
	//  WinDrawChars("Shankar",6,100,50);
	return false;
}

static unsigned char EncodeMunduL(unsigned char u) 
{
	if(u < 26)  return 'A'+u;
	if(u < 52)  return 'a'+(u-26);
	if(u < 62)  return '0'+(u-52);
	if(u == 62) return '+';
	
	return '/';
}


int decode_base64(unsigned char *dest, unsigned char *src) 
{
	if(src && *src) 
	{
		unsigned char *p= dest;
		int k, l = StrLen((char*)src)+1;
		unsigned char *buf= (unsigned char *)MemPtrNew(l);
		
		
		for(k=0, l=0; src[k]; k++) 
		{
			if(is_base64(src[k])) 
			{
				buf[l++]= src[k];
			}
		} 
		for(k=0; k<l; k+=4) 
		{
			unsigned char c1='A', c2='A', c3='A', c4='A';
			unsigned char b1=0, b2=0, b3=0, b4=0;
			
			c1= buf[k];
			
			if(k+1<l) 
			{
				c2= buf[k+1];
			}
			
			if(k+2<l) 
			{
				c3= buf[k+2];
			}
			
			if(k+3<l) 
			{
				c4= buf[k+3];
			}
			
			b1= DecodeMunduL(c1);
			b2= DecodeMunduL(c2);
			b3= DecodeMunduL(c3);
			b4= DecodeMunduL(c4);
			
			*p++=((b1<<2)|(b2>>4) );
			
			if(c3 != '=') 
			{
				*p++=(((b2&0xf)<<4)|(b3>>2) );
			}
			
			if(c4 != '=') 
			{
				*p++=(((b3&0x3)<<6)|b4 );
			}
		}
		
		MemPtrFree(buf);
		
		return(p-dest);
	}
	
	return false;
}


unsigned char *encode_base64(int size, unsigned char *src) 
{
	int i;
	unsigned char *out, *p;
	
	if(!src)
		return NULL;
	
	if(!size)
		size= StrLen((char *)src);
    
	out= (UInt8*)MemPtrNew((sizeof(char))*(size*4/3+4));
	MemSet(out,size*4/3+4,0);
	
	p= out;
    
	for(i=0; i<size; i+=3) 
	{
		unsigned char  b1=0, b2=0, b3=0, b4=0, b5=0, b6=0, b7=0;
		
		b1 = src[i];
		
		if(i+1<size)
			b2 = src[i+1];
		
		if(i+2<size)
			b3 = src[i+2];
		
		b4= b1>>2;
		b5= ((b1&0x3)<<4)|(b2>>4);
		b6= ((b2&0xf)<<2)|(b3>>6);
		b7= b3&0x3f;
		
		*p++= EncodeMunduL(b4);
		*p++= EncodeMunduL(b5);
		
		if(i+1<size) 
		{
			*p++= EncodeMunduL(b6);
		} else 
		{
			*p++= '=';
		}
		
		if(i+2<size) 
		{
			*p++= EncodeMunduL(b7);
		} 
		else 
		{
			*p++= '=';
		}
	}
	
	return (unsigned char*)out;
}

//#include "base64.h"



/*
 static inline bool is_base64(unsigned char c) {
 return (isalnum(c) || (c == '+') || (c == '/'));
 
 }
 */

ShareLibMNLGlobalsType * LockMNLGlobal(void)
{
	ShareLibMNLGlobalsType *glpObjP;
	glpObjP = (ShareLibMNLGlobalsType*) malloc(sizeof(ShareLibMNLGlobalsType)); 
	memset(glpObjP,0,sizeof(ShareLibMNLGlobalsType));
	return glpObjP;
}
void UnlockMNLGlobal(ShareLibMNLGlobalsType *shareLibMNLGlobalsPtr)
{
	free(shareLibMNLGlobalsPtr);
	shareLibMNLGlobalsPtr = 0;
}
int MemPtrSetOwner(void *da,int x)
{
	return 0;
}
/***********************************************************************
 *
 * FUNCTION:    
 *		MunduRC4Encrypt
 *
 * DESCRIPTION: 
 *		This function is used to encrypt data using the RC4 algo
 *		
 * PARAMETERS:  
 *		keyByteP	-	key to be used to encrypt data
 *		keyLenLong	-	length of the key
 *		inputByteP	-	data to be encrypted
 *		inputLenLong-	length of data to be encrypted
 *
 * RETURNED:    
 *		Encrypted data -Allocated by this function, should be freed
 *						by the caller
 *
 ***********************************************************************/
UInt8* MunduRC4Encrypt (UInt8* keyByteP, Int32 keyLenLong, UInt8* inputByteP, Int32 inputLenLong, Boolean old,Rc4TypeEnum rc4Enum)
{
	UInt8*	outputByteP=0;
	UInt8 temp;
	
	//UInt8 	keyDataCharP[256], boxDataCharP[256];
	UInt8 	*keyDataCharP, *boxDataCharP;

	Int32	iLong=0, aLong=0, jLong=0, kLong=0,mLong = 0, xLong=0;
	RC4VarType rc4Var;
	ShareLibMNLGlobalsType* shareLibMNLGlobalsPtr = LockMNLGlobal();
	
	if(rc4Enum == RC4WholeData || rc4Enum == RC4ChunkInit)
	{
		if (shareLibMNLGlobalsPtr->rc4Var.keyDataCharP)
		{
			MemPtrFree (shareLibMNLGlobalsPtr->rc4Var.keyDataCharP);
		}
		if (shareLibMNLGlobalsPtr->rc4Var.boxDataCharP)
		{
			MemPtrFree (shareLibMNLGlobalsPtr->rc4Var.boxDataCharP);
		}
	
		MemSet(&shareLibMNLGlobalsPtr->rc4Var, sizeof(RC4VarType), 0);
		shareLibMNLGlobalsPtr->rc4Var.keyDataCharP = MemPtrNew (256);
		MemPtrSetOwner (shareLibMNLGlobalsPtr->rc4Var.keyDataCharP, 0);
		shareLibMNLGlobalsPtr->rc4Var.boxDataCharP = MemPtrNew (256);
		MemPtrSetOwner (shareLibMNLGlobalsPtr->rc4Var.boxDataCharP, 0);
	}
	rc4Var = shareLibMNLGlobalsPtr->rc4Var;
	keyDataCharP = rc4Var.keyDataCharP;
	boxDataCharP = rc4Var.boxDataCharP;
	UnlockMNLGlobal(shareLibMNLGlobalsPtr);
	//	Allocate memory for the output
	//	since this is a stream cipher, 
	//	lets allocate the same amt of memory as the input
	outputByteP=MemPtrNew(inputLenLong+1);
	//	reset all memory to be used in this function
	MemSet(outputByteP, inputLenLong+1, 0);
	if(rc4Enum == RC4WholeData || rc4Enum == RC4ChunkInit)
	{
		MemSet(keyDataCharP, 256, 0);
		MemSet(boxDataCharP, 256, 0);
		
		for (iLong=0; iLong<256; iLong++)
		{
			keyDataCharP[iLong] = (UInt8)(keyByteP[iLong % keyLenLong]);
			boxDataCharP[iLong] = iLong;
		}
			
		//	innitialize the state table 
		for (jLong=iLong=0; iLong<256; iLong++)
		{
			jLong = (jLong + boxDataCharP[iLong] + keyDataCharP[iLong]) % 256;
			if(old==true)
			{
				boxDataCharP[iLong] ^= boxDataCharP[jLong];
				boxDataCharP[jLong] ^= boxDataCharP[iLong];
				boxDataCharP[iLong] ^= boxDataCharP[jLong];
			}
			else
			{
				temp = boxDataCharP[jLong];
				boxDataCharP[jLong] = boxDataCharP[iLong];
				boxDataCharP[iLong] = temp;
			}	
		}
	 }
	//	xor the pseudo random bytes with the plain text &
	//	generate the cipher text
	aLong=rc4Var.aLong ;
	jLong=rc4Var.jLong ;
	iLong=rc4Var.iLong ;
	for (; iLong<rc4Var.totalLong+inputLenLong; iLong++,xLong++)
	{
		aLong = (aLong + 1) % 256;
		
		jLong = (jLong + boxDataCharP[aLong]) % 256;
		if(old==true)
		{
			boxDataCharP[aLong] ^= boxDataCharP[jLong];
			boxDataCharP[jLong] ^= boxDataCharP[aLong];
			boxDataCharP[aLong] ^= boxDataCharP[jLong];
		}
		else
		{
			temp= boxDataCharP[jLong];
			boxDataCharP[jLong] = boxDataCharP[aLong];
			boxDataCharP[aLong] = temp;
		}
		kLong = boxDataCharP[((boxDataCharP[aLong] + boxDataCharP[jLong]) % 256)];
		outputByteP[xLong] = (UInt8)(inputByteP[mLong]) ^ kLong;
		mLong++;
	}
	rc4Var.totalLong = rc4Var.totalLong + inputLenLong;
	rc4Var.aLong = aLong;
	rc4Var.jLong = jLong;
	rc4Var.iLong = iLong;

	shareLibMNLGlobalsPtr = LockMNLGlobal();
	if(rc4Enum==RC4ChunkEnd || rc4Enum==RC4WholeData)
	{
		if (shareLibMNLGlobalsPtr->rc4Var.keyDataCharP)
		{
			MemPtrFree (shareLibMNLGlobalsPtr->rc4Var.keyDataCharP);
			
		}
		if (shareLibMNLGlobalsPtr->rc4Var.boxDataCharP)
		{
			MemPtrFree (shareLibMNLGlobalsPtr->rc4Var.boxDataCharP);
		}
		
		MemSet(&shareLibMNLGlobalsPtr->rc4Var, sizeof(RC4VarType), 0);
	}
	if(rc4Enum==RC4ChunkInit||rc4Enum== RC4ChunkContinue)
	{
		shareLibMNLGlobalsPtr->rc4Var = rc4Var;
	}
	UnlockMNLGlobal(shareLibMNLGlobalsPtr);

	//	return the cipher text
	return outputByteP;
}

/***********************************************************************
 *
 * FUNCTION:    
 *		MunduRC4Decrypt
 *
 * DESCRIPTION: 
 *		This function is used to decrypt data using the RC4 algo
 *		
 * PARAMETERS:  
 *		keyByteP	-	key to be used to decrypt data
 *		keyLenLong	-	length of the key
 *		inputByteP	-	data to be encrypted
 *		inputLenLong-	length of data to be encrypted
 *
 * RETURNED:    
 *		Decrypted data -Allocated by this function, should be freed
 *						by the caller
 *
 ***********************************************************************/
UInt8* MunduRC4Decrypt (UInt8* keyByteP, Int32 keyLenLong, UInt8* inputByteP, 
						Int32 inputLenLong,Boolean oldB)
{
	//	return the cipher text
	return MunduRC4Encrypt (keyByteP, keyLenLong, inputByteP, inputLenLong,oldB,RC4WholeData);
}

/***********************************************************************
 *
 * FUNCTION:    
 *		MunduRC4Bin2Hex
 *
 * DESCRIPTION: 
 *		This function copnverts binary data to hex
 *		
 * PARAMETERS:  
 *		inputByteP	-	binary data 
 *		inputLenLong-	length of binary data
 *
 * RETURNED:    
 *		hex string
 *
 ***********************************************************************/
Char* MunduRC4Bin2Hex(UInt8* inputByteP, Int32 inputLenLong)
{
	Char hexChars[17] = "0123456789abcdef";
	Int32 iLong=0, jLong=0;
	UInt8 firstByte=0;
	UInt8 secondByte=0;
	Char* hexCharP=0;
	
	hexCharP=MemPtrNew((inputLenLong*2)+20);
	MemSet(hexCharP, (inputLenLong*2)+20, '\0');

	for (iLong=0 ; iLong<inputLenLong ; iLong++) 
	{
		firstByte = inputByteP[iLong] / 16;
		secondByte = inputByteP[iLong] % 16;
		hexCharP[jLong] = hexChars[firstByte];
		hexCharP[jLong + 1] = hexChars[secondByte];
		jLong+=2;
	}
	
	return hexCharP;
}

/***********************************************************************
 *
 * FUNCTION:    
 *		MunduRC4Hex2Bin
 *
 * DESCRIPTION: 
 *		This function converts hex data to binary format
 *		
 * PARAMETERS:  
 *		hexCharP	-	hex data
 *
 * RETURNED:    
 *		binary data
 *
 ***********************************************************************/
UInt8* MunduRC4Hex2Bin(UInt8* hexCharP, Int32 inputLenLong)
{
	UInt8* 	byteP=0;
	Int32	iLong=0, jLong=0;
	
	byteP = MemPtrNew(inputLenLong/2 + 20);
	MemSet(byteP, inputLenLong/2 +20, 0);

	for(iLong=jLong=0; iLong< inputLenLong; jLong++) 
	{ 
		byteP[jLong] = (HexValue(hexCharP[iLong]) << 4) + HexValue(hexCharP[iLong+1]); 
		iLong += 2; 
	} 
	
	return byteP;
}

/***********************************************************************
 *
 * FUNCTION:    
 *		HexValue
 *
 * DESCRIPTION: 
 *		This function is used to convert a hex value to its binary
 *		equivalent
 *		
 * PARAMETERS:  
 *		cByte
 *
 * RETURNED:    
 *		Integer value
 *
 ***********************************************************************/
static	Int32 HexValue(UInt8 cByte)
{ 
   if(cByte > 96 && cByte < 103) return (cByte - 87); // a - f 
   if(cByte > 64 && cByte < 71) return (cByte - 55); // A - F 
   return (cByte - 48); // assume its 0-9 
}

void MakeMD5Hash(Char* challengeStrCharP, Char** authResponseCharP)
{
	//Int32 lenLong = 0;
	
	MD5_CTX context;
	
//	Char* hexstrCharP = 0;
//	Char* pswdCharP = 0;							// 
	Char digestChar[20];
	// lets allocate memory for the magic string.
	//Char* magicStringCharP = (Char*) MemPtrNew(StrLen("JXQ6J@TUOGYV@N0M") + 1);
	//StrCopy(magicStringCharP, "JXQ6J@TUOGYV@N0M");
		
	// concatenating the magic string to the challengestring.
	//StrCat(challengeStrCharP, magicStringCharP);
		
	MemSet(digestChar, 20, 0);
	
	// make the password hash now!
	MyMD5Init (&context);
	MyMD5Update (&context, (UInt8*)challengeStrCharP, StrLen(challengeStrCharP));
	MyMD5Final ((UInt8*)digestChar, &context);
	*authResponseCharP = MemToHexString(digestChar,16);
}

void InItMD5CTX(MD5_CTX *context)
{
	MyMD5Init (context);
}

void UpdateMD5CTX(MD5_CTX *context,Char* challengeStrCharP,int len)
{

	MyMD5Update (context, (UInt8*)challengeStrCharP, len);
}

void FinalMD5CTX(MD5_CTX *context,Char** authResponseCharP,Boolean isHexB)
{
	Char *digestChar = MemPtrNew(22);

	MemSet(digestChar, 20, 0);
	
	MyMD5Final ((UInt8*)digestChar, context);
	if(isHexB == true)
	{
		*authResponseCharP = MemToHexString(digestChar,16);
	}
	else
	{
		*authResponseCharP = MemPtrNew(20);
		MemMove (*authResponseCharP, digestChar, 16);
	}
	MemPtrFree(digestChar);
}

void MunduMD5Hash(UInt8* challengeStrCharP,UInt32 lenUShort, UInt8* authResponseCharP)
{
	//Int32 lenLong = 0;
	MD5_CTX context;
				// 
  	// lets allocate memory for the magic string.
	// concatenating the magic string to the challengestring.
	
	// make the password hash now!
	MyMD5Init (&context);
	MyMD5Update (&context, challengeStrCharP, lenUShort);
	MyMD5Final (authResponseCharP, &context);
	//*authResponseCharP = MemToHexString(digestChar,StrLen(digestChar));
}

UInt8* EncryptInfo(MunduSecuriteEnum secureEnum,UInt8* inputDataCharP,UInt32 lenULong,UInt32 *outlenULongP,Boolean urlencodeB,Boolean nohex)
{
	UInt8 *key;
	UInt16 codeUShort;//use to store integer value
	UInt8* encDataCharP; 
	UInt8* encByteP;
	UInt8* hexCharP;
	UInt8 keyEncChar[32];
	UInt8 keyEncChar1[32];
	UInt8 codeChar[30];//use to convert code int to char
	UInt16 firstUShort,secondUShort,onesFirstUShort,onesSecondUShort;
	UInt32 resultULong,sumULong;
	UInt8 secondByte,firstByte;
	Int32 size = 100;
	long longVar = 0;
	char *newEncodeCharP,*mainDataCharP=0;
	UInt8 *sendDataCharP;
	codeUShort=0;
	if(secureEnum==MunduRC4New)
	{
		encByteP = MunduRC4Encrypt ("mukesh", 6, inputDataCharP, lenULong,true,RC4WholeData);
		*outlenULongP = lenULong;
		return encByteP;
	}
	if(secureEnum==MunduNewIncription)
	{
		encByteP =(unsigned char*) malloc(lenULong+10);
		*outlenULongP = lenULong;
		for(codeUShort=0;codeUShort<lenULong;++codeUShort)
		{
			encByteP[codeUShort] = inputDataCharP[codeUShort]+CONST_DIGIT;
		}
		encByteP[codeUShort]=0;
		return encByteP;
	}
	if(secureEnum==MunduSecureData)
	{
		key = MemPtrNew(150);
		StrCopy((char *)key,MYHASHKEY);
		MemSet(keyEncChar, 32, 0);
		MunduMD5Hash(key,StrLen((Char*)key),keyEncChar);//hash the data
		longVar = SysRandom(0);;
		codeUShort=(UInt16)longVar;//get random no
		StrIToA((char*)codeChar,codeUShort);
		
		#ifdef _NEW_METHOD_
				sprintf(key,"%s:mundu:%d",MYHASHKEY,codeUShort);
				MunduMD5Hash(key,strlen(key),keyEncChar1);//hash the data with 
		#else
				MunduMD5Hash(key,StrLen((Char*)key),keyEncChar);//hash the data
				MemMove(keyEncChar+16,codeChar,StrLen((char*)codeChar));
				MunduMD5Hash(keyEncChar,16+StrLen((char*)codeChar),keyEncChar1);//hash the data
		#endif	
		//printf("\n random %s %d %ld",codeChar,codeUShort,longVar);
		
		hexCharP = (UInt8*)MunduRC4Bin2Hex(keyEncChar1, 16);
		
		encDataCharP=MemPtrNew(lenULong+5);//extra 5 char is use for precaution
		encByteP=0;
		encByteP=MunduRC4Encrypt (keyEncChar1, 16, inputDataCharP, lenULong,true,RC4WholeData);
		firstUShort=SysRandom(0);//get random no that has to send  
		secondUShort=firstUShort<<4;//move in left
		//get ones complement of this no
		onesFirstUShort=~firstUShort;
		onesSecondUShort=~secondUShort;
		sumULong=(UInt32)onesFirstUShort+(UInt32)onesSecondUShort+(UInt32)firstUShort+(UInt32)secondUShort;
		resultULong=sumULong%lenULong;
		//printf("\n\norgkey = %s,key=%s , randomVar=%d,code=%d,first=%donceF=%d,second=%d,onceSec=%d ,sum= %d\n\n",key,hexCharP,firstUShort,codeUShort,firstUShort,onesFirstUShort,secondUShort,onesSecondUShort,sumULong);
		
		firstByte =firstUShort>>8;//get high byte
		secondByte=(firstUShort<<8)>>8;//get low byte
		//StrNCopy(encDataCharP,encByteP,resultULong);//seprate data in two parts
		StrPrintF((char*)encDataCharP,"%c%c",firstByte,secondByte);//store random value
		firstByte =codeUShort>>8;//get high byte
		secondByte=(codeUShort<<8)>>8;//get low byte
		StrPrintF((char*)(encDataCharP+resultULong+2),"%c%c",firstByte,secondByte);//store random value
		MemMove(encDataCharP+2,encByteP,resultULong);//copy portion of data
		MemMove(encDataCharP+4+resultULong,encByteP+resultULong,lenULong-resultULong);//copy portion of data
		//StrNCat(encDataCharP,encByteP,resultULong);//seprate data in two parts
		if(nohex==0)
		{	
			hexCharP = (UInt8*)MunduRC4Bin2Hex(encDataCharP, lenULong+4);
			MemPtrFree(encByteP);
			MemPtrFree(encDataCharP);
			*outlenULongP=(lenULong+4)*2;//get length of text
			MemPtrFree(key);
			return hexCharP;//return data
		}
		else {
			MemPtrFree(encByteP);
			
			*outlenULongP=lenULong+4;//get length of text
			return encDataCharP;
		}

	}
	if(secureEnum==MunduLicenseEncryption || secureEnum == MunduSpeakEncryption)
	{
		char ch1,ch2;
		key = MemPtrNew(StrLen(MUNDULICENSEKEY)+50);
		//StrCopy((char *)key,MYHASHKEY);
		firstUShort=SysRandom(0);//get random no that has to send  
		encByteP = (UInt8*)&firstUShort;
		firstUShort = firstUShort%99;
		if(firstUShort<10)
		{
			firstUShort+=10;
		}
		//*encByteP = '1';
		//*(encByteP+1) = '0';
		//firstUShort = 56;
		ch1 = *encByteP;
		ch2 = *(encByteP+1);
		if(ch1 ==0)
		{
			ch1 = 1;
		}
		if(ch2 ==0)
		{
			ch2 = 1;
		}
		//StrPrintF((char*)key,"%s:%c%c",MUNDULICENSEKEY,ch1,ch2);
		StrPrintF((char*)key,"%s:%d",MUNDULICENSEKEY,firstUShort);
		//WinDrawChars((char*)key,8,10,10);
		//StrPrintF((char*)key,"%s:%c%c",MUNDULICENSEKEY,'P','A');
		
		encByteP=0;
		encByteP=MunduRC4Encrypt (key, StrLen(MUNDULICENSEKEY)+3, inputDataCharP, lenULong,false,RC4WholeData);
		MemPtrFree(key);
		
		if(secureEnum==MunduLicenseEncryption)
		{		
			newEncodeCharP = (char*)encode_base64(lenULong,encByteP);
			MemPtrFree(encByteP);
			if(urlencodeB)
			{
				//mainDataCharP  = HTTP_UrlEncode(newEncodeCharP,StrLen(newEncodeCharP),&size);
				MemPtrFree(newEncodeCharP);
			}
			else
			{
					mainDataCharP  =newEncodeCharP;// HTTP_UrlEncode(newEncodeCharP,StrLen(newEncodeCharP),&size);
			
			}
		}
		else
		{
			hexCharP = (UInt8*)MunduRC4Bin2Hex(encByteP, lenULong);
			MemPtrFree(encByteP);
	
			
		}	
		
		
		sendDataCharP = MemPtrNew(size+50);
		
		*outlenULongP = StrLen((char*)mainDataCharP)+2 +5;
		//StrPrintF((char*)sendDataCharP,"DATA=%s%c%c",mainDataCharP,ch1,ch2);
		
		StrPrintF((char*)sendDataCharP,"DATA=%s%d",mainDataCharP,firstUShort);
		//StrPrintF((char*)sendDataCharP,"%s%c%c",mainDataCharP,'P','A');
	
		//StrPrintF((char*)sendDataCharP,"%s%d",mainDataCharP,firstUShort);
		MemPtrFree(mainDataCharP);
		
		
		return sendDataCharP;//return data
	}
	return 0;//return data

}
UInt8* DecryptInfo(MunduSecuriteEnum secureEnum,UInt8* hexDataCharP,UInt32 lenULong,UInt32 *outlenULongP,Boolean noHex)
{
	UInt8 *key ;
	UInt16 codeUShort;
	UInt8*  decByteP; 
	Int32 decLenLong;
	UInt8* tempCharP=0;
	UInt8 keyEncChar[32];
	UInt8 keyEncChar1[32];
	UInt8 codeChar[30];//use to convert code int to char
	UInt32 tempULong;
	unsigned char *encCharP;//use to get binary data
	
	//use for dynamic integer
	UInt16 firstUShort,secondUShort,onesFirstUShort,onesSecondUShort;
	UInt32 resultULong,sumULong;
	UInt8 secondByte,firstByte;
	MemSet(keyEncChar, 32, 0);
	if(noHex==0)
	{	
		decLenLong=lenULong/2-4;//get actual length of data
	}
	else {
		decLenLong = lenULong-4;
	}

	if(decLenLong<=0)
		return 0;//no text
	if(secureEnum==MunduRC4New)
	{
		encCharP = MunduRC4Encrypt ("mukesh", 6, hexDataCharP, lenULong,true,RC4WholeData);
		*outlenULongP = lenULong;
		return encCharP;
	}
	if(secureEnum==MunduNewIncription)
	{
		encCharP =(unsigned char*) malloc(lenULong+10);
		*outlenULongP = lenULong;
		for(codeUShort=0;codeUShort<lenULong;++codeUShort)
		{
			encCharP[codeUShort] = hexDataCharP[codeUShort]-CONST_DIGIT;
		}
		encCharP[codeUShort]=0;
		return encCharP;
	}
	if(secureEnum==MunduSecureData)
	{	
		key = MemPtrNew(150);
		StrCopy((char *)key,MYHASHKEY);
			
		decByteP=MemPtrNew(decLenLong+4);//extra 4 char is use for precaution
		if(decByteP==0)
			return 0;//error
		if(noHex==0)
		{	
			encCharP=MunduRC4Hex2Bin((UInt8*)hexDataCharP,lenULong);
		}
		else {
			encCharP=malloc(lenULong+4);
			MemMove(encCharP,hexDataCharP,lenULong);
			
		}

		firstByte=	*(encCharP);//get first byte
		secondByte= *(encCharP+1);//get second byte
		firstUShort=(UInt16)firstByte*256+secondByte;//get integer
		secondUShort=firstUShort<<4;//move in left
		//get one's complement of of this no
		onesFirstUShort=~firstUShort;
		onesSecondUShort=~secondUShort;
		sumULong=(UInt32)onesFirstUShort+(UInt32)onesSecondUShort+(UInt32)firstUShort+(UInt32)secondUShort;
		
		resultULong=sumULong%decLenLong;
		tempULong=resultULong+2;//this is position where dynamic integer is store
		firstByte =	*(encCharP+tempULong);//get high byte of dynamic integer
		tempULong=tempULong+1;
		secondByte= *(encCharP+tempULong);//get low byte of dynamic integer
		codeUShort=(UInt16)firstByte*256+secondByte;//get integer
		//printf("\n\n randomVar=%d,code=%d,first=%donceF=%d,second=%d,onceSec=%d ,sum= %d\n\n",firstUShort,codeUShort,firstUShort,onesFirstUShort,secondUShort,onesSecondUShort,sumULong);
		
		#ifdef _NEW_METHOD_
			sprintf(key,"%s:mundu:%d",MYHASHKEY,codeUShort);
			MunduMD5Hash(key,strlen(key),keyEncChar1);//hash the data with 
		#else
			MunduMD5Hash(key,StrLen((Char*)key),keyEncChar);//hash the data
			StrIToA((char*)codeChar,codeUShort);
			MemMove(keyEncChar+16,codeChar,StrLen((char*)codeChar));//attech dynamic integer with key
			MunduMD5Hash(keyEncChar,16+StrLen((char*)codeChar),keyEncChar1);//hash the data with 
		#endif
		//get data from Receiving 
		tempULong=2;
		if(resultULong!=0)//if it is not on first byte
			MemMove(decByteP,encCharP+tempULong,resultULong);//get first half data
		tempULong=resultULong+4;//
		MemMove(decByteP+resultULong,encCharP+tempULong,decLenLong-resultULong);//get remaining data
		//get decryptData
		tempCharP = MunduRC4Encrypt ((UInt8*)keyEncChar1, 16, decByteP, decLenLong,true,RC4WholeData);
		MemPtrFree(encCharP);encCharP=0;
		MemPtrFree(decByteP);
		*outlenULongP=decLenLong;//store length of data
		MemPtrFree(key);
		return tempCharP;
	}	
	
	return 0;

} 
void log_message(char *filename,char *message)
{
FILE *logfile;
	logfile=fopen(filename,"a");
	if(!logfile) return;
	fprintf(logfile,"\n\nmsg=\n%s    \n=end\n\n",message);
	fclose(logfile);
}

void testEncription(char *testP)
{
	#define TESTSTRING "shankar jaikishan"
	
	UInt32 outlenULong = 0,decLen=0;
	UInt8 *resultP;
	UInt8 *decResultP;
	//UInt8* EncryptInfo(MunduSecuriteEnum secureEnum,UInt8* inputDataCharP,UInt32 lenULong,UInt32 *outlenULongP,Boolean urlEncode);
	//UInt8* DecryptInfo(MunduSecuriteEnum secureEnum,UInt8* hexDataCharP,UInt32 lenULong,UInt32 *outlenULongP);
	if(testP==0)
	{
		testP = TESTSTRING;
	}
	resultP = EncryptInfo(MunduSecureData,(UInt8*)testP,strlen(testP),&outlenULong,0,1);
	decResultP = DecryptInfo(MunduSecureData,resultP,outlenULong,&decLen,1);
	log_message("/usr/src/mylog.txt",(char*)decResultP);	
	free(resultP);
	free(decResultP);


}
void testHash(char *testP)
{
	char str[20];
	char *hexCharP;

	if(testP==0)
	{
		testP = "shankar";
	}
	MunduMD5Hash(testP,StrLen(testP),str);
	hexCharP = (UInt8*)MunduRC4Bin2Hex(str, 16);
	printf("\nmd5Hash=%s\n%d\n",hexCharP,sizeof(UINT4));
	free(hexCharP);

}

