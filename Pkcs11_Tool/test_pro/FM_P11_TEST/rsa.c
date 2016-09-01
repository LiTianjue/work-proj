#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include "pkcs11.h"
#include "fmpkcs11.h"
#include "pkcs11s.h"
#include "g_head.h"

#ifdef  OS_WINDOWS
#include <process.h>
#include <windows.h>
#else
#include <pthread.h>
#endif

extern CK_BBOOL g_ifthread;
void FreeAttribute(CK_ATTRIBUTE_PTR attribute, CK_ULONG num)
{
	CK_ULONG i;
	for (i=0; i<num; i++)
	{
		free(attribute[i].pValue);
	}
}

FLAG RSA1024Test_out()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_MECHANISM mGenRSAKey	= {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_ULONG RSAPubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG RSAPriKeyClass = CKO_PRIVATE_KEY;
	CK_ULONG RSAKeyType = CKK_RSA;
	CK_ULONG ModuluBits = 1024;
	CK_BBOOL isTrue = TRUE;
	CK_ATTRIBUTE aRSAPubKey[] = {
		{CKA_CLASS, &RSAPubKeyClass, sizeof(RSAPubKeyClass)},
		{CKA_KEY_TYPE, &RSAKeyType, sizeof(RSAKeyType)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)},
		{CKA_MODULUS_BITS, &ModuluBits, sizeof(ModuluBits)}
								}; 
	CK_ATTRIBUTE aRSAPriKey[] = {
		{CKA_CLASS, &RSAPriKeyClass, sizeof(RSAPriKeyClass)},
		{CKA_KEY_TYPE, &RSAKeyType, sizeof(RSAKeyType)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
								};

	CK_ATTRIBUTE CreateRSAPubKey[] = {
		{CKA_MODULUS, NULL_PTR, 0},
		{CKA_MODULUS_BITS, NULL_PTR, 0},
		{CKA_PUBLIC_EXPONENT, NULL_PTR, 0},
		{CKA_CLASS, NULL_PTR, 0}
								};

	CK_ATTRIBUTE CreateRSAPriKey[] = {
		{CKA_MODULUS, NULL_PTR, 0},
		{CKA_PUBLIC_EXPONENT, NULL_PTR, 0},
		{CKA_PRIVATE_EXPONENT, NULL_PTR, 0},
		{CKA_PRIME_1, NULL_PTR, 0},
		{CKA_PRIME_2, NULL_PTR, 0},
		{CKA_EXPONENT_1, NULL_PTR, 0},
		{CKA_EXPONENT_2, NULL_PTR, 0},
		{CKA_COEFFICIENT, NULL_PTR, 0},
		{CKA_CLASS, NULL_PTR, 0}
								};

	CK_OBJECT_HANDLE hRSAPubKey = 0;
	CK_OBJECT_HANDLE hRSAPriKey = 0;
	CK_ULONG i = 0;
	CK_MECHANISM mRSAEncryptPad = {CKM_RSA_PKCS, NULL_PTR, 0};
	CK_MECHANISM mRSAEncryptRaw = {CKM_RSA_X_509, NULL_PTR, 0};
	CK_BYTE indata[128] = {0x00};
	CK_BYTE outdata[128] = {0x00};
	CK_BYTE temp[128] = {0x00};
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;



	printf("RSA Outside Encrypt and Decrypt!\n");
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
	rv = C_GenerateKeyPair(hSession, &mGenRSAKey, aRSAPubKey, 4, aRSAPriKey, 3, &hRSAPubKey, &hRSAPriKey);
	C_CloseSession(hSession);

	C_OpenSession(SlotId, CKF_SERIAL_SESSION |CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GetAttributeValue(hSession, hRSAPubKey, CreateRSAPubKey, 4);
	if (rv == 0)
	{
		CreateRSAPubKey[0].pValue = malloc(CreateRSAPubKey[0].ulValueLen);
		if (CreateRSAPubKey[0].pValue == NULL)
		{
			printf("RSA1024Test()->malloc ERROR!\n");
			C_CloseSession(hSession);
			return -1;
		}
		CreateRSAPubKey[1].pValue = malloc(CreateRSAPubKey[1].ulValueLen);
		if (CreateRSAPubKey[1].pValue == NULL)
		{
			printf("RSA1024Test()->malloc ERROR!\n");
			FreeAttribute(CreateRSAPubKey, 1);
			C_CloseSession(hSession);
			return -1;
		}
		CreateRSAPubKey[2].pValue = malloc(CreateRSAPubKey[2].ulValueLen);
		if (CreateRSAPubKey[2].pValue == NULL)
		{
			printf("RSA1024Test()->malloc ERROR!\n");
			FreeAttribute(CreateRSAPubKey, 2);
			C_CloseSession(hSession);
			return -1;
		}
		CreateRSAPubKey[3].pValue = malloc(CreateRSAPubKey[3].ulValueLen);
		if (CreateRSAPubKey[3].pValue == NULL)
		{
			printf("RSA1024Test()->malloc ERROR!\n");
			FreeAttribute(CreateRSAPubKey, 3);
			C_CloseSession(hSession);
			return -1;
		}
		rv = C_GetAttributeValue(hSession, hRSAPubKey, CreateRSAPubKey, 4);
		rv = C_CreateObject(hSession, CreateRSAPubKey, 4, &hRSAPubKey);
	}	
	FreeAttribute(CreateRSAPubKey, 4);
	
	rv = C_GetAttributeValue(hSession, hRSAPriKey, CreateRSAPriKey, 9);
	if (rv == 0)
	{
		CreateRSAPriKey[0].pValue = malloc(CreateRSAPriKey[0].ulValueLen);
		if (CreateRSAPriKey[0].pValue == NULL)
		{
			printf("RSA1024Test()->malloc ERROR!\n");
			C_CloseSession(hSession);
			return -1;
		}
		CreateRSAPriKey[1].pValue = malloc(CreateRSAPriKey[1].ulValueLen);
		if (CreateRSAPriKey[1].pValue == NULL)
		{
			printf("RSA1024Test()->malloc ERROR!\n");
			FreeAttribute(CreateRSAPriKey, 1);
			C_CloseSession(hSession);
			return -1;
		}
		CreateRSAPriKey[2].pValue = malloc(CreateRSAPriKey[2].ulValueLen);
		if (CreateRSAPriKey[2].pValue == NULL)
		{
			printf("RSA1024Test()->malloc ERROR!\n");
			FreeAttribute(CreateRSAPriKey, 2);
			C_CloseSession(hSession);
			return -1;
		}
		CreateRSAPriKey[3].pValue = malloc(CreateRSAPriKey[3].ulValueLen);
		if (CreateRSAPriKey[3].pValue == NULL)
		{
			printf("RSA1024Test()->malloc ERROR!\n");
			FreeAttribute(CreateRSAPriKey, 3);
			C_CloseSession(hSession);
			return -1;
		}
		CreateRSAPriKey[4].pValue = malloc(CreateRSAPriKey[4].ulValueLen);
		if (CreateRSAPriKey[4].pValue == NULL)
		{
			printf("RSA1024Test()->malloc ERROR!\n");
			FreeAttribute(CreateRSAPriKey, 4);
			C_CloseSession(hSession);
			return -1;
		}
		CreateRSAPriKey[5].pValue = malloc(CreateRSAPriKey[5].ulValueLen);
		if (CreateRSAPriKey[5].pValue == NULL)
		{
			printf("RSA1024Test()->malloc ERROR!\n");
			FreeAttribute(CreateRSAPriKey, 5);
			C_CloseSession(hSession);
		    return -1;
		}
		CreateRSAPriKey[6].pValue = malloc(CreateRSAPriKey[6].ulValueLen);
		if (CreateRSAPriKey[6].pValue == NULL)
		{
			printf("RSA1024Test()->malloc ERROR!\n");
			FreeAttribute(CreateRSAPriKey, 6);
			C_CloseSession(hSession);
			return -1;
		}
		CreateRSAPriKey[7].pValue = malloc(CreateRSAPriKey[7].ulValueLen);
		if (CreateRSAPriKey[7].pValue == NULL)
		{
			printf("RSA1024Test()->malloc ERROR!\n");
			FreeAttribute(CreateRSAPriKey, 7);
			C_CloseSession(hSession);
			return -1;
		}
		CreateRSAPriKey[8].pValue = malloc(CreateRSAPriKey[8].ulValueLen);
		if (CreateRSAPriKey[8].pValue == NULL)
		{
			printf("RSA1024Test()->malloc ERROR!\n");
			FreeAttribute(CreateRSAPriKey, 8);
			C_CloseSession(hSession);
			return -1;
		}
		rv = C_GetAttributeValue(hSession, hRSAPriKey, CreateRSAPriKey, 9);
		rv = C_CreateObject(hSession, CreateRSAPriKey, 9, &hRSAPriKey);
	}
	FreeAttribute(CreateRSAPriKey, 9);

	memset(indata, 0x11, 111);
	memset(outdata, 0x00, 128);
	memset(temp, 0x00, 128);
	rv = C_EncryptInit(hSession, &mRSAEncryptPad, hRSAPubKey);
	rv = C_Encrypt(hSession, indata, 111, /*outdata*/NULL, &outlength);

	rv = C_DecryptInit(hSession, &mRSAEncryptPad, hRSAPriKey);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);


	if (memcmp(indata, temp, 111) == 0)
	{
#ifdef OS_WINDOWS
		printf("OK RSA1024 PADDING!\n");
#else
		printf("OK RSA1024 PADDING!father %d, i'm %d\n", getppid(), getpid());
#endif
	}
	else
	{
#ifdef OS_WINDOWS
		printf("ERROR RSA1024 PADDING!\n");
#else
		printf("ERROR RSA1024 PADDING!father %d, i'm %d\n", getppid(), getpid());
#endif
	}

	memset(indata, 0x1c, 128);
	memset(outdata, 0x00, 128);
	memset(temp, 0x00, 128);
	rv = C_EncryptInit(hSession, &mRSAEncryptRaw, hRSAPubKey);
	rv = C_Encrypt(hSession, indata, 128, outdata, &outlength);
	
	rv = C_DecryptInit(hSession, &mRSAEncryptRaw, hRSAPriKey);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	if (memcmp(indata, temp, 128) == 0)
	{
#ifdef OS_WINDOWS
		printf("OK RSA1024 RAW!\n");
#else
		printf("OK RSA1024 RAW!father %d, i'm %d\n", getppid(), getpid());
#endif
	}
	else
	{
#ifdef OS_WINDOWS
		printf("ERROR RSA1024 RAW!\n");
#else
		printf("ERROR RSA1024 RAW!father %d, i'm %d\n", getppid(), getpid());
#endif
	}
	return 0;
}

FLAG RSA1024Test_in()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_MECHANISM mGenRSAKey	= {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_ULONG RSAPubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG RSAPriKeyClass = CKO_PRIVATE_KEY;
	CK_ULONG RSAKeyType = CKK_RSA;
	CK_ULONG ModuluBits = 1024;
	CK_BBOOL isTrue = TRUE;   //save object in session!
	CK_BYTE RSAPubLabel[] = "RSA_PUBLIC_KEY_9";
	CK_BYTE RSAPriLabel[] = "RSA_PRIVATE_KEY_9";
 	CK_ATTRIBUTE aRSAPubKey[] = {
		{CKA_CLASS, &RSAPubKeyClass, sizeof(RSAPubKeyClass)},
//		{CKA_LABEL, &RSAPubLabel, sizeof(RSAPubLabel)},
		{CKA_KEY_TYPE, &RSAKeyType, sizeof(RSAKeyType)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)},
		{CKA_MODULUS_BITS, &ModuluBits, sizeof(ModuluBits)}
	}; 
	CK_ATTRIBUTE aRSAPriKey[] = {
		{CKA_CLASS, &RSAPriKeyClass, sizeof(RSAPriKeyClass)},
		{CKA_KEY_TYPE, &RSAKeyType, sizeof(RSAKeyType)},
//		{CKA_LABEL, &RSAPriLabel, sizeof(RSAPriLabel)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
								};
	CK_OBJECT_HANDLE hRSAPubKey = 0;
	CK_OBJECT_HANDLE hRSAPriKey = 0;
	
	CK_MECHANISM mRSAEncryptPad = {CKM_RSA_PKCS, NULL_PTR, 0};
	CK_MECHANISM mRSAEncryptRaw = {CKM_RSA_X_509, NULL_PTR, 0};

	CK_BYTE indata[128] = {0x00};
	CK_BYTE outdata[128] = {0x00};
	CK_BYTE temp[128] = {0x00};
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;

	CK_ATTRIBUTE CreateRSAPubKey[] = {
		{CKA_CLASS, NULL_PTR, 0},
		{CKA_MODULUS, NULL_PTR, 0},
		{CKA_MODULUS_BITS, NULL_PTR, 0},
		{CKA_PUBLIC_EXPONENT, NULL_PTR, 0}
									};
	printf("RSA Inside Encrypt and Decrypt!\n");

	memset(indata, 0xcc, 112);
	memset(outdata, 0x00, 128);
	memset(temp, 0x00, 128);
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKeyPair(hSession, &mGenRSAKey, aRSAPubKey, 4, aRSAPriKey, 3, &hRSAPubKey, &hRSAPriKey);
	rv = C_EncryptInit(hSession, &mRSAEncryptPad, hRSAPubKey);
	rv = C_Encrypt(hSession, indata, 112, outdata, &outlength);
	rv = C_DecryptInit(hSession, &mRSAEncryptPad, hRSAPriKey);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	if (memcmp(indata, temp, 112) == 0 && templength == 112)
	{
#ifdef OS_WINDOWS
		printf("OK RSA1024 PADDING!\n");
#else
		printf("OK RSA1024 PADDING!father %d, i'm %d\n", getppid(), getpid());
#endif
	}
	else
	{
#ifdef OS_WINDOWS
		printf("ERROR RSA1024 PADDING!\n");
#else
		printf("ERROR RSA1024 PADDING!father %d, i'm %d\n", getppid(), getpid());
#endif
	}

	memset(indata, 0x12, 128);
	memset(outdata, 0x00, 128);
	memset(temp, 0x00, 128);
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKeyPair(hSession, &mGenRSAKey, aRSAPubKey, 4, aRSAPriKey, 3, &hRSAPubKey, &hRSAPriKey);
	rv = C_EncryptInit(hSession, &mRSAEncryptRaw, hRSAPubKey);
	rv = C_Encrypt(hSession, indata, 128, outdata, &outlength);
	rv = C_DecryptInit(hSession, &mRSAEncryptRaw, hRSAPriKey);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	if (memcmp(indata, temp, 128) == 0)
	{
		printf("OK RSA1024 Raw!\n");
	}
	else
	{
		printf("ERROR RSA1024 Raw!\n");
	}
	if (!g_ifthread)
	{
		printf("RSA Crossing Encrypt and Decrypt!\n");
		memset(indata, 0x12, 90);
		memset(outdata, 0x00, 128);
		memset(temp, 0x00, 128);
		rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
		C_Login(hSession, CKU_SO, "11111111", 8);
#endif
		rv = C_GenerateKeyPair(hSession, &mGenRSAKey, aRSAPubKey, 4, aRSAPriKey, 3, &hRSAPubKey, &hRSAPriKey);
		rv = C_GetAttributeValue(hSession, hRSAPubKey, CreateRSAPubKey, 4);
		if (rv == 0)
		{
			CreateRSAPubKey[0].pValue = malloc(CreateRSAPubKey[0].ulValueLen);
			if (CreateRSAPubKey[0].pValue == NULL)
			{
				printf("RSA1024Test_in->malloc ERROR!\n");
				C_CloseSession(hSession);
				return -1;
			}
			CreateRSAPubKey[1].pValue = malloc(CreateRSAPubKey[1].ulValueLen);
			if (CreateRSAPubKey[1].pValue == NULL)
			{
				printf("RSA1024Test_in->malloc ERROR!\n");
				FreeAttribute(CreateRSAPubKey, 1);
				C_CloseSession(hSession);
				return -1;
			}
			CreateRSAPubKey[2].pValue = malloc(CreateRSAPubKey[2].ulValueLen);
			if (CreateRSAPubKey[2].pValue == NULL)
			{
				printf("RSA1024Test_in->malloc ERROR!\n");
				FreeAttribute(CreateRSAPubKey, 2);
				C_CloseSession(hSession);
				return -1;
			}
			CreateRSAPubKey[3].pValue = malloc(CreateRSAPubKey[3].ulValueLen);
			if (CreateRSAPubKey[3].pValue == NULL)
			{
				printf("RSA1024Test_in->malloc ERROR!\n");
				FreeAttribute(CreateRSAPubKey, 3);
				C_CloseSession(hSession);
				return -1;
			}
			rv = C_GetAttributeValue(hSession, hRSAPubKey, CreateRSAPubKey, 4);
			rv = C_CreateObject(hSession, CreateRSAPubKey, 4, &hRSAPubKey);
		}
		FreeAttribute(CreateRSAPubKey, 4);
		rv = C_EncryptInit(hSession, &mRSAEncryptPad, hRSAPubKey);
		rv = C_Encrypt(hSession, indata, 90, outdata, &outlength);
		rv = C_DecryptInit(hSession, &mRSAEncryptPad, hRSAPriKey);
		rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
		if (memcmp(indata, temp, 90) == 0 && templength == 90)
		{
			printf("OK RSA1024 Crossing!\n");
		}
		else
		{
			printf("ERROR RSA1024 Crossing!\n");
		}
	}	
	return 0;
}

FLAG RSA2048Test_out()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_ULONG RSAPubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG RSAPriKeyClass = CKO_PRIVATE_KEY;
	CK_ULONG RSAKeyType = CKK_RSA;
	CK_ULONG ModuluBits = 2048;
	CK_BBOOL isTrue = TRUE;
	CK_ATTRIBUTE aRSAPubKey[] = {
		{CKA_CLASS, &RSAPubKeyClass, sizeof(RSAPubKeyClass)},
		{CKA_MODULUS_BITS, &ModuluBits, sizeof(ModuluBits)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)},
		{CKA_KEY_TYPE, &RSAKeyType, sizeof(RSAKeyType)}
	};

	CK_ATTRIBUTE aRSAPriKey[] = {
		{CKA_CLASS, &RSAPriKeyClass, sizeof(RSAPriKeyClass)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)},
		{CKA_KEY_TYPE, &RSAKeyType, sizeof(RSAKeyType)}
	};

	CK_ATTRIBUTE CreateRSAPubKey[] = {
		{CKA_MODULUS, NULL_PTR, 0},
		{CKA_MODULUS_BITS, NULL_PTR, 0},
		{CKA_PUBLIC_EXPONENT, NULL_PTR, 0},
		{CKA_CLASS, NULL_PTR, 0}
	};
	
	CK_ATTRIBUTE CreateRSAPriKey[] = {
		{CKA_MODULUS, NULL_PTR, 0},
		{CKA_PUBLIC_EXPONENT, NULL_PTR, 0},
		{CKA_PRIVATE_EXPONENT, NULL_PTR, 0},
		{CKA_PRIME_1, NULL_PTR, 0},
		{CKA_PRIME_2, NULL_PTR, 0},
		{CKA_EXPONENT_1, NULL_PTR, 0},
		{CKA_EXPONENT_2, NULL_PTR, 0},
		{CKA_COEFFICIENT, NULL_PTR, 0},
		{CKA_CLASS, NULL_PTR, 0}
								};
	
	CK_MECHANISM mRSAGenKey = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_OBJECT_HANDLE hRSAPubKey = 0;
	CK_OBJECT_HANDLE hRSAPriKey = 0;

	CK_MECHANISM mRSAEncryptPad = {CKM_RSA_PKCS, NULL_PTR, 0};
	CK_MECHANISM mRSAEncryptRaw = {CKM_RSA_X_509, NULL_PTR, 0};
	CK_BYTE indata[256] = {0x00};
	CK_BYTE outdata[256] = {0x00};
	CK_BYTE temp[256] = {0x00};
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;
	
	printf("RSA2048 Outside Encrypt and Decrypt!\n");
	memset(indata, 0x45, 36);
	memset(outdata, 0x00, 256);
	memset(temp, 0x00, 256);
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKeyPair(hSession, &mRSAGenKey, aRSAPubKey, 4, aRSAPriKey, 3, &hRSAPubKey, &hRSAPriKey);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
    rv = C_GetAttributeValue(hSession, hRSAPubKey, CreateRSAPubKey, 4);
	if (rv == 0)
	{
		CreateRSAPubKey[0].pValue = malloc(CreateRSAPubKey[0].ulValueLen);
		if (CreateRSAPubKey[0].pValue == NULL)
		{
			printf("RSA2048Test_out->malloc ERROR!\n");
			C_CloseSession(hSession);
			return -1;
		}
		CreateRSAPubKey[1].pValue = malloc(CreateRSAPubKey[1].ulValueLen);
		if (CreateRSAPubKey[1].pValue == NULL)
		{
			printf("RSA2048Test_out->malloc ERROR!\n");
			FreeAttribute(CreateRSAPubKey, 1);
			C_CloseSession(hSession);
			return -1;
		}
		CreateRSAPubKey[2].pValue = malloc(CreateRSAPubKey[2].ulValueLen);
		if (CreateRSAPubKey[2].pValue == NULL)
		{
			printf("RSA2048Test_out->malloc ERROR!\n");
			FreeAttribute(CreateRSAPubKey, 2);
			C_CloseSession(hSession);
			return -1;
		}
		CreateRSAPubKey[3].pValue = malloc(CreateRSAPubKey[3].ulValueLen);
		if (CreateRSAPubKey[3].pValue == NULL)
		{
			printf("RSA2048Test_out->malloc ERROR!\n");
			FreeAttribute(CreateRSAPubKey, 3);
			C_CloseSession(hSession);
			return -1;
		}
		rv = C_GetAttributeValue(hSession, hRSAPubKey, CreateRSAPubKey, 4);
		rv = C_CreateObject(hSession, CreateRSAPubKey, 4, &hRSAPubKey);
	}
	FreeAttribute(CreateRSAPubKey, 4);

	rv = C_EncryptInit(hSession, &mRSAEncryptPad, hRSAPubKey);
	rv = C_Encrypt(hSession, indata, 36, outdata, &outlength);

	rv = C_GetAttributeValue(hSession, hRSAPriKey, CreateRSAPriKey, 9);
	if (rv == 0)
	{
		CreateRSAPriKey[0].pValue = malloc(CreateRSAPriKey[0].ulValueLen);
		if (CreateRSAPriKey[0].pValue == NULL)
		{
			printf("RSA2048Test_out->malloc ERROR!\n");
			C_CloseSession(hSession);
			return -1;
		}
		CreateRSAPriKey[1].pValue = malloc(CreateRSAPriKey[1].ulValueLen);
		if (CreateRSAPriKey[1].pValue == NULL)
		{
			printf("RSA2048Test_out->malloc ERROR!\n");
			FreeAttribute(CreateRSAPriKey, 1);
			C_CloseSession(hSession);
			return -1;
		}
		CreateRSAPriKey[2].pValue = malloc(CreateRSAPriKey[2].ulValueLen);
		if (CreateRSAPriKey[2].pValue == NULL)
		{
			printf("RSA2048Test_out->malloc ERROR!\n");
			FreeAttribute(CreateRSAPriKey, 2);
			C_CloseSession(hSession);
			return -1;
		}
		CreateRSAPriKey[3].pValue = malloc(CreateRSAPriKey[3].ulValueLen);
		if (CreateRSAPriKey[3].pValue == NULL)
		{
			printf("RSA2048Test_out->malloc ERROR!\n");
			FreeAttribute(CreateRSAPriKey, 3);
			C_CloseSession(hSession);
			return -1;
		}
		CreateRSAPriKey[4].pValue = malloc(CreateRSAPriKey[4].ulValueLen);
		if (CreateRSAPriKey[4].pValue == NULL)
		{
			printf("RSA2048Test_out->malloc ERROR!\n");
			FreeAttribute(CreateRSAPriKey, 4);
			C_CloseSession(hSession);
			return -1;
		}
		CreateRSAPriKey[5].pValue = malloc(CreateRSAPriKey[5].ulValueLen);
		if (CreateRSAPriKey[5].pValue == NULL)
		{
			printf("RSA2048Test_out->malloc ERROR!\n");
			FreeAttribute(CreateRSAPriKey, 5);
			C_CloseSession(hSession);
			return -1;
		}
		CreateRSAPriKey[6].pValue = malloc(CreateRSAPriKey[6].ulValueLen);
		if (CreateRSAPriKey[6].pValue == NULL)
		{
			printf("RSA2048Test_out->malloc ERROR!\n");
			FreeAttribute(CreateRSAPriKey, 6);
			C_CloseSession(hSession);
			return -1;
		}
		CreateRSAPriKey[7].pValue = malloc(CreateRSAPriKey[7].ulValueLen);
		if (CreateRSAPriKey[7].pValue == NULL)
		{
			printf("RSA2048Test_out->malloc ERROR!\n");
			FreeAttribute(CreateRSAPriKey, 7);
			C_CloseSession(hSession);
			return -1;
		}
		CreateRSAPriKey[8].pValue = malloc(CreateRSAPriKey[8].ulValueLen);
		if (CreateRSAPriKey[8].pValue == NULL)
		{
			printf("RSA2048Test_out->malloc ERROR!\n");
			FreeAttribute(CreateRSAPriKey, 8);
			C_CloseSession(hSession);
			return -1;
		}
		rv = C_GetAttributeValue(hSession, hRSAPriKey, CreateRSAPriKey, 9);
		rv = C_CreateObject(hSession, CreateRSAPriKey, 9, &hRSAPriKey);
	}
	FreeAttribute(CreateRSAPriKey, 9);

	rv = C_DecryptInit(hSession, &mRSAEncryptPad, hRSAPriKey);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
	if (memcmp(indata, temp, 36) == 0 && templength == 36)
	{
#ifdef OS_WINDOWS
		printf("OK RSA2048 PADDING!\n");
#else
		printf("OK RSA2048 PADDING!father %d, i'm %d\n", getppid(), getpid());
#endif
	}
	else
	{
#ifdef OS_WINDOWS
		printf("ERROR RSA2048 PADDING!\n");
#else
		printf("ERROR RSA2048 PADDING!father %d, i'm %d\n", getppid(), getpid());
#endif
	}
	memset(indata, 0x23, 256);
	memset(outdata, 0x00, 256);
	memset(temp, 0x00, 256);
	rv = C_EncryptInit(hSession, &mRSAEncryptRaw, hRSAPubKey);
	rv = C_Encrypt(hSession, indata, 256, outdata, &outlength);
	rv = C_DecryptInit(hSession, &mRSAEncryptRaw, hRSAPriKey);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
	if (memcmp(indata, temp, 256) == 0)
	{
#ifdef OS_WINDOWS
		printf("OK RSA2048 Raw!\n");
#else
		printf("OK RSA2048 Raw!father %d, i'm %d\n", getppid(), getpid());
#endif
	}
	else
	{
#ifdef OS_WINDOWS
		printf("ERROR RSA2048 Raw!\n");
#else
		printf("ERROR RSA2048 Raw!father %d, i'm %d\n", getppid(), getpid());
#endif
	}
	return 0;
}

FLAG RSA2048Test_in()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_BYTE RSAPubLabel[] = "RSA_PUBLIC_KEY_8";
	CK_BYTE RSAPriLabel[] = "RSA_PRIVATE_KEY_8";
	CK_BBOOL isFalse = FALSE;
	CK_ULONG ModuluBits = 2048;
	CK_ULONG RSAPubClass = CKO_PUBLIC_KEY;
	CK_ULONG RSAPriClass = CKO_PRIVATE_KEY;

	CK_ATTRIBUTE aRSAPubKey[] = {
		{CKA_CLASS, &RSAPubClass, sizeof(RSAPubClass)},
		{CKA_MODULUS_BITS, &ModuluBits, sizeof(ModuluBits)},
		{CKA_TOKEN, &isFalse, sizeof(isFalse)},
		{CKA_LABEL, &RSAPubLabel, sizeof(RSAPubLabel)}
								};

	CK_ATTRIBUTE aRSAPriKey[] = {
		{CKA_CLASS, &RSAPriClass, sizeof(RSAPriClass)},
		{CKA_TOKEN, &isFalse, sizeof(isFalse)},
		{CKA_LABEL, &RSAPriLabel, sizeof(RSAPriLabel)}
								};

	CK_ATTRIBUTE CreateRSAPriKey[] = {
		{CKA_MODULUS, NULL_PTR, 0},
		{CKA_PUBLIC_EXPONENT, NULL_PTR, 0},
		{CKA_PRIVATE_EXPONENT, NULL_PTR, 0},
		{CKA_PRIME_1, NULL_PTR, 0},
		{CKA_PRIME_2, NULL_PTR, 0},
		{CKA_EXPONENT_1, NULL_PTR, 0},
		{CKA_EXPONENT_2, NULL_PTR, 0},
		{CKA_COEFFICIENT, NULL_PTR, 0},
		{CKA_CLASS, NULL_PTR, 0}
								};
	CK_MECHANISM mRSAGenKey = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mRSAEncryptPad = {CKM_RSA_PKCS, NULL_PTR, 0};
	CK_MECHANISM mRSAEncryptRaw = {CKM_RSA_X_509, NULL_PTR, 0};
	CK_OBJECT_HANDLE hRSAPubKey = 0;
	CK_OBJECT_HANDLE hRSAPriKey = 0;
	
	CK_BYTE indata[256];
	CK_BYTE outdata[256];
	CK_BYTE temp[256];
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;
	
	printf("RSA2048 Inside Encrypt and Decrypt!\n");
	memset(indata, 0x55, 95);
	memset(outdata, 0x00, 256);
	memset(temp, 0x00, 256);
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKeyPair(hSession, &mRSAGenKey, aRSAPubKey, 4, aRSAPriKey, 3, &hRSAPubKey, &hRSAPriKey);
	rv = C_EncryptInit(hSession, &mRSAEncryptPad, hRSAPubKey);
	rv = C_Encrypt(hSession, indata, 95, outdata, &outlength);
	rv = C_DecryptInit(hSession, &mRSAEncryptPad, hRSAPriKey);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
	if (memcmp(indata, temp, 95) == 0 && templength == 95)
	{
#ifdef OS_WINDOWS
		printf("OK RSA2048 PAD!\n");
#else
		printf("OK RSA2048 PAD!father %d, i'm %d\n", getppid(), getpid());
#endif
	}
	else
	{
#ifdef OS_WINDOWS
		printf("ERROR RSA2048 PAD!\n");
#else
		printf("ERROR RSA2048 PAD!father %d, i'm %d\n", getppid(), getpid());
#endif
	}
	memset(indata, 0x10, 256);
	memset(outdata, 0x00, 256);
	memset(temp, 0x00, 256);
	rv = C_EncryptInit(hSession, &mRSAEncryptRaw, hRSAPubKey);
	rv = C_Encrypt(hSession, indata, 256, outdata, &outlength);
	rv = C_DecryptInit(hSession, &mRSAEncryptRaw, hRSAPriKey);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
	if (memcmp(indata, temp, 256) == 0)
	{
#ifdef OS_WINDOWS
		printf("OK RSA2048 Raw!\n");
#else
		printf("OK RSA2048 Raw!father %d, i'm %d\n", getppid(), getpid());
#endif
	}
	else
	{
#ifdef OS_WINDOWS
		printf("ERROR RSA2048 Raw!\n");
#else
		printf("ERROR RSA2048 Raw!father %d, i'm %d\n", getppid(), getpid());
#endif
	}
	
	if (!g_ifthread)
	{
		printf("RSA2048 Crossing Encrypt and Decrypt!\n");
		rv = C_GetAttributeValue(hSession, hRSAPriKey, CreateRSAPriKey, 9);
		if (rv == 0)
		{
			CreateRSAPriKey[0].pValue = malloc(CreateRSAPriKey[0].ulValueLen);
			if (CreateRSAPriKey[0].pValue == NULL)
			{
				printf("RSA2048Test_out->malloc ERROR!\n");
				C_CloseSession(hSession);
				return -1;
			}
			CreateRSAPriKey[1].pValue = malloc(CreateRSAPriKey[1].ulValueLen);
			if (CreateRSAPriKey[1].pValue == NULL)
			{
				printf("RSA2048Test_out->malloc ERROR!\n");
				FreeAttribute(CreateRSAPriKey, 1);
				C_CloseSession(hSession);
				return -1;
			}
			CreateRSAPriKey[2].pValue = malloc(CreateRSAPriKey[2].ulValueLen);
			if (CreateRSAPriKey[2].pValue == NULL)
			{
				printf("RSA2048Test_out->malloc ERROR!\n");
				FreeAttribute(CreateRSAPriKey, 2);
				C_CloseSession(hSession);
				return -1;
			}
			CreateRSAPriKey[3].pValue = malloc(CreateRSAPriKey[3].ulValueLen);
			if (CreateRSAPriKey[3].pValue == NULL)
			{
				printf("RSA2048Test_out->malloc ERROR!\n");
				FreeAttribute(CreateRSAPriKey, 3);
				C_CloseSession(hSession);
				return -1;
			}
			CreateRSAPriKey[4].pValue = malloc(CreateRSAPriKey[4].ulValueLen);
			if (CreateRSAPriKey[4].pValue == NULL)
			{
				printf("RSA2048Test_out->malloc ERROR!\n");
				FreeAttribute(CreateRSAPriKey, 4);
				C_CloseSession(hSession);
				return -1;
			}
			CreateRSAPriKey[5].pValue = malloc(CreateRSAPriKey[5].ulValueLen);
			if (CreateRSAPriKey[5].pValue == NULL)
			{
				printf("RSA2048Test_out->malloc ERROR!\n");
				FreeAttribute(CreateRSAPriKey, 5);
				C_CloseSession(hSession);
				return -1;
			}
			CreateRSAPriKey[6].pValue = malloc(CreateRSAPriKey[6].ulValueLen);
			if (CreateRSAPriKey[6].pValue == NULL)
			{
				printf("RSA2048Test_out->malloc ERROR!\n");
				FreeAttribute(CreateRSAPriKey, 6);
				C_CloseSession(hSession);
				return -1;
			}
			CreateRSAPriKey[7].pValue = malloc(CreateRSAPriKey[7].ulValueLen);
			if (CreateRSAPriKey[7].pValue == NULL)
			{
				printf("RSA2048Test_out->malloc ERROR!\n");
				FreeAttribute(CreateRSAPriKey, 7);
				C_CloseSession(hSession);
				return -1;
			}
			CreateRSAPriKey[8].pValue = malloc(CreateRSAPriKey[8].ulValueLen);
			if (CreateRSAPriKey[8].pValue == NULL)
			{
				printf("RSA2048Test_out->malloc ERROR!\n");
				FreeAttribute(CreateRSAPriKey, 8);
				C_CloseSession(hSession);
				return -1;
			}
			rv = C_GetAttributeValue(hSession, hRSAPriKey, CreateRSAPriKey, 9);
			rv = C_CreateObject(hSession, CreateRSAPriKey, 9, &hRSAPriKey);
		}
		FreeAttribute(CreateRSAPriKey, 9);
		memset(indata, 0x10, 256);
		memset(outdata, 0x00, 256);
		memset(temp, 0x00, 256);
		rv = C_EncryptInit(hSession, &mRSAEncryptRaw, hRSAPubKey);
		rv = C_Encrypt(hSession, indata, 256, outdata, &outlength);
		rv = C_DecryptInit(hSession, &mRSAEncryptRaw, hRSAPriKey);
		rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
		if (memcmp(indata, temp, 256) == 0)
		{
#ifdef OS_WINDOWS
			printf("OK RSA2048 Crossing!\n");
#else
			printf("OK RSA2048 Crossing!father %d, i'm %d\n", getppid(), getpid());
#endif
		}
		else
		{
#ifdef OS_WINDOWS
			printf("ERROR RSA2048 Crossing!\n");
#else
			printf("ERROR RSA2048 Crossing!father %d, i'm %d\n", getppid(), getpid());
#endif
		}
		
		C_CloseSession(hSession);
	}
	
	return 0;
}

#ifdef OS_WINDOWS
void RSA1024SpeedTest()
{
	CK_RV rv = 0;
	CK_ULONG i = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_MECHANISM mGenRSAKey	= {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mRSAEncryptPad = {CKM_RSA_PKCS, NULL_PTR, 0};
	CK_ULONG RSAPubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG RSAPriKeyClass = CKO_PRIVATE_KEY;
	CK_OBJECT_HANDLE hRSAPubKey = 0;
	CK_OBJECT_HANDLE hRSAPriKey = 0;
	CK_ULONG RSAKeyType = CKK_RSA;
	CK_ULONG ModuluBits = 1024;
	CK_BBOOL isTrue = FALSE;
	CK_ATTRIBUTE aRSAPubKey[] = {
		{CKA_CLASS, &RSAPubKeyClass, sizeof(RSAPubKeyClass)},
		{CKA_KEY_TYPE, &RSAKeyType, sizeof(RSAKeyType)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)},
		{CKA_MODULUS_BITS, &ModuluBits, sizeof(ModuluBits)}
	}; 
	CK_ATTRIBUTE aRSAPriKey[] = {
		{CKA_CLASS, &RSAPriKeyClass, sizeof(RSAPriKeyClass)},
		{CKA_KEY_TYPE, &RSAKeyType, sizeof(RSAKeyType)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
								};
	LARGE_INTEGER Frequency;
	LARGE_INTEGER StartNum;
	LARGE_INTEGER EndNum;
	double Second = 0;
	
	CK_BYTE indata[128];
	CK_BYTE outdata[128];
	CK_BYTE temp[128];
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;
	memset(indata, 0x88, 116);
	memset(outdata, 0x00, 128);
	memset(temp, 0x00, 128);

	QueryPerformanceFrequency(&Frequency);
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession); 
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	QueryPerformanceCounter(&StartNum);
	for (i=0; i<LOOPTIMES; i++)
	{
		C_GenerateKeyPair(hSession, &mGenRSAKey, aRSAPubKey, 4, aRSAPriKey, 3, &hRSAPubKey, &hRSAPriKey);
	}
	QueryPerformanceCounter(&EndNum);
	Second = (double)(((EndNum.QuadPart - StartNum.QuadPart)+0.0)/Frequency.QuadPart);
	printf("Generate RSA1024 Key Time is %03f s\n", Second/LOOPTIMES);

	QueryPerformanceCounter(&StartNum);
	for (i=0; i<LOOPTIMES; i++)
	{
		rv = C_EncryptInit(hSession, &mRSAEncryptPad, hRSAPubKey);	
		rv = C_Encrypt(hSession, indata, 116, outdata, &outlength);
		rv = C_DecryptInit(hSession, &mRSAEncryptPad, hRSAPriKey);
		rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
	}
	QueryPerformanceCounter(&EndNum);
	Second = (double)(((EndNum.QuadPart - StartNum.QuadPart)+0.0)/Frequency.QuadPart);
	printf("RSA1024 Encrypt and Decrypt Time is %03f s\n", Second/LOOPTIMES);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);
}

void RSA2048SpeedTest()
{
	CK_RV rv = 0;
	CK_ULONG i = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_MECHANISM mGenRSAKey	= {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mRSAEncryptPad = {CKM_RSA_PKCS, NULL_PTR, 0};
	CK_ULONG RSAPubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG RSAPriKeyClass = CKO_PRIVATE_KEY;
	CK_OBJECT_HANDLE hRSAPubKey = 0;
	CK_OBJECT_HANDLE hRSAPriKey = 0;
	CK_ULONG RSAKeyType = CKK_RSA;
	CK_ULONG ModuluBits = 2048;
	CK_BBOOL isTrue = FALSE;
	CK_ATTRIBUTE aRSAPubKey[] = {
		{CKA_CLASS, &RSAPubKeyClass, sizeof(RSAPubKeyClass)},
		{CKA_KEY_TYPE, &RSAKeyType, sizeof(RSAKeyType)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)},
		{CKA_MODULUS_BITS, &ModuluBits, sizeof(ModuluBits)}
	}; 
	CK_ATTRIBUTE aRSAPriKey[] = {
		{CKA_CLASS, &RSAPriKeyClass, sizeof(RSAPriKeyClass)},
		{CKA_KEY_TYPE, &RSAKeyType, sizeof(RSAKeyType)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
	};
	LARGE_INTEGER Frequency;
	LARGE_INTEGER StartNum;
	LARGE_INTEGER EndNum;
	double Second = 0;
	
	CK_BYTE indata[256];
	CK_BYTE outdata[256];
	CK_BYTE temp[256];
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;
	memset(indata, 0x88, 116);
	memset(outdata, 0x00, 256);
	memset(temp, 0x00, 256);
	
	QueryPerformanceFrequency(&Frequency);
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession); 
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	QueryPerformanceCounter(&StartNum);
	for (i=0; i<LOOPTIMES; i++)
	{
		C_GenerateKeyPair(hSession, &mGenRSAKey, aRSAPubKey, 4, aRSAPriKey, 3, &hRSAPubKey, &hRSAPriKey);
	}
	QueryPerformanceCounter(&EndNum);
	Second = (double)(((EndNum.QuadPart - StartNum.QuadPart)+0.0)/Frequency.QuadPart);
	printf("Generate RSA2048 Key Time is %03f s\n", Second/LOOPTIMES);
	
	QueryPerformanceCounter(&StartNum);
	for (i=0; i<LOOPTIMES; i++)
	{
		rv = C_EncryptInit(hSession, &mRSAEncryptPad, hRSAPubKey);	
		rv = C_Encrypt(hSession, indata, 116, outdata, &outlength);
		rv = C_DecryptInit(hSession, &mRSAEncryptPad, hRSAPriKey);
		rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
	}
	QueryPerformanceCounter(&EndNum);
	Second = (double)(((EndNum.QuadPart - StartNum.QuadPart)+0.0)/Frequency.QuadPart);
	printf("RSA2048 Encrypt and Decrypt Time is %03f s\n", Second/LOOPTIMES);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);
}
#endif

