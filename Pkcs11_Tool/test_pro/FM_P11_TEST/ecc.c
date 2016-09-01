#include <stdio.h>
#include <string.h>
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

extern void FreeAttribute(CK_ATTRIBUTE_PTR attribute, CK_ULONG num);

FLAG ECCTest_out()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_OBJECT_HANDLE hECCPubKey = 0;
	CK_OBJECT_HANDLE hECCPriKey = 0;
	CK_BBOOL isTrue = TRUE;
	CK_ULONG ECCPubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG ECCPriKeyClass = CKO_PRIVATE_KEY;
	CK_BYTE Id[] = "MY_ECC_KEY";

	CK_ATTRIBUTE ECCPubKey[] = {
		{CKA_CLASS, &ECCPubKeyClass, sizeof(ECCPubKeyClass)},
		{CKA_ID, &Id, strlen(Id)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
								};

	CK_ATTRIBUTE ECCPriKey[] = {
		{CKA_CLASS, &ECCPriKeyClass, sizeof(ECCPriKeyClass)},
		{CKA_ID, &Id, strlen(Id)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
								};

	CK_ATTRIBUTE CreateECCPubKey[] = {
		{CKA_CLASS, NULL_PTR, 0},
		{CKA_MODULUS_BITS, NULL_PTR, 0},
		{CKA_ID, NULL_PTR, 0},
		{CKA_EC_POINT, NULL_PTR, 0}
								};

	CK_ATTRIBUTE CreateECCPriKey[] = {
		{CKA_CLASS, NULL_PTR, 0},
		{CKA_ID, NULL_PTR, 0},
		{CKA_MODULUS_BITS, NULL_PTR, 0},
		{CKA_VALUE, NULL_PTR, 0}
								};
	
	CK_MECHANISM ECCGenKey = {CKM_ECDSA_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mECCEncrypt = {CKM_ECDSA_PKCS, NULL_PTR, 0};
	CK_BYTE indata[160] = {0x00};
	CK_BYTE outdata[300] = {0x00};
	CK_BYTE temp[300] = {0x00};
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;

	printf("ECC Outside Encrypt and Decrypt!\n");
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKeyPair(hSession, &ECCGenKey, ECCPubKey, 3, ECCPriKey, 3, &hECCPubKey, &hECCPriKey);
	rv = C_CloseSession(hSession);

	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GetAttributeValue(hSession, hECCPubKey, CreateECCPubKey, 4);
	if (rv == 0)
	{
		CreateECCPubKey[0].pValue = malloc(CreateECCPubKey[0].ulValueLen);
		if (CreateECCPubKey[0].pValue == NULL)
		{
			printf("ECCTest_out->malloc ERROR!\n");
			return -1;
		}
		CreateECCPubKey[1].pValue = malloc(CreateECCPubKey[1].ulValueLen);
		if (CreateECCPubKey[1].pValue == NULL)
		{
			printf("ECCTest_out->malloc ERROR!\n");
			FreeAttribute(CreateECCPubKey, 1);
			return -1;
		}
		CreateECCPubKey[2].pValue = malloc(CreateECCPubKey[2].ulValueLen);
		if (CreateECCPubKey[2].pValue == NULL)
		{
			printf("ECCTest_out->malloc ERROR!\n");
			FreeAttribute(CreateECCPubKey, 2);
			return -1;
		}
		CreateECCPubKey[3].pValue = malloc(CreateECCPubKey[3].ulValueLen);
		if (CreateECCPubKey[3].pValue == NULL)
		{
			printf("ECCTest_out->malloc ERROR!\n");
			FreeAttribute(CreateECCPubKey, 3);
			return -1;
		}
		rv = C_GetAttributeValue(hSession, hECCPubKey, CreateECCPubKey, 4);
		rv = C_DestroyObject(hSession, hECCPubKey);
		rv = C_CreateObject(hSession, CreateECCPubKey, 4, &hECCPubKey);
	}
	FreeAttribute(CreateECCPubKey, 4);

	memset(indata, 0x33, 110);
	memset(outdata, 0x00, 300);
	memset(temp, 0x00, 300);
	
	rv = C_EncryptInit(hSession, &mECCEncrypt, hECCPubKey);
	rv = C_Encrypt(hSession, indata, 110, outdata, &outlength);

	rv = C_GetAttributeValue(hSession, hECCPriKey, CreateECCPriKey, 4);
	if (rv == 0)
	{
		CreateECCPriKey[0].pValue = malloc(CreateECCPriKey[0].ulValueLen);
		if (CreateECCPriKey[0].pValue == NULL)
		{
			printf("ECCTest_out->malloc ERROR!\n");
			return -1;
		}
		CreateECCPriKey[1].pValue = malloc(CreateECCPriKey[1].ulValueLen);
		if (CreateECCPriKey[1].pValue == NULL)
		{
			printf("ECCTest_out->malloc ERROR!\n");
			FreeAttribute(CreateECCPriKey, 1);
			return -1;
		}
	
		CreateECCPriKey[2].pValue = malloc(CreateECCPriKey[2].ulValueLen);
		if (CreateECCPriKey[2].pValue == NULL)
		{
			printf("ECCTest_out->malloc ERROR!\n");
			FreeAttribute(CreateECCPriKey, 2);
			return -1;
		}
		CreateECCPriKey[3].pValue = malloc(CreateECCPriKey[3].ulValueLen);
		if (CreateECCPriKey[3].pValue == NULL)
		{
			printf("ECCTest_out->malloc ERROR!\n");
			FreeAttribute(CreateECCPriKey, 3);
			return -1;
		}
		rv = C_GetAttributeValue(hSession, hECCPriKey, CreateECCPriKey, 4);
		rv = C_DestroyObject(hSession, hECCPriKey);
		rv = C_CreateObject(hSession, CreateECCPriKey, 4, &hECCPriKey);
	}
	FreeAttribute(CreateECCPriKey, 4);

	rv = C_DecryptInit(hSession, &mECCEncrypt, hECCPriKey);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	if (memcmp(indata, temp, 110) == 0 && templength == 110)
	{
		printf("OK ECC OUT!\n");
	}
	else
	{
		printf("ERROR ECC OUT!\n");
	}
	return 0;
}

FLAG ECCTest_in()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_ULONG ECCPubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG ECCPriKeyClass = CKO_PRIVATE_KEY;
	CK_BYTE ECCPubLabel[] = "ECC_PUBLIC_KEY_7";
	CK_BYTE ECCPriLabel[] = "ECC_PRIVATE_KEY_7";
	CK_BBOOL isFalse = TRUE;
	
	CK_ATTRIBUTE ECCPubKey[] = {
		{CKA_CLASS, &ECCPubKeyClass, sizeof(ECCPubKeyClass)},
		{CKA_LABEL, &ECCPubLabel, sizeof(ECCPubLabel)},
		{CKA_TOKEN, &isFalse, sizeof(isFalse)}
							};
	
	CK_ATTRIBUTE ECCPriKey[] = {
		{CKA_CLASS, &ECCPriKeyClass, sizeof(ECCPriKeyClass)},
		{CKA_LABEL, &ECCPriLabel, sizeof(ECCPriLabel)},
		{CKA_TOKEN, &isFalse, sizeof(isFalse)}
							};

	CK_ATTRIBUTE CreateECCPriKey[] = {
		{CKA_CLASS, NULL_PTR, 0},
		{CKA_MODULUS_BITS, NULL_PTR, 0},
		{CKA_VALUE, NULL_PTR, 0}
							};

	CK_MECHANISM ECCGenKey = {CKM_ECDSA_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mECCEncrypt = {CKM_ECDSA_PKCS, NULL_PTR, 0};
	CK_OBJECT_HANDLE hECCPubKey = 0;
	CK_OBJECT_HANDLE hECCPriKey = 0;

	CK_BYTE indata[160] = {0x00};
	CK_BYTE outdata[300] = {0x00};
	CK_BYTE temp[300] = {0x00};
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;
	
	memset(indata, 0x31, 40);
	memset(outdata, 0x00, 300);
	memset(temp, 0x00, 300);
	
	printf("ECC Inside Encrypt and Decrypt!\n");
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKeyPair(hSession, &ECCGenKey, ECCPubKey, 3, ECCPriKey, 3, &hECCPubKey, &hECCPriKey);

	rv = C_EncryptInit(hSession, &mECCEncrypt, hECCPubKey);
	rv = C_Encrypt(hSession, indata, 40, outdata, &outlength);
	rv = C_DecryptInit(hSession, &mECCEncrypt, hECCPriKey);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
	if (memcmp(indata, temp, 40) == 0 && templength == 40)
	{
		printf("OK ECC IN!\n");
	}
	else
	{
		printf("ERROR ECC IN!\n");
	}

	printf("ECC Crossing Encrypt and Decrypt!\n");
	memset(indata, 0x33, 110);
	memset(outdata, 0x00, 300);
	memset(temp, 0x00, 300);

	rv = C_GetAttributeValue(hSession, hECCPriKey, CreateECCPriKey, 3);
	if (rv == 0)
	{
		CreateECCPriKey[0].pValue = malloc(CreateECCPriKey[0].ulValueLen);
		if (CreateECCPriKey[0].pValue == NULL)
		{
			printf("ECCTest_out->malloc ERROR!\n");
			return -1;
		}
		CreateECCPriKey[1].pValue = malloc(CreateECCPriKey[1].ulValueLen);
		if (CreateECCPriKey[1].pValue == NULL)
		{
			printf("ECCTest_out->malloc ERROR!\n");
			FreeAttribute(CreateECCPriKey, 1);
			return -1;
		}
		
		CreateECCPriKey[2].pValue = malloc(CreateECCPriKey[2].ulValueLen);
		if (CreateECCPriKey[2].pValue == NULL)
		{
			printf("ECCTest_out->malloc ERROR!\n");
			FreeAttribute(CreateECCPriKey, 2);
			return -1;
		}
		rv = C_GetAttributeValue(hSession, hECCPriKey, CreateECCPriKey, 3);
		rv = C_CreateObject(hSession, CreateECCPriKey, 3, &hECCPriKey);
	}
	FreeAttribute(CreateECCPriKey, 3);

	rv = C_EncryptInit(hSession, &mECCEncrypt, hECCPubKey);
	rv = C_Encrypt(hSession, indata, 110, outdata, &outlength);
	rv = C_DecryptInit(hSession, &mECCEncrypt, hECCPriKey);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
	if (memcmp(indata, temp, 110) == 0 && templength == 110)
	{
		printf("OK ECC Crossing!\n");
	}
	else
	{
		printf("ERROR ECC Crossing!\n");
	}
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);

	return 0;
}

#ifdef OS_WINDOWS

void ECCSpeedTest()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_OBJECT_HANDLE hECCPubKey = 0;
	CK_OBJECT_HANDLE hECCPriKey = 0;
	CK_BBOOL isTrue = FALSE;
	CK_ULONG ECCPubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG ECCPriKeyClass = CKO_PRIVATE_KEY;
	CK_BYTE Id[] = "MY_ECC_KEY";
	
	CK_ATTRIBUTE ECCPubKey[] = {
		{CKA_CLASS, &ECCPubKeyClass, sizeof(ECCPubKeyClass)},
		{CKA_ID, &Id, strlen(Id)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
	};
	
	CK_ATTRIBUTE ECCPriKey[] = {
		{CKA_CLASS, &ECCPriKeyClass, sizeof(ECCPriKeyClass)},
		{CKA_ID, &Id, strlen(Id)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
	};
	
	CK_MECHANISM ECCGenKey = {CKM_ECDSA_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mECCEncrypt = {CKM_ECDSA_PKCS, NULL_PTR, 0};
	CK_BYTE indata[160] = {0x00};
	CK_BYTE outdata[300] = {0x00};
	CK_BYTE temp[300] = {0x00};
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;
	CK_ULONG i = 0;

	LARGE_INTEGER Frequency;
	LARGE_INTEGER StartNum;
	LARGE_INTEGER EndNum;
	double Second;

	memset(indata, 0x42, 111);
	memset(outdata, 0x00, 300);
	memset(temp, 0x00, 300);

	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	QueryPerformanceFrequency(&Frequency);
	QueryPerformanceCounter(&StartNum);
	for (i=0; i<LOOPTIMES; i++)
	{
		C_GenerateKeyPair(hSession, &ECCGenKey, ECCPubKey, 3, ECCPriKey, 3, &hECCPubKey, &hECCPriKey);
	}
	QueryPerformanceCounter(&EndNum);
	Second = (double)(((EndNum.QuadPart - StartNum.QuadPart)+0.0)/Frequency.QuadPart);
	printf("Generate ECC Key Time is: %03f s\n", Second/LOOPTIMES);
	
	QueryPerformanceCounter(&StartNum);
	for (i=0; i<LOOPTIMES; i++)
	{
		C_EncryptInit(hSession, &mECCEncrypt, hECCPubKey);
		C_Encrypt(hSession, indata, 111, outdata, &outlength);
		C_DecryptInit(hSession, &mECCEncrypt, hECCPriKey);
		C_Decrypt(hSession, outdata, outlength, temp, &templength);
	}
	QueryPerformanceCounter(&EndNum);
	Second = (double)(((EndNum.QuadPart - StartNum.QuadPart)+0.0)/Frequency.QuadPart);
	printf("ECC Encrypt and Decrypt Time is: %03f s\n", Second/LOOPTIMES);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);

}

#endif

