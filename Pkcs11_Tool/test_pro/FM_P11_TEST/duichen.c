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
extern CK_BBOOL g_ifpt;
void FreeAttribute();
void StartThread(void * pParam);

FLAG SM1Test_ECB();
FLAG SM1Test_CBC();
FLAG SM1Test_CBC_PAD();
FLAG AESTest_ECB();
FLAG AESTest_CBC();
FLAG AESTest_CBC_PAD();
FLAG DES3Test_ECB();
FLAG DESTest_CBC();
FLAG DESTest_CBC_PAD();
FLAG DESTest_ECB();
FLAG DESTest_CBC();
FLAG DESTest_CBC_PAD();

#ifdef OS_LINUX
FLAG (*duichen_func[])() = {SM1Test_ECB, SM1Test_CBC, SM1Test_CBC_PAD, AESTest_ECB, AESTest_CBC, AESTest_CBC_PAD, DES3Test_ECB,
DESTest_CBC, DESTest_CBC_PAD, DESTest_ECB, DESTest_CBC, DESTest_CBC_PAD};
#endif

FLAG SM1Test_ECB()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_OBJECT_HANDLE hSM1Key = 0;
	CK_MECHANISM mSM1GenKey = {CKM_SM1_GEN, NULL_PTR, 0};
	CK_MECHANISM mSM1Encrypt = {CKM_SM1_ECB, NULL_PTR, 0};
	CK_ULONG SM1KeyClass = CKO_SECRET_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_BYTE_PTR  indata = NULL_PTR;
	CK_ULONG length = 0;
	CK_BYTE_PTR outdata = NULL_PTR;
	CK_BYTE_PTR temp = NULL_PTR;
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;

	CK_ATTRIBUTE aSM1Key[] = {
		{CKA_CLASS, &SM1KeyClass, sizeof(SM1KeyClass)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
						};
	
	CK_ATTRIBUTE CreateSM1Key[] = {
		{CKA_CLASS, NULL_PTR, 0},
		{CKA_VALUE, NULL_PTR, 0}
						};

	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKey(hSession, &mSM1GenKey, aSM1Key, 2, &hSM1Key);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);


	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GetAttributeValue(hSession, hSM1Key, CreateSM1Key, 2);
	if (rv == 0)
	{
		CreateSM1Key[0].pValue = malloc(CreateSM1Key[0].ulValueLen);
		if (CreateSM1Key[0].pValue == NULL)
		{
			printf("SM1Test_ECB->malloc!\n");
			return -1;
		}
		CreateSM1Key[1].pValue = malloc(CreateSM1Key[1].ulValueLen);
		if (CreateSM1Key[1].pValue == NULL)
		{
			printf("SM1Test_ECB->malloc!\n");
			FreeAttribute(1);
			return -1;
		}
		rv = C_GetAttributeValue(hSession, hSM1Key, CreateSM1Key, 2);
		rv = C_DestroyObject(hSession, hSM1Key);
		rv = C_CreateObject(hSession, CreateSM1Key, 2, &hSM1Key);
	}
	FreeAttribute(CreateSM1Key, 2);
	if (!g_ifthread)
	{
		printf("please input data length, must be multiple of 16:\n");
		scanf("%d", &length);
		if (length % 16 != 0)
		{
			printf("The length is not multipel of 16");
			return -1;
		}
	}
    else
	{
		length = 16000;
	}
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("SM1Test_ECB->malloc!\n");
		return -1;
	}
	outdata = (CK_BYTE_PTR)malloc(length);
	if (outdata == NULL)
	{
		printf("SM1Test_ECB->malloc!\n");
		free(indata);
		return -1;
	}
	temp = (CK_BYTE_PTR)malloc(length);
	if (temp == NULL)
	{
		printf("SM1Test_ECB->malloc!\n");
		free(indata);
		free(outdata);
		return -1;
	}

	rv = C_GenerateRandom(hSession, indata, length);
	rv = C_EncryptInit(hSession, &mSM1Encrypt, hSM1Key);
	rv = C_Encrypt(hSession, indata, length, outdata, &outlength);
	rv = C_DecryptInit(hSession, &mSM1Encrypt, hSM1Key);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
	if (memcmp(indata, temp, templength) == 0 && templength == length)
	{
		printf("OK SM1 ECB !\n");
	}
	else
	{
		printf("ERROR SM1 ECB !\n");
	}
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);

	free(outdata);
	free(temp);
	free(indata);
	return 0;
}

FLAG SM1Test_CBC()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_OBJECT_HANDLE hSM1Key = 0;
	CK_MECHANISM mSM1GenKey = {CKM_SM1_GEN, NULL_PTR, 0};
	CK_MECHANISM mSM1Encrypt = {CKM_SM1_CBC, "1234567812345678", 16};
	CK_ULONG SM1KeyClass = CKO_SECRET_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_BYTE_PTR  indata = NULL_PTR;
	CK_ULONG length = 0;
	CK_BYTE_PTR outdata = NULL_PTR;
	CK_BYTE_PTR temp = NULL_PTR;
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;

	CK_ATTRIBUTE aSM1Key[] = {
		{CKA_CLASS, &SM1KeyClass, sizeof(SM1KeyClass)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
						};
	
	CK_ATTRIBUTE CreateSM1Key[] = {
		{CKA_CLASS, NULL_PTR, 0},
		{CKA_VALUE, NULL_PTR, 0}
						};

	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKey(hSession, &mSM1GenKey, aSM1Key, 2, &hSM1Key);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);


	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GetAttributeValue(hSession, hSM1Key, CreateSM1Key, 2);
	if (rv == 0)
	{
		CreateSM1Key[0].pValue = malloc(CreateSM1Key[0].ulValueLen);
		if (CreateSM1Key[0].pValue == NULL)
		{
			printf("SM1Test_CBC->malloc!\n");
			return -1;
		}
		CreateSM1Key[1].pValue = malloc(CreateSM1Key[1].ulValueLen);
		if (CreateSM1Key[1].pValue == NULL)
		{
			printf("SM1Test_CBC->malloc!\n");
			FreeAttribute(1);
			return -1;
		}
		rv = C_GetAttributeValue(hSession, hSM1Key, CreateSM1Key, 2);
		rv = C_DestroyObject(hSession, hSM1Key);
		rv = C_CreateObject(hSession, CreateSM1Key, 2, &hSM1Key);
	}
	FreeAttribute(CreateSM1Key, 2);

	if (!g_ifthread)
	{
		printf("please input data length, must be multiple of 16:\n");
		scanf("%d", &length);
		if (length % 16 != 0)
		{
			printf("The length is not multipel of 16");
			return -1;
		}
	}
	else
	{
		length = 16000;
	}
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("SM1Test_CBC->malloc!\n");
		return -1;
	}
	outdata = (CK_BYTE_PTR)malloc(length);
	if (outdata == NULL)
	{
		printf("SM1Test_CBC->malloc!\n");
		free(indata);
		return -1;
	}
	temp = (CK_BYTE_PTR)malloc(length);
	if (temp == NULL)
	{
		printf("SM1Test_CBC->malloc!\n");
		free(indata);
		free(outdata);
		return -1;
	}

	rv = C_GenerateRandom(hSession, indata, length);
	rv = C_EncryptInit(hSession, &mSM1Encrypt, hSM1Key);
	rv = C_Encrypt(hSession, indata, length, outdata, &outlength);
	rv = C_DecryptInit(hSession, &mSM1Encrypt, hSM1Key);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
	if (memcmp(indata, temp, templength) == 0 && templength == length)
	{
		printf("OK SM1 CBC !\n");
	}
	else
	{
		printf("ERROR SM1 CBC !\n");
	}
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);

	free(outdata);
	free(temp);
	free(indata);
	return 0;
}

FLAG SM1Test_CBC_PAD()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_OBJECT_HANDLE hSM1Key = 0;
	CK_MECHANISM mSM1GenKey = {CKM_SM1_GEN, NULL_PTR, 0};
	CK_MECHANISM mSM1Encrypt = {CKM_SM1_CBC_PAD, "1234567812345678", 16};
	CK_ULONG SM1KeyClass = CKO_SECRET_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_BYTE_PTR  indata = NULL_PTR;
	CK_ULONG length = 0;
	CK_BYTE_PTR outdata = NULL_PTR;
	CK_BYTE_PTR temp = NULL_PTR;
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;

	CK_ATTRIBUTE aSM1Key[] = {
		{CKA_CLASS, &SM1KeyClass, sizeof(SM1KeyClass)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
						};
	
	CK_ATTRIBUTE CreateSM1Key[] = {
		{CKA_CLASS, NULL_PTR, 0},
		{CKA_VALUE, NULL_PTR, 0}
						};

	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKey(hSession, &mSM1GenKey, aSM1Key, 2, &hSM1Key);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);


	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GetAttributeValue(hSession, hSM1Key, CreateSM1Key, 2);
	if (rv == 0)
	{
		CreateSM1Key[0].pValue = malloc(CreateSM1Key[0].ulValueLen);
		if (CreateSM1Key[0].pValue == NULL)
		{
			printf("SM1Test_CBC_PAD->malloc!\n");
			return -1;
		}
		CreateSM1Key[1].pValue = malloc(CreateSM1Key[1].ulValueLen);
		if (CreateSM1Key[1].pValue == NULL)
		{
			printf("SM1Test_CBC_PAD->malloc!\n");
			FreeAttribute(1);
			return -1;
		}
		rv = C_GetAttributeValue(hSession, hSM1Key, CreateSM1Key, 2);
		rv = C_DestroyObject(hSession, hSM1Key);
		rv = C_CreateObject(hSession, CreateSM1Key, 2, &hSM1Key);
	}
	FreeAttribute(CreateSM1Key, 2);
	if (!g_ifthread)
	{
		printf("please input data length:\n");
		scanf("%d", &length);
	}
	else
	{
		length = 12345;
	}
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("SM1Test_CBC_PAD->malloc!\n");
		return -1;
	}
	outdata = (CK_BYTE_PTR)malloc(length+16);
	if (outdata == NULL)
	{
		printf("SM1Test_CBC_PAD->malloc!\n");
		free(indata);
		return -1;
	}
	temp = (CK_BYTE_PTR)malloc(length+16);
	if (temp == NULL)
	{
		printf("SM1Test_CBC_PAD->malloc!\n");
		free(indata);
		free(outdata);
		return -1;
	}

	rv = C_GenerateRandom(hSession, indata, length);
	rv = C_EncryptInit(hSession, &mSM1Encrypt, hSM1Key);
	rv = C_Encrypt(hSession, indata, length, outdata, &outlength);
	rv = C_DecryptInit(hSession, &mSM1Encrypt, hSM1Key);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
	if (memcmp(indata, temp, templength) == 0 && templength == length)
	{
		printf("OK SM1 CBC PAD !\n");
	}
	else
	{
		printf("ERROR SM1 CBC PAD !\n");
	}
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);

	free(outdata);
	free(temp);
	free(indata);
	return 0;
}

FLAG DESTest_ECB()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_OBJECT_HANDLE hDESKey = 0;
	CK_MECHANISM mDESGenKey = {CKM_DES_KEY_GEN, NULL_PTR, 0};
	CK_MECHANISM mDESEncrypt = {CKM_DES_ECB, NULL_PTR, 0};
	CK_ULONG DESKeyClass = CKO_SECRET_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_BYTE_PTR  indata = NULL_PTR;
	CK_ULONG length = 0;
	CK_BYTE_PTR outdata = NULL_PTR;
	CK_BYTE_PTR temp = NULL_PTR;
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;
	
	CK_ATTRIBUTE aDESKey[] = {
		{CKA_CLASS, &DESKeyClass, sizeof(DESKeyClass)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
	};
	
	CK_ATTRIBUTE CreateDESKey[] = {
		{CKA_CLASS, NULL_PTR, 0},
		{CKA_VALUE, NULL_PTR, 0}
	};
	
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKey(hSession, &mDESGenKey, aDESKey, 2, &hDESKey);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);


	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GetAttributeValue(hSession, hDESKey, CreateDESKey, 2);
	if (rv == 0)
	{
		CreateDESKey[0].pValue = malloc(CreateDESKey[0].ulValueLen);
		if (CreateDESKey[0].pValue == NULL)
		{
			printf("DESTest->malloc!\n");
			return -1;
		}
		CreateDESKey[1].pValue = malloc(CreateDESKey[1].ulValueLen);
		if (CreateDESKey[1].pValue == NULL)
		{
			printf("DESTest->malloc!\n");
			FreeAttribute(CreateDESKey, 1);
			return -1;
		}
		rv = C_GetAttributeValue(hSession, hDESKey, CreateDESKey, 2);
		rv = C_DestroyObject(hSession, hDESKey);
		rv = C_CreateObject(hSession, CreateDESKey, 2, &hDESKey);
	}
	FreeAttribute(CreateDESKey, 2);
	
	if (!g_ifthread)
	{
		printf("please input data length, must be multiple of 8:\n");
		scanf("%d", &length);
		if (length % 8 != 0)
		{
			printf("The length is not multipel of 8");
			return -1;
		}
	}
	else
	{
		length = 8000;
	}
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("DESTest_ECB->malloc!\n");
		return -1;
	}
	outdata = (CK_BYTE_PTR)malloc(length);
	if (outdata == NULL)
	{
		printf("DESTest_ECB->malloc!\n");
		free(indata);
		return -1;
	}
	temp = (CK_BYTE_PTR)malloc(length);
	if (temp == NULL)
	{
		printf("SM1Test->malloc!\n");
		free(indata);
		free(outdata);
		return -1;
	}
	
	rv = C_GenerateRandom(hSession, indata, length);
	rv = C_EncryptInit(hSession, &mDESEncrypt, hDESKey);
	rv = C_Encrypt(hSession, indata, length, outdata, &outlength);
	rv = C_DecryptInit(hSession, &mDESEncrypt, hDESKey);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
	if (memcmp(indata, temp, templength) == 0 && templength == length)
	{
		printf("OK DES ECB !\n");
	}
	else
	{
		printf("ERROR DES ECB !\n");
	}
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);

	free(outdata);
	free(temp);
	free(indata);
	return 0;
}

FLAG DESTest_CBC()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_OBJECT_HANDLE hDESKey = 0;
	CK_MECHANISM mDESGenKey = {CKM_DES_KEY_GEN, NULL_PTR, 0};
	CK_MECHANISM mDESEncrypt = {CKM_DES_CBC, "12345678", 8};
	CK_ULONG DESKeyClass = CKO_SECRET_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_BYTE_PTR  indata = NULL_PTR;
	CK_ULONG length = 0;
	CK_BYTE_PTR outdata = NULL_PTR;
	CK_BYTE_PTR temp = NULL_PTR;
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;
	
	CK_ATTRIBUTE aDESKey[] = {
		{CKA_CLASS, &DESKeyClass, sizeof(DESKeyClass)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
	};
	
	CK_ATTRIBUTE CreateDESKey[] = {
		{CKA_CLASS, NULL_PTR, 0},
		{CKA_VALUE, NULL_PTR, 0}
	};
	
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKey(hSession, &mDESGenKey, aDESKey, 2, &hDESKey);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GetAttributeValue(hSession, hDESKey, CreateDESKey, 2);
	if (rv == 0)
	{
		CreateDESKey[0].pValue = malloc(CreateDESKey[0].ulValueLen);
		if (CreateDESKey[0].pValue == NULL)
		{
			printf("DESTest_CBC->malloc!\n");
			return -1;
		}
		CreateDESKey[1].pValue = malloc(CreateDESKey[1].ulValueLen);
		if (CreateDESKey[1].pValue == NULL)
		{
			printf("DESTest_CBC->malloc!\n");
			FreeAttribute(CreateDESKey, 1);
			return -1;
		}
		rv = C_GetAttributeValue(hSession, hDESKey, CreateDESKey, 2);
		rv = C_DestroyObject(hSession, hDESKey);
		rv = C_CreateObject(hSession, CreateDESKey, 2, &hDESKey);
	}
	FreeAttribute(CreateDESKey, 2);
	
	if (!g_ifthread)
	{
		printf("please input data length, must be multiple of 8:\n");
		scanf("%d", &length);
		if (length % 8 != 0)
		{
			printf("The length is not multipel of 8");
			return -1;
		}
	}
	else
	{
		length = 8000;
	}
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("DESTest_CBC->malloc!\n");
		return -1;
	}
	outdata = (CK_BYTE_PTR)malloc(length);
	if (outdata == NULL)
	{
		printf("DESTest_CBC->malloc!\n");
		free(indata);
		return -1;
	}
	temp = (CK_BYTE_PTR)malloc(length);
	if (temp == NULL)
	{
		printf("DESTest_CBC->malloc!\n");
		free(indata);
		free(outdata);
		return -1;
	}
	
	rv = C_GenerateRandom(hSession, indata, length);
	rv = C_EncryptInit(hSession, &mDESEncrypt, hDESKey);
	rv = C_Encrypt(hSession, indata, length, outdata, &outlength);
	rv = C_DecryptInit(hSession, &mDESEncrypt, hDESKey);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
	if (memcmp(indata, temp, templength) == 0 && templength == length)
	{
		printf("OK DES CBC !\n");
	}
	else
	{
		printf("ERROR DES CBC !\n");
	}
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);

	free(outdata);
	free(temp);
	free(indata);
	return 0;
}

FLAG DESTest_CBC_PAD()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_OBJECT_HANDLE hDESKey = 0;
	CK_MECHANISM mDESGenKey = {CKM_DES_KEY_GEN, NULL_PTR, 0};
	CK_MECHANISM mDESEncrypt = {CKM_DES_CBC_PAD, "12345678", 8};
	CK_ULONG DESKeyClass = CKO_SECRET_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_BYTE_PTR  indata = NULL_PTR;
	CK_ULONG length = 0;
	CK_BYTE_PTR outdata = NULL_PTR;
	CK_BYTE_PTR temp = NULL_PTR;
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;


	CK_ATTRIBUTE aDESKey[] = {
		{CKA_CLASS, &DESKeyClass, sizeof(DESKeyClass)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
						};
	
	CK_ATTRIBUTE CreateDESKey[] = {
		{CKA_CLASS, NULL_PTR, 0},
		{CKA_VALUE, NULL_PTR, 0}
						};

	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKey(hSession, &mDESGenKey, aDESKey, 2, &hDESKey);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);


	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GetAttributeValue(hSession, hDESKey, CreateDESKey, 2);
	if (rv == 0)
	{
		CreateDESKey[0].pValue = malloc(CreateDESKey[0].ulValueLen);
		if (CreateDESKey[0].pValue == NULL)
		{
			printf("DESTest_CBC_PAD->malloc!\n");
			return -1;
		}
		CreateDESKey[1].pValue = malloc(CreateDESKey[1].ulValueLen);
		if (CreateDESKey[1].pValue == NULL)
		{
			printf("DESTest_CBC_PAD->malloc!\n");
			FreeAttribute(CreateDESKey, 1);
			return -1;
		}
		rv = C_GetAttributeValue(hSession, hDESKey, CreateDESKey, 2);
		rv = C_DestroyObject(hSession, hDESKey);
		rv = C_CreateObject(hSession, CreateDESKey, 2, &hDESKey);
	}
	FreeAttribute(CreateDESKey, 2);

	if (!g_ifthread)
	{
		printf("please input data length:\n");
		scanf("%d", &length);
	}
	else
	{
		length = 5120;
	}
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("DESTest_CBC_PAD->malloc!\n");
		return -1;
		}
	outdata = (CK_BYTE_PTR)malloc(length+16);
	if (outdata == NULL)
	{
		printf("DESTest_CBC_PAD->malloc!\n");
		free(indata);
		return -1;
	}
	temp = (CK_BYTE_PTR)malloc(length+16);
	if (temp == NULL)
	{
		printf("DESTest_CBC_PAD->malloc!\n");
		free(indata);
		free(outdata);
		return -1;
	}

	rv = C_GenerateRandom(hSession, indata, length);
	rv = C_EncryptInit(hSession, &mDESEncrypt, hDESKey);
	rv = C_Encrypt(hSession, indata, length, outdata, &outlength);
	rv = C_DecryptInit(hSession, &mDESEncrypt, hDESKey);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
	if (memcmp(indata, temp, templength) == 0 && templength == length)
	{
		printf("OK DES CBC PAD !\n");
	}
	else
	{
		printf("ERROR DES CBC PAD !\n");
	}
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);

	free(outdata);
	free(temp);
	free(indata);
	return 0;
}

FLAG DES3Test_ECB()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_OBJECT_HANDLE hDES3Key = 0;
	CK_MECHANISM mDES3GenKey = {CKM_DES3_KEY_GEN, NULL_PTR, 0};
	CK_MECHANISM mDES3Encrypt = {CKM_DES3_ECB, NULL_PTR, 0};
	CK_ULONG DES3KeyClass = CKO_SECRET_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_BYTE_PTR  indata = NULL_PTR;
	CK_ULONG length = 0;
	CK_BYTE_PTR outdata = NULL_PTR;
	CK_BYTE_PTR temp = NULL_PTR;
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;
	
	CK_ATTRIBUTE aDES3Key[] = {
		{CKA_CLASS, &DES3KeyClass, sizeof(DES3KeyClass)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
	};
	
	CK_ATTRIBUTE CreateDES3Key[] = {
		{CKA_CLASS, NULL_PTR, 0},
		{CKA_VALUE, NULL_PTR, 0}
	};
	
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKey(hSession, &mDES3GenKey, aDES3Key, 2, &hDES3Key);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GetAttributeValue(hSession, hDES3Key, CreateDES3Key, 2);
	if (rv == 0)
	{
		CreateDES3Key[0].pValue = malloc(CreateDES3Key[0].ulValueLen);
		if (CreateDES3Key[0].pValue == NULL)
		{
			printf("DES3Test_ECB->malloc!\n");
			return -1;
		}
		CreateDES3Key[1].pValue = malloc(CreateDES3Key[1].ulValueLen);
		if (CreateDES3Key[1].pValue == NULL)
		{
			printf("DES3Test_ECB->malloc!\n");
			FreeAttribute(CreateDES3Key, 1);
			return -1;
		}
		rv = C_GetAttributeValue(hSession, hDES3Key, CreateDES3Key, 2);
		rv = C_DestroyObject(hSession, hDES3Key);
		rv = C_CreateObject(hSession, CreateDES3Key, 2, &hDES3Key);
	}
	FreeAttribute(CreateDES3Key, 2);
	
	if (!g_ifthread)
	{
		printf("please input data length, must be multiple of 8:\n");
		scanf("%d", &length);
		if (length % 8 != 0)
		{
			printf("The length is not multipel of 8");
			return -1;
		}
	}
	else
	{
		length = 8000;
	}
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("DES3Test_ECB->malloc!\n");
		return -1;
	}
	outdata = (CK_BYTE_PTR)malloc(length);
	if (outdata == NULL)
	{
		printf("DES3Test_ECB->malloc!\n");
		free(indata);
		return -1;
	}
	temp = (CK_BYTE_PTR)malloc(length);
	if (temp == NULL)
	{
		printf("DES3Test_ECB->malloc!\n");
		free(indata);
		free(outdata);
		return -1;
	}
	
	rv = C_GenerateRandom(hSession, indata, length);
	rv = C_EncryptInit(hSession, &mDES3Encrypt, hDES3Key);
	rv = C_Encrypt(hSession, indata, length, outdata, &outlength);
	rv = C_DecryptInit(hSession, &mDES3Encrypt, hDES3Key);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
	if (memcmp(indata, temp, templength) == 0 && templength == length)
	{
		printf("OK DES3 ECB !\n");
	}
	else
	{
		printf("ERROR DES3 ECB !\n");
	}
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);

	free(outdata);
	free(temp);
	free(indata);
	return 0;
}

FLAG DES3Test_CBC()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_OBJECT_HANDLE hDES3Key = 0;
	CK_MECHANISM mDES3GenKey = {CKM_DES3_KEY_GEN, NULL_PTR, 0};
	CK_MECHANISM mDES3Encrypt = {CKM_DES3_CBC, "12345678", 8};
	CK_ULONG DES3KeyClass = CKO_SECRET_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_BYTE_PTR  indata = NULL_PTR;
	CK_ULONG length = 0;
	CK_BYTE_PTR outdata = NULL_PTR;
	CK_BYTE_PTR temp = NULL_PTR;
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;
	
	CK_ATTRIBUTE aDES3Key[] = {
		{CKA_CLASS, &DES3KeyClass, sizeof(DES3KeyClass)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
	};
	
	CK_ATTRIBUTE CreateDES3Key[] = {
		{CKA_CLASS, NULL_PTR, 0},
		{CKA_VALUE, NULL_PTR, 0}
	};
	
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKey(hSession, &mDES3GenKey, aDES3Key, 2, &hDES3Key);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GetAttributeValue(hSession, hDES3Key, CreateDES3Key, 2);
	if (rv == 0)
	{
		CreateDES3Key[0].pValue = malloc(CreateDES3Key[0].ulValueLen);
		if (CreateDES3Key[0].pValue == NULL)
		{
			printf("DES3Test_CBC->malloc!\n");
			return -1;
		}
		CreateDES3Key[1].pValue = malloc(CreateDES3Key[1].ulValueLen);
		if (CreateDES3Key[1].pValue == NULL)
		{
			printf("DES3Test_CBC->malloc!\n");
			FreeAttribute(CreateDES3Key, 1);
			return -1;
		}
		rv = C_GetAttributeValue(hSession, hDES3Key, CreateDES3Key, 2);
		rv = C_DestroyObject(hSession, hDES3Key);
		rv = C_CreateObject(hSession, CreateDES3Key, 2, &hDES3Key);
	}
	FreeAttribute(CreateDES3Key, 2);
	
	if (!g_ifthread)
	{
		printf("please input data length, must be multiple of 8:\n");
		scanf("%d", &length);
		if (length % 8 != 0)
		{
			printf("The length is not multipel of 8");
			return -1;
		}
	}
	else
	{
		length = 8000;
	}
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("DES3Test_CBC->malloc!\n");
		return -1;
	}
	outdata = (CK_BYTE_PTR)malloc(length);
	if (outdata == NULL)
	{
		printf("DES3Test_CBC->malloc!\n");
		free(indata);
		return -1;
	}
	temp = (CK_BYTE_PTR)malloc(length);
	if (temp == NULL)
	{
		printf("DES3Test_CBC->malloc!\n");
		free(indata);
		free(outdata);
		return -1;
	}
	
	rv = C_GenerateRandom(hSession, indata, length);
	rv = C_EncryptInit(hSession, &mDES3Encrypt, hDES3Key);
	rv = C_Encrypt(hSession, indata, length, outdata, &outlength);
	rv = C_DecryptInit(hSession, &mDES3Encrypt, hDES3Key);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
	if (memcmp(indata, temp, templength) == 0 && templength == length)
	{
		printf("OK DES3 CBC !\n");
	}
	else
	{
		printf("ERROR DES3 CBC !\n");
	}
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);

	free(outdata);
	free(temp);
	free(indata);
	return 0;
}

FLAG DES3Test_CBC_PAD()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_OBJECT_HANDLE hDES3Key = 0;
	CK_MECHANISM mDES3GenKey = {CKM_DES3_KEY_GEN, NULL_PTR, 0};
	CK_MECHANISM mDES3Encrypt = {CKM_DES3_CBC_PAD, "12345678", 8};
	CK_ULONG DES3KeyClass = CKO_SECRET_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_BYTE_PTR  indata = NULL_PTR;
	CK_ULONG length = 0;
	CK_BYTE_PTR outdata = NULL_PTR;
	CK_BYTE_PTR temp = NULL_PTR;
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;

	CK_ATTRIBUTE aDES3Key[] = {
		{CKA_CLASS, &DES3KeyClass, sizeof(DES3KeyClass)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
						};
	
	CK_ATTRIBUTE CreateDES3Key[] = {
		{CKA_CLASS, NULL_PTR, 0},
		{CKA_VALUE, NULL_PTR, 0}
						};

	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKey(hSession, &mDES3GenKey, aDES3Key, 2, &hDES3Key);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);


	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GetAttributeValue(hSession, hDES3Key, CreateDES3Key, 2);
	if (rv == 0)
	{
		CreateDES3Key[0].pValue = malloc(CreateDES3Key[0].ulValueLen);
		if (CreateDES3Key[0].pValue == NULL)
		{
			printf("DES3Test_CBC_PAD->malloc!\n");
			return -1;
		}
		CreateDES3Key[1].pValue = malloc(CreateDES3Key[1].ulValueLen);
		if (CreateDES3Key[1].pValue == NULL)
		{
			printf("DES3est_CBC_PAD->malloc!\n");
			FreeAttribute(CreateDES3Key, 1);
			return -1;
		}
		rv = C_GetAttributeValue(hSession, hDES3Key, CreateDES3Key, 2);
		rv = C_DestroyObject(hSession, hDES3Key);
		rv = C_CreateObject(hSession, CreateDES3Key, 2, &hDES3Key);
	}
	FreeAttribute(CreateDES3Key, 2);

	if (!g_ifthread)
	{
		printf("please input data length:\n");
		scanf("%d", &length);
	}
	else
	{
		length = 12365;
	}
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("DES3Test_CBC_PAD->malloc!\n");
		return -1;
	}
	outdata = (CK_BYTE_PTR)malloc(length+16);
	if (outdata == NULL)
	{
		printf("DES3Test_CBC_PAD->malloc!\n");
		free(indata);
		return -1;
	}
	temp = (CK_BYTE_PTR)malloc(length+16);
	if (temp == NULL)
	{
		printf("DES3Test_CBC_PAD->malloc!\n");
		free(indata);
		free(outdata);
		return -1;
	}

	rv = C_GenerateRandom(hSession, indata, length);
	rv = C_EncryptInit(hSession, &mDES3Encrypt, hDES3Key);
	rv = C_Encrypt(hSession, indata, length, outdata, &outlength);
	rv = C_DecryptInit(hSession, &mDES3Encrypt, hDES3Key);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
	if (memcmp(indata, temp, templength) == 0 && templength == length)
	{
		printf("OK DES3 CBC PAD !\n");
	}
	else
	{
		printf("ERROR DES3 CBC PAD !\n");
	}
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);

	free(outdata);
	free(temp);
	free(indata);
	return 0;
}

FLAG AESTest_ECB()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_OBJECT_HANDLE hAESKey = 0;
	CK_MECHANISM mAESGenKey = {CKM_AES_KEY_GEN, NULL_PTR, 0};
	CK_MECHANISM mAESEncrypt = {CKM_AES_ECB, NULL_PTR, 0};
	CK_ULONG AESKeyClass = CKO_SECRET_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_BYTE_PTR  indata = NULL_PTR;
	CK_ULONG length = 0;
	CK_BYTE_PTR outdata = NULL_PTR;
	CK_BYTE_PTR temp = NULL_PTR;
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;
	
	CK_ATTRIBUTE aAESKey[] = {
		{CKA_CLASS, &AESKeyClass, sizeof(AESKeyClass)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
	};
	
	CK_ATTRIBUTE CreateAESKey[] = {
		{CKA_CLASS, NULL_PTR, 0},
		{CKA_VALUE, NULL_PTR, 0}
	};
	
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKey(hSession, &mAESGenKey, aAESKey, 2, &hAESKey);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GetAttributeValue(hSession, hAESKey, CreateAESKey, 2);
	if (rv == 0)
	{
		CreateAESKey[0].pValue = malloc(CreateAESKey[0].ulValueLen);
		if (CreateAESKey[0].pValue == NULL)
		{
			printf("AESTest_ECB->malloc!\n");
			return -1;
		}
		CreateAESKey[1].pValue = malloc(CreateAESKey[1].ulValueLen);
		if (CreateAESKey[1].pValue == NULL)
		{
			printf("AESTest_ECB->malloc!\n");
			FreeAttribute(CreateAESKey, 1);
			return -1;
		}
		rv = C_GetAttributeValue(hSession, hAESKey, CreateAESKey, 2);
		rv = C_DestroyObject(hSession, hAESKey);
		rv = C_CreateObject(hSession, CreateAESKey, 2, &hAESKey);
	}
	FreeAttribute(CreateAESKey, 2);
	
	if (!g_ifthread)
	{
		printf("please input data length, must be multiple of 16:\n");
		scanf("%d", &length);
		if (length % 16 != 0)
		{
			printf("The length is not multipel of 16");
			return -1;
		}
	}
	else
	{
		length = 16000;
	}
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("AESTest_ECB->malloc!\n");
		return -1;
	}
	outdata = (CK_BYTE_PTR)malloc(length);
	if (outdata == NULL)
	{
		printf("AESTest_ECB->malloc!\n");
		free(indata);
		return -1;
	}
	temp = (CK_BYTE_PTR)malloc(length);
	if (temp == NULL)
	{
		printf("AESTest_ECB->malloc!\n");
		free(indata);
		free(outdata);
		return -1;
	}
	
	rv = C_GenerateRandom(hSession, indata, length);
	rv = C_EncryptInit(hSession, &mAESEncrypt, hAESKey);
	rv = C_Encrypt(hSession, indata, length, outdata, &outlength);
	rv = C_DecryptInit(hSession, &mAESEncrypt, hAESKey);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
	if (memcmp(indata, temp, templength) == 0 && templength == length)
	{
		printf("OK AES ECB !\n");
	}
	else
	{
		printf("ERROR AES ECB !\n");
	}
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);

	free(outdata);
	free(temp);
	free(indata);
	return 0;
}

FLAG AESTest_CBC()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_OBJECT_HANDLE hAESKey = 0;
	CK_MECHANISM mAESGenKey = {CKM_AES_KEY_GEN, NULL_PTR, 0};
	CK_MECHANISM mAESEncrypt = {CKM_AES_CBC, "123456789abcdef0", 16};
	CK_ULONG AESKeyClass = CKO_SECRET_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_BYTE_PTR  indata = NULL_PTR;
	CK_ULONG length = 0;
	CK_BYTE_PTR outdata = NULL_PTR;
	CK_BYTE_PTR temp = NULL_PTR;
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;
	
	CK_ATTRIBUTE aAESKey[] = {
		{CKA_CLASS, &AESKeyClass, sizeof(AESKeyClass)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
	};
	
	CK_ATTRIBUTE CreateAESKey[] = {
		{CKA_CLASS, NULL_PTR, 0},
		{CKA_VALUE, NULL_PTR, 0}
	};
	
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKey(hSession, &mAESGenKey, aAESKey, 2, &hAESKey);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GetAttributeValue(hSession, hAESKey, CreateAESKey, 2);
	if (rv == 0)
	{
		CreateAESKey[0].pValue = malloc(CreateAESKey[0].ulValueLen);
		if (CreateAESKey[0].pValue == NULL)
		{
			printf("AESTest_CBC->malloc!\n");
			return -1;
		}
		CreateAESKey[1].pValue = malloc(CreateAESKey[1].ulValueLen);
		if (CreateAESKey[1].pValue == NULL)
		{
			printf("AESTest_CBC->malloc!\n");
			FreeAttribute(CreateAESKey, 1);
			return -1;
		}
		rv = C_GetAttributeValue(hSession, hAESKey, CreateAESKey, 2);
		rv = C_DestroyObject(hSession, hAESKey);
		rv = C_CreateObject(hSession, CreateAESKey, 2, &hAESKey);
	}
	FreeAttribute(CreateAESKey, 2);
	
	if (!g_ifthread)
	{
		printf("please input data length, must be multiple of 16:\n");
		scanf("%d", &length);
		if (length % 16 != 0)
		{
			printf("The length is not multipel of 16");
			return -1;
		}
	}
	else
	{
		length = 16000;
	}
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("AESTest_CBC->malloc!\n");
		return -1;
	}
	outdata = (CK_BYTE_PTR)malloc(length);
	if (outdata == NULL)
	{
		printf("AESTest_CBC->malloc!\n");
		free(indata);
		return -1;
	}
	temp = (CK_BYTE_PTR)malloc(length);
	if (temp == NULL)
	{
		printf("AESTest_CBC->malloc!\n");
		free(indata);
		free(outdata);
		return -1;
	}
	
	rv = C_GenerateRandom(hSession, indata, length);
	rv = C_EncryptInit(hSession, &mAESEncrypt, hAESKey);
	rv = C_Encrypt(hSession, indata, length, outdata, &outlength);
	rv = C_DecryptInit(hSession, &mAESEncrypt, hAESKey);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
	if (memcmp(indata, temp, templength) == 0 && templength == length)
	{
		printf("OK AES CBC !\n");
	}
	else
	{
		printf("ERROR AES CBC !\n");
	}
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);

	free(outdata);
	free(temp);
	free(indata);
	return 0;
}

FLAG AESTest_CBC_PAD()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_OBJECT_HANDLE hAESKey = 0;
	CK_MECHANISM mAESGenKey = {CKM_AES_KEY_GEN, NULL_PTR, 0};
	CK_MECHANISM mAESEncrypt = {CKM_AES_CBC_PAD, "123456789abcdef0", 16};
	CK_ULONG AESKeyClass = CKO_SECRET_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_BYTE_PTR  indata = NULL_PTR;
	CK_ULONG length = 0;
	CK_BYTE_PTR outdata = NULL_PTR;
	CK_BYTE_PTR temp = NULL_PTR;
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;
	
	CK_ATTRIBUTE aAESKey[] = {
		{CKA_CLASS, &AESKeyClass, sizeof(AESKeyClass)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
	};
	
	CK_ATTRIBUTE CreateAESKey[] = {
		{CKA_CLASS, NULL_PTR, 0},
		{CKA_VALUE, NULL_PTR, 0}
	};
	
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKey(hSession, &mAESGenKey, aAESKey, 2, &hAESKey);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GetAttributeValue(hSession, hAESKey, CreateAESKey, 2);
	if (rv == 0)
	{
		CreateAESKey[0].pValue = malloc(CreateAESKey[0].ulValueLen);
		if (CreateAESKey[0].pValue == NULL)
		{
			printf("AESTest_CBC_PAD->malloc!\n");
			return -1;
		}
		CreateAESKey[1].pValue = malloc(CreateAESKey[1].ulValueLen);
		if (CreateAESKey[1].pValue == NULL)
		{
			printf("AESTest_CBC_PAD->malloc!\n");
			FreeAttribute(CreateAESKey, 1);
			return -1;
		}
		rv = C_GetAttributeValue(hSession, hAESKey, CreateAESKey, 2);
		rv = C_DestroyObject(hSession, hAESKey);
		rv = C_CreateObject(hSession, CreateAESKey, 2, &hAESKey);
	}
	FreeAttribute(CreateAESKey, 2);
	
	if (!g_ifthread)
	{
		printf("please input data length:\n");
		scanf("%d", &length);
	}
	else
	{
		length = 32251;
	}
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("AESTest_CBC_PAD->malloc!\n");
		return -1;
	}
	outdata = (CK_BYTE_PTR)malloc(length+16);
	if (outdata == NULL)
	{
		printf("AESTest_CBC_PAD->malloc!\n");
		free(indata);
		return -1;
	}
	temp = (CK_BYTE_PTR)malloc(length+16);
	if (temp == NULL)
	{
		printf("AESTest_CBC_PAD->malloc!\n");
		free(indata);
		free(outdata);
		return -1;
	}
	
	rv = C_GenerateRandom(hSession, indata, length);
	rv = C_EncryptInit(hSession, &mAESEncrypt, hAESKey);
	rv = C_Encrypt(hSession, indata, length, outdata, &outlength);
	rv = C_DecryptInit(hSession, &mAESEncrypt, hAESKey);
	rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
	if (memcmp(indata, temp, templength) == 0 && templength == length)
	{
		printf("OK AES CBC PAD !\n");
	}
	else
	{
		printf("ERROR AES CBC PAD !\n");
	}
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);

	free(outdata);
	free(temp);
	free(indata);
	return 0;
}

void DuiChen()
{
	CK_ULONG id = 0;
	while (1)
	{
		printf("##############################################\n");
		printf("#  1. SM1_ECB          7. DES3_ECB           #\n");
		printf("#  2. SM1_CBC          8. DES3_CBC           #\n");
		printf("#  3. SM1_CBC_PAD      9. DES3_CBC_PAD       #\n");
		printf("#  4. DES_ECB          10. AES_ECB           #\n");
		printf("#  5. DES_CBC          11. AES_CBC           #\n");
		printf("#  6. DES_CBC_PAD      12. AES_CBC_PAD       #\n");
		printf("#                       0. exit              #\n");
		printf("##############################################\n");
		printf("\n");
		printf("Please select:");
		scanf("%d", &id);

		switch (id)
		{
		case 1:
			SM1Test_ECB();
			break;
		case 2:
			SM1Test_CBC();
			break;
		case 3:
			SM1Test_CBC_PAD();
			break;
		case 4:
			DESTest_ECB();
			break;
		case 5:
			DESTest_CBC();
			break;
		case 6:
			DESTest_CBC_PAD();
			break;
		case 7:
			DES3Test_ECB();
			break;
		case 8:
			DES3Test_CBC();
			break;
		case 9:
			DES3Test_CBC_PAD();
			break;
		case 10:
			AESTest_ECB();
			break;
		case 11:
			AESTest_CBC();
			break;
		case 12:
			AESTest_CBC_PAD();
			break;
		case 0:
			return;
			break;
		default:
			break;
		}//switch
	}//while
}

#ifdef OS_LINUX
void StratProcess_d(int param)
{
	pid_t p;
	int i = 0;
	for (i=0; i<MAX_PROCESS_NUM; i++)
	{
		p = fork();
		if (p < 0)
		{
			printf("fork error\n");
		}
		if (p == 0)
		{
			printf("my father is %d, i'm %d\n", getppid(), getpid());
			if (g_ifpt)
			{
				StartThread(duichen_func[param]);
			}else
			{
			    duichen_func[param]();
			}
			exit(0);
		}
	}	
}

void DuiChenProcess()
{
	CK_ULONG id = 0;
	
	while (1)
	{
		printf("##############################################\n");
		printf("#  1. SM1_ECB          7. DES3_ECB           #\n");
		printf("#  2. SM1_CBC          8. DES3_CBC           #\n");
		printf("#  3. SM1_CBC_PAD      9. DES3_CBC_PAD       #\n");
		printf("#  4. DES_ECB          10. AES_ECB           #\n");
		printf("#  5. DES_CBC          11. AES_CBC           #\n");
		printf("#  6. DES_CBC_PAD      12. AES_CBC_PAD       #\n");
		printf("#                       0. exit              #\n");
		printf("##############################################\n");
		printf("\n");
		printf("Please select:");
		scanf("%d", &id);
		
		switch (id)
		{
		case 1:
			StratProcess_d(0);		
			break;
		case 2:
			StratProcess_d(1);
			break;
		case 3:
			StratProcess_d(2);
			break;
		case 4:
			StratProcess_d(9);
			break;
		case 5:
			StratProcess_d(10);
			break;
		case 6:
			StratProcess_d(11);
			break;
		case 7:
			StratProcess_d(6);
			break;
		case 8:
			StratProcess_d(7);
			break;
		case 9:
			StratProcess_d(8);
			break;
		case 10:
			StratProcess_d(3);
			break;
		case 11:
			StratProcess_d(4);
			break;
		case 12:
			StratProcess_d(5);
			break;
		case 0:
			return;
			break;
		default:
			break;
		}//switch
	}//while
}
#endif

void DuiChenThread()
{
	CK_ULONG id = 0;

	while (1)
	{
		printf("##############################################\n");
		printf("#  1. SM1_ECB          7. DES3_ECB           #\n");
		printf("#  2. SM1_CBC          8. DES3_CBC           #\n");
		printf("#  3. SM1_CBC_PAD      9. DES3_CBC_PAD       #\n");
		printf("#  4. DES_ECB          10. AES_ECB           #\n");
		printf("#  5. DES_CBC          11. AES_CBC           #\n");
		printf("#  6. DES_CBC_PAD      12. AES_CBC_PAD       #\n");
		printf("#                       0. exit              #\n");
		printf("##############################################\n");
		printf("\n");
		printf("Please select:");
		scanf("%d", &id);
		
		switch (id)
		{
		case 1:
			StartThread(SM1Test_ECB);
			break;
		case 2:
			StartThread(SM1Test_CBC);
			break;
		case 3:
			StartThread(SM1Test_CBC_PAD);
			break;
		case 4:
			StartThread(DESTest_ECB);
			break;
		case 5:
			StartThread(DESTest_CBC);
			break;
		case 6:
			StartThread(DESTest_CBC_PAD);
			break;
		case 7:
			StartThread(DES3Test_ECB);
			break;
		case 8:
			StartThread(DES3Test_CBC);
			break;
		case 9:
			StartThread(DES3Test_CBC_PAD);
			break;
		case 10:
			StartThread(AESTest_ECB);
			break;
		case 11:
			StartThread(AESTest_CBC);
			break;
		case 12:
			StartThread(AESTest_CBC_PAD);
			break;
		case 0:
			return;
			break;
		default:
			break;
		}//switch
	}//while
}

#ifdef OS_WINDOWS

void DuiChenSpeedTest(CK_MECHANISM_PTR pGenKey, CK_MECHANISM_PTR pEncrypt, CK_BYTE_PTR pName)
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_OBJECT_HANDLE hKey = 0;
	CK_ULONG KeyClass = CKO_SECRET_KEY;
	CK_BBOOL isTrue = FALSE;
	CK_ULONG i = 0;

	CK_BYTE  indata[960];
	CK_BYTE outdata[2000];
	CK_BYTE temp[2000];
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;
	
	CK_ATTRIBUTE aKey[] = {
		{CKA_CLASS, &KeyClass, sizeof(KeyClass)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
	};

	LARGE_INTEGER Frequency;
	LARGE_INTEGER StartNum;
	LARGE_INTEGER EndNum;
	double Second = 0;

	memset(indata, 0x13, 960);
	memset(outdata, 0x00, 1000);
	memset(temp, 0x00, 1000);

    QueryPerformanceFrequency(&Frequency);
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	QueryPerformanceCounter(&StartNum);
	for (i=0; i<LOOPTIMES; i++)
	{
		rv = C_GenerateKey(hSession, pGenKey, aKey, 2, &hKey);
	}
	QueryPerformanceCounter(&EndNum);
	Second = (double)(((EndNum.QuadPart - StartNum.QuadPart)+0.0)/Frequency.QuadPart);
	printf("Generate %s Key Time is %03f s\n", pName, Second/LOOPTIMES);

	QueryPerformanceCounter(&StartNum);
	for (i=0; i<LOOPTIMES; i++)
	{
		rv = C_EncryptInit(hSession, pEncrypt, hKey);
		rv = C_Encrypt(hSession, indata, 960, outdata, &outlength);
		rv = C_DecryptInit(hSession, pEncrypt, hKey);
		rv = C_Decrypt(hSession, outdata, outlength, temp, &templength);
	}
	QueryPerformanceCounter(&EndNum);
	Second = (double)(((EndNum.QuadPart - StartNum.QuadPart)+0.0)/Frequency.QuadPart);
	printf("%s Encrypt and Decrypt Speed is %02fMB/s\n", pName, (960*LOOPTIMES+0.0)/1024/1024/Second);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);

}

void DuiChenSpeed()
{
	CK_ULONG id = 0;
	CK_MECHANISM mGen;
	CK_MECHANISM mEnc;
	while (1)
	{
		printf("##############################################\n");
		printf("#  1. SM1_ECB          7. DES3_ECB           #\n");
		printf("#  2. SM1_CBC          8. DES3_CBC           #\n");
		printf("#  3. SM1_CBC_PAD      9. DES3_CBC_PAD       #\n");
		printf("#  4. DES_ECB          10. AES_ECB           #\n");
		printf("#  5. DES_CBC          11. AES_CBC           #\n");
		printf("#  6. DES_CBC_PAD      12. AES_CBC_PAD       #\n");
		printf("#                       0. exit              #\n");
		printf("##############################################\n");
		printf("\n");
		printf("Please select:");
		scanf("%d", &id);
		
		switch (id)
		{
		case 1:
			mGen.mechanism = CKM_SM1_GEN;
			mEnc.mechanism = CKM_SM1_ECB;
			DuiChenSpeedTest(&mGen, &mEnc, "SM1_ECB");
			break;
		case 2:
			mGen.mechanism = CKM_SM1_GEN;
			mEnc.mechanism = CKM_SM1_CBC;
			mEnc.mechanism = CKM_SM1_CBC_PAD;
			mEnc.pParameter = "1234567812345678";
			DuiChenSpeedTest(&mGen, &mEnc, "SM1_CBC");
			break;
		case 3:
			mGen.mechanism = CKM_SM1_GEN;
			mEnc.mechanism = CKM_SM1_CBC_PAD;
			mEnc.pParameter = "1234567812345678";
			mEnc.ulParameterLen = 16;
			DuiChenSpeedTest(&mGen, &mEnc, "SM1_CBC_PAD");
			break;
		case 4:
			mGen.mechanism = CKM_DES_KEY_GEN;
			mEnc.mechanism = CKM_DES_ECB;
			DuiChenSpeedTest(&mGen, &mEnc, "DES_ECB");
			break;
		case 5:
			mGen.mechanism = CKM_DES_KEY_GEN;
			mEnc.mechanism = CKM_DES_CBC;
			mEnc.pParameter = "12345678";
			mEnc.ulParameterLen = 8;
			DuiChenSpeedTest(&mGen, &mEnc, "DES_CBC");
			break;
		case 6:
			mGen.mechanism = CKM_DES_KEY_GEN;
			mEnc.mechanism = CKM_DES_CBC_PAD;
			mEnc.pParameter = "12345678";
			mEnc.ulParameterLen = 8;
			DuiChenSpeedTest(&mGen, &mEnc, "DES_CBC_PAD");
			break;
		case 7:
			mGen.mechanism = CKM_DES3_KEY_GEN;
			mEnc.mechanism = CKM_DES3_ECB;
			DuiChenSpeedTest(&mGen, &mEnc, "DES3_ECB");
			break;
		case 8:
			mGen.mechanism = CKM_DES3_KEY_GEN;
			mEnc.mechanism = CKM_DES3_CBC;
			mEnc.pParameter = "12345678";
			mEnc.ulParameterLen = 8;
			DuiChenSpeedTest(&mGen, &mEnc, "DES3_CBC");
			break;
		case 9:
			mGen.mechanism = CKM_DES3_KEY_GEN;
			mEnc.mechanism = CKM_DES3_CBC_PAD;
			mEnc.pParameter = "12345678";
			mEnc.ulParameterLen = 8;
			DuiChenSpeedTest(&mGen, &mEnc, "DES3_CBC_PAD");
			break;
		case 10:
			mGen.mechanism = CKM_AES_KEY_GEN;
			mEnc.mechanism = CKM_AES_ECB;
			DuiChenSpeedTest(&mGen, &mEnc, "AES_ECB");
			break;
		case 11:
			mGen.mechanism = CKM_AES_KEY_GEN;
			mEnc.mechanism = CKM_AES_CBC;
			mEnc.pParameter = "1234567812345678";
			mEnc.ulParameterLen = 16;
			DuiChenSpeedTest(&mGen, &mEnc, "AES_CBC");
			break;
		case 12:
			mGen.mechanism = CKM_AES_KEY_GEN;
			mEnc.mechanism = CKM_AES_CBC_PAD;
			mEnc.pParameter = "1234567812345678";
			mEnc.ulParameterLen = 16;
			DuiChenSpeedTest(&mGen, &mEnc, "AES_CBC_PAD");
			break;
		case 0:
			return;
			break;
		default:
			break;
		}//switch
	}//while
}

#endif

