#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <stdlib.h>


#include "pkcs11.h"
#include "fmpkcs11.h"
#include "pkcs11s.h"
#include "g_head.h"

#ifdef  OS_WINDOWS
#include <windows.h>
#else
#include <pthread.h>
#endif

extern CK_BBOOL g_ifpt;
extern void PrintData(CK_BYTE_PTR p, CK_ULONG len);
void StartThread(void * pParam);

FLAG WrapTest_RSA();
FLAG WrapTest_ECC();
FLAG WrapTest_DES3();
FLAG WrapTest_AES();
FLAG WrapTest_SM1();

#ifdef OS_LINUX
FLAG (*wrap_func[])() = {WrapTest_RSA, WrapTest_ECC, WrapTest_DES3, WrapTest_AES, WrapTest_SM1};
#endif

FLAG WrapTest_RSA()
{

	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_OBJECT_HANDLE hRSAPubKey = 0;
	CK_OBJECT_HANDLE hRSAPriKey = 0;
	CK_OBJECT_HANDLE hECCPubKey = 0;
	CK_OBJECT_HANDLE hECCPriKey = 0;
	CK_OBJECT_HANDLE hKey = 0;
	CK_ULONG KeyType = CKK_DES;
	CK_ULONG PubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG PriKeyClass = CKO_PRIVATE_KEY;
	CK_ULONG KeyClass = CKO_SECRET_KEY;
	CK_BBOOL isFalse = FALSE;
	CK_BBOOL isTrue = TRUE;
	CK_ULONG ModulusBits = 1024;
	CK_MECHANISM mRSAGenKey = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mGenKey = {CKM_DES_KEY_GEN, NULL_PTR, 0};
	CK_MECHANISM mWrap = {CKM_RSA_PKCS, NULL_PTR, 0};
	CK_BYTE RSAPubLabel[] = "RSA_PUBLIC_KEY_0";
	CK_BYTE RSAPriLabel[] = "RSA_PRIVATE_KEY_0";

	CK_ATTRIBUTE aRSAPubKey[] = {
		{CKA_CLASS, &PubKeyClass, sizeof(PubKeyClass)},
		{CKA_TOKEN, &isFalse, sizeof(isFalse)},
		{CKA_WRAP, &isTrue, sizeof(isTrue)},
		{CKA_LABEL, RSAPubLabel, sizeof(RSAPubLabel)},
		{CKA_MODULUS_BITS, &ModulusBits, sizeof(ModulusBits)}
								};

	CK_ATTRIBUTE aRSAPriKey[] = {
		{CKA_CLASS, &PriKeyClass, sizeof(PriKeyClass)},
		{CKA_TOKEN, &isFalse, sizeof(isFalse)},
		{CKA_LABEL, RSAPriLabel, sizeof(RSAPriLabel)},
		{CKA_UNWRAP, &isTrue, sizeof(isTrue)}
								};
	
	CK_ATTRIBUTE aKey[] = {
		{CKA_CLASS, &KeyClass, sizeof(KeyClass)},
		{CKA_EXTRACTABLE, &isTrue, sizeof(isTrue)}
							};

	CK_ATTRIBUTE aUnwrapKey[] = {
		{CKA_CLASS, &KeyClass, sizeof(KeyClass)},
		{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)}
							};

	CK_ATTRIBUTE GetValue1[] = {
		{CKA_VALUE, NULL_PTR, 0}
							};
	CK_ATTRIBUTE GetValue2[] = {
		{CKA_VALUE, NULL_PTR, 0}
							};

	CK_OBJECT_HANDLE hNewKey = 0;

	CK_BYTE RSAResult[128] = {0x00};
	CK_ULONG RSAResultLen = 0;

	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKeyPair(hSession, &mRSAGenKey, aRSAPubKey, 5, aRSAPriKey, 4, &hRSAPubKey, &hRSAPriKey);
	rv = C_GenerateKey(hSession, &mGenKey, aKey, 2, &hKey);
	memset(RSAResult, 0x00, 128);

	rv = C_GetAttributeValue(hSession, hKey, GetValue1, 1);
	if (rv == 0)
	{
		GetValue1[0].pValue = (CK_BYTE_PTR)malloc(GetValue1[0].ulValueLen);
		if (GetValue1[0].pValue == NULL)
		{
			printf("WrapTest_RSA->malloc ERROR!\n");
		}
		rv = C_GetAttributeValue(hSession, hKey, GetValue1, 1);
	}
	rv = C_WrapKey(hSession, &mWrap, hRSAPubKey, hKey, RSAResult, &RSAResultLen);
	if (rv == 0)
	{
		printf("OK Wrap_RSA !\n");
	}
	else
	{
		printf("ERROR Wrap_RSA !\n");
	}

	rv = C_UnwrapKey(hSession, &mWrap, hRSAPriKey, RSAResult, RSAResultLen, aUnwrapKey, 2, &hNewKey);
	if (rv == 0)
	{
		printf("OK Unwrap_RSA OK!\n");
	}
	else
	{
		printf("ERROR Unwrap_RSA !\n");
	}
	rv = C_GetAttributeValue(hSession, hNewKey, GetValue2, 1);
	if (rv == 0)
	{
		GetValue2[0].pValue = (CK_BYTE_PTR)malloc(GetValue2[0].ulValueLen);
		if (GetValue2[0].pValue == NULL)
		{
			printf("WrapTest_RSA->malloc ERROR!\n");
		}
		rv = C_GetAttributeValue(hSession, hNewKey, GetValue2, 1);
	}

	if (memcmp(GetValue1[0].pValue, GetValue2[0].pValue, GetValue2[0].ulValueLen) == 0 && GetValue2[0].ulValueLen != 0)
	{
		printf("OK RSA Wrap and Unwrap !\n");
	}
	else
	{
		printf("ERROR RSA Wrap and Unwrap !\n");
	}

	free(GetValue1[0].pValue);
	free(GetValue2[0].pValue);
	C_CloseAllSessions(hSession);	
	return 0;
}

FLAG WrapTest_ECC()
{

	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_OBJECT_HANDLE hRSAPubKey = 0;
	CK_OBJECT_HANDLE hRSAPriKey = 0;
	CK_OBJECT_HANDLE hECCPubKey = 0;
	CK_OBJECT_HANDLE hECCPriKey = 0;
	CK_OBJECT_HANDLE hKey = 0;
	CK_ULONG KeyType = CKK_AES;
	CK_ULONG PubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG PriKeyClass = CKO_PRIVATE_KEY;
	CK_ULONG KeyClass = CKO_SECRET_KEY;
	CK_BBOOL isFalse = FALSE;
	CK_BBOOL isTrue = TRUE;
	CK_MECHANISM mECCGenKey = {CKM_SM2_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mGenKey = {CKM_AES_KEY_GEN, NULL_PTR, 0};
	CK_MECHANISM mWrap = {CKM_SM2, NULL_PTR, 0};
	CK_ATTRIBUTE aECCPubKey[] = {
		{CKA_CLASS, &PubKeyClass, sizeof(PubKeyClass)},
		{CKA_TOKEN, &isFalse, sizeof(isFalse)},
		{CKA_WRAP, &isTrue, sizeof(isTrue)}
								};

	CK_ATTRIBUTE aECCPriKey[] = {
		{CKA_CLASS, &PriKeyClass, sizeof(PriKeyClass)},
		{CKA_TOKEN, &isFalse, sizeof(isFalse)},
		{CKA_UNWRAP, &isTrue, sizeof(isTrue)}
								};
	
	CK_ATTRIBUTE aKey[] = {
		{CKA_CLASS, &KeyClass, sizeof(KeyClass)},
		{CKA_EXTRACTABLE, &isTrue, sizeof(isTrue)}
							};

	CK_ATTRIBUTE aUnwrapKey[] = {
		{CKA_CLASS, &KeyClass, sizeof(KeyClass)},
		{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)}
							};

	CK_ATTRIBUTE GetValue1[] = {
		{CKA_VALUE, NULL_PTR, 0}
							};
	CK_ATTRIBUTE GetValue2[] = {
		{CKA_VALUE, NULL_PTR, 0}
							};

	CK_OBJECT_HANDLE hNewKey = 0;

	CK_BYTE ECCResult[300] = {0x00};
	CK_ULONG ECCResultLen = 0;

	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKeyPair(hSession, &mECCGenKey, aECCPubKey, 3, aECCPriKey, 3, &hECCPubKey, &hECCPriKey);
	rv = C_GenerateKey(hSession, &mGenKey, aKey, 2, &hKey);
	memset(ECCResult, 0x00, 300);
	//get the value attribute
	rv = C_GetAttributeValue(hSession, hKey, GetValue1, 1);
	if (rv == 0)
	{
		GetValue1[0].pValue = (CK_BYTE_PTR)malloc(GetValue1[0].ulValueLen);
		if (GetValue1[0].pValue == NULL)
		{
			printf("WrapTest_ECC->malloc ERROR!\n");
		}
		rv = C_GetAttributeValue(hSession, hKey, GetValue1, 1);
	}
	rv = C_WrapKey(hSession, &mWrap, hECCPubKey, hKey, ECCResult, &ECCResultLen);
	if (rv == 0)
	{
		printf("OK Wrap_ECC !\n");
	}
	else
	{
		printf("ERROR Wrap_ECC !\n");
	}

	rv = C_UnwrapKey(hSession, &mWrap, hECCPriKey, ECCResult, ECCResultLen, aUnwrapKey, 2, &hNewKey);
	if (rv == 0)
	{
		printf("OK Unwrap_ECC !\n");
	}
	else
	{
		printf("ERROR Unwrap_ECC !\n");
	}
	rv = C_GetAttributeValue(hSession, hNewKey, GetValue2, 1);
	if (rv == 0)
	{
		GetValue2[0].pValue = (CK_BYTE_PTR)malloc(GetValue2[0].ulValueLen);
		if (GetValue2[0].pValue == NULL)
		{
			printf("WrapTest_ECC->malloc ERROR!\n");
		}
		rv = C_GetAttributeValue(hSession, hNewKey, GetValue2, 1);
	}

	if (memcmp(GetValue1[0].pValue, GetValue2[0].pValue, GetValue2[0].ulValueLen) == 0 && GetValue2[0].ulValueLen != 0)
	{
		printf("OK ECC Wrap and Unwrap !\n");
	}
	else
	{
		printf("ERROR ECC Wrap and Unwrap !\n");
	}

	free(GetValue1[0].pValue);
	free(GetValue2[0].pValue);
	C_CloseAllSessions(hSession);	
	return 0;
}

FLAG WrapTest_DES3()
{

	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_OBJECT_HANDLE hRSAPubKey = 0;
	CK_OBJECT_HANDLE hRSAPriKey = 0;
	CK_OBJECT_HANDLE hECCPubKey = 0;
	CK_OBJECT_HANDLE hECCPriKey = 0;
	CK_OBJECT_HANDLE hKey = 0;
	CK_ULONG KeyType = CKK_SM2;
	CK_ULONG PubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG PriKeyClass = CKO_PRIVATE_KEY;
	CK_ULONG KeyClass = CKO_SECRET_KEY;
	CK_BBOOL isFalse = FALSE;
	CK_BBOOL isTrue = TRUE;
	CK_MECHANISM mECCGenKey = {CKM_SM2_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mGenKey = {CKM_DES3_KEY_GEN, NULL_PTR, 0};
	CK_MECHANISM mWrap = {CKM_DES3_CBC_PAD, "12345678", 8};
	CK_ATTRIBUTE aECCPubKey[] = {
		{CKA_CLASS, &PubKeyClass, sizeof(PubKeyClass)},
		{CKA_TOKEN, &isFalse, sizeof(isFalse)},
		{CKA_WRAP, &isTrue, sizeof(isTrue)}
								};

	CK_ATTRIBUTE aECCPriKey[] = {
		{CKA_CLASS, &PriKeyClass, sizeof(PriKeyClass)},
		{CKA_TOKEN, &isFalse, sizeof(isFalse)},
		{CKA_UNWRAP, &isTrue, sizeof(isTrue)}
								};
	
	CK_ATTRIBUTE aKey[] = {
		{CKA_CLASS, &KeyClass, sizeof(KeyClass)},
		{CKA_EXTRACTABLE, &isTrue, sizeof(isTrue)}
							};

	CK_ATTRIBUTE aUnwrapKey[] = {
		{CKA_CLASS, &PriKeyClass, sizeof(PriKeyClass)},
		{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)}
							};

	CK_ATTRIBUTE GetValue1[] = {
		{CKA_VALUE, NULL_PTR, 0}
							};
	CK_ATTRIBUTE GetValue2[] = {
		{CKA_VALUE, NULL_PTR, 0}
							};

	CK_OBJECT_HANDLE hNewKey = 0;

	CK_BYTE ECCResult[300] = {0x00};
	CK_ULONG ECCResultLen = 0;

	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKeyPair(hSession, &mECCGenKey, aECCPubKey, 3, aECCPriKey, 3, &hECCPubKey, &hECCPriKey);
	rv = C_GenerateKey(hSession, &mGenKey, aKey, 2, &hKey);
	memset(ECCResult, 0x00, 300);
	//get the value attribute
	rv = C_GetAttributeValue(hSession, hECCPriKey, GetValue1, 1);
	if (rv == 0)
	{
		GetValue1[0].pValue = (CK_BYTE_PTR)malloc(GetValue1[0].ulValueLen);
		if (GetValue1[0].pValue == NULL)
		{
			printf("WrapTest_DES3->malloc ERROR!\n");
		}
		rv = C_GetAttributeValue(hSession, hECCPriKey, GetValue1, 1);
	}
	rv = C_WrapKey(hSession, &mWrap, hKey, hECCPriKey, ECCResult, &ECCResultLen);
	if (rv == 0)
	{
		printf("OK Wrap_DES3 !\n");
	}
	else
	{
		printf("ERROR Wrap_DES3 !\n");
	}

	rv = C_UnwrapKey(hSession, &mWrap, hKey, ECCResult, ECCResultLen, aUnwrapKey, 2, &hNewKey);
	if (rv == 0)
	{
		printf("OK Unwrap_DES3 !\n");
	}
	else
	{
		printf("ERROR Unwrap_DES3 !\n");
	}
	rv = C_GetAttributeValue(hSession, hNewKey, GetValue2, 1);
	if (rv == 0)
	{
		GetValue2[0].pValue = (CK_BYTE_PTR)malloc(GetValue2[0].ulValueLen);
		if (GetValue2[0].pValue == NULL)
		{
			printf("WrapTest_DES3->malloc ERROR!\n");
		}
		rv = C_GetAttributeValue(hSession, hNewKey, GetValue2, 1);
	}

	if (memcmp(GetValue1[0].pValue, GetValue2[0].pValue, GetValue2[0].ulValueLen) == 0 && GetValue2[0].ulValueLen != 0)
	{
		printf("OK DES3 Wrap and Unwrap !\n");
	}
	else
	{
		printf("ERROR DES3 Wrap and Unwrap !\n");
	}

	free(GetValue1[0].pValue);
	free(GetValue2[0].pValue);
	C_CloseAllSessions(hSession);	
	return 0;
}

FLAG WrapTest_AES()
{

	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_OBJECT_HANDLE hRSAPubKey = 0;
	CK_OBJECT_HANDLE hRSAPriKey = 0;
	CK_OBJECT_HANDLE hKey = 0;
	CK_ULONG PubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG PriKeyClass = CKO_PRIVATE_KEY;
	CK_ULONG KeyClass = CKO_SECRET_KEY;
	CK_BBOOL isFalse = FALSE;
	CK_BBOOL isTrue = TRUE;
	CK_ULONG ModulusBits = 1024;
	CK_ULONG KeyType = CKK_RSA;
	CK_MECHANISM mRSAGenKey = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mGenKey = {CKM_AES_KEY_GEN, NULL_PTR, 0};
	CK_MECHANISM mWrap = {CKM_AES_CBC_PAD, "1234567812345678", 16};
	CK_ATTRIBUTE aRSAPubKey[] = {
		{CKA_CLASS, &PubKeyClass, sizeof(PubKeyClass)},
		{CKA_TOKEN, &isFalse, sizeof(isFalse)},
		{CKA_MODULUS_BITS, &ModulusBits, sizeof(ModulusBits)}
								};

	CK_ATTRIBUTE aRSAPriKey[] = {
		{CKA_CLASS, &PriKeyClass, sizeof(PriKeyClass)},
		{CKA_TOKEN, &isFalse, sizeof(isFalse)},
		{CKA_EXTRACTABLE, &isTrue, sizeof(isTrue)}
								};
	
	CK_ATTRIBUTE aKey[] = {
		{CKA_CLASS, &KeyClass, sizeof(KeyClass)},
		{CKA_WRAP, &isTrue, sizeof(isTrue)},
		{CKA_UNWRAP, &isTrue, sizeof(isTrue)}
							};

	CK_ATTRIBUTE aUnwrapKey[] = {
		{CKA_CLASS, &PriKeyClass, sizeof(PriKeyClass)},
		{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)}
							};

	CK_ATTRIBUTE GetValue1[] = {
		{CKA_COEFFICIENT, NULL_PTR, 0}
							};
	CK_ATTRIBUTE GetValue2[] = {
		{CKA_COEFFICIENT, NULL_PTR, 0}
							};

	CK_OBJECT_HANDLE hNewKey = 0;

	CK_BYTE RSAResult[1600] = {0x00};
	CK_ULONG RSAResultLen = 0;

	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKeyPair(hSession, &mRSAGenKey, aRSAPubKey, 3, aRSAPriKey, 3, &hRSAPubKey, &hRSAPriKey);
	rv = C_GenerateKey(hSession, &mGenKey, aKey, 3, &hKey);
	memset(RSAResult, 0x00, 1600);

	rv = C_GetAttributeValue(hSession, hRSAPriKey, GetValue1, 1);
	if (rv == 0)
	{
		GetValue1[0].pValue = (CK_BYTE_PTR)malloc(GetValue1[0].ulValueLen);
		if (GetValue1[0].pValue == NULL)
		{
			printf("WrapTest_AES->malloc ERROR!\n");
		}
		rv = C_GetAttributeValue(hSession, hRSAPriKey, GetValue1, 1);
	}
	rv = C_WrapKey(hSession, &mWrap, hKey, hRSAPriKey, RSAResult, &RSAResultLen);
	if (rv == 0)
	{
		printf("OK Wrap_AES !\n");
	}
	else
	{
		printf("ERROR Wrap_AES !\n");
	}

	rv = C_UnwrapKey(hSession, &mWrap, hKey, RSAResult, RSAResultLen, aUnwrapKey, 2, &hNewKey);
	if (rv == 0)
	{
		printf("OK Unwrap_AES !\n");
	}
	else
	{
		printf("ERROR Unwrap_AES !\n");
	}
	rv = C_GetAttributeValue(hSession, hNewKey, GetValue2, 1);
	if (rv == 0)
	{
		GetValue2[0].pValue = (CK_BYTE_PTR)malloc(GetValue2[0].ulValueLen);
		if (GetValue2[0].pValue == NULL)
		{
			printf("WrapTest_RSA->malloc ERROR!\n");
		}
		rv = C_GetAttributeValue(hSession, hNewKey, GetValue2, 1);
	}

	if (memcmp(GetValue1[0].pValue, GetValue2[0].pValue, GetValue2[0].ulValueLen) == 0 && GetValue2[0].ulValueLen != 0)
	{
		printf("OK AES Wrap and Unwrap !\n");
	}
	else
	{
		printf("ERROR AES Wrap and Unwrap !\n");
	}

	free(GetValue1[0].pValue);
	free(GetValue2[0].pValue);
	C_CloseAllSessions(hSession);	
	return 0;
}

FLAG WrapTest_SM1()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_MECHANISM mGenSM1Key = {CKM_SM1_GEN, NULL_PTR, 0};
	CK_MECHANISM mGenDES3Key = {CKM_DES3_KEY_GEN, NULL_PTR, 0};
	CK_MECHANISM mSM1Encrypt = {CKM_SM1_CBC_PAD, "1234567812345678", 16};
	CK_OBJECT_HANDLE hSM1Key = 0;
	CK_OBJECT_HANDLE hDES3Key = 0;
	CK_OBJECT_HANDLE hNewDES3Key = 0;
	CK_ULONG KeyClass = CKO_SECRET_KEY;
	CK_BBOOL isTrue = TRUE;

	CK_ATTRIBUTE aSM1[] = {
		{CKA_CLASS, &KeyClass, sizeof(KeyClass)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
							};
	CK_ATTRIBUTE aDES3[] = {
		{CKA_CLASS, &KeyClass, sizeof(KeyClass)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
							};
	CK_ATTRIBUTE GetDES3[] = {
		{CKA_VALUE, NULL_PTR, 0}
							};
	CK_ATTRIBUTE aNewDES3[] = {
		{CKA_CLASS, &KeyClass, sizeof(KeyClass)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
							};
	CK_ATTRIBUTE GetNewDes3[] = {
		{CKA_VALUE, NULL_PTR, 0}
							};
	CK_BYTE SM1Result[32] = {0x00};
	CK_ULONG ResultLenght = 0;

	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKey(hSession, &mGenSM1Key, aSM1, 2, &hSM1Key);
	rv = C_GenerateKey(hSession, &mGenDES3Key, aDES3, 2, &hDES3Key);
	rv = C_GetAttributeValue(hSession, hDES3Key, GetDES3, 1);
	if (rv == 0)
	{
		GetDES3[0].pValue = malloc(GetDES3[0].ulValueLen);
		if (GetDES3[0].pValue == NULL)
		{
			printf("WrapTest_SM1->malloc ERROR!\n");
			C_CloseSession(hSession);
			return -1;
		}
		rv = C_GetAttributeValue(hSession, hDES3Key, GetDES3, 1);
	}
	rv = C_WrapKey(hSession, &mSM1Encrypt, hSM1Key, hDES3Key, SM1Result, &ResultLenght);
	if (rv == 0)
	{
		printf("OK Wrap_SM1 !\n");
	}
	else
	{
		printf("ERROR Wrap_SM1 !\n");
	}
	rv = C_UnwrapKey(hSession, &mSM1Encrypt, hSM1Key, SM1Result, ResultLenght, aNewDES3, 2, &hNewDES3Key);
	if (rv == 0)
	{
		printf("OK Unwrap_SM1 !\n");
	}
	else
	{
		printf("ERROR Unwrap_SM1 !\n");
	}
	rv = C_GetAttributeValue(hSession, hNewDES3Key, GetNewDes3, 1);
	if (rv == 0)
	{
		GetNewDes3[0].pValue = malloc(GetNewDes3[0].ulValueLen);
		if (GetNewDes3[0].pValue == NULL)
		{
			printf("WrapTest_SM1->malloc ERROR!\n");
			free(GetDES3[0].pValue);
			C_CloseSession(hSession);
			return -1;
		}
		rv = C_GetAttributeValue(hSession, hNewDES3Key, GetNewDes3, 1);
	}
	if (memcmp(GetDES3[0].pValue, GetNewDes3[0].pValue, GetDES3[0].ulValueLen) == 0 && GetDES3[0].ulValueLen != 0)
	{
		printf("OK SM1 Wrap and Unwrap !\n");
	}
	else
	{
		printf("ERROR SM1 Wrap and Unwrap !\n");
	}
	free(GetDES3[0].pValue);
	free(GetNewDes3[0].pValue);
#ifdef DEVICE_KEY
	//C_Logout(hSession);
#endif
	C_CloseSession(hSession);
	return 0;
}

void TestWrap()
{
	CK_ULONG id = 0;
	while (1)
	{
		printf("##############################################\n");
		printf("#  1. RSA1024-->DES                          #\n");
		printf("#  2. ECC-->AES                              #\n");
		printf("#  3. DES3-->ECC                             #\n");
		printf("#  4. AES-->RSA1024                          #\n");
		printf("#  5. SM1-->DES3                             #\n");
		printf("#  0. exit                                   #\n");
		printf("##############################################\n");
		printf("\n");
		printf("Please select:");
		scanf("%d", &id);
		
		switch (id)
		{
		case 1:
			WrapTest_RSA();
			break;
		case 2:
			WrapTest_ECC();
			break;
		case 3:
			WrapTest_DES3();
			break;
		case 4:
			WrapTest_AES();
			break;
		case 5:
			WrapTest_SM1();
		case 0:
			return;
			break;
		default:
			break;
		}
	}//while
}

#ifdef OS_LINUX
void StratProcess_w(int param)
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
				StartThread(wrap_func[param]);
			}else
			{
			    wrap_func[param]();
			}
			exit(0);
		}
	}
	
}

void TestWrapProcess()
{
	CK_ULONG id = 0;
	
	while (1)
	{
		printf("##############################################\n");
		printf("#  1. RSA1024-->DES                          #\n");
		printf("#  2. ECC-->AES                              #\n");
		printf("#  3. DES3-->ECC                             #\n");
		printf("#  4. AES-->RSA1024                          #\n");
		printf("#  5. SM1-->DES3                             #\n");
		printf("#  0. exit                                   #\n");
		printf("##############################################\n");
		printf("\n");
		printf("Please select:");
		scanf("%d", &id);
		
		switch (id)
		{
		case 1:
			StratProcess_w(0);			
			break;
		case 2:
			StratProcess_w(1);
			break;
		case 3:
			StratProcess_w(2);
			break;
		case 4:
			StratProcess_w(3);
			break;
		case 5:
			StratProcess_w(4);	
		case 0:
			return;
			break;
		default:
			break;
		}
	}//while
}
#endif

void TestWrapThread()
{
	CK_ULONG id = 0;

	while (1)
	{
		printf("##############################################\n");
		printf("#  1. RSA1024-->DES                          #\n");
		printf("#  2. ECC-->AES                              #\n");
		printf("#  3. DES3-->ECC                             #\n");
		printf("#  4. AES-->RSA1024                          #\n");
		printf("#  5. SM1-->DES3                             #\n");
		printf("#  0. exit                                   #\n");
		printf("##############################################\n");
		printf("\n");
		printf("Please select:");
		scanf("%d", &id);
		
		switch (id)
		{
		case 1:
			StartThread(WrapTest_RSA);
			break;
		case 2:
			StartThread(WrapTest_ECC);
			break;
		case 3:
			StartThread(WrapTest_DES3);
			break;
		case 4:
			StartThread(WrapTest_AES);
			break;
		case 5:
			StartThread(WrapTest_SM1);
		case 0:
			return;
			break;
		default:
			break;
		}
	}//while
}


