#include <stdio.h>
#include <memory.h>
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

void StartThread(void * pParam);
extern CK_BBOOL g_ifthread;
extern CK_BBOOL g_ifpt;

#ifdef  OS_WINDOWS
extern CRITICAL_SECTION critial_section;
#else
extern pthread_mutex_t  linux_mutex;
#endif

FLAG SignRSA();
FLAG SignECC();
FLAG SignRSA3Steps();
FLAG SignECC3Steps();
FLAG SignMD2_RSA2048();
FLAG SignMD5_RSA1024();
FLAG SignSHA1_RSA1024();
FLAG SignSHA256_RSA1024();
FLAG SignSHA384_RSA1024();
FLAG SignSHA512_RSA1024();
FLAG SignSM3_SM2();
FLAG SignRecover();

#ifdef OS_LINUX
FLAG (*sign_func[])() = {SignRSA, SignECC, SignMD2_RSA2048, SignMD5_RSA1024, SignSHA1_RSA1024, SignSHA256_RSA1024, SignSHA384_RSA1024,
SignSHA512_RSA1024, SignSM3_SM2, SignRecover};
#endif

FLAG SignRecover()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_MECHANISM mRSAGenKey = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mSign = {CKM_RSA_PKCS, NULL_PTR, 0};
	CK_ULONG PubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG PriKeyClass = CKO_PRIVATE_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_ULONG MoudlusBits = 1024;
	CK_OBJECT_HANDLE hRSAPubKey = 0;
	CK_OBJECT_HANDLE hRSAPriKey = 0;
	CK_BYTE_PTR indata = NULL_PTR;
	CK_BYTE outdata[128] = {0x00};
	CK_BYTE temp[128] = {0x00};
	CK_ULONG templength = 0;
	CK_ULONG outlength = 0;
	CK_ULONG length = 0;
	
	CK_ATTRIBUTE aRSAPubKey[] = {
		{CKA_CLASS, &PubKeyClass, sizeof(PubKeyClass)},
		{CKA_MODULUS_BITS, &MoudlusBits, sizeof(MoudlusBits)}
								};
	
	CK_ATTRIBUTE aRSAPriKey[] = {
		{CKA_CLASS, &PriKeyClass, sizeof(PriKeyClass)},
		{CKA_SIGN_RECOVER, &isTrue, sizeof(isTrue)}
								};

	memset(outdata, 0x00, 128);
	memset(temp, 0x00, 128);
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKeyPair(hSession, &mRSAGenKey, aRSAPubKey, 2, aRSAPriKey, 2, &hRSAPubKey, &hRSAPriKey);
	if (!g_ifthread)
	{
		printf("please input data length, must be less than 117:\n");
		scanf("%d", &length);
		if(length > 117)
		{
			printf("length is larger than 117\n");
			return -1;
		}
	}
	else
	{
		length = 111;
	}
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("SignRSA->malloc ERROR!\n");
		return -1;
	}
	
    rv = C_GenerateRandom(hSession, indata, length);
	rv = C_SignRecoverInit(hSession, &mSign, hRSAPriKey);
	rv = C_SignRecover(hSession, indata, length, outdata, &outlength);
	if (rv == 0)
	{
		printf("OK SignRecover !\n");
	}
	else
	{
		printf("ERROR SignRecover !\n");
		free(indata);
		return -1;
	}
	rv = C_VerifyRecoverInit(hSession, &mSign, hRSAPubKey);
	rv = C_VerifyRecover(hSession, outdata, outlength, temp, &templength);
	if (rv == 0)
	{
		printf("OK VerifyRecover !\n");
	}
	else
	{
		printf("ERROR VerifyRecover !\n");
		free(indata);
		return -1;
	}
	free(indata);
	C_CloseAllSessions(hSession);
	return 0;
}


FLAG SignRSA()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_MECHANISM mRSAGenKey = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mSign = {CKM_RSA_PKCS, NULL_PTR, 0};
	CK_ULONG PubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG PriKeyClass = CKO_PRIVATE_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_ULONG MoudlusBits = 1024;
	CK_OBJECT_HANDLE hRSAPubKey = 0;
	CK_OBJECT_HANDLE hRSAPriKey = 0;
	CK_BYTE_PTR indata = NULL_PTR;
	CK_BYTE outdata[128] = {0x00};
	CK_ULONG templength = 0;
	CK_ULONG outlength = 0;
	CK_ULONG length = 0;

	CK_ATTRIBUTE aRSAPubKey[] = {
		{CKA_CLASS, &PubKeyClass, sizeof(PubKeyClass)},
		{CKA_MODULUS_BITS, &MoudlusBits, sizeof(MoudlusBits)}
								};
	
	CK_ATTRIBUTE aRSAPriKey[] = {
		{CKA_CLASS, &PriKeyClass, sizeof(PriKeyClass)},
								};
	memset(outdata, 0x00, 128);
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKeyPair(hSession, &mRSAGenKey, aRSAPubKey, 2, aRSAPriKey, 1, &hRSAPubKey, &hRSAPriKey);
	if (!g_ifthread)
	{
		printf("please input data length, must be less than 117:\n");
		scanf("%d", &length);
		if(length > 117)
		{
			printf("length is larger than 117\n");
			return -1;
		}
	}
	else
	{
		length = 111;
	}
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("SignRSA->malloc ERROR!\n");
		return -1;
	}

    rv = C_GenerateRandom(hSession, indata, length);
	rv = C_SignInit(hSession, &mSign, hRSAPriKey);
	rv = C_Sign(hSession, indata, length, NULL, &outlength);
	rv = C_Sign(hSession, indata, length, outdata, &outlength);

	rv = C_VerifyInit(hSession, &mSign, hRSAPubKey);
	rv = C_Verify(hSession, indata, length, outdata, outlength);
	if (rv == 0)
	{
		printf("OK SignRSA !\n");
	}
	else
	{
		printf("ERROR SignRSA !\n");
		free(indata);
		return -1;
	}
	free(indata);
	C_CloseAllSessions(hSession);
	return 0;
}

FLAG SignRSA3Steps()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_MECHANISM mRSAGenKey = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mSign = {CKM_RSA_PKCS, NULL_PTR, 0};
	CK_ULONG PubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG PriKeyClass = CKO_PRIVATE_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_ULONG MoudlusBits = 1024;
	CK_OBJECT_HANDLE hRSAPubKey = 0;
	CK_OBJECT_HANDLE hRSAPriKey = 0;
	CK_BYTE_PTR indata = NULL_PTR;
	CK_BYTE outdata[128] = {0x00};
	CK_ULONG templength = 0;
	CK_ULONG outlength = 0;
	CK_ULONG length = 0;
	CK_MECHANISM mSignUpdate = {CKM_SHA1_RSA_PKCS, NULL_PTR, 0};
	
	CK_ULONG times = 0;
	CK_ULONG i = 0;

	CK_ULONG count = 0;
	
 	CK_BYTE RSAPubLabel[] = "RSA_PUBLIC_KEY_32";
 	CK_BYTE RSAPriLabel[] = "RSA_PRIVATE_KEY_32";

	CK_ULONG RSAKeyType = CKK_RSA;
	CK_BYTE Id[] = "MY_TEST_KEY";

	CK_ATTRIBUTE aRSAPubKey[] = {
		{CKA_ID, &Id, strlen(Id)},
		{CKA_CLASS, &PubKeyClass, sizeof(PubKeyClass)},
		{CKA_LABEL, &RSAPubLabel, sizeof(RSAPubLabel)},
		{CKA_KEY_TYPE, &RSAKeyType, sizeof(RSAKeyType)}, 
		{CKA_TOKEN, &isTrue, sizeof(isTrue)},
		{CKA_MODULUS_BITS, &MoudlusBits, sizeof(MoudlusBits)}
	};
	
	CK_ATTRIBUTE aRSAPriKey[] = {
		{CKA_ID, &Id, strlen(Id)},
		{CKA_CLASS, &PriKeyClass, sizeof(PriKeyClass)},
		{CKA_KEY_TYPE, &RSAKeyType, sizeof(RSAKeyType)}, 
		{CKA_LABEL, &RSAPriLabel, sizeof(RSAPriLabel)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}					
	};

	CK_ATTRIBUTE CreateRSAPubKey[] = {
/*		{CKA_ID, &Id, strlen(Id)},*/
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

	CK_ATTRIBUTE GetValue1[] = {
		{CKA_ID, NULL_PTR, 0}
							};
	CK_OBJECT_HANDLE hKey = 0;

	memset(outdata, 0x00, 128);
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif

	rv = C_GenerateKeyPair(hSession, &mRSAGenKey, aRSAPubKey, 6, aRSAPriKey, 5, &hRSAPubKey, &hRSAPriKey);
	if (!g_ifthread)
	{
		printf("please input data length:\n");
		scanf("%d", &length);
	}
	rv = C_GetAttributeValue(hSession, hRSAPriKey, /*CreateRSAPriKey*/ GetValue1, 1);

	rv = C_FindObjectsInit(hSession, aRSAPubKey, 6);	
	rv = C_FindObjects(hSession, &hRSAPubKey, sizeof(hRSAPubKey)/sizeof(CK_OBJECT_HANDLE), &count);
	rv = C_FindObjectsFinal(hSession);
	if (rv != 0)
	{
		return -1;
	}

	rv = C_FindObjectsInit(hSession, aRSAPriKey, 5);	
	rv = C_FindObjects(hSession, &hRSAPriKey, sizeof(hRSAPriKey)/sizeof(CK_OBJECT_HANDLE), &count);
	rv = C_FindObjectsFinal(hSession);
	if (rv != 0)
	{
		return -1;
	}

	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("SignRSA->malloc ERROR!\n");
		return -1;
	}
	
	rv = C_GenerateRandom(hSession, indata, length);
	rv = C_SignInit(hSession, &mSignUpdate, hRSAPriKey);
    rv = C_SignUpdate(hSession, indata, length);
	rv = C_SignFinal(hSession,NULL,&outlength);
	rv = C_SignFinal(hSession,outdata,&outlength);
	if (rv != 0)
	{
		return -1;
	}	
	
	rv = C_VerifyInit(hSession, &mSignUpdate, hRSAPubKey);
	rv = C_VerifyUpdate(hSession, indata, length);
	rv = C_VerifyFinal(hSession,outdata,outlength);
	if (rv == 0)
	{
		printf("OK SignRSA !\n");
	}
	else
	{
		printf("ERROR SignRSA !\n");
		free(indata);
		return -1;
	}
	free(indata);
	C_CloseAllSessions(hSession);
	return 0;
}

FLAG SignECC()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_MECHANISM mECCGenKey = {CKM_SM2_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mSign = {CKM_SM2, NULL_PTR, 0};
	CK_ULONG PubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG PriKeyClass = CKO_PRIVATE_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_OBJECT_HANDLE hECCPubKey = 0;
	CK_OBJECT_HANDLE hECCPriKey = 0;
	CK_BYTE_PTR indata = NULL_PTR;
	CK_BYTE outdata[300] = {0x00};
	CK_ULONG outlength = 0;
	CK_ULONG length = 0;
	CK_BYTE ECCPubLabel[] = "ECC_PUBLIC_KEY_4";
	CK_BYTE ECCPriLabel[] = "ECC_PRIVATE_KEY_4";

	CK_ATTRIBUTE aECCPubKey[] = {
		{CKA_CLASS, &PubKeyClass, sizeof(PubKeyClass)},
//		{CKA_LABEL, ECCPubLabel, sizeof(ECCPubLabel)},
		{CKA_VERIFY, &isTrue, sizeof(isTrue)}
								};
	
	CK_ATTRIBUTE aECCPriKey[] = {
		{CKA_CLASS, &PriKeyClass, sizeof(PriKeyClass)},
//		{CKA_LABEL, &ECCPriLabel, sizeof(ECCPriLabel)},
		{CKA_SIGN, &isTrue, sizeof(isTrue)}
								};
	memset(outdata, 0x00, 300);
	
	if (!g_ifthread)
	{
		printf("please input data length, must be less than 32:\n");
		scanf("%d", &length);
		if(length > 32)
		{
			printf("length is larger than 32\n");
			return -1;
		}
	}
	else
	{
		length = 19;
	}
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("SignECC->malloc ERROR!\n");
		return -1;
	}

	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKeyPair(hSession, &mECCGenKey, aECCPubKey, 2, aECCPriKey, 2, &hECCPubKey, &hECCPriKey);

    rv = C_GenerateRandom(hSession, indata, length);
	rv = C_SignInit(hSession, &mSign, hECCPriKey);
	rv = C_Sign(hSession, indata, length, NULL, &outlength);
	rv = C_Sign(hSession, indata, length, outdata, &outlength);

	rv = C_VerifyInit(hSession, &mSign, hECCPubKey);
	rv = C_Verify(hSession, indata, length, outdata, outlength);
	if (rv == 0)
	{
		printf("OK SignECC !\n");
	}
	else
	{
		printf("ERROR SignECC !\n");
		free(indata);
		return -1;
	}
	free(indata);
	C_CloseAllSessions(hSession);
	return 0;
}

FLAG SignECC3Steps()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_MECHANISM mECCGenKey = {CKM_SM2_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mSign = {CKM_SM2, NULL_PTR, 0};
	CK_ULONG PubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG PriKeyClass = CKO_PRIVATE_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_OBJECT_HANDLE hECCPubKey = 0;
	CK_OBJECT_HANDLE hECCPriKey = 0;
	CK_BYTE_PTR indata = NULL_PTR;
	CK_BYTE outdata[300] = {0x00};
	CK_ULONG outlength = 0;
	CK_ULONG length = 0;
	CK_BYTE ECCPubLabel[] = "ECC_PUBLIC_KEY_4";
	CK_BYTE ECCPriLabel[] = "ECC_PRIVATE_KEY_4";
	
	CK_MECHANISM mSignUpdate = {CKM_ECDSA_PKCS, NULL_PTR, 0};
	
	CK_ATTRIBUTE aECCPubKey[] = {
		{CKA_CLASS, &PubKeyClass, sizeof(PubKeyClass)},
		{CKA_VERIFY, &isTrue, sizeof(isTrue)}
	};
	
	CK_ATTRIBUTE aECCPriKey[] = {
		{CKA_CLASS, &PriKeyClass, sizeof(PriKeyClass)},
		{CKA_SIGN, &isTrue, sizeof(isTrue)}
	};
	memset(outdata, 0x00, 300);
	
	if (!g_ifthread)
	{
		printf("please input data length, must be less than 32:\n");
		scanf("%d", &length);
		if(length > 32)
		{
			printf("length is larger than 32\n");
			return -1;
		}
	}
	else
	{
		length = 19;
	}
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("SignECC->malloc ERROR!\n");
		return -1;
	}
	
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKeyPair(hSession, &mECCGenKey, aECCPubKey, 2, aECCPriKey, 2, &hECCPubKey, &hECCPriKey);
	
	rv = C_GenerateRandom(hSession, indata, length);
	rv = C_SignInit(hSession, &mSignUpdate, hECCPriKey);
    rv = C_SignUpdate(hSession, indata, length);
	rv = C_SignFinal(hSession,NULL,&outlength);
	rv = C_SignFinal(hSession,outdata,&outlength);
	
	
	rv = C_VerifyInit(hSession, &mSignUpdate, hECCPubKey);
	rv = C_VerifyUpdate(hSession, indata, length);
	rv = C_VerifyFinal(hSession,outdata,outlength);
	if (rv == 0)
	{
		printf("OK SignECC !\n");
	}
	else
	{
		printf("ERROR SignECC !\n");
		free(indata);
		return -1;
	}
	free(indata);
	C_CloseAllSessions(hSession);
	return 0;
}

FLAG SignMD2_RSA2048()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_MECHANISM mRSAGenKey = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mSign = {CKM_MD2_RSA_PKCS, NULL_PTR, 0};
	CK_ULONG PubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG PriKeyClass = CKO_PRIVATE_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_ULONG MoudlusBits = 2048;
	CK_OBJECT_HANDLE hRSAPubKey = 0;
	CK_OBJECT_HANDLE hRSAPriKey = 0;
	CK_BYTE_PTR indata = NULL_PTR;
	CK_BYTE outdata[256] = {0x00};
	CK_ULONG templength = 0;
	CK_ULONG outlength = 0;
	CK_ULONG length = 0;

	CK_ATTRIBUTE aRSAPubKey[] = {
		{CKA_CLASS, &PubKeyClass, sizeof(PubKeyClass)},
		{CKA_MODULUS_BITS, &MoudlusBits, sizeof(MoudlusBits)}
								};
	
	CK_ATTRIBUTE aRSAPriKey[] = {
		{CKA_CLASS, &PriKeyClass, sizeof(PriKeyClass)},
								};
	memset(outdata, 0x00, 256);
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKeyPair(hSession, &mRSAGenKey, aRSAPubKey, 2, aRSAPriKey, 1, &hRSAPubKey, &hRSAPriKey);
	if (!g_ifthread)
	{
		printf("please input data length:\n");
		scanf("%d", &length);
	}
	else
	{
		length = 12366;
	}

	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("SignMD2_RSA2048->malloc ERROR!\n");
		return -1;
	}

    rv = C_GenerateRandom(hSession, indata, length);
	rv = C_SignInit(hSession, &mSign, hRSAPriKey);
	rv = C_Sign(hSession, indata, length, outdata, &outlength);
	rv = C_VerifyInit(hSession, &mSign, hRSAPubKey);
	rv = C_Verify(hSession, indata, length, outdata, outlength);
	if (rv == 0)
	{
		printf("OK SignMD2_RSA2048 !\n");
	}
	else
	{
		printf("ERROR SignMD2_RSA2048 !\n");
		free(indata);
		return -1;
	}

	free(indata);
	C_CloseAllSessions(hSession);
	return 0;
}

FLAG SignMD5_RSA1024()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_MECHANISM mRSAGenKey = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mSign = {CKM_MD5_RSA_PKCS, NULL_PTR, 0};
	CK_ULONG PubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG PriKeyClass = CKO_PRIVATE_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_ULONG MoudlusBits = 1024;
	CK_OBJECT_HANDLE hRSAPubKey = 0;
	CK_OBJECT_HANDLE hRSAPriKey = 0;
	CK_BYTE_PTR indata = NULL_PTR;
	CK_BYTE outdata[128] = {0x00};
	CK_ULONG templength = 0;
	CK_ULONG outlength = 0;
	CK_ULONG length = 0;
	CK_BBOOL isToken = TRUE;

	CK_ATTRIBUTE aRSAPubKey[] = {
		{CKA_CLASS, &PubKeyClass, sizeof(PubKeyClass)},
        {CKA_TOKEN, &isToken, sizeof(isToken)},
		{CKA_MODULUS_BITS, &MoudlusBits, sizeof(MoudlusBits)}
	};
	
	CK_ATTRIBUTE aRSAPriKey[] = {
		{CKA_CLASS, &PriKeyClass, sizeof(PriKeyClass)},
		{CKA_TOKEN, &isToken, sizeof(isToken)}
	};
	memset(outdata, 0x00, 128);
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKeyPair(hSession, &mRSAGenKey, aRSAPubKey, 3, aRSAPriKey, 2, &hRSAPubKey, &hRSAPriKey);
	if (!g_ifthread)
	{
		printf("please input data length:\n");
		scanf("%d", &length);
	}
	else
	{
		length = 15;
	}
	
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("SignMD5_RSA1024->malloc ERROR!\n");
		return -1;
	}
	
    rv = C_GenerateRandom(hSession, indata, length);
	rv = C_SignInit(hSession, &mSign, hRSAPriKey);
	rv = C_Sign(hSession, indata, length, outdata, &outlength);
	rv = C_VerifyInit(hSession, &mSign, hRSAPubKey);
	rv = C_Verify(hSession, indata, length, outdata, outlength);
	if (rv == 0)
	{
		printf("OK SignMD5_RSA1024 !\n");
	}
	else
	{
		printf("ERROR SignMD5_RSA1024 !\n");
		free(indata);
		return -1;
	}
	
	free(indata);
	C_CloseAllSessions(hSession);
	return 0;
}

FLAG SignSHA1_RSA1024()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_MECHANISM mRSAGenKey = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mSign = {CKM_SHA1_RSA_PKCS, NULL_PTR, 0};
	CK_ULONG PubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG PriKeyClass = CKO_PRIVATE_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_ULONG MoudlusBits = 1024;
	CK_OBJECT_HANDLE hRSAPubKey = 0;
	CK_OBJECT_HANDLE hRSAPriKey = 0;
	CK_BYTE_PTR indata = NULL_PTR;
	CK_BYTE outdata[128] = {0x00};
	CK_ULONG templength = 0;
	CK_ULONG outlength = 0;
	CK_ULONG length = 0;
	
	CK_ATTRIBUTE aRSAPubKey[] = {
		{CKA_CLASS, &PubKeyClass, sizeof(PubKeyClass)},
		{CKA_MODULUS_BITS, &MoudlusBits, sizeof(MoudlusBits)}
	};
	
	CK_ATTRIBUTE aRSAPriKey[] = {
		{CKA_CLASS, &PriKeyClass, sizeof(PriKeyClass)},
	};
	memset(outdata, 0x00, 128);
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKeyPair(hSession, &mRSAGenKey, aRSAPubKey, 2, aRSAPriKey, 1, &hRSAPubKey, &hRSAPriKey);
	if (!g_ifthread)
	{
		printf("please input data length:\n");
		scanf("%d", &length);
	}
	else
	{
		length = 1000;
	}
	
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("SignSHA1_RSA1024->malloc ERROR!\n");
		return -1;
	}
	
    rv = C_GenerateRandom(hSession, indata, length);
	rv = C_SignInit(hSession, &mSign, hRSAPriKey);
	rv = C_Sign(hSession, indata, length, outdata, &outlength);
	rv = C_VerifyInit(hSession, &mSign, hRSAPubKey);
	rv = C_Verify(hSession, indata, length, outdata, outlength);
	if (rv == 0)
	{
		printf("OK SignSHA1_RSA1024 !\n");
	}
	else
	{
		printf("ERROR SignSHA1_RSA1024 !\n");
		free(indata);
		return -1;
	}
	
	free(indata);
	C_CloseAllSessions(hSession);
	return 0;
}

FLAG SignSHA256_RSA1024()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_MECHANISM mRSAGenKey = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mSign = {CKM_SHA256_RSA_PKCS, NULL_PTR, 0};
	CK_ULONG PubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG PriKeyClass = CKO_PRIVATE_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_ULONG MoudlusBits = 1024;
	CK_OBJECT_HANDLE hRSAPubKey = 0;
	CK_OBJECT_HANDLE hRSAPriKey = 0;
	CK_BYTE_PTR indata = NULL_PTR;
	CK_BYTE outdata[128] = {0x00};
	CK_ULONG templength = 0;
	CK_ULONG outlength = 0;
	CK_ULONG length = 0;
	
	CK_ATTRIBUTE aRSAPubKey[] = {
		{CKA_CLASS, &PubKeyClass, sizeof(PubKeyClass)},
		{CKA_MODULUS_BITS, &MoudlusBits, sizeof(MoudlusBits)}
	};
	
	CK_ATTRIBUTE aRSAPriKey[] = {
		{CKA_CLASS, &PriKeyClass, sizeof(PriKeyClass)},
	};
	memset(outdata, 0x00, 128);
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKeyPair(hSession, &mRSAGenKey, aRSAPubKey, 2, aRSAPriKey, 1, &hRSAPubKey, &hRSAPriKey);
	if (!g_ifthread)
	{
		printf("please input data length:\n");
		scanf("%d", &length);
	}
	else
	{
		length = 321554;
	}
	
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("SignSHA256_RSA1024->malloc ERROR!\n");
		return -1;
	}
	
    rv = C_GenerateRandom(hSession, indata, length);
	rv = C_SignInit(hSession, &mSign, hRSAPriKey);
	rv = C_Sign(hSession, indata, length, outdata, &outlength);
	rv = C_VerifyInit(hSession, &mSign, hRSAPubKey);
	rv = C_Verify(hSession, indata, length, outdata, outlength);
	if (rv == 0)
	{
		printf("OK SignSHA256_RSA1024 !\n");
	}
	else
	{
		printf("ERROR SignSHA256_RSA1024 !\n");
		free(indata);
		return -1;
	}
	
	free(indata);
	C_CloseAllSessions(hSession);
	return 0;
}

FLAG SignSHA384_RSA1024()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_MECHANISM mRSAGenKey = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mSign = {CKM_SHA384_RSA_PKCS, NULL_PTR, 0};
	CK_ULONG PubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG PriKeyClass = CKO_PRIVATE_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_ULONG MoudlusBits = 1024;
	CK_OBJECT_HANDLE hRSAPubKey = 0;
	CK_OBJECT_HANDLE hRSAPriKey = 0;
	CK_BYTE_PTR indata = NULL_PTR;
	CK_BYTE outdata[128] = {0x00};
	CK_ULONG templength = 0;
	CK_ULONG outlength = 0;
	CK_ULONG length = 0;
	
	CK_ATTRIBUTE aRSAPubKey[] = {
		{CKA_CLASS, &PubKeyClass, sizeof(PubKeyClass)},
		{CKA_MODULUS_BITS, &MoudlusBits, sizeof(MoudlusBits)}
	};
	
	CK_ATTRIBUTE aRSAPriKey[] = {
		{CKA_CLASS, &PriKeyClass, sizeof(PriKeyClass)},
	};
	memset(outdata, 0x00, 128);
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKeyPair(hSession, &mRSAGenKey, aRSAPubKey, 2, aRSAPriKey, 1, &hRSAPubKey, &hRSAPriKey);
	if (!g_ifthread)
	{
		printf("please input data length:\n");
		scanf("%d", &length);
	}
	else
	{
		length = 54120;
	}
	
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("SignSHA384_RSA1024->malloc ERROR!\n");
		return -1;
	}
	
    rv = C_GenerateRandom(hSession, indata, length);
	rv = C_SignInit(hSession, &mSign, hRSAPriKey);
	rv = C_Sign(hSession, indata, length, outdata, &outlength);
	rv = C_VerifyInit(hSession, &mSign, hRSAPubKey);
	rv = C_Verify(hSession, indata, length, outdata, outlength);
	if (rv == 0)
	{
		printf("OK SignSHA384_RSA1024 !\n");
	}
	else
	{
		printf("ERROR SignSHA384_RSA1024 !\n");
		free(indata);
		return -1;
	}
	
	free(indata);
	C_CloseAllSessions(hSession);
	return 0;
}

FLAG SignSHA512_RSA1024()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_MECHANISM mRSAGenKey = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mSign = {CKM_SHA512_RSA_PKCS, NULL_PTR, 0};
	CK_ULONG PubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG PriKeyClass = CKO_PRIVATE_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_ULONG MoudlusBits = 1024;
	CK_OBJECT_HANDLE hRSAPubKey = 0;
	CK_OBJECT_HANDLE hRSAPriKey = 0;
	CK_BYTE_PTR indata = NULL_PTR;
	CK_BYTE outdata[128] = {0x00};
	CK_ULONG templength = 0;
	CK_ULONG outlength = 0;
	CK_ULONG length = 0;
	
	CK_ATTRIBUTE aRSAPubKey[] = {
		{CKA_CLASS, &PubKeyClass, sizeof(PubKeyClass)},
		{CKA_MODULUS_BITS, &MoudlusBits, sizeof(MoudlusBits)}
	};
	
	CK_ATTRIBUTE aRSAPriKey[] = {
		{CKA_CLASS, &PriKeyClass, sizeof(PriKeyClass)},
	};
	memset(outdata, 0x00, 128);
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKeyPair(hSession, &mRSAGenKey, aRSAPubKey, 2, aRSAPriKey, 1, &hRSAPubKey, &hRSAPriKey);
	if (!g_ifthread)
	{
		printf("please input data length:\n");
		scanf("%d", &length);
	}
	else
	{
		length = 12897;
	}
	
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("SignSHA512_RSA1024->malloc ERROR!\n");
		return -1;
	}
	
    rv = C_GenerateRandom(hSession, indata, length);
	rv = C_SignInit(hSession, &mSign, hRSAPriKey);
	rv = C_Sign(hSession, indata, length, outdata, &outlength);
	rv = C_VerifyInit(hSession, &mSign, hRSAPubKey);
	rv = C_Verify(hSession, indata, length, outdata, outlength);
	if (rv == 0)
	{
		printf("OK SignSHA512_RSA1024 !\n");
	}
	else
	{
		printf("ERROR SignSHA512_RSA1024 !\n");
		free(indata);
		return -1;
	}
	
	free(indata);
	C_CloseAllSessions(hSession);
	return 0;
}

FLAG SignSM3_SM2()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_MECHANISM mECCGenKey = {CKM_SM2_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_MECHANISM mSign = {CKM_SM3_SM2, NULL_PTR, 0};
	CK_ULONG PubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG PriKeyClass = CKO_PRIVATE_KEY;
	CK_BBOOL isTrue = TRUE;
	CK_OBJECT_HANDLE hECCPubKey = 0;
	CK_OBJECT_HANDLE hECCPriKey = 0;
	CK_BYTE_PTR indata = NULL_PTR;
	CK_BYTE outdata[300] = {0x00};
	CK_ULONG outlength = 0;
	CK_ULONG length = 0;
	
	CK_ATTRIBUTE aECCPubKey[] = {
		{CKA_CLASS, &PubKeyClass, sizeof(PubKeyClass)},
		{CKA_VERIFY, &isTrue, sizeof(isTrue)}
	};
	
	CK_ATTRIBUTE aECCPriKey[] = {
		{CKA_CLASS, &PriKeyClass, sizeof(PriKeyClass)},
		{CKA_SIGN, &isTrue, sizeof(isTrue)}
	};
	memset(outdata, 0x00, 300);
	
	if (!g_ifthread)
	{
		printf("please input data length:\n");
		scanf("%d", &length);
	}
	else
	{
		length = 9999;
	}

	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("SignSM3_SM2->malloc ERROR!\n");
		return -1;
	}
	
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKeyPair(hSession, &mECCGenKey, aECCPubKey, 2, aECCPriKey, 2, &hECCPubKey, &hECCPriKey);
	
    rv = C_GenerateRandom(hSession, indata, length);
	rv = C_SignInit(hSession, &mSign, hECCPriKey);
	rv = C_Sign(hSession, indata, length, outdata, &outlength);
	rv = C_VerifyInit(hSession, &mSign, hECCPubKey);
	rv = C_Verify(hSession, indata, length, outdata, outlength);
	if (rv == 0)
	{
		printf("OK SignSM3_SM2 !\n");
	}
	else
	{
		printf("ERROR SignSM3_SM2 !\n");
		free(indata);
		return -1;
	}
	free(indata);
	C_CloseAllSessions(hSession);
	return 0;
}

void SignTest()
{
	CK_ULONG id = 0;
	while (1)
	{
		printf("##############################################\n");
		printf("#  1. rsa sign         7. SHA384_RSA         #\n");
		printf("#  2. ecc sign         8. SHA512_RSA         #\n");
		printf("#  3. MD2_RSA          9. SM3_SM2            #\n");
		printf("#  4. MD5_RSA          10. Sign Recover      #\n");
		printf("#  5. SHA1_RSA         11. rsa sign(3 steps) #\n");
		printf("#  6. SHA256_RSA       12. ecc sign(3 steps) #\n");
		printf("#                      0. exit               #\n");
		printf("##############################################\n");
		printf("\n");
		printf("Please select:");
		scanf("%d", &id);

		switch (id)
		{
		case 1:
			SignRSA();
			break;
		case 2:
			SignECC();
			break;
		case 3:
			SignMD2_RSA2048();
			break;
		case 4:
			SignMD5_RSA1024();
			break;
		case 5:
			SignSHA1_RSA1024();
			break;
		case 6:
			SignSHA256_RSA1024();
			break;
		case 7:
			SignSHA384_RSA1024();
			break;
		case 8:
			SignSHA512_RSA1024();
			break;
		case 9:
			SignSM3_SM2();
			break;
		case 10:
			SignRecover();
			break;
		case 11:
			SignRSA3Steps();
			break;
		case 12:
			SignECC3Steps();
			break;
		case 0:
			return;
			break;
		default:
			break;
		}
	}//while
}

#ifdef OS_LINUX
void StratProcess_s(int param)
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
				StartThread(sign_func[param]);
			}else
			{
			    sign_func[param]();
			}
			exit(0);
		}
	}
	
}

void SignTestProcess()
{
	CK_ULONG id = 0;
	g_ifthread = 1;
	while (1)
	{
		printf("##############################################\n");
		printf("#  1. rsa sign         6. SHA256_RSA         #\n");
		printf("#  2. ecc sign         7. SHA384_RSA         #\n");
		printf("#  3. MD2_RSA2048      8. SHA512_RSA         #\n");
		printf("#  4. MD5_RSA          9. SM3_SM2            #\n");
		printf("#  5. SHA1_RSA         10. Sign Recover      #\n");
		printf("#                      0. exit               #\n");
		printf("##############################################\n");
		printf("\n");
		printf("Please select:");
		scanf("%d", &id);
		
		switch (id)
		{
		case 1:
			StratProcess_s(0);		
			break;
		case 2:
		    StratProcess_s(1);
			break;
		case 3:
			StratProcess_s(2);
			break;
		case 4:
			StratProcess_s(3);
			break;
		case 5:
			StratProcess_s(4);
			break;
		case 6:
			StratProcess_s(5);
			break;
		case 7:
			StratProcess_s(6);
			break;
		case 8:
			StratProcess_s(7);
			break;
		case 9:
			StratProcess_s(8);
			break;
		case 10:
			StratProcess_s(9);
			break;
		case 0:
			return;
			break;
		default:
			break;
		}
	}//while
	g_ifthread = 0;
}
#endif

void SignTestThread()
{
	CK_ULONG id = 0;
#ifdef  OS_WINDOWS	
	InitializeCriticalSection(&critial_section);
#endif
	while (1)
	{
		printf("##############################################\n");
		printf("#  1. rsa sign         6. SHA256_RSA         #\n");
		printf("#  2. ecc sign         7. SHA384_RSA         #\n");
		printf("#  3. MD2_RSA2048      8. SHA512_RSA         #\n");
		printf("#  4. MD5_RSA          9. SM3_SM2            #\n");
		printf("#  5. SHA1_RSA         10. Sign Recover      #\n");
		printf("#                      0. exit               #\n");
		printf("##############################################\n");
		printf("\n");
		printf("Please select:");
		scanf("%d", &id);
		
		switch (id)
		{
		case 1:
			StartThread(SignRSA);
			break;
		case 2:
			StartThread(SignECC);
			break;
		case 3:
			StartThread(SignMD2_RSA2048);
			break;
		case 4:
			StartThread(SignMD5_RSA1024);
			break;
		case 5:
			StartThread(SignSHA1_RSA1024);
			break;
		case 6:
			StartThread(SignSHA256_RSA1024);
			break;
		case 7:
			StartThread(SignSHA384_RSA1024);
			break;
		case 8:
			StartThread(SignSHA512_RSA1024);
			break;
		case 9:
			StartThread(SignSM3_SM2);
			break;
		case 10:
			StartThread(SignRecover);
			break;
		case 0:
			goto dd;
			break;
		default:
			break;
		}
	}//while
dd:
#ifdef  OS_WINDOWS
	DeleteCriticalSection(&critial_section);
#else
	pthread_mutex_destroy(&linux_mutex);
#endif
}


