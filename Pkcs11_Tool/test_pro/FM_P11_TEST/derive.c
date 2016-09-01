#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include <stdlib.h>

#include "pkcs11.h"
#include "fmpkcs11.h"
#include "pkcs11s.h"
#include "g_head.h"

#ifdef  OS_WINDOWS
#include <windows.h>
#endif

extern void FreeAttribute(CK_ATTRIBUTE_PTR attribute, CK_ULONG num);

CK_RV DeriveTest()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_BBOOL isTrue = TRUE;
	CK_BBOOL isFalse = FALSE;
    CK_ULONG length = 48;
	CK_OBJECT_HANDLE hSM1Key = 0;
	CK_OBJECT_HANDLE hNewSM1Key = 0;
	CK_MECHANISM mSM1GenKey = {CKM_SSL3_PRE_MASTER_KEY_GEN, NULL_PTR, 0};
	CK_ULONG SM1KeyClass = CKO_SECRET_KEY;
	CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR ssl3 = NULL;
	CK_MECHANISM mDeriveRSAKey; 
	CK_ATTRIBUTE aSM1Key[] = {
		{CKA_CLASS, &SM1KeyClass, sizeof(SM1KeyClass)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
	};
	
	CK_BYTE uClientRandom[] = {
		0xc4, 0xcc, 0x56, 0x3a, 0x51, 0xe9, 0xa1, 0x49, 0xe5, 0x9b,
			0xda, 0x94, 0x9c, 0x3f, 0xbb, 0xfb, 0x29, 0x41, 0x97, 0x5e,
			0xf4, 0x6d, 0xef, 0xc4, 0x07, 0xf9, 0x05, 0xd2, 0x67, 0x1c,
			0xff, 0x87, 0x4a, 0x91, 0xe3, 0xb8, 0x49, 0x5d, 0x8d, 0x5f,
			0x78, 0x67, 0xbb, 0x2c, 0x1a, 0x96, 0x5d, 0x32
	};
    CK_BYTE uServerRandom[] = {
		0x9f, 0x54, 0x1b, 0xdf, 0x9d, 0x9f, 0xbb, 0xf0, 0x3b, 0x0f,
			0xe2, 0x78, 0x7c, 0xc3, 0xf0, 0xea, 0x58, 0x2d, 0x7d, 0x62,
			0xe8, 0x1b, 0xf5, 0x89, 0x4d, 0x37, 0x24, 0xaa, 0x82, 0xc6,
			0xec, 0x6e, 0x59, 0x46, 0x22, 0x0a, 0x7a, 0x83, 0x5e, 0x48,
			0xd4, 0x0f, 0x8f, 0x6f, 0x16, 0x9b, 0x74, 0x1a
	};
	
	ssl3 = malloc(sizeof(CK_SSL3_MASTER_KEY_DERIVE_PARAMS));
	ssl3->pVersion= malloc(sizeof(CK_VERSION));
	ssl3->RandomInfo.pClientRandom =malloc(length);
    ssl3->RandomInfo.pServerRandom =malloc(length);
	
	ssl3->pVersion->major = '1';
	ssl3->pVersion->minor = '0';

 	memcpy(ssl3->RandomInfo.pClientRandom,uServerRandom,sizeof(uServerRandom));
	ssl3->RandomInfo.ulClientRandomLen = length;
 	memcpy(ssl3->RandomInfo.pServerRandom,uServerRandom,sizeof(uServerRandom));
	ssl3->RandomInfo.ulServerRandomLen = length;

	mDeriveRSAKey.mechanism = CKM_SSL3_MASTER_KEY_DERIVE;
	mDeriveRSAKey.pParameter = ssl3;
	mDeriveRSAKey.ulParameterLen = sizeof(ssl3);

	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_GenerateKey(hSession, &mSM1GenKey, aSM1Key, 2, &hSM1Key);

	rv = C_DeriveKey(hSession, &mDeriveRSAKey, hSM1Key, aSM1Key, 2, &hNewSM1Key);
	if (rv != 0)
	{
		printf("C_DeriveKey ERROR\n");
	}
	else
	{
		printf("C_DeriveKey OK\n");
	}

	free(ssl3->pVersion);
	free(ssl3->RandomInfo.pClientRandom);
	free(ssl3->RandomInfo.pServerRandom);
	free(ssl3);
	
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);

	return 0;
}	


