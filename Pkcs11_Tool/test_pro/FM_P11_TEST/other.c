#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include <string.h>
#include "pkcs11.h"
#include "fmpkcs11.h"
#include "pkcs11s.h"
#include "g_head.h"

CK_RV OtherTest()
{
	CK_RV rv = 0;
	CK_INFO Info;
	CK_FUNCTION_LIST_PTR pFunctionList = NULL;
	CK_ULONG SlotCounter = 0;
	CK_SLOT_ID_PTR pSlotList = NULL;
	CK_SLOT_INFO SlotInfo;
	CK_TOKEN_INFO TokenInfo;
	CK_ULONG Counter = 0;
	CK_SLOT_ID SlotId = 0;
	CK_MECHANISM_TYPE_PTR pMechanism = NULL;

	rv = C_GetInfo(&Info);
	if (rv == 0)
	{
		printf("C_GetInfo OK!\n");
	}
	else
	{
		printf("C_GetInfo ERROR!\n");
	}

	rv = C_GetFunctionList(&pFunctionList);
	if (rv == 0)
	{
		printf("C_GetFunctionList OK!\n");
	}
	else
	{
		printf("C_GetFunctionList ERROR!\n");
	}

	rv = C_GetSlotList(TRUE, NULL_PTR, &SlotCounter);
	if (rv == 0 && SlotCounter>0)
	{
		pSlotList = malloc(SlotCounter * sizeof(CK_SLOT_ID));
		if (pSlotList == NULL)
		{
			printf("C_GetSlotList->malloc ERROR!\n");
		}
		else
		{
			rv = C_GetSlotList(TRUE, pSlotList, &SlotCounter);
			if (rv == 0)
			{
				printf("C_GetSlotList OK!\n");
			}
			else
			{
				printf("C_GetSlotList ERROR!\n");
			}
		}
		
	}

	rv = C_GetSlotInfo(pSlotList[0], &SlotInfo);
	if (rv == 0)
	{
		printf("C_GetSlotInfo OK!\n");
	}
	else
	{
		printf("C_GetSlotInfo ERROR!\n");
	}

	rv = C_GetTokenInfo(pSlotList[0], &TokenInfo);
	if (rv == 0)
	{
		printf("C_GetTokenInfo OK!\n");
	}
	else
	{
		printf("C_GetTokenInfo ERROR!\n");
	}
	
	rv = C_GetMechanismList(SlotId, NULL_PTR, &Counter);
	if (rv == 0 && Counter > 0)
	{
		pMechanism = malloc(Counter * sizeof(CK_MECHANISM_TYPE));
		if (pMechanism == NULL)
		{
			printf("C_GetMechanismList->malloc ERROR!\n");
		}
		else
		{
			rv = C_GetMechanismList(SlotId, pMechanism, &Counter);
			if (rv == 0)
			{
				printf("C_GetMechanismList OK!\n");
			}
			else
			{
				printf("C_GetMechanismList ERROR!\n");
			}
		}
	}



	free(pMechanism);
	free(pSlotList);
	return 0;
}

void tool()
{
	int slotcount = 0;
	int rv = 0;
	CK_SLOT_ID slotid;
	int id = 0;
	CK_SESSION_HANDLE hsession;
	//CK_SESSION_INFO sessioninfo;
	CK_BYTE publabel[] = "RSA_PUBLIC_KEY_1";
	CK_BYTE prilabel[] = "RSA_PRIVATE_KEY_1";
	CK_ULONG objectclass = CKO_PRIVATE_KEY;
	CK_ULONG keytype = CKK_RSA;
	CK_BBOOL isTrue = TRUE;
	CK_ATTRIBUTE temp1[] = {
		{CKA_LABEL, publabel, strlen(publabel)}
	};

	CK_ATTRIBUTE temp2[] = {
		{CKA_CLASS, &objectclass, sizeof(objectclass)},
		{CKA_LABEL, prilabel, strlen(prilabel)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)},
		{CKA_KEY_TYPE, &keytype, sizeof(keytype)}
	};

	CK_BYTE mod[128] = {0x00};
	CK_BYTE e[4] = {0x00};


	CK_ATTRIBUTE find[] = {
		{CKA_MODULUS, mod, 128},
		{CKA_PUBLIC_EXPONENT, e, 4}
	};

	CK_OBJECT_HANDLE rsapub1;
	//CK_OBJECT_HANDLE rsapri1;
	CK_ULONG reccount = 0;

	rv = C_GetSlotList(FALSE, NULL, &slotcount);
	if (rv != 0)
	{
		printf("ERROR C_GetSlotList\n");
	}
	rv = C_GetSlotList(FALSE, &slotid, &slotcount);
	if (rv != 0)
	{
		printf("ERROR C_GetSlotList\n");
	}
//	C_OpenSession(id, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL, NULL, &hsession);
//	C_GetSessionInfo(hsession, &sessioninfo);
//	C_CloseSession(hsession);

	rv = C_OpenSession(id, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL, NULL, &hsession);
	if (rv != 0)
	{
		printf("ERROR C_OpenSession rv = %08x\n", rv);
	}
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
 	rv = C_FindObjectsInit(hsession, temp1, 1);
 	if (rv != 0)
 	{
 		printf("ERROR C_FindObjectsInit\n");
 	}

	rv = C_FindObjects(hsession, &rsapub1, 1, &reccount);
	if (rv != 0)
	{
		printf("ERROR C_FindObjects\n");
 	}

 	rv = C_FindObjectsFinal(hsession);
	if (rv != 0)
	{
		printf("ERROR C_FindObjectsFinal\n");
 	}
/*
 	C_FindObjectsInit(hsession, temp2, 4);
 	C_FindObjects(hsession, &rsapri1, 1, &reccount);
 	C_FindObjectsFinal(hsession);

	C_GetAttributeValue(hsession, rsapri1, find, 2);
*/
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hsession);
	if (rv != 0)
	{
		printf("ERROR C_CloseSession rv = %08x\n", rv);
	}
}
