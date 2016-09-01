#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <stdlib.h>


#include "pkcs11.h"
#include "fmpkcs11.h"
#include "pkcs11s.h"
#include "g_head.h"

#ifdef  OS_WINDOWS
#include <windows.h>
#endif

extern CK_BBOOL g_DataFlag;

CK_RV CreateData()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_ULONG ObjectClass = CKO_DATA;
	CK_OBJECT_HANDLE hData1 = 0;
	CK_OBJECT_HANDLE hData2 = 0;
	CK_OBJECT_HANDLE hData3 = 0;
	CK_BYTE Label[] = "this is a data object!";
	CK_BYTE Id1[] = "ypf1";
	CK_BYTE Id2[] = "ypf2";
	CK_BYTE Id3[] = "ypf3";
	CK_BYTE Value[] = "1234567890";
	CK_BBOOL isTure = TRUE;

	CK_ATTRIBUTE aData1[] = {
		{CKA_CLASS, &ObjectClass, sizeof(ObjectClass)},
		{CKA_LABEL, &Label, strlen(Label)},
		{CKA_VALUE, &Value, strlen(Value)},
		{CKA_ID, &Id1, strlen(Id1)},
		{CKA_TOKEN, &isTure, sizeof(isTure)}
							};
	CK_ATTRIBUTE aData2[] = {
		{CKA_CLASS, &ObjectClass, sizeof(ObjectClass)},
		{CKA_LABEL, &Label, strlen(Label)},
		{CKA_VALUE, &Value, strlen(Value)},
		{CKA_ID, &Id2, strlen(Id2)},
		{CKA_TOKEN, &isTure, sizeof(isTure)}
							};
	CK_ATTRIBUTE aData3[] = {
		{CKA_CLASS, &ObjectClass, sizeof(ObjectClass)},
		{CKA_LABEL, &Label, strlen(Label)},
		{CKA_VALUE, &Value, strlen(Value)},
		{CKA_ID, &Id3, strlen(Id3)},
		{CKA_TOKEN, &isTure, sizeof(isTure)}
							};
	
	CK_ATTRIBUTE SetData[] = {
		{CKA_CLASS, &ObjectClass, sizeof(ObjectClass)},
		{CKA_LABEL, &Label, strlen(Label)},
		{CKA_VALUE, &Value, strlen(Value)},
		{CKA_TOKEN, &isTure, sizeof(isTure)}
							};
	
	if (g_DataFlag == 0)
	{
		rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
		C_Login(hSession, CKU_SO, "11111111", 8);
#endif
		rv = C_CreateObject(hSession, aData1, 5, &hData1);
		if (rv == 0)
		{
			printf("Have Created Data1 Object!\n");
		}
		else
		{
			printf("Create Data1 Object ERROR!\n");
			return -1;
		}
		rv = C_CreateObject(hSession, aData2, 5, &hData2);
		if (rv == 0)
		{
			printf("Have Created Data2 Object!\n");
		}
		else
		{
			printf("Create Data2 Object ERROR!\n");
			return -1;
		}
		rv = C_CreateObject(hSession, aData3, 5, &hData3);
		if (rv == 0)
		{
			printf("Have Created Data3 Object!\n");
		}
		else
		{
			printf("Create Data3 Object ERROR!\n");
			return -1;
		}
		rv = C_SetAttributeValue(hSession, hData1, SetData, 3);
		if (rv == 0)
		{
			printf("Have Modified Data1 Object!\n");
		}
		else
		{
			printf("Modify Data1 Object ERROR!\n");
			return -1;
		}
		rv = C_DestroyObject(hSession, hData2);
		if (rv == 0)
		{
			printf("Have Deleted Data2 Object!\n");
		}
		else
		{
			printf("Delete Data2 Object ERROR!\n");
			return -1;
		}
		C_CloseSession(hSession);
#ifdef DEVICE_KEY
		C_Logout(hSession);
#endif
		g_DataFlag = 1;
	}
	else
	{
		printf("Data Objects Have Been Created!\n");
		printf("Please select '10' in main menu!\n");
	}
	return 0;
}

CK_RV TestData()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_ULONG ObjectClass = CKO_DATA;
	CK_OBJECT_HANDLE hData1 = 0;
	CK_OBJECT_HANDLE hData3 = 0;
	CK_ULONG hData1Counter = 0;
	CK_ULONG hData3Counter = 0;
	CK_BYTE Label[] = "this is a data object!";
	CK_BYTE Id3[] = "ypf3";
	CK_BYTE Value[] = "1234567890";
	CK_BBOOL isTure = TRUE;

	CK_ATTRIBUTE Data1[] = {
		{CKA_CLASS, &ObjectClass, sizeof(ObjectClass)},
		{CKA_LABEL, &Label, strlen(Label)},
		{CKA_VALUE, &Value, strlen(Value)},
		{CKA_TOKEN, &isTure, sizeof(isTure)}
							};

	CK_ATTRIBUTE aData3[] = {
		{CKA_CLASS, &ObjectClass, sizeof(ObjectClass)},
		{CKA_LABEL, &Label, strlen(Label)},
		{CKA_VALUE, &Value, strlen(Value)},
		{CKA_ID, &Id3, strlen(Id3)},
		{CKA_TOKEN, &isTure, sizeof(isTure)}
							};
	


	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_FindObjectsInit(hSession, Data1, 4);
	rv = C_FindObjects(hSession, &hData1, 1, &hData1Counter);
	if (rv == 0 && hData1Counter == 1)
	{
		printf("Find Data Object OK!\n");
	}
	else
	{
		printf("Find Data Object ERROR!\n");
		if (g_DataFlag == 0)
		{
			printf("Data Objects Have not Been Created!\n");
     		printf("Please select '9' in main menu!\n");
		}
		return -1;
	}
	rv = C_FindObjectsFinal(hSession);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);

		
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_FindObjectsInit(hSession, aData3, 5);
	rv = C_FindObjects(hSession, &hData3, 1, &hData3Counter);
	if (rv == 0 && hData3Counter == 1)
	{
		printf("Find Data Object OK!\n");
	}
	else
	{
		printf("Find Data Object ERROR!\n");
		if (g_DataFlag == 0)
		{
			printf("Data Objects Have not Been Created!\n");
			printf("Please select '9' in main menu!\n");
		}
		return -1;
	}
	rv = C_FindObjectsFinal(hSession);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);
	return 0;
}

