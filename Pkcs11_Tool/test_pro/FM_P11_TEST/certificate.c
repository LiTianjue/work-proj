#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#include "pkcs11.h"
#include "fmpkcs11.h"
#include "pkcs11s.h"
#include "g_head.h"


extern CK_BBOOL g_CertificateFlag;
extern void PrintData(CK_BYTE_PTR p, CK_ULONG len);

CK_RV CreateCertificate()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	FILE *pfile = NULL;
	CK_ULONG ObjectClass = CKO_CERTIFICATE;
	CK_BBOOL isTrue = TRUE;
	CK_BYTE buffer[3000] = {0x00};
	CK_ULONG CertificateLen = 0;
	CK_OBJECT_HANDLE hCertificate = 0;

	CK_ATTRIBUTE aCertificate[] = {
		{CKA_CLASS, &ObjectClass, sizeof(ObjectClass)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)},
		{CKA_VALUE, NULL_PTR, 0}
								};
	
	if (g_CertificateFlag == 0)
	{
		rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
		C_Login(hSession, CKU_SO, "11111111", 8);
#endif
		pfile = fopen("cer.cer", "rb");
		if (!pfile)
		{
			printf("Open Certificate ERROR!\n");
			return -1;
		}
		CertificateLen = fread(buffer, 1, 3000, pfile);
		fclose(pfile);
	
		
		aCertificate[2].pValue = (CK_BYTE_PTR)malloc(CertificateLen);
		if (aCertificate[2].pValue == NULL)
		{
			printf("CreateCertificate->malloc ERROR!\n");
			return -1;
		}
		memcpy(aCertificate[2].pValue, buffer, CertificateLen);
		aCertificate[2].ulValueLen = CertificateLen;

		rv = C_CreateObject(hSession, aCertificate, 3, &hCertificate);
		if (rv == 0)
		{
			printf("Have Created Certificate Object!\n");
		}
		else
		{
			printf("Create Certificate Object ERROR!\n");
		}
		
		free(aCertificate[2].pValue);
#ifdef DEVICE_KEY
		C_Logout(hSession);
#endif
		C_CloseSession(hSession);
		g_CertificateFlag = 1;
	}
	else
	{
		printf("Certificate Objects Have Been Created!\n");
		printf("Please select '11' in main menu!\n");
	}
	return 0;
}

CK_RV TestCertificate()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	FILE *pfile = NULL;
	CK_ULONG ObjectClass = CKO_CERTIFICATE;
	CK_BBOOL isTrue = TRUE;
	CK_BYTE buffer[3000] = {0x00};
	CK_ULONG CertificateLen = 0;
	CK_OBJECT_HANDLE hCertificate = 0;
	CK_ULONG hCertificateCounter = 0;

	CK_ATTRIBUTE aCertificate[] = {
		{CKA_CLASS, &ObjectClass, sizeof(ObjectClass)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)},
		{CKA_VALUE, NULL_PTR, 0}
	};
	
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	pfile = fopen("cer.cer", "rb");
	if (!pfile)
	{
		printf("Open Certificate ERROR!\n");
		return -1;
	}
	CertificateLen = fread(buffer, 1, 3000, pfile);
	fclose(pfile);
	
	
	aCertificate[2].pValue = (CK_BYTE_PTR)malloc(CertificateLen);
	if (aCertificate[2].pValue == NULL)
	{
		printf("CreateCertificate->malloc ERROR!\n");
		return -1;
	}
	memcpy(aCertificate[2].pValue, buffer, CertificateLen);
	aCertificate[2].ulValueLen = CertificateLen;
	
	rv = C_FindObjectsInit(hSession, aCertificate, 3);
	rv = C_FindObjects(hSession, &hCertificate, 1, &hCertificateCounter);
	if (rv == 0 && hCertificateCounter == 1)
	{
		printf("Find Certificate Object OK!\n");
	}
	else
	{
		printf("Find Certificate Object ERROR!\n");
		if (g_CertificateFlag == 0)
		{
			printf("Certificate Objects Have not Been Created!\n");
			printf("Please select '11' in main menu!\n");
		}
	}


	free(aCertificate[2].pValue);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);
	return 0;
}

