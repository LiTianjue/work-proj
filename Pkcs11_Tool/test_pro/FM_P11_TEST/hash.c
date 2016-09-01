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

void StartThread(void * pParam);
extern CK_BBOOL g_ifthread;
extern CK_BBOOL g_ifpt;

#ifdef  OS_WINDOWS
CRITICAL_SECTION critial_section;
#else
pthread_mutex_t  linux_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

FLAG MD2Test();
FLAG MD5Test();
FLAG SHA1Test();
FLAG SHA256Test();
FLAG SHA384Test();
FLAG SHA512Test();
FLAG SM3Test();

#ifdef OS_LINUX
FLAG (*hash_func[])() = {MD2Test, MD5Test, SHA1Test, SHA256Test, SHA384Test, SHA512Test, SM3Test};
#endif

void PrintData(CK_BYTE_PTR p, CK_ULONG len)
{
	CK_ULONG i = 0;
	for (i=0; i<len; i++)
	{
		if (i%16 ==0)
		{
			printf("\n");
		}
		printf("%02x, ", p[i]);
	}
	printf("\n");
}

FLAG MD2Test()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_ULONG length = 0;
	CK_MECHANISM mMD2 = {CKM_MD2, NULL_PTR, 0};
	CK_BYTE_PTR indata = NULL;
	CK_BYTE outdata[16] = {0x00};
	CK_BYTE temp[16] = {0x00};
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;
	CK_ULONG times = 0;
	CK_ULONG i = 0;

	if (!g_ifthread)
	{
		printf("please input MD2 data length:\n");
		scanf("%d", &length);
	}
	else
	{
		length = 12378;
	}
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("MD2Test->malloc\n");
		return -1;
	}
	
	memset(indata, 0x43, length);
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_DigestInit(hSession, &mMD2);
//	rv = C_GenerateRandom(hSession, indata, length);
	rv = C_Digest(hSession, indata, length, outdata, &outlength);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);


	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_DigestInit(hSession, &mMD2);
	times = length / 1024; //deal with 1K data each time
	for (i=0; i<times; i++)
	{
		rv = C_DigestUpdate(hSession, &indata[i*1024], 1024);
	}
	rv = C_DigestUpdate(hSession, &indata[times*1024], (length%1024));
	rv = C_DigestFinal(hSession, temp, &templength);
	if (memcmp(outdata, temp, templength) == 0 && outlength == 16 && templength == 16)
	{
		if (g_ifthread)
		{
#ifdef  OS_WINDOWS
			EnterCriticalSection(&critial_section);
#else
			pthread_mutex_lock(&linux_mutex);
#endif

		}
		
		printf("MD2 OK!\n");
		PrintData(outdata, outlength);
		if (g_ifthread)
		{
#ifdef	OS_WINDOWS
			LeaveCriticalSection(&critial_section);	
#else
			pthread_mutex_unlock(&linux_mutex);
#endif
			
		}
		
	}
	else
	{
		printf("MD2 ERROR!\n");
	}
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	free(indata);
	return 0;
}

FLAG MD5Test()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_ULONG length = 0;
	CK_MECHANISM mMD5 = {CKM_MD5, NULL_PTR, 0};
	CK_BYTE_PTR indata = NULL;
	CK_BYTE outdata[16] = {0x00};
	CK_BYTE temp[16] = {0x00};
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;
	CK_ULONG times = 0;
	CK_ULONG i = 0;

	CK_OBJECT_HANDLE hSM1Key = 0;
	CK_MECHANISM mSM1GenKey = {CKM_AES_CBC, NULL_PTR, 0};
	CK_ULONG SM1KeyClass = CKO_SECRET_KEY;
	CK_BBOOL isTrue = FALSE;
	CK_BYTE SM1KeyValue[] = {
		0xc4, 0xcc, 0x56, 0x3a, 0x51, 0xe9, 0xa1, 0x49, 0xe5, 0x9b,
		0xda, 0x94, 0x9c, 0x3f, 0xbb, 0xfb
	};

	CK_ATTRIBUTE aSM1Key[] = {
		{CKA_CLASS, &SM1KeyClass, sizeof(SM1KeyClass)},
		{CKA_VALUE, SM1KeyValue, sizeof(SM1KeyValue)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
						};
	
	if (!g_ifthread)
	{
		printf("please input MD5 data length:\n");
		scanf("%d", &length);
	}
	else
	{
		length = 32156;
	}
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("MD5Test->malloc\n");
		return -1;
	}
	
	memset(indata, 0x23, length);
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_DigestInit(hSession, &mMD5);
//	rv = C_GenerateRandom(hSession, indata, length);
	rv = C_Digest(hSession, indata, length, outdata, &outlength);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_DigestInit(hSession, &mMD5);
	times = length / 1024; //deal with 1K data each time
	for (i=0; i<times; i++)
	{
		rv = C_DigestUpdate(hSession, &indata[i*1024], 1024);
	}
	rv = C_DigestUpdate(hSession, &indata[times*1024], (length%1024));
	rv = C_DigestFinal(hSession, temp, &templength);
	if (memcmp(outdata, temp, templength) == 0 && outlength == 16 && templength == 16)
	{
		if (g_ifthread)
		{
#ifdef  OS_WINDOWS
			EnterCriticalSection(&critial_section);
#else
			pthread_mutex_lock(&linux_mutex);
#endif
			
		}
		
		printf("\nMD5 OK!");
		PrintData(outdata, outlength);
		if (g_ifthread)
		{
#ifdef  OS_WINDOWS
			LeaveCriticalSection(&critial_section);	
#else
			pthread_mutex_unlock(&linux_mutex);
#endif
			
		}
	}
	else
	{
		printf("\nMD5 ERROR!\n");
	}
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	free(indata);

	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	
	rv = C_GenerateKey(hSession, &mSM1GenKey, aSM1Key, 3, &hSM1Key);
	
	rv = C_DigestInit(hSession, &mMD5);
	
	rv = C_DigestKey(hSession, hSM1Key);
	
	rv = C_DigestFinal(hSession, outdata, &outlength);

	if(rv == 0)
	{
		if (g_ifthread)
		{
#ifdef  OS_WINDOWS
			EnterCriticalSection(&critial_section);
#else
			pthread_mutex_lock(&linux_mutex);
#endif
			
		}
		
		printf("\nMD5 C_DigestKey OK!");
		PrintData(outdata, outlength);
		if (g_ifthread)
		{
#ifdef  OS_WINDOWS
			LeaveCriticalSection(&critial_section);	
#else
			pthread_mutex_unlock(&linux_mutex);
#endif
			
		}
	}
	else
	{
		printf("\nMD5 C_DigestKey ERROR!\n");
	}
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);
	return 0;
}

FLAG SHA1Test()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_ULONG length = 0;
	CK_MECHANISM mSHA1 = {CKM_SHA_1, NULL_PTR, 0};
	CK_BYTE_PTR indata = NULL;
	CK_BYTE outdata[20] = {0x00};
	CK_BYTE temp[20] = {0x00};
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;
	CK_ULONG times = 0;
	CK_ULONG i = 0;
	
	if (!g_ifthread)
	{
		printf("please input SHA1 data length:\n");
		scanf("%d", &length);
	}
	else
	{
		length = 7856;
	}
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("SHA1Test->malloc\n");
		return -1;
	}
	
	memset(indata, 0x11, length);
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_DigestInit(hSession, &mSHA1);
//	rv = C_GenerateRandom(hSession, indata, length);
	rv = C_Digest(hSession, indata, length, outdata, &outlength);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_DigestInit(hSession, &mSHA1);
	times = length / 1024; //deal with 1K data each time
	for (i=0; i<times; i++)
	{
		rv = C_DigestUpdate(hSession, &indata[i*1024], 1024);
	}
	rv = C_DigestUpdate(hSession, &indata[times*1024], (length%1024));
	rv = C_DigestFinal(hSession, temp, &templength);
	if (memcmp(outdata, temp, templength) == 0 && outlength == 20 && templength == 20)
	{
		if (g_ifthread)
		{
#ifdef  OS_WINDOWS
			EnterCriticalSection(&critial_section);
#else
			pthread_mutex_lock(&linux_mutex);
#endif
		}
		
		printf("SHA1 OK!\n");
		PrintData(outdata, outlength);
		if (g_ifthread)
		{
#ifdef  OS_WINDOWS
			LeaveCriticalSection(&critial_section);	
#else
			pthread_mutex_unlock(&linux_mutex);
#endif	
		}
	}
	else
	{
		printf("SHA1 ERROR!\n");
	}
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	free(indata);
	return 0;
}

FLAG SHA256Test()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_ULONG length = 0;
	CK_MECHANISM mSHA256 = {CKM_SHA256, NULL_PTR, 0};
	CK_BYTE_PTR indata = NULL;
	CK_BYTE outdata[32] = {0x00};
	CK_BYTE temp[32] = {0x00};
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;
	CK_ULONG times = 0;
	CK_ULONG i = 0;
	
	if (!g_ifthread)
	{
		printf("please input SHA256 data length:\n");
		scanf("%d", &length);
	}
	else
		length = 234;
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("SHA256Test->malloc\n");
		return -1;
	}
	
	memset(indata, 0xcd, length);
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_DigestInit(hSession, &mSHA256);
//	rv = C_GenerateRandom(hSession, indata, length);
	rv = C_Digest(hSession, indata, length, outdata, &outlength);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_DigestInit(hSession, &mSHA256);
	times = length / 1024; //deal with 1K data each time
	for (i=0; i<times; i++)
	{
		rv = C_DigestUpdate(hSession, &indata[i*1024], 1024);
	}
	rv = C_DigestUpdate(hSession, &indata[times*1024], (length%1024));
	rv = C_DigestFinal(hSession, temp, &templength);
	if (memcmp(outdata, temp, templength) == 0 && outlength == 32 && templength == 32)
	{
		if (g_ifthread)
		{
#ifdef  OS_WINDOWS
			EnterCriticalSection(&critial_section);
#else
			pthread_mutex_lock(&linux_mutex);
#endif
		}
		
		printf("SHA256 OK!\n");
		PrintData(outdata, outlength);
		if (g_ifthread)
		{
#ifdef  OS_WINDOWS
			LeaveCriticalSection(&critial_section);	
#else
			pthread_mutex_unlock(&linux_mutex);
#endif		
		}
	}
	else
	{
		printf("SHA256 ERROR!\n");
	}
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	free(indata);
	return 0;
}

FLAG SHA384Test()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_ULONG length = 0;
	CK_MECHANISM mSHA384 = {CKM_SHA384, NULL_PTR, 0};
	CK_BYTE_PTR indata = NULL;
	CK_BYTE outdata[48] = {0x00};
	CK_BYTE temp[48] = {0x00};
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;
	CK_ULONG times = 0;
	CK_ULONG i = 0;
	
	if (!g_ifthread)
	{
		printf("please input SHA384 data length:\n");
		scanf("%d", &length);
	}
	else
	{
		length = 123;
	}
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("SHA384Test->malloc\n");
		return -1;
	}
	
	memset(indata, 0x23, length);
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_DigestInit(hSession, &mSHA384);
//	rv = C_GenerateRandom(hSession, indata, length);
	rv = C_Digest(hSession, indata, length, outdata, &outlength);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_DigestInit(hSession, &mSHA384);
	times = length / 1024; //deal with 1K data each time
	if (times >= 1)
	{
		for (i=0; i<times; i++)
		{
			rv = C_DigestUpdate(hSession, &indata[i*1024], 1024);
		}
	}	
	rv = C_DigestUpdate(hSession, &indata[times*1024], (length%1024));
	rv = C_DigestFinal(hSession, temp, &templength);
	if (memcmp(outdata, temp, templength) == 0 && outlength == 48 && templength == 48)
	{
		if (g_ifthread)
		{
#ifdef  OS_WINDOWS
			EnterCriticalSection(&critial_section);
#else
			pthread_mutex_lock(&linux_mutex);
#endif	
		}
		
		printf("SHA384 OK!\n");
		PrintData(outdata, outlength);
		if (g_ifthread)
		{
#ifdef  OS_WINDOWS
			LeaveCriticalSection(&critial_section);	
#else
			pthread_mutex_unlock(&linux_mutex);
#endif		
		}
	}
	else
	{
		printf("SHA384 ERROR!\n");
	}
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	free(indata);
	return 0;
}

FLAG SHA512Test()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_ULONG length = 0;
	CK_MECHANISM mSHA512 = {CKM_SHA512, NULL_PTR, 0};
	CK_BYTE_PTR indata = NULL;
	CK_BYTE outdata[64] = {0x00};
	CK_BYTE temp[64] = {0x00};
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;
	CK_ULONG times = 0;
	CK_ULONG i = 0;
	
	if (!g_ifthread)
	{
		printf("please input SHA512 data length:\n");
		scanf("%d", &length);
	}
	else
		length = 3456;
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("SHA512Test->malloc\n");
		return -1;
	}
	
	memset(indata, 0xe4, length);
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_DigestInit(hSession, &mSHA512);
//	rv = C_GenerateRandom(hSession, indata, length);
	rv = C_Digest(hSession, indata, length, outdata, &outlength);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_DigestInit(hSession, &mSHA512);
	times = length / 1024; //deal with 1K data each time
	if (times >= 1)
	{
		for (i=0; i<times; i++)
		{
			rv = C_DigestUpdate(hSession, &indata[i*1024], 1024);
		}
	}	
	rv = C_DigestUpdate(hSession, &indata[times*1024], (length%1024));
	rv = C_DigestFinal(hSession, temp, &templength);
	if (memcmp(outdata, temp, templength) == 0 && outlength == 64 && templength == 64)
	{
		if (g_ifthread)
		{
#ifdef  OS_WINDOWS
			EnterCriticalSection(&critial_section);
#else
			pthread_mutex_lock(&linux_mutex);
#endif	
		}
		
		printf("SHA512 OK!\n");
		PrintData(outdata, outlength);
		if (g_ifthread)
		{
#ifdef  OS_WINDOWS
			LeaveCriticalSection(&critial_section);	
#else
			pthread_mutex_unlock(&linux_mutex);
#endif		
		}
	}
	else
	{
		printf("SHA512 ERROR!\n");
	}
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	free(indata);
	return 0;
}

FLAG SM3Test()
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_ULONG length = 0;
	CK_MECHANISM mSM3 = {CKM_SM3, NULL_PTR, 0};
	CK_BYTE_PTR indata = NULL;
	CK_BYTE outdata[32] = {0x00};
	CK_BYTE temp[32] = {0x00};
	CK_ULONG outlength = 0;
	CK_ULONG templength = 0;
	CK_ULONG times = 0;
	CK_ULONG i = 0;
	
	if (!g_ifthread)
	{
		printf("please input SM3 data length:\n");
		scanf("%d", &length);
	}
	else
		length = 123;
	indata = (CK_BYTE_PTR)malloc(length);
	if (indata == NULL)
	{
		printf("SM3Test->malloc\n");
		return -1;
	}
	
	memset(indata, 0xdd, length);
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_DigestInit(hSession, &mSM3);
//	rv = C_GenerateRandom(hSession, indata, length);
	rv = C_Digest(hSession, indata, length, outdata, &outlength);
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	
	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	rv = C_DigestInit(hSession, &mSM3);
	times = length / 1024; //deal with 1K data each time
	if (times >= 1)
	{
		for (i=0; i<times; i++)
		{
			rv = C_DigestUpdate(hSession, &indata[i*1024], 1024);
		}
	}	
	rv = C_DigestUpdate(hSession, &indata[times*1024], (length%1024));
	rv = C_DigestFinal(hSession, temp, &templength);
	if (memcmp(outdata, temp, templength) == 0 && outlength == 32 && templength == 32)
	{
		if (g_ifthread)
		{
#ifdef  OS_WINDOWS
			EnterCriticalSection(&critial_section);
#else
			pthread_mutex_lock(&linux_mutex);
#endif	
		}
		
		printf("SM3 OK!\n");
		PrintData(outdata, outlength);
		if (g_ifthread)
		{
#ifdef  OS_WINDOWS
			LeaveCriticalSection(&critial_section);	
#else
			pthread_mutex_unlock(&linux_mutex);
#endif	
		}
	}
	else
	{
		printf("SM3 ERROR!\n");
	}
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	rv = C_CloseSession(hSession);

	free(indata);
	return 0;
}

void Hash()
{
	CK_ULONG id = 0;
	while (1)
	{
		printf("##############################################\n");
		printf("#  1. MD2                  5. SHA_384        #\n");
		printf("#  2. MD5                  6. SHA_512        #\n");
		printf("#  3. SHA_1                7. SM3            #\n");
		printf("#  4. SHA_256              0. EXIT           #\n");
		printf("##############################################\n");
		printf("\n");
		printf("Please select:");
		scanf("%d", &id);

		switch (id)
		{
		case 1:
			MD2Test();
			break;
		case 2:
			MD5Test();
			break;
		case 3:
			SHA1Test();
			break;
		case 4:
			SHA256Test();
			break;
		case 5:
			SHA384Test();
			break;
		case 6:
			SHA512Test();
			break;
		case 7:
			SM3Test();
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
void StratProcess_h(int param)
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
				StartThread(hash_func[param]);
			}else
			{
			    hash_func[param]();
			}
			exit(0);
		}
	}
	
}

void HashProcess()
{
	CK_ULONG id = 0;
	g_ifthread = 1;
	while (1)
	{
		printf("##############################################\n");
		printf("#  1. MD2                  5. SHA_384        #\n");
		printf("#  2. MD5                  6. SHA_512        #\n");
		printf("#  3. SHA_1                7. SM3            #\n");
		printf("#  4. SHA_256              0. EXIT           #\n");
		printf("##############################################\n");
		printf("\n");
		printf("Please select:");
		scanf("%d", &id);
		
		switch (id)
		{
		case 1:
            StratProcess_h(0);			
			break;
		case 2:
			StratProcess_h(1);
			break;
		case 3:
			StratProcess_h(2);
			break;
		case 4:
			StratProcess_h(3);
			break;
		case 5:
			StratProcess_h(4);
			break;
		case 6:
			StratProcess_h(5);
			break;
		case 7:
			StratProcess_h(6);
			break;
		case 0:
			return;
			break;
		default:
			break;
		}//switch
	}//while
	g_ifthread = 0;
}
#endif

void HashThread()
{
	CK_ULONG id = 0;
#ifdef  OS_WINDOWS
	InitializeCriticalSection(&critial_section);
#else
	pthread_mutex_init(&linux_mutex, NULL);
#endif
	
	while (1)
	{
		printf("##############################################\n");
		printf("#  1. MD2                  5. SHA_384        #\n");
		printf("#  2. MD5                  6. SHA_512        #\n");
		printf("#  3. SHA_1                7. SM3            #\n");
		printf("#  4. SHA_256              0. EXIT           #\n");
		printf("##############################################\n");
		printf("\n");
		printf("Please select:");
		scanf("%d", &id);
		
		switch (id)
		{
		case 1:
			StartThread(MD2Test);
			break;
		case 2:
			StartThread(MD5Test);
			break;
		case 3:
			StartThread(SHA1Test);
			break;
		case 4:
			StartThread(SHA256Test);
			break;
		case 5:
			StartThread(SHA384Test);
			break;
		case 6:
			StartThread(SHA512Test);
			break;
		case 7:
			StartThread(SM3Test);
			break;
		case 0:
			return;
			break;
		default:
			break;
		}//switch
	}//while
#ifdef  OS_WINDOWS
	DeleteCriticalSection(&critial_section);
#else
	pthread_mutex_destroy(&linux_mutex);
#endif
	
}

#ifdef OS_WINDOWS
void HashSpeedTest(CK_MECHANISM_PTR pHash, CK_BYTE_PTR pName)
{
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_OBJECT_HANDLE hKey = 0;
	CK_ULONG KeyClass = CKO_SECRET_KEY;
	CK_BBOOL isTrue = FALSE;
	CK_ULONG i = 0;
	
	CK_BYTE indata[1024] = {0x00};
	CK_BYTE hash[64] = {0x00};
	CK_ULONG hashlength = 0;


	LARGE_INTEGER Frequency;
	LARGE_INTEGER StartNum;
	LARGE_INTEGER EndNum;
	double Second = 0;

	memset(indata, 0x22, 1024);
	memset(hash, 0x00, 64);
	rv = C_OpenSession(SlotId, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	QueryPerformanceFrequency(&Frequency);
	QueryPerformanceCounter(&StartNum);
	for (i=0; i<LOOPTIMES; i++)
	{
		C_DigestInit(hSession, pHash);
		C_Digest(hSession, indata, 1024, hash, &hashlength);
	}
	QueryPerformanceCounter(&EndNum);
	Second = (double)(((EndNum.QuadPart - StartNum.QuadPart)+0.0)/Frequency.QuadPart);
	printf("%s Digest Speed is %02fMB/s\n", pName, (0.0+LOOPTIMES)/(1024*Second));
#ifdef DEVICE_KEY
	C_Logout(hSession);
#endif
	C_CloseSession(hSession);

}

void HashSpeed()
{
	CK_ULONG id = 0;
	CK_MECHANISM mHash = {0, NULL_PTR, 0};
	while (1)
	{
		printf("##############################################\n");
		printf("#  1. MD2                  5. SHA_384        #\n");
		printf("#  2. MD5                  6. SHA_512        #\n");
		printf("#  3. SHA_1                7. SM3            #\n");
		printf("#  4. SHA_256              0. EXIT           #\n");
		printf("##############################################\n");
		printf("\n");
		printf("Please select:");
		scanf("%d", &id);
		
		switch (id)
		{
		case 1:
			mHash.mechanism = CKM_MD2;
			HashSpeedTest(&mHash, "MD2");
			break;
		case 2:
			mHash.mechanism = CKM_MD5;
			HashSpeedTest(&mHash, "MD5");
			break;
		case 3:
			mHash.mechanism = CKM_SHA_1;
			HashSpeedTest(&mHash, "SHA1");
			break;
		case 4:
			mHash.mechanism = CKM_SHA256;
			HashSpeedTest(&mHash, "SHA256");
			break;
		case 5:
			mHash.mechanism = CKM_SHA384;
			HashSpeedTest(&mHash, "SHA384");
			break;
		case 6:
			mHash.mechanism = CKM_SHA512;
			HashSpeedTest(&mHash, "SHA512");
			break;
		case 7:
			mHash.mechanism = CKM_SM3;
			HashSpeedTest(&mHash, "SM3");
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

