#include <stdio.h>
#include <stdlib.h>
#include "pkcs11.h"
#include "fmpkcs11.h"
#include "pkcs11s.h"
#include "g_head.h"
#if 1
//#ifdef  OS_WINDOWS
//#include <process.h>
//#include <windows.h>
//#else
#include <pthread.h>
//#endif

FLAG RSA1024Test_out();
FLAG RSA1024Test_in();
FLAG RSA2048Test_out();
FLAG RSA2048Test_in();
FLAG ECCTest_out();
FLAG ECCTest_in();

#ifdef OS_LINUX
FLAG (*func[])() = {RSA1024Test_out, RSA1024Test_in, RSA2048Test_out, RSA2048Test_in, ECCTest_out, ECCTest_in};
#endif

void DuiChen();
void DuiChenThread();
void DuiChenProcess();

void Hash();
void HashThread();
void HashProcess();

void TestWrap();
void TestWrapThread();
void TestWrapProcess();

void SignTest();
void SignTestThread();
void SignTestProcess();

extern void tool();

CK_RV CreateData();
CK_RV TestData();
CK_RV CreateCertificate();
CK_RV TestCertificate();
CK_RV DeriveTest();
CK_RV OtherTest();

#ifdef OS_WINDOWS
void RSA1024SpeedTest();
void RSA2048SpeedTest();
void ECCSpeedTest();
void DuiChenSpeed();
void HashSpeed();
#endif

CK_BBOOL g_DataFlag = 0;
CK_BBOOL g_CertificateFlag = 0;
CK_BBOOL g_ifthread = 0;
CK_BBOOL g_ifpt = 0;

void StartThread(void * pParam)
{
	CK_ULONG i = 0;
#ifdef  OS_WINDOWS
	HANDLE hThread[MAX_THREAD_NUM];
	CK_ULONG ThreadId[MAX_THREAD_NUM];


	for (i=0; i<MAX_THREAD_NUM; i++)
	{
		hThread[i] = (HANDLE)_beginthreadex(NULL, 0, pParam, NULL_PTR, 0, &ThreadId[i]);
	}

	for (i=0; i<MAX_THREAD_NUM; i++)
	{
		WaitForSingleObject(hThread[i], INFINITE);
		CloseHandle(hThread[i]);
	}
#else
	pthread_t linux_thread[MAX_THREAD_NUM];
	int rv = 0;

	for (i=0; i<MAX_THREAD_NUM; i++)
	{
		rv = pthread_create(&linux_thread[i], NULL, pParam, NULL);
		if (rv != 0)
		{
			printf("Create Thread ERROR %d!\n", i);
		}
	}
	for (i=0; i<MAX_THREAD_NUM; i++)
	{
		rv = pthread_join(linux_thread[i], NULL);
		if (rv != 0)
		{
			printf("pthread_join error\n");
		}
	}

#endif
}

#ifdef OS_LINUX
void StratProcess(int param)
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
			if (g_ifpt == 1)
			{
				StartThread(func[param]);
			}else
			{
				func[param]();
			}			
			exit(0);
		}
	}	
}
#endif

void FunctionTest()
{
	CK_ULONG id = 0;

	g_DataFlag = 0;
    g_CertificateFlag = 0;
	g_ifthread = 0;
/*	
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_ULONG ECCPubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG ECCPriKeyClass = CKO_PRIVATE_KEY;
	CK_BYTE ECCPubLabel[] = "ECC_PUBLIC_KEY_7";
	CK_BYTE ECCPriLabel[] = "ECC_PRIVATE_KEY_7";
	CK_BBOOL isFalse = FALSE;
	
	CK_ATTRIBUTE ECCPubKey[] = {
		{CKA_CLASS, &ECCPubKeyClass, sizeof(ECCPubKeyClass)},
		{CKA_LABEL, &ECCPubLabel, sizeof(ECCPubLabel)},
		{CKA_TOKEN, &isFalse, sizeof(isFalse)}
	};
	
	CK_ATTRIBUTE ECCPriKey[] = {
		{CKA_CLASS, &ECCPriKeyClass, sizeof(ECCPriKeyClass)},
		{CKA_LABEL, &ECCPriLabel, sizeof(ECCPriLabel)},
		{CKA_TOKEN, &isFalse, sizeof(isFalse)}
	CK_MECHANISM ECCGenKey = {CKM_ECDSA_KEY_PAIR_GEN, NULL_PTR, 0};
	C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
#ifdef DEVICE_KEY
	C_Login(hSession, CKU_SO, "11111111", 8);
#endif
	C_GenerateKeyPair(hSession, &ECCGenKey, ECCPubKey, 3, ECCPriKey, 3, &hECCPubKey, &hECCPriKey);
	C_CloseSession(hSession);
*/
	while (1)
	{
		printf("##############################################\n");
		printf("#          1. rsa 1024                       #\n");
		printf("#          2. rsa 2048                       #\n");
		printf("#          3. ecc test                       #\n");
		printf("#          4. duichen                        #\n");
		printf("#          5. hash                           #\n");
		printf("#          6. wrap and unwrap                #\n");
		printf("#          7. sign test                      #\n");
		printf("#          8. derive test                    #\n");
		printf("#          9. Data Object Operation          #\n");
		printf("#          10. Data Object Test              #\n");
		printf("#          11. Certificate Object Operation  #\n");
		printf("#          12. Certificate Object Test       #\n");
		printf("#          13. Other Test                    #\n");
		printf("#          14. tool                          #\n");
		printf("#          0. exit                           #\n");
		printf("##############################################\n");
		printf("\n");
		printf("Please select:");
		scanf("%d", &id);

		switch (id)
		{
		case 1:
			RSA1024Test_out();
            RSA1024Test_in();
			break;
		case 2:
			RSA2048Test_out();
            RSA2048Test_in();
			break;
		case 3:
			ECCTest_out();
            ECCTest_in();
			break;
		case 4:
			DuiChen();
			break;
		case 5:
			Hash();
			break;
		case 6:
			TestWrap();
			break;
		case 7:
			SignTest();
			break;
		case 8:
			DeriveTest();
			break;
		case 9:
			CreateData();
			break;
		case 10:
			TestData();
			break;
		case 11:
			CreateCertificate();
			break;
		case 12:
			TestCertificate();
			break;
		case 13:
			OtherTest();
			break;
		case 14:
			tool();
			break;
		case 0:
			return;
			break;
		default:
			break;			
		}
	}
}

void ThreadTest()
{
	CK_ULONG id = 0;
	
	g_ifthread = 1;
	while (1)
	{
		printf("##############################################\n");
		printf("#          1. rsa 1024                       #\n");
		printf("#          2. rsa 2048                       #\n");
		printf("#          3. ecc test                       #\n");
		printf("#          4. duichen                        #\n");
		printf("#          5. hash                           #\n");
		printf("#          6. wrap and unwrap                #\n");
		printf("#          7. sign test                      #\n");
		printf("#          8. derive test                    #\n");
		printf("#          9. tool                           #\n");
		printf("#          0. exit                           #\n");
		printf("##############################################\n");
		printf("\n");
		printf("Please select:");
		scanf("%d", &id);
		
		switch (id)
		{
		case 1:
			StartThread(RSA1024Test_out);
			break;
		case 2:
			StartThread(RSA2048Test_out);
//			StartThread(RSA2048Test_in);
			break;
		case 3:
			StartThread(ECCTest_out);
			break;
		case 4:
			DuiChenThread();
			break;
		case 5:
			HashThread();
			break;
		case 6:
			TestWrapThread();
			break;
		case 7:
			SignTestThread();
			break;
		case 8:
			StartThread(RSA1024Test_in);
			break;
		case 9:
			StartThread(tool);
			break;
		case 0:
			return;
			break;
		default:
			break;
		}
	}
	g_ifthread = 0;
}

#ifdef OS_WINDOWS
void SpeedTest()
{
	CK_ULONG id = 0;
	
	while (1)
	{
		printf("##############################################\n");
		printf("#          1. rsa                            #\n");
		printf("#          2. ecc                            #\n");
		printf("#          3. duichen                        #\n");
		printf("#          4. hash                           #\n");
		printf("#          0. exit                           #\n");
		printf("##############################################\n");
		printf("\n");
		printf("Please select:");
		scanf("%d", &id);
		
		switch (id)
		{
		case 1:
			RSA1024SpeedTest();
			RSA2048SpeedTest();
			break;
		case 2:
			ECCSpeedTest();
			break;
		case 3:
			DuiChenSpeed();
			break;
		case 4:
			HashSpeed();
			break;
		case 0:
			return;
			break;
		default:
			break;
		}
	}
}
#endif

#ifdef OS_LINUX
void ProcessTest()
{
	CK_ULONG id = 0;
	
	g_ifthread = 1;
	while (1)
	{
		printf("##############################################\n");
		printf("#          1. rsa 1024                       #\n");
		printf("#          2. rsa 2048                       #\n");
		printf("#          3. ecc test                       #\n");
		printf("#          4. duichen                        #\n");
		printf("#          5. hash                           #\n");
		printf("#          6. wrap and unwrap                #\n");
		printf("#          7. sign test                      #\n");
		printf("#          0. exit                           #\n");
		printf("##############################################\n");
		printf("\n");
		printf("Please select:");
		scanf("%d", &id);
		
		switch (id)
		{
		case 1:
			StratProcess(0);
//			StratProcess(1);
			break;
		case 2:
			StratProcess(2);
//			StratProcess(3);
			break;
		case 3:
			StratProcess(4);
//			StratProcess(5);
			break;
		case 4:
			DuiChenProcess();
			break;
		case 5:
			HashProcess();
			break;
		case 6:	
			TestWrapProcess();
        	break;
		case 7:
			SignTestProcess();
			break;
		case 0:
			return;
			break;
		default:
			break;
		}
	}
	g_ifthread = 0;
}

void ProcessAndThread()
{
	CK_ULONG id = 0;
	
	g_ifthread = 1;
	g_ifpt = 1;
	while (1)
	{
		printf("##############################################\n");
		printf("#          1. rsa 1024                       #\n");
		printf("#          2. rsa 2048                       #\n");
		printf("#          3. ecc test                       #\n");
		printf("#          4. duichen                        #\n");
		printf("#          5. hash                           #\n");
		printf("#          6. wrap and unwrap                #\n");
		printf("#          7. sign test                      #\n");
		printf("#          0. exit                           #\n");
		printf("##############################################\n");
		printf("\n");
		printf("Please select:");
		scanf("%d", &id);
		
		switch (id)
		{
		case 1:
			StratProcess(0);//1024 out
			break;
		case 2:
			StratProcess(2);//2048 out
			break;
		case 3:
			StratProcess(4);//ecc out
			break;
		case 4:
			DuiChenProcess();
			break;
		case 5:
			HashProcess();
			break;
		case 6:	
			TestWrapProcess();
			break;
		case 7:
			SignTestProcess();
			break;
		case 0:
			return;
			break;
		default:
			break;
		}
	}
	g_ifthread = 0;
    g_ifpt = 0;
}
#endif

#endif

void main()
{
	CK_ULONG id = 0;
	int rv = 0;

	rv = C_Initialize(NULL_PTR);
    if (rv != 0)
    {
		printf("initialize error\n");
		return;   //2014-6-23 初始化失败直接退出
    }

	//add by andy test

	CK_SESSION_HANDLE hSession = 0;
	CK_BYTE_PTR indata = NULL_PTR;
	CK_BYTE_PTR outdata = NULL_PTR;
	CK_BYTE_PTR temp = NULL_PTR;
	CK_ULONG length = 128;

	indata = (CK_BYTE_PTR)malloc(length);
	outdata = (CK_BYTE_PTR)malloc(length);
	temp = (CK_BYTE_PTR)malloc(length);
	//if error
	 CK_MECHANISM mGenRSAKey = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
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


#if 0
	while (1)
	{
		printf("##############################################\n");
		printf("#          1. Function Test                  #\n");
#ifdef OS_WINDOWS
		printf("#          2. Speed Test                     #\n");
#endif
		printf("#          3. Thread Test                    #\n");
#ifdef OS_LINUX
		printf("#          4. Process Test                   #\n");
		printf("#          5. Process and Thread             #\n");
#endif
		printf("#          0. exit                           #\n");
		printf("##############################################\n");
		printf("\n");
		printf("Please select:");
		scanf("%d", &id);

		switch (id)
		{
		case 1:
			FunctionTest();
			break;
#ifdef OS_WINDOWS
		case 2:
			SpeedTest();
			break;
#endif
		case 3:
			ThreadTest();
			break;
#ifdef OS_LINUX
		case 4:
			ProcessTest();
			break;
		case 5:
			ProcessAndThread();
			break;
#endif
		case 0:
			return;
			break;
		default:
			break;
		}
	}
#endif
	free(indata);
	free(outdata);
	free(temp);
	//free(pinfo);
	C_Finalize(NULL_PTR);
}

