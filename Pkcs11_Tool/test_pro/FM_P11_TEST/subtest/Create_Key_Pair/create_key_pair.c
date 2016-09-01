#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include "pkcs11.h"
#include "fmpkcs11.h"
#include "pkcs11s.h"
#include "g_head.h"



#define RSA_KEY		0
#define ECC_KEY		1

void help(char *app)
{
	printf("**********************************************\n");
	printf("* usage:\n");
	printf("* %s -t	(the type of keypair RSA/ECC, RSA for)\n",app);
	printf("*    \t-n (the byte of key RSA(1024/2048),ECC(256))\n");
	printf("*    \t-i (Set number of KeyPair )\n");
	printf("*    \t-d (the ID for KeyPair )\n");
	printf("**********************************************\n");

}

int main(int argc,char **argv)
{	
	
	int keytype = RSA_KEY;
	int keybyte = 1024;
	int keynum	= 20;
	//char ID[64] = "10086";
	CK_BYTE ID[] = "RSA_KEYPAIR_0";

	//parse command
	int ch;
	opterr= 1;		//有错误的选项时报错
	if(argc == 1)
	{
		help(argv[0]);
		return 0;
	}
	while((ch = getopt(argc,argv,"t:n:i:d:e:"))!= -1) {
		switch(ch) {
			case 't':
				if(!strcmp(optarg,"ECC"))
				{
					keytype = ECC_KEY;
				}
				break;
			case 'n':
				keybyte = atoi(optarg);
				break;
			case 'i':
				keynum = atoi(optarg);
				break;
				/*
			case 'd':
				strcpy(ID,optarg);
				break;
				*/
		}
	}
	printf("===KEY_PAIR_GEN_OPT====\n");
	printf(" Key Tyep : %s\n",(keytype==ECC_KEY)?"ECC":"RSA");
	printf(" Key Byte : %d\n",keybyte);
	printf(" Key NUM  : %d\n",keynum);
	printf(" Key ID   : %s\n",ID);
	printf("=======================\n");
	

	//For pkcs11
	CK_RV rv = 0;
	CK_SLOT_ID SlotId = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_MECHANISM mGenRSAKey	= {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_ULONG RSAPubKeyClass = CKO_PUBLIC_KEY;
	CK_ULONG RSAPriKeyClass = CKO_PRIVATE_KEY;
	CK_ULONG RSAKeyType = CKK_RSA;
	CK_ULONG ModuluBits = 1024;
	CK_BBOOL isTrue = TRUE;
	
	//CK_BYTE RSAPubLabel[64] = {0};
	//CK_BYTE RSAPriLabel[64] = {0};
	//sprintf(RSAPubLabel,"RSA_PUBLIC_KEY_%d",keynum);	
	//sprintf(RSAPriLabel,"RSA_PRIVATE_KEY_%d",keynum);	
	CK_BYTE RSAPubLabel[]="RSA_PUBLIC_KEY_0";
	CK_BYTE RSAPriLabel[]="RSA_PRIVATE_KEY_0";
		//"RSA_PRIVATE_KEY_10";

	printf("%s\n%s\n",RSAPubLabel,RSAPriLabel);

 	CK_ATTRIBUTE aRSAPubKey[] = {
		{CKA_CLASS, &RSAPubKeyClass, sizeof(RSAPubKeyClass)},
		{CKA_LABEL, &RSAPubLabel, sizeof(RSAPubLabel)},
		{CKA_KEY_TYPE, &RSAKeyType, sizeof(RSAKeyType)},
		{CKA_ID,&ID,sizeof(ID)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)},
		{CKA_MODULUS_BITS, &ModuluBits, sizeof(ModuluBits)}
	}; 
	CK_ATTRIBUTE aRSAPriKey[] = {
		{CKA_CLASS, &RSAPriKeyClass, sizeof(RSAPriKeyClass)},
		{CKA_KEY_TYPE, &RSAKeyType, sizeof(RSAKeyType)},
		{CKA_ID,&ID,sizeof(ID)},
		{CKA_LABEL, &RSAPriLabel, sizeof(RSAPriLabel)},
		{CKA_TOKEN, &isTrue, sizeof(isTrue)}
		//{CKA_MODULUS_BITS, &ModuluBits, sizeof(ModuluBits)}
								};
	CK_OBJECT_HANDLE hRSAPubKey = 0;
	CK_OBJECT_HANDLE hRSAPriKey = 0;
	
	CK_ATTRIBUTE CreateRSAPubKey[] = {
		{CKA_CLASS, NULL_PTR, 0},
		{CKA_MODULUS, NULL_PTR, 0},
		{CKA_MODULUS_BITS, NULL_PTR, 0},
		{CKA_PUBLIC_EXPONENT, NULL_PTR, 0}
									};

	rv = C_Initialize(NULL_PTR);
	if(rv != 0)
	{
		printf("*****Initalize Smart Card Error*******\n");
		return 0;
	}
	printf("----Init Smart Card Success----\n");

	rv = C_OpenSession(SlotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL, &hSession);
	printf("----Open Session Success----\n");

	rv = C_GenerateKeyPair(hSession, &mGenRSAKey, aRSAPubKey, 6, aRSAPriKey, 5, &hRSAPubKey, &hRSAPriKey);
	if(rv != 0)
	{
		printf("************GenerateKeyPair Fail***************\n");
	}
		printf("----GenerateKeyPair Success----\n");
		
	rv = C_CloseSession(hSession);
	C_Finalize(NULL_PTR);
	return 0;


}
