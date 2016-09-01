/*
* Copyright (c), yw
*
* �ļ�����: pkcs11s.h
* ժ    Ҫ: pkcs#11�Զ�����ƺ꣬��׼��û�ж��塣
* �ļ���ʶ:
*
* �ļ��汾: 1.0
* ��    ��: 
* �޸�����: 2009-09
*
* ԭ  �汾: ��
* ԭ  ����: ��
* �������: ��
*/
#ifndef _PKCS11E1_H_
#define _PKCS11E1_H_ 

#ifdef __cplusplus
extern "C" {
#endif

//�Զ������뿨�ĶԳ��㷨��
#define	CKM_SM1_GEN		CKM_VENDOR_DEFINED+0x0f
#define CKM_SM1			CKM_VENDOR_DEFINED+1
#define CKM_SM1_ECB		CKM_VENDOR_DEFINED+0x10
#define CKM_SM1_CBC		CKM_VENDOR_DEFINED+0x11
#define CKM_SM1_CBC_PAD CKM_VENDOR_DEFINED+4

#define CKM_SSF33_CBC	CKM_VENDOR_DEFINED+20

#define CKK_SM1			CKK_VENDOR_DEFINED+1
//�Զ���
#define CKM_ECDSA_PKCS	CKM_VENDOR_DEFINED + 10
#define CKM_SM3_ECDSA	CKM_VENDOR_DEFINED + 11
#define CKM_SM3			CKM_VENDOR_DEFINED + 12

#define CKM_SM2					CKM_VENDOR_DEFINED +0x8000
#define CKM_SM2_KEY_PAIR_GEN	CKM_SM2+0x00000001
#define CKM_SM3_SM2				CKM_SM2+0x00000100
#define CKM_SM2_RAW				CKM_SM2+0x00000200
#define CKK_SM2					CKK_VENDOR_DEFINED + 4

#ifdef __cplusplus
}
#endif
   
#endif
