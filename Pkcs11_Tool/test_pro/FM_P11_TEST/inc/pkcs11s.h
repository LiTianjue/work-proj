/*
* Copyright (c), yw
*
* 文件名称: pkcs11s.h
* 摘    要: pkcs#11自定义机制宏，标准中没有定义。
* 文件标识:
*
* 文件版本: 1.0
* 作    者: 
* 修改日期: 2009-09
*
* 原  版本: 无
* 原  作者: 无
* 完成日期: 无
*/
#ifndef _PKCS11E1_H_
#define _PKCS11E1_H_ 

#ifdef __cplusplus
extern "C" {
#endif

//自定义密码卡的对称算法宏
#define	CKM_SM1_GEN		CKM_VENDOR_DEFINED+0x0f
#define CKM_SM1			CKM_VENDOR_DEFINED+1
#define CKM_SM1_ECB		CKM_VENDOR_DEFINED+0x10
#define CKM_SM1_CBC		CKM_VENDOR_DEFINED+0x11
#define CKM_SM1_CBC_PAD CKM_VENDOR_DEFINED+4

#define CKM_SSF33_CBC	CKM_VENDOR_DEFINED+20

#define CKK_SM1			CKK_VENDOR_DEFINED+1
//自定义
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
