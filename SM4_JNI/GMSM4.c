#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <jni.h>
#include <sm4.h>


#define PRINT_ERROR() \
	fprintf(stderr,"err:%s %d\n",__FILE__,__LINE__)

#define SM4_CRYPTO_BLOCK_SIZE 16

typedef struct UserKey
{
	unsigned char data[SM4_CRYPTO_BLOCK_SIZE];
}USER_KEY;

static struct SM4_CONTEXT
{
	USER_KEY UserKey;

	int context_init;

} SM4_Context;



/*
 * Class:     com_hzih_jni_Sm4Jni
 * Method:    setKey
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_com_hzih_jni_Sm4Jni_setKey
  (JNIEnv *env, jobject thzs, jbyteArray in)
{
	int ret = -1;
	unsigned char *keybuf = NULL;
	size_t keylen;

	if(!(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env,in,0)))
	{
		PRINT_ERROR();
		goto end;
	}

	keylen = (size_t)(*env)->GetArrayLength(env,in);
	if(keylen != SM4_CRYPTO_BLOCK_SIZE) {
		PRINT_ERROR();
		goto end;	
	}

	memcpy(SM4_Context.UserKey.data,keybuf,SM4_CRYPTO_BLOCK_SIZE);
	SM4_Context.context_init = 1;

	ret = 0;

end:
	if(keybuf) 
		(*env)->ReleaseByteArrayElements(env,in,(jbyte *)keybuf,JNI_ABORT);

	return ret;
}

/*
 * Class:     com_hzih_jni_Sm4Jni
 * Method:    encryptJni
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_hzih_jni_Sm4Jni_encryptJni
  (JNIEnv *env, jobject thzs, jbyteArray in)
{
	jbyteArray ret = NULL;
	unsigned char *inbuf = NULL;
	unsigned char *outbuf = NULL;

	size_t inlen,outlen;
	if(SM4_Context.context_init <= 0)
	{
		PRINT_ERROR();
		goto end;
	}
	if (!(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))) {
		PRINT_ERROR();
		goto end;
	}	
	inlen = (size_t)(*env)->GetArrayLength(env, in);
	if (inlen <= 0) {
		PRINT_ERROR();
		goto end;
	}

	outlen = ((inlen-1)/(SM4_CRYPTO_BLOCK_SIZE) +1)*SM4_CRYPTO_BLOCK_SIZE;
	if (!(outbuf = malloc(outlen+1))) {
		PRINT_ERROR();
		goto end;
	}
	bzero(outbuf, outlen);

	/* sm4 struff */
	sm4_context ctx;
	sm4_setkey_enc(&ctx,SM4_Context.UserKey.data);
	sm4_crypt_ecb(&ctx,1,inlen,inbuf,outbuf);
	/* end sm4 struff */


	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		PRINT_ERROR();
		goto end;
	}

	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

end:
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	if (outbuf) free(outbuf);
	return ret;
}

/*
 * Class:     com_hzih_jni_Sm4Jni
 * Method:    decryptJni
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_hzih_jni_Sm4Jni_decryptJni
  (JNIEnv *env, jobject thzs, jbyteArray in)
{
	jbyteArray ret = NULL;
	unsigned char *inbuf = NULL;
	unsigned char *outbuf = NULL;

	size_t inlen,outlen;
	if(SM4_Context.context_init <= 0)
	{
		PRINT_ERROR();
		goto end;
	}
	if (!(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))) {
		PRINT_ERROR();
		goto end;
	}	
	inlen = (size_t)(*env)->GetArrayLength(env, in);
	if (inlen <= 0) {
		PRINT_ERROR();
		goto end;
	}

	outlen = ((inlen-1)/SM4_CRYPTO_BLOCK_SIZE +1)*SM4_CRYPTO_BLOCK_SIZE;
	if (!(outbuf = malloc(outlen + 1))) {
		PRINT_ERROR();
		goto end;
	}
	bzero(outbuf, outlen);

	/* sm4 struff */
	sm4_context ctx;
	sm4_setkey_dec(&ctx,SM4_Context.UserKey.data);
	sm4_crypt_ecb(&ctx,0,inlen,inbuf,outbuf);
	/* end sm4 struff */


	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		PRINT_ERROR();
		goto end;
	}

	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

end:
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	if (outbuf) free(outbuf);
	return ret;
}
