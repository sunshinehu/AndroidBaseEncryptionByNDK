#include <string.h>
#include <jni.h>

/***
 *
 * 加解密本地c实现
 * by sunshineHu
 * 2015/7/18
 *简单的加密（ascaii码加密c实现，偏移量根据手机序列号，保证不同手机产生的编码不同）
 */


//jstring to char*
char* jstringTostring(JNIEnv* env, jstring jstr)
{
       char* rtn = NULL;
       jclass clsstring = env->FindClass("java/lang/String");
       jstring strencode = env->NewStringUTF("utf-8");
       jmethodID mid = env->GetMethodID(clsstring, "getBytes", "(Ljava/lang/String;)[B");
       jbyteArray barr= (jbyteArray)env->CallObjectMethod(jstr, mid, strencode);
       jsize alen = env->GetArrayLength(barr);
       jbyte* ba = env->GetByteArrayElements(barr, JNI_FALSE);
       rtn = (char*)malloc(alen + 1);
       memcpy(rtn, ba, alen);
       rtn[alen] = '\0';
       env->ReleaseByteArrayElements(barr, ba, 0);
       return rtn;
}

//char* to jstring
jstring stoJstring(JNIEnv* env, const char* pat)
{
       jclass strClass = env->FindClass("java/lang/String");
       jmethodID ctorID = env->GetMethodID(strClass, "<init>", "([BLjava/lang/String;)V");
       jbyteArray bytes = env->NewByteArray(strlen(pat));
       env->SetByteArrayRegion(bytes, 0, strlen(pat), (jbyte*)pat);
       jstring encoding = env->NewStringUTF("utf-8");
       return (jstring)env->NewObject(strClass, ctorID, bytes, encoding);
}



extern "C"
JNIEXPORT jstring JNICALL Java_com_sunshinehu_encryption_EncryptionUtils_encodeMethod1(JNIEnv *env, jclass obj, jstring pwd, jstring code){


	char *a=jstringTostring(env,pwd);

	int lenth=strlen(a);

	char *b=jstringTostring(env,code);


	while(*a!='\0'){

		if(*b!='\0'){
			*a=*a-((*b)&13);
			b++;
		}else{
			*a=*a-13;
		}

		a++;

	}

	a=a-lenth;


	jstring result=stoJstring(env,a);


	return result;


}





extern "C"
JNIEXPORT jstring JNICALL Java_com_sunshinehu_encryption_EncryptionUtils_decodeMethod1(JNIEnv *env, jclass obj, jstring pwd, jstring code){


	char *a=jstringTostring(env,pwd);

	int lenth=strlen(a);

	char *b=jstringTostring(env,code);


	while(*a!='\0'){

		if(*b!='\0'){
			*a=*a+((*b)&13);
			b++;
		}else{
			*a=*a+13;
		}

		a++;

	}

	a=a-lenth;


	jstring result=stoJstring(env,a);

	return result;


}



extern "C"
JNIEXPORT jstring JNICALL Java_com_sunshinehu_encryption_EncryptionUtils_encodeMethod2(JNIEnv *env, jclass type,
															 jstring origin_) {
	const char *origin = env->GetStringUTFChars(origin_, 0);

	// TODO

	env->ReleaseStringUTFChars(origin_, origin);

	return env->NewStringUTF("Hello world");
}



extern "C"
JNIEXPORT jstring JNICALL Java_com_sunshinehu_encryption_EncryptionUtils_decodeMethod2(JNIEnv *env, jclass type,
															 jstring result_) {
	const char *result = env->GetStringUTFChars(result_, 0);

	// TODO

	env->ReleaseStringUTFChars(result_, result);

	return env->NewStringUTF("Hello world");
}

