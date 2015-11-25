#include <string.h>
#include <jni.h>
#include <android/log.h>
#include <stdio.h>

//包名
#define PACKAGE_NAME "com.sunshinehu.encryption"
#define SIGNATURE "3082030d308201f5a0030201020204547fda2d300d06092a864886f70d01010b05003037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f6964204465627567301e170d3135303631373131313834375a170d3435303630393131313834375a3037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f696420446562756730820122300d06092a864886f70d01010105000382010f003082010a02820101009035f0d5177856699a9c78e0923a1921e8ab845a15bcf3880df4795d77a10d177b155a8036cb3592d310633c98fcb90590712ff4016b75b9019faaab0e98dfd65aecd732935a7ddf7ed3febe1b6af08192adc4faff31e2281cad3bc127c43ee01c3dcaaff248278089aabc6948c96eb23c969396a462198cb53efd91e30858b545ce9a5d32803db1986676b5cb469590e24f9c4fc9a71968a8efcc675a2c10c4aa1af9387478b8d5efb04ebf18fd2cacb30605f845eec3a9043c72e4e21a0ead9af47477ac3345cebb17fad800ab6f8f699462a8cb08450bf0237113433265a264cc97122a80a6e973041add1b5f4bce667b75717d9194214415d24faac318290203010001a321301f301d0603551d0e04160414df35b605c8ac272c53a99daac93fda86846f4f58300d06092a864886f70d01010b050003820101002172f953281816196ff681436002a067261822f6e6331c8603046c8b8315b27d5fcab1c48cc378afbdef87cbf95df764645e7da2c765f5e54b05e3a6f90f79ef73d46f98d5c5fb3228da9b427db957595f19566a304a6ec0933723d5306ee35ccf35910455ebca82da0fa2f44d1304d8ff64813bb2d18752539c01b0bd8a0d07009aaf5c4630a4db9391445829433133e8bc1fcea49957ba8cc1d2adfb112c9b8df4eb093ef3bf3e2810d982bb6e9176a528a483f33375d5343babac7b6243d4695de9d098152f74fe37cae23e064881673d8e41a6bc0b78ca563d75004348ac613a8d63d85b2ba10d653e2ca3d73d46ee67579960c88b1dd21c33aaaaf0f43b"
#define CODE_LENTH 9
//矩阵的长度为9，主要考虑到两个方面，其一，矩阵求逆计算量比较大，其二，矩阵越大产生的加密结果也越大，设计中是小于16位int的

int *mycode=NULL;//加密矩阵
int *mycode2=NULL;//逆矩阵

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


//得到设备唯一编码（由包名，签名，设备序列号共同生成）
int* getSerialNo(JNIEnv *env, jobject context){

    if(mycode!=NULL){
        return mycode;
    }

    //获取methodid
    jclass contextCls=env->GetObjectClass(context);

    //context.getPackageManager
    jmethodID methodId=env->GetMethodID(contextCls,"getPackageManager","()Landroid/content/pm/PackageManager;");
    jobject packageManager=env->CallObjectMethod(context,methodId);
    if(packageManager==NULL){
        __android_log_print(ANDROID_LOG_ERROR,"Encryption","Get package manager error!");
        jclass excCls = env ->FindClass("java/lang/RuntimeException");
        env->ThrowNew(excCls,"getPackage name error in C code");
    }

    //context.getPackageName
    methodId=env->GetMethodID(contextCls,"getPackageName","()Ljava/lang/String;");
    jstring packageName= (jstring) env->CallObjectMethod(context,methodId);
    if(packageName==NULL){
        __android_log_print(ANDROID_LOG_ERROR,"Encryption","getPackage name error");
        jclass excCls = env ->FindClass("java/lang/RuntimeException");
        env->ThrowNew(excCls,"getPackage name error in C code");
    }

    //package name 校验
    const char* name=env->GetStringUTFChars(packageName,0);
    if(strcmp(name,PACKAGE_NAME)!=0){
        __android_log_print(ANDROID_LOG_ERROR,"Encryption","package name verify error");
        jclass excCls = env ->FindClass("java/lang/RuntimeException");
        env->ThrowNew(excCls,"package name verify error");
    }

    env->DeleteLocalRef(contextCls);

    //PackageManager.getPackageInfo(Sting, int)
    jclass packageManagerCls=env->GetObjectClass(packageManager);
    methodId=env->GetMethodID(packageManagerCls,"getPackageInfo","(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    env->DeleteLocalRef(packageManagerCls);
    jobject packageInfo=env->CallObjectMethod(packageManager,methodId,packageName,64);
    if(packageInfo==NULL){
        __android_log_print(ANDROID_LOG_ERROR,"Encryption","getPackage info error");
        jclass excCls = env ->FindClass("java/lang/RuntimeException");
        env->ThrowNew(excCls,"getPackage info error in C code");
    }

    //PackageInfo.sinature[0]
    jclass packageInfoCls=env->GetObjectClass(packageInfo);
    jfieldID field=env->GetFieldID(packageInfoCls,"signatures","[Landroid/content/pm/Signature;");
    env->DeleteLocalRef(packageInfoCls);
    jobjectArray signatures= (jobjectArray) env->GetObjectField(packageInfo,field);
    if(signatures==NULL){
        __android_log_print(ANDROID_LOG_ERROR,"Encryption","get signatures error");
        jclass excCls = env ->FindClass("java/lang/RuntimeException");
        env->ThrowNew(excCls,"get signatures error in C code");
    }

    jobject signature=env->GetObjectArrayElement(signatures,0);

    //Sinature.toCharString
    jclass signatureCls=env->GetObjectClass(signature);
    methodId=env->GetMethodID(signatureCls,"toCharsString","()Ljava/lang/String;");
    jstring signString= (jstring) env->CallObjectMethod(signature,methodId);

    //签名 校验
    const char* sign=env->GetStringUTFChars(signString,0);
    if(strcmp(sign,SIGNATURE)!=0){
        __android_log_print(ANDROID_LOG_ERROR,"Encryption","package name verify error");
        jclass excCls = env ->FindClass("java/lang/RuntimeException");
        env->ThrowNew(excCls,"package name verify error");
    }

    //设备识别码
    //android.os.build.Serial
    jclass buildCls=env->FindClass("android/os/Build");
    if(buildCls==NULL){
        __android_log_print(ANDROID_LOG_ERROR,"Encryption","get build serial error");
        jclass excCls = env ->FindClass("java/lang/RuntimeException");
        env->ThrowNew(excCls,"get build serial error");
    }
    jfieldID serialFild=env->GetStaticFieldID(buildCls,"SERIAL","Ljava/lang/String;");
    jstring serialNo= (jstring) env->GetStaticObjectField(buildCls,serialFild);
    const char* serial=env->GetStringUTFChars(serialNo,0);

    env->DeleteLocalRef(buildCls);

    env->DeleteLocalRef(signatureCls);
    env->DeleteLocalRef(packageManager);
    env->DeleteLocalRef(packageInfo);
    env->DeleteLocalRef(signatures);


    mycode= (int *) malloc(CODE_LENTH * sizeof(int));

    for(int i=0;i<CODE_LENTH;i++){
        int a,b,c;
        if(i<strlen(name)){
            a=name[i];
        }
        if(i<strlen(serial)){
            b=serial[i];
        }
        if(i<strlen(sign)){
            c=sign[i];
        }
        mycode[i]=(a+b+c)&(2^16/3);
    }

    env->ReleaseStringUTFChars(packageName,name);
    env->ReleaseStringUTFChars(signString,sign);
    env->ReleaseStringUTFChars(serialNo,serial);

    return mycode;

}




int* getArray(const char* a) {

    int lenth = strlen(a);
    int colums = lenth / 3;
    if (lenth % 3 != 0) {
        colums ++;
    }
    int **p = (int**)malloc(sizeof(int*)*colums);

    for (int i = 0; i < colums; i++) {

        p[i] = (int*)malloc(sizeof(int) * 3);

    }
    for (int i = 0; i < colums; i++) {

        for (int j = 0; j < 3; j++) {

            if ((3 * i + j) < lenth) {
                p[i][j] = a[3 * i + j];
            }else {
                p[i][j] = -1;
            }

        }

    }

    int **q = (int**)malloc(sizeof(int*)*colums);

    for (int i = 0; i < colums; i++) {

        q[i] = (int*)malloc(sizeof(int) * 3);

    }

    if(mycode==NULL){
        return NULL;
    }


    for (int i = 0; i < colums; i++) {

        for (int j = 0; j < 3; j++) {

            q[i][j] = p[i][0] * mycode[j] + p[i][1] * mycode[3+j] + p[i][2] * mycode[6+j];

        }

    }

    int* result = (int*)malloc(sizeof(int)*colums*3);

    for (int i = 0; i < colums * 3; i++) {
        int num = q[i / 3][i % 3];
        result[i] = num;
    }


    return result;

}






extern "C"
JNIEXPORT jintArray JNICALL Java_com_sunshinehu_encryption_EncryptionUtils_getCode(JNIEnv *env, jclass type) {

    // TODO
    jintArray array=env->NewIntArray(9);
    if(mycode==NULL){
        __android_log_print(ANDROID_LOG_ERROR,"mycode","null");
        return array;
    }
    __android_log_print(ANDROID_LOG_ERROR,"mycode","not null");
    env->SetIntArrayRegion(array,0,9,mycode);
/*
    for(int i=0;i<20;i++){
        char a2[5];
        sprintf(a2,"%d",mycode[i]);
        __android_log_print(ANDROID_LOG_ERROR,"mycode",a2);
    }*/
    return array;


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
JNIEXPORT jintArray JNICALL Java_com_sunshinehu_encryption_EncryptionUtils_encodeMethod2(JNIEnv *env, jclass type,
                                                             jstring origin_, jobject context) {
    const char *origin = env->GetStringUTFChars(origin_, 0);
    int *code=getSerialNo(env,context);
    int* result=getArray(origin);
    env->ReleaseStringUTFChars(origin_, origin);

    int len=strlen(origin);
    if(len%3!=0){
        len=(len/3+1)*3;
    }
    jintArray array=env->NewIntArray(len);
    env->SetIntArrayRegion(array,0,len,result);

    return array;
}


extern "C"
JNIEXPORT jstring JNICALL Java_com_sunshinehu_encryption_EncryptionUtils_decodeMethod2(JNIEnv *env, jclass type,
                                                             jstring result_, jobject context) {
    const char *result = env->GetStringUTFChars(result_, 0);

    // TODO

    env->ReleaseStringUTFChars(result_, result);

    return env->NewStringUTF("Hello world");
}
