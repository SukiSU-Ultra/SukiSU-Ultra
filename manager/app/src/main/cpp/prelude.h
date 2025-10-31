
#ifndef KERNELSU_PRELUDE_H
#define KERNELSU_PRELUDE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <jni.h>
#include <android/log.h>

#define GetEnvironment() (*env)
#define NativeBridge(fn, rtn, ...) JNIEXPORT rtn JNICALL  Java_com_sukisu_ultra_Natives_##fn(JNIEnv* env, jclass clazz, __VA_ARGS__)
#define NativeBridgeNP(fn, rtn) JNIEXPORT rtn JNICALL Java_com_sukisu_ultra_Natives_##fn(JNIEnv* env, jclass clazz)

// Macros to simplify field setup
#define SET_BOOLEAN_FIELD(obj, cls, fieldName, value) do { \
	jfieldID field = GetEnvironment()->GetFieldID(env, cls, #fieldName, "Z"); \
	GetEnvironment()->SetBooleanField(env, obj, field, value); \
} while(0)

#define SET_INT_FIELD(obj, cls, fieldName, value) do { \
	jfieldID field = GetEnvironment()->GetFieldID(env, cls, #fieldName, "I"); \
	GetEnvironment()->SetIntField(env, obj, field, value); \
} while(0)

#define SET_STRING_FIELD(obj, cls, fieldName, value) do { \
	jfieldID field = GetEnvironment()->GetFieldID(env, cls, #fieldName, "Ljava/lang/String;"); \
	GetEnvironment()->SetObjectField(env, obj, field, GetEnvironment()->NewStringUTF(env, value)); \
} while(0)

#define SET_OBJECT_FIELD(obj, cls, fieldName, value) do { \
	jfieldID field = GetEnvironment()->GetFieldID(env, cls, #fieldName, "Ljava/util/List;"); \
	GetEnvironment()->SetObjectField(env, obj, field, value); \
} while(0)

// Macros for creating Java objects
#define CREATE_JAVA_OBJECT(className) ({ \
	jclass cls = GetEnvironment()->FindClass(env, className); \
	jmethodID constructor = GetEnvironment()->GetMethodID(env, cls, "<init>", "()V"); \
	GetEnvironment()->NewObject(env, cls, constructor); \
})

// Macros for creating ArrayList
#define CREATE_ARRAYLIST() ({ \
	jclass arrayListCls = GetEnvironment()->FindClass(env, "java/util/ArrayList"); \
	jmethodID constructor = GetEnvironment()->GetMethodID(env, arrayListCls, "<init>", "()V"); \
	GetEnvironment()->NewObject(env, arrayListCls, constructor); \
})

// Macros for adding elements to an ArrayList
#define ADD_TO_LIST(list, item) do { \
	jclass cls = GetEnvironment()->GetObjectClass(env, list); \
	jmethodID addMethod = GetEnvironment()->GetMethodID(env, cls, "add", "(Ljava/lang/Object;)Z"); \
	GetEnvironment()->CallBooleanMethod(env, list, addMethod, item); \
} while(0)

// Macros for creating Java objects with parameter constructors
#define CREATE_JAVA_OBJECT_WITH_PARAMS(className, signature, ...) ({ \
	jclass cls = GetEnvironment()->FindClass(env, className); \
	jmethodID constructor = GetEnvironment()->GetMethodID(env, cls, "<init>", signature); \
	GetEnvironment()->NewObject(env, cls, constructor, __VA_ARGS__); \
})

#ifdef NDEBUG
#define LogDebug(...) (void)0
#else
#define LogDebug(...) __android_log_print(ANDROID_LOG_DEBUG, "KernelSU", __VA_ARGS__)
#endif

#endif
