
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

#ifdef NDEBUG
#define LogDebug(...) (void)0
#else
#define LogDebug(...) __android_log_print(ANDROID_LOG_DEBUG, "KernelSU", __VA_ARGS__)
#endif

#endif
