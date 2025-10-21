#include "prelude.h"
#include "ksu.h"

#include <jni.h>
#include <sys/prctl.h>
#include <android/log.h>
#include <string.h>


NativeBridge(becomeManager, jboolean, jstring pkg) {
    const char* cpkg = GetEnvironment()->GetStringUTFChars(env, pkg, JNI_FALSE);
    bool result = become_manager(cpkg);

    GetEnvironment()->ReleaseStringUTFChars(env, pkg, cpkg);
    return result;
}

NativeBridgeNP(getVersion, jint) {
    return get_version();
}

// get VERSION FULL
NativeBridgeNP(getFullVersion, jstring) {
    char buff[255] = { 0 };
    get_full_version((char *) &buff);
    return GetEnvironment()->NewStringUTF(env, buff);
}

NativeBridgeNP(getAllowList, jintArray) {
    int uids[1024];
    int size = 0;
    bool result = get_allow_list(uids, &size);

    LogDebug("getAllowList: %d, size: %d", result, size);

    if (result) {
        jintArray array = GetEnvironment()->NewIntArray(env, size);
        GetEnvironment()->SetIntArrayRegion(env, array, 0, size, uids);

        return array;
    }

    return GetEnvironment()->NewIntArray(env, 0);
}

NativeBridgeNP(isSafeMode, jboolean) {
    return is_safe_mode();
}

NativeBridgeNP(isLkmMode, jboolean) {
    return is_lkm_mode();
}

static void fillIntArray(JNIEnv *env, jobject list, int *data, int count) {
    jclass cls = GetEnvironment()->GetObjectClass(env, list);
    jmethodID add = GetEnvironment()->GetMethodID(env, cls, "add", "(Ljava/lang/Object;)Z");
    jclass integerCls = GetEnvironment()->FindClass(env, "java/lang/Integer");
    jmethodID constructor = GetEnvironment()->GetMethodID(env, integerCls, "<init>", "(I)V");
    for (int i = 0; i < count; ++i) {
        jobject integer = GetEnvironment()->NewObject(env, integerCls, constructor, data[i]);
        GetEnvironment()->CallBooleanMethod(env, list, add, integer);
    }
}

static void addIntToList(JNIEnv *env, jobject list, int ele) {
    jclass cls = GetEnvironment()->GetObjectClass(env, list);
    jmethodID add = GetEnvironment()->GetMethodID(env, cls, "add", "(Ljava/lang/Object;)Z");
    jclass integerCls = GetEnvironment()->FindClass(env, "java/lang/Integer");
    jmethodID constructor = GetEnvironment()->GetMethodID(env, integerCls, "<init>", "(I)V");
    jobject integer = GetEnvironment()->NewObject(env, integerCls, constructor, ele);
    GetEnvironment()->CallBooleanMethod(env, list, add, integer);
}

static uint64_t capListToBits(JNIEnv *env, jobject list) {
    jclass cls = GetEnvironment()->GetObjectClass(env, list);
    jmethodID get = GetEnvironment()->GetMethodID(env, cls, "get", "(I)Ljava/lang/Object;");
    jmethodID size = GetEnvironment()->GetMethodID(env, cls, "size", "()I");
    jint listSize = GetEnvironment()->CallIntMethod(env, list, size);
    jclass integerCls = GetEnvironment()->FindClass(env, "java/lang/Integer");
    jmethodID intValue = GetEnvironment()->GetMethodID(env, integerCls, "intValue", "()I");
    uint64_t result = 0;
    for (int i = 0; i < listSize; ++i) {
        jobject integer = GetEnvironment()->CallObjectMethod(env, list, get, i);
        int data = GetEnvironment()->CallIntMethod(env, integer, intValue);

        if (cap_valid(data)) {
            result |= (1ULL << data);
        }
    }

    return result;
}

static int getListSize(JNIEnv *env, jobject list) {
    jclass cls = GetEnvironment()->GetObjectClass(env, list);
    jmethodID size = GetEnvironment()->GetMethodID(env, cls, "size", "()I");
    return GetEnvironment()->CallIntMethod(env, list, size);
}

static void fillArrayWithList(JNIEnv *env, jobject list, int *data, int count) {
    jclass cls = GetEnvironment()->GetObjectClass(env, list);
    jmethodID get = GetEnvironment()->GetMethodID(env, cls, "get", "(I)Ljava/lang/Object;");
    jclass integerCls = GetEnvironment()->FindClass(env, "java/lang/Integer");
    jmethodID intValue = GetEnvironment()->GetMethodID(env, integerCls, "intValue", "()I");
    for (int i = 0; i < count; ++i) {
        jobject integer = GetEnvironment()->CallObjectMethod(env, list, get, i);
        data[i] = GetEnvironment()->CallIntMethod(env, integer, intValue);
    }
}

NativeBridge(getAppProfile, jobject, jstring pkg, jint uid) {
    if (GetEnvironment()->GetStringLength(env, pkg) > KSU_MAX_PACKAGE_NAME) {
        return NULL;
    }

    char key[KSU_MAX_PACKAGE_NAME] = { 0 };
    const char* cpkg = GetEnvironment()->GetStringUTFChars(env, pkg, nullptr);
    strcpy(key, cpkg);
    GetEnvironment()->ReleaseStringUTFChars(env, pkg, cpkg);

    struct app_profile profile = { 0 };
    profile.version = KSU_APP_PROFILE_VER;

    strcpy(profile.key, key);
    profile.current_uid = uid;

    bool useDefaultProfile = !get_app_profile(key, &profile);

    jclass cls = GetEnvironment()->FindClass(env, "com/sukisu/ultra/Natives$Profile");
    jmethodID constructor = GetEnvironment()->GetMethodID(env, cls, "<init>", "()V");
    jobject obj = GetEnvironment()->NewObject(env, cls, constructor);
    jfieldID keyField = GetEnvironment()->GetFieldID(env, cls, "name", "Ljava/lang/String;");
    jfieldID currentUidField = GetEnvironment()->GetFieldID(env, cls, "currentUid", "I");
    jfieldID allowSuField = GetEnvironment()->GetFieldID(env, cls, "allowSu", "Z");

    jfieldID rootUseDefaultField = GetEnvironment()->GetFieldID(env, cls, "rootUseDefault", "Z");
    jfieldID rootTemplateField = GetEnvironment()->GetFieldID(env, cls, "rootTemplate", "Ljava/lang/String;");

    jfieldID uidField = GetEnvironment()->GetFieldID(env, cls, "uid", "I");
    jfieldID gidField = GetEnvironment()->GetFieldID(env, cls, "gid", "I");
    jfieldID groupsField = GetEnvironment()->GetFieldID(env, cls, "groups", "Ljava/util/List;");
    jfieldID capabilitiesField = GetEnvironment()->GetFieldID(env, cls, "capabilities", "Ljava/util/List;");
    jfieldID domainField = GetEnvironment()->GetFieldID(env, cls, "context", "Ljava/lang/String;");
    jfieldID namespacesField = GetEnvironment()->GetFieldID(env, cls, "namespace", "I");

    jfieldID nonRootUseDefaultField = GetEnvironment()->GetFieldID(env, cls, "nonRootUseDefault", "Z");
    jfieldID umountModulesField = GetEnvironment()->GetFieldID(env, cls, "umountModules", "Z");

    GetEnvironment()->SetObjectField(env, obj, keyField, GetEnvironment()->NewStringUTF(env, profile.key));
    GetEnvironment()->SetIntField(env, obj, currentUidField, profile.current_uid);

    if (useDefaultProfile) {
        // no profile found, so just use default profile:
        // don't allow root and use default profile!
        LogDebug("use default profile for: %s, %d", key, uid);

        // allow_su = false
        // non root use default = true
        GetEnvironment()->SetBooleanField(env, obj, allowSuField, false);
        GetEnvironment()->SetBooleanField(env, obj, nonRootUseDefaultField, true);

        return obj;
    }

    bool allowSu = profile.allow_su;

    if (allowSu) {
        GetEnvironment()->SetBooleanField(env, obj, rootUseDefaultField, (jboolean) profile.rp_config.use_default);
        if (strlen(profile.rp_config.template_name) > 0) {
            GetEnvironment()->SetObjectField(env, obj, rootTemplateField,
                                             GetEnvironment()->NewStringUTF(env, profile.rp_config.template_name));
        }

        GetEnvironment()->SetIntField(env, obj, uidField, profile.rp_config.profile.uid);
        GetEnvironment()->SetIntField(env, obj, gidField, profile.rp_config.profile.gid);

        jobject groupList = GetEnvironment()->GetObjectField(env, obj, groupsField);
        int groupCount = profile.rp_config.profile.groups_count;
        if (groupCount > KSU_MAX_GROUPS) {
            LogDebug("kernel group count too large: %d???", groupCount);
            groupCount = KSU_MAX_GROUPS;
        }
        fillIntArray(env, groupList, profile.rp_config.profile.groups, groupCount);

        jobject capList = GetEnvironment()->GetObjectField(env, obj, capabilitiesField);
        for (int i = 0; i <= CAP_LAST_CAP; i++) {
            if (profile.rp_config.profile.capabilities.effective & (1ULL << i)) {
                addIntToList(env, capList, i);
            }
        }

        GetEnvironment()->SetObjectField(env, obj, domainField,
                                         GetEnvironment()->NewStringUTF(env, profile.rp_config.profile.selinux_domain));
        GetEnvironment()->SetIntField(env, obj, namespacesField, profile.rp_config.profile.namespaces);
        GetEnvironment()->SetBooleanField(env, obj, allowSuField, profile.allow_su);
    } else {
        GetEnvironment()->SetBooleanField(env, obj, nonRootUseDefaultField, profile.nrp_config.use_default);
        GetEnvironment()->SetBooleanField(env, obj, umountModulesField, profile.nrp_config.profile.umount_modules);
    }

    return obj;
}

NativeBridge(setAppProfile, jboolean, jobject profile) {
    jclass cls = GetEnvironment()->FindClass(env, "com/sukisu/ultra/Natives$Profile");

    jfieldID keyField = GetEnvironment()->GetFieldID(env, cls, "name", "Ljava/lang/String;");
    jfieldID currentUidField = GetEnvironment()->GetFieldID(env, cls, "currentUid", "I");
    jfieldID allowSuField = GetEnvironment()->GetFieldID(env, cls, "allowSu", "Z");

    jfieldID rootUseDefaultField = GetEnvironment()->GetFieldID(env, cls, "rootUseDefault", "Z");
    jfieldID rootTemplateField = GetEnvironment()->GetFieldID(env, cls, "rootTemplate", "Ljava/lang/String;");

    jfieldID uidField = GetEnvironment()->GetFieldID(env, cls, "uid", "I");
    jfieldID gidField = GetEnvironment()->GetFieldID(env, cls, "gid", "I");
    jfieldID groupsField = GetEnvironment()->GetFieldID(env, cls, "groups", "Ljava/util/List;");
    jfieldID capabilitiesField = GetEnvironment()->GetFieldID(env, cls, "capabilities", "Ljava/util/List;");
    jfieldID domainField = GetEnvironment()->GetFieldID(env, cls, "context", "Ljava/lang/String;");
    jfieldID namespacesField = GetEnvironment()->GetFieldID(env, cls, "namespace", "I");

    jfieldID nonRootUseDefaultField = GetEnvironment()->GetFieldID(env, cls, "nonRootUseDefault", "Z");
    jfieldID umountModulesField = GetEnvironment()->GetFieldID(env, cls, "umountModules", "Z");

    jobject key = GetEnvironment()->GetObjectField(env, profile, keyField);
    if (!key) {
        return false;
    }
    if (GetEnvironment()->GetStringLength(env, (jstring) key) > KSU_MAX_PACKAGE_NAME) {
        return false;
    }

    const char* cpkg = GetEnvironment()->GetStringUTFChars(env, (jstring) key, nullptr);
    char p_key[KSU_MAX_PACKAGE_NAME] = { 0 };
    strcpy(p_key, cpkg);
    GetEnvironment()->ReleaseStringUTFChars(env, (jstring) key, cpkg);

    jint currentUid = GetEnvironment()->GetIntField(env, profile, currentUidField);

    jint uid = GetEnvironment()->GetIntField(env, profile, uidField);
    jint gid = GetEnvironment()->GetIntField(env, profile, gidField);
    jobject groups = GetEnvironment()->GetObjectField(env, profile, groupsField);
    jobject capabilities = GetEnvironment()->GetObjectField(env, profile, capabilitiesField);
    jobject domain = GetEnvironment()->GetObjectField(env, profile, domainField);
    jboolean allowSu = GetEnvironment()->GetBooleanField(env, profile, allowSuField);
    jboolean umountModules = GetEnvironment()->GetBooleanField(env, profile, umountModulesField);

    struct app_profile p = { 0 };
    p.version = KSU_APP_PROFILE_VER;

    strcpy(p.key, p_key);
    p.allow_su = allowSu;
    p.current_uid = currentUid;

    if (allowSu) {
        p.rp_config.use_default = GetEnvironment()->GetBooleanField(env, profile, rootUseDefaultField);
        jobject templateName = GetEnvironment()->GetObjectField(env, profile, rootTemplateField);
        if (templateName) {
            const char* ctemplateName = GetEnvironment()->GetStringUTFChars(env, (jstring) templateName, nullptr);
            strcpy(p.rp_config.template_name, ctemplateName);
            GetEnvironment()->ReleaseStringUTFChars(env, (jstring) templateName, ctemplateName);
        }

        p.rp_config.profile.uid = uid;
        p.rp_config.profile.gid = gid;

        int groups_count = getListSize(env, groups);
        if (groups_count > KSU_MAX_GROUPS) {
            LogDebug("groups count too large: %d", groups_count);
            return false;
        }
        p.rp_config.profile.groups_count = groups_count;
        fillArrayWithList(env, groups, p.rp_config.profile.groups, groups_count);

        p.rp_config.profile.capabilities.effective = capListToBits(env, capabilities);

        const char* cdomain = GetEnvironment()->GetStringUTFChars(env, (jstring) domain, nullptr);
        strcpy(p.rp_config.profile.selinux_domain, cdomain);
        GetEnvironment()->ReleaseStringUTFChars(env, (jstring) domain, cdomain);

        p.rp_config.profile.namespaces = GetEnvironment()->GetIntField(env, profile, namespacesField);
    } else {
        p.nrp_config.use_default = GetEnvironment()->GetBooleanField(env, profile, nonRootUseDefaultField);
        p.nrp_config.profile.umount_modules = umountModules;
    }

    return set_app_profile(&p);
}

NativeBridge(uidShouldUmount, jboolean, jint uid) {
    return uid_should_umount(uid);
}

NativeBridgeNP(isSuEnabled, jboolean) {
    return is_su_enabled();
}

NativeBridge(setSuEnabled, jboolean, jboolean enabled) {
    return set_su_enabled(enabled);
}

// Check if KPM is enabled
NativeBridgeNP(isKPMEnabled, jboolean) {
    return is_KPM_enable();
}

// Get HOOK type
NativeBridgeNP(getHookType, jstring) {
    char hook_type[16];
    get_hook_type(hook_type, sizeof(hook_type));
    return GetEnvironment()->NewStringUTF(env, hook_type);
}

// dynamic manager
NativeBridge(setDynamicManager, jboolean, jint size, jstring hash) {
    if (!hash) {
        LogDebug("setDynamicManager: hash is null");
        return false;
    }

    const char* chash = GetEnvironment()->GetStringUTFChars(env, hash, nullptr);
    bool result = set_dynamic_manager((unsigned int)size, chash);
    GetEnvironment()->ReleaseStringUTFChars(env, hash, chash);

    LogDebug("setDynamicManager: size=0x%x, result=%d", size, result);
    return result;
}

NativeBridgeNP(getDynamicManager, jobject) {
    struct dynamic_manager_user_config config;
    bool result = get_dynamic_manager(&config);

    if (!result) {
        LogDebug("getDynamicManager: failed to get dynamic manager config");
        return NULL;
    }

    jobject obj = CREATE_JAVA_OBJECT("com/sukisu/ultra/Natives$DynamicManagerConfig");
    jclass cls = GetEnvironment()->FindClass(env, "com/sukisu/ultra/Natives$DynamicManagerConfig");

    SET_INT_FIELD(obj, cls, size, (jint)config.size);
    SET_STRING_FIELD(obj, cls, hash, config.hash);

    LogDebug("getDynamicManager: size=0x%x, hash=%.16s...", config.size, config.hash);
    return obj;
}

NativeBridgeNP(clearDynamicManager, jboolean) {
    bool result = clear_dynamic_manager();
    LogDebug("clearDynamicManager: result=%d", result);
    return result;
}

// Get a list of active managers
NativeBridgeNP(getManagersList, jobject) {
    struct manager_list_info managerListInfo;
    bool result = get_managers_list(&managerListInfo);

    if (!result) {
        LogDebug("getManagersList: failed to get active managers list");
        return NULL;
    }

    jobject obj = CREATE_JAVA_OBJECT("com/sukisu/ultra/Natives$ManagersList");
    jclass managerListCls = GetEnvironment()->FindClass(env, "com/sukisu/ultra/Natives$ManagersList");

    SET_INT_FIELD(obj, managerListCls, count, (jint)managerListInfo.count);

    jobject managersList = CREATE_ARRAYLIST();

    for (int i = 0; i < managerListInfo.count; i++) {
        jobject managerInfo = CREATE_JAVA_OBJECT_WITH_PARAMS(
                "com/sukisu/ultra/Natives$ManagerInfo",
                "(II)V",
                (jint)managerListInfo.managers[i].uid,
                (jint)managerListInfo.managers[i].signature_index
        );
        ADD_TO_LIST(managersList, managerInfo);
    }

    SET_OBJECT_FIELD(obj, managerListCls, managers, managersList);

    LogDebug("getManagersList: count=%d", managerListInfo.count);
    return obj;
}

NativeBridge(verifyModuleSignature, jboolean, jstring modulePath) {
#if defined(__aarch64__) || defined(_M_ARM64) || defined(__arm__) || defined(_M_ARM)
    if (!modulePath) {
        LogDebug("verifyModuleSignature: modulePath is null");
        return false;
    }

    const char* cModulePath = GetEnvironment()->GetStringUTFChars(env, modulePath, nullptr);
    bool result = verify_module_signature(cModulePath);
    GetEnvironment()->ReleaseStringUTFChars(env, modulePath, cModulePath);

    LogDebug("verifyModuleSignature: path=%s, result=%d", cModulePath, result);
    return result;
#else
    LogDebug("verifyModuleSignature: not supported on non-ARM architecture");
    return false;
#endif
}

NativeBridgeNP(isUidScannerEnabled, jboolean) {
    return is_uid_scanner_enabled();
}

NativeBridge(setUidScannerEnabled, jboolean, jboolean enabled) {
    return set_uid_scanner_enabled(enabled);
}

NativeBridgeNP(clearUidScannerEnvironment, jboolean) {
    return clear_uid_scanner_environment();
}