#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>

#define KERNEL_SU_OPTION 0xDEADBEEF

// Command definitions
#define CMD_SUSFS_SHOW_VERSION 0x555e1
#define CMD_SUSFS_SHOW_ENABLED_FEATURES 0x555e2
#define CMD_SUSFS_SHOW_VARIANT 0x555e3
#define CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE 0x555e4
#define CMD_SUSFS_IS_SUS_SU_READY 0x555f0
#define CMD_SUSFS_SUS_SU 0x60000

// SUS_SU modes
#define SUS_SU_DISABLED 0
#define SUS_SU_WITH_HOOKS 2

struct st_sus_su {
    int mode;
};

// Function prototypes
int enable_sus_su(int last_working_mode, int target_working_mode);
int get_sus_su_working_mode(int* mode);

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <support|version|variant|features|sus_su <0|2|mode>>\n", argv[0]);
        return 1;
    }

    int error = -1;

    if (strcmp(argv[1], "version") == 0) {
        char version[16];
        prctl(KERNEL_SU_OPTION, CMD_SUSFS_SHOW_VERSION, version, NULL, &error);
        printf("%s\n", error ? "Invalid" : version);
    } else if (strcmp(argv[1], "variant") == 0) {
        char variant[16];
        prctl(KERNEL_SU_OPTION, CMD_SUSFS_SHOW_VARIANT, variant, NULL, &error);
        printf("%s\n", error ? "Invalid" : variant);
    } else if (strcmp(argv[1], "features") == 0) {
        char *enabled_features;
        size_t bufsize = getpagesize() * 2;
        enabled_features = (char *)malloc(bufsize);
        if (!enabled_features) {
            perror("malloc");
            return -ENOMEM;
        }
        prctl(KERNEL_SU_OPTION, CMD_SUSFS_SHOW_ENABLED_FEATURES, enabled_features, bufsize, &error);
        if (!error) {
            printf("%s", enabled_features);
        } else {
            printf("Invalid\n");
        }
        free(enabled_features);
    } else if (strcmp(argv[1], "support") == 0) {
        char *enabled_features;
        size_t bufsize = getpagesize() * 2;
        enabled_features = (char *)malloc(bufsize);
        if (!enabled_features) {
            perror("malloc");
            return -ENOMEM;
        }
        prctl(KERNEL_SU_OPTION, CMD_SUSFS_SHOW_ENABLED_FEATURES, enabled_features, bufsize, &error);
        printf("%s\n", error || !strlen(enabled_features) ? "Unsupported" : "Supported");
        free(enabled_features);
    } else if (argc == 3 && strcmp(argv[1], "sus_su") == 0) {
        int last_working_mode, target_working_mode;
        char* endptr;

        if (get_sus_su_working_mode(&last_working_mode)) {
            return 1;
        }

        if (strcmp(argv[2], "mode") == 0) {
            printf("%d\n", last_working_mode);
            return 0;
        }

        target_working_mode = strtol(argv[2], &endptr, 10);
        if (*endptr != '\0') {
            fprintf(stderr, "Invalid argument: %s\n", argv[2]);
            return 1;
        }

        if (target_working_mode == SUS_SU_WITH_HOOKS) {
            bool is_sus_su_ready;
            prctl(KERNEL_SU_OPTION, CMD_SUSFS_IS_SUS_SU_READY, &is_sus_su_ready, NULL, &error);
            if (error || !is_sus_su_ready) {
                printf("[-] sus_su mode %d must be run during or after service stage\n", SUS_SU_WITH_HOOKS);
                return 1;
            }
            if (last_working_mode == SUS_SU_WITH_HOOKS) {
                printf("[-] sus_su is already in mode %d\n", last_working_mode);
                return 1;
            }
            enable_sus_su(last_working_mode, SUS_SU_WITH_HOOKS);
        } else if (target_working_mode == SUS_SU_DISABLED) {
            if (last_working_mode == SUS_SU_DISABLED) {
                printf("[-] sus_su is already in mode %d\n", last_working_mode);
                return 1;
            }
            enable_sus_su(last_working_mode, SUS_SU_DISABLED);
        } else {
            fprintf(stderr, "Invalid mode: %d\n", target_working_mode);
            return 1;
        }
    } else {
        fprintf(stderr, "Invalid argument: %s\n", argv[1]);
        return 1;
    }

    return 0;
}

// Helper functions
int enable_sus_su(int last_working_mode, int target_working_mode) {
    struct st_sus_su info = {target_working_mode};
    int error = -1;
    prctl(KERNEL_SU_OPTION, CMD_SUSFS_SUS_SU, &info, NULL, &error);
    if (!error) {
        printf("[+] sus_su mode %d is enabled\n", target_working_mode);
    }
    return error;
}

int get_sus_su_working_mode(int* mode) {
    int error = -1;
    prctl(KERNEL_SU_OPTION, CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE, mode, NULL, &error);
    return error;
}