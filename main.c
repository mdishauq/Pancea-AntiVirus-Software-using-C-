#include <stdio.h>
#include <windows.h>
#include <string.h>
#include "malware.h"
#include <stdlib.h>
#include <stdbool.h>

#define READ_BUFFER_SIZE 4096
#define MAX_PATH_LENGTH 1024

/* Global counters */
static int total_files = 0;
static int total_threats = 0;

int scan_directory(const char *base_path);

int main(int argc, char *argv[]) {

    char path[MAX_PATH_LENGTH];

    if (argc > 1) {
        strncpy(path, argv[1], MAX_PATH_LENGTH - 1);
        path[MAX_PATH_LENGTH - 1] = '\0';
    } else {
        printf("Enter directory path to scan: ");
        if (fgets(path, sizeof(path), stdin) == NULL) {
            printf("Input failed.\n");
            return 1;
        }
        path[strcspn(path, "\r\n")] = '\0';
    }

    if (path[0] == '\0') {
        printf("Invalid path.\n");
        return 1;
    }

    printf("\n=== PANACEA Antivirus Scanner ===\n");
    printf("Scanning path: %s\n\n", path);

    scan_directory(path);

    printf("\n=== Scan Summary ===\n");
    printf("Files scanned   : %d\n", total_files);
    printf("Threats detected: %d\n", total_threats);
    printf("====================\n");

    return 0;
}

int scan_directory(const char *base_path) {

    char search_path[MAX_PATH_LENGTH];
    snprintf(search_path, sizeof(search_path), "%s\\*", base_path);

    WIN32_FIND_DATAA finddata;
    HANDLE handle = FindFirstFileA(search_path, &finddata);

    if (handle == INVALID_HANDLE_VALUE) {
        return 0;
    }

    do {
        if (strcmp(finddata.cFileName, ".") == 0 ||
            strcmp(finddata.cFileName, "..") == 0) {
            continue;
        }

        /* Handle directories (skip reparse points) */
        if ((finddata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            !(finddata.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {

            char sub_path[MAX_PATH_LENGTH];
            snprintf(sub_path, sizeof(sub_path), "%s\\%s", base_path, finddata.cFileName);
            scan_directory(sub_path);
            continue;
        }

        /* Handle files */
        if (!(finddata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {

            total_files++;

            char full_path[MAX_PATH_LENGTH];
            snprintf(full_path, sizeof(full_path), "%s\\%s", base_path, finddata.cFileName);

            FILE *file = fopen(full_path, "rb");
            if (!file) {
                printf("[WARN] Could not open file: %s\n", full_path);
                continue;
            }

            unsigned char data[READ_BUFFER_SIZE];
            size_t bytes_read;
            bool malware_detected = false;

            size_t max_len = get_max_signature_length();
            size_t carry_size = max_len - 1;

            unsigned char carry_store[carry_size];
            size_t carry_len = 0;

            while ((bytes_read = fread(data, 1, READ_BUFFER_SIZE, file)) > 0) {

                size_t combined_len = carry_len + bytes_read;
                unsigned char combined_buffer[combined_len];

                memcpy(combined_buffer, carry_store, carry_len);
                memcpy(combined_buffer + carry_len, data, bytes_read);

                for (size_t sig = 0; sig < SIGNATURE_COUNT; sig++) {

                    const unsigned char *pattern = signature_db[sig].pattern;
                    size_t pattern_len = signature_db[sig].length;

                    if (combined_len < pattern_len)
                        continue;

                    for (size_t i = 0; i <= combined_len - pattern_len; i++) {
                        if (memcmp(combined_buffer + i, pattern, pattern_len) == 0) {
                            printf("[DETECTED] %-25s -> %s\n",
                                   signature_db[sig].name,
                                   full_path);
                            total_threats++;
                            malware_detected = true;
                            break;
                        }
                    }

                    if (malware_detected)
                        break;
                }

                /* Update carry buffer */
                if (combined_len >= carry_size) {
                    memcpy(carry_store,
                           combined_buffer + combined_len - carry_size,
                           carry_size);
                    carry_len = carry_size;
                } else {
                    memcpy(carry_store, combined_buffer, combined_len);
                    carry_len = combined_len;
                }

                if (malware_detected)
                    break;
            }

            fclose(file);
        }

    } while (FindNextFileA(handle, &finddata));

    FindClose(handle);
    return 0;
}
