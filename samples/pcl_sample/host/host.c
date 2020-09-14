// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>

// Include the untrusted helloworld header that is generated
// during the build. This file is generated by calling the
// sdk tool oeedger8r against the helloworld.edl file.
#include "helloworld_u.h"

bool check_simulate_opt(int* argc, const char* argv[])
{
    for (int i = 0; i < *argc; i++)
    {
        if (strcmp(argv[i], "--simulate") == 0)
        {
            fprintf(stdout, "Running in simulation mode\n");
            memmove(&argv[i], &argv[i + 1], (*argc - i) * sizeof(char*));
            (*argc)--;
            return true;
        }
    }
    return false;
}

// This is the function that the enclave will call back into to
// print a message.
void host_helloworld()
{
    fprintf(stdout, "Enclave called into host to print: Hello World!\n");
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    int ret = 1;
    oe_enclave_t* enclave = NULL;

    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    if (check_simulate_opt(&argc, argv))
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }

    if (argc != 2)
    {
        fprintf(
            stderr, "Usage: %s enclave_image_path [ --simulate  ]\n", argv[0]);
        goto exit;
    }

    uint8_t* sealed_blob = NULL;
    FILE* fsealp = fopen("sealed_key.bin", "rb");
    size_t sealed_blob_size = 0;
    if (NULL != fsealp)
    {
        // Read file size:
        fseek(fsealp, 0L, SEEK_END);
        sealed_blob_size = ftell(fsealp);
        fseek(fsealp, 0L, SEEK_SET);
        // Read file into buffer:
        sealed_blob = new uint8_t[sealed_blob_size];
        read_num = fread(sealed_blob, 1, sealed_blob_size, fsealp);
        if (read_num != sealed_blob_size)
        {
            delete[] sealed_blob;
            sealed_blob = NULL;
            printf("Warning: Failed to read sealed blob.\n");
        }
    }
    // file operations to read the sealed blob
    oe_enclave_setting_t settings[] = {{
        .setting_type = OE_ENCLAVE_SETTING_PCL,
        .u.sealed_blob = sealed_blob,
    }};

    // Create the enclave
    result = oe_create_helloworld_enclave(
        argv[1], OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "oe_create_helloworld_enclave(): result=%u (%s)\n",
            result,
            oe_result_str(result));
        goto exit;
    }

    // Call into the enclave
    result = enclave_helloworld(enclave);
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "calling into enclave_helloworld failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
        goto exit;
    }

    ret = 0;

exit:
    // Clean up the enclave if we created one
    if (enclave)
        oe_terminate_enclave(enclave);

    return ret;
}
