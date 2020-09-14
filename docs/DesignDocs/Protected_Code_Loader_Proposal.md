Open Enclave Protected Code Loader
====

This design document proposes a utility of protecting IP sections in ELF file.


# Motivation
Current Open Enclave SDK provides code integrity and data confidentiality but 
not binary confidentiality. The signed enclave binary is in plaintext and can 
be reverse engineered to reveal code logic and secret data embedded in the 
enclave image. 

The Open Enclave Protected Code Loader shall enable providing confidentiality 
and integrity to the IP sections in enclave image, i.e. , the ELF file.

# User Experience
Build-time encryption:
When user builds their enclave image, the Open Enclave Protected Code Loader
provides an encryption tool to encrypt the ELF file before the encalve image
gets signed. 
User should deliver an encryption key to the encryption tool for encrypting.
Enclave Load-time:
On Enclave Load time, if the image is encrypted, it need to be decrypted 
inside enclave loader, this step is invisible to user. But the decryption 
key is required for the enclave loader to decrypt the encrypted enclave. 

# Specification

## Protect Code Loader Software Work Flow in Open Enclave
### Build time encryption 
    A seperate tool is provided at enclave build time to encrypt the enclave image right
    before signing process, this can ensure on creating and loading process, the code remain
    as a normal enclave image is handled, also this design doesn't affect ECREATE operation by
    sgx_common_loader 
### load time decryption
    On enclave initliazation operation(EINIT operation), right before relocation, 
    the encrypted enclave image need to be decrypted and than perform the relocation
    operation.

## Elf sections to be encrypted
relocatable sections in ELF file


## ELF sections Left plaintext
### PCL table entry 
A PCL table entry is built into the Enclave image by linking to PCL lib, this part
contains enclave decryption info on enclave loading and must remain plaintext

Definition of PCL entry:

### Other sections left plaintext


## Encryption Algorithms in Protected Code Loader
Using AES-128-GCM as the encryption/decryption algorithm, currently from openssl lib,
upon enclave loading, using sgx-ssl lib

## Deliver the Encryption Key in a secure way


## APIs and libs
oe_create_encrypted_enclave(const char *file_name)


## Debugging consideration when user launches an Encrypted Enclave



# Alternatives
1. Open Enclave Protected Code Loader in currently implementation baked encryption into enclave image.

# Authors

- Xiangping Ji (@jixiangp)
