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

In enclave make file, the enclave should link to a static lib "liboepcl.a",
and then using oeenrypt tool to encrypt the enclave image right before
signing process.
**** TO be done****
add encryption command line here


Enclave Load-time:
On Enclave Load time, if the image is encrypted, it need to be decrypted 
inside enclave loader, this step is invisible to user. But the decryption 
key is required for the enclave loader to decrypt the encrypted enclave. 
**** To be done *****
add decryption flow here


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
A PCL table entry (a section called ".pcltbl" in ELF file)is built into the Enclave image by 
linking to PCL lib, this part contains enclave decryption info on enclave loading and must 
remain plaintext

Definition of PCL entry:
typedef struct pcl_table_t_
{
    pcl_status_e pcl_state;                   // Current state of PCL
    uint32_t     reserved1[3];                // Must be 0
    uint8_t      pcl_guid[SGX_PCL_GUID_SIZE]; // GUID must match GUID in Sealed blob
    size_t       sealed_blob_size;            // Size of selaed blob
    uint32_t     reserved2[2];                // Must be 0
    uint8_t      sealed_blob[PCL_SEALED_BLOB_SIZE]; // For security, sealed blob is copied into enclave
    uint8_t      decryption_key_hash[SGX_SHA256_HASH_SIZE]; // SHA256 digest of decryption key
    uint32_t     num_rvas;                    // Number of RVAs
    uint32_t     reserved3[3];                // Must be 0
    rva_size_tag_iv_t rvas_sizes_tags_ivs[PCL_MAX_NUM_ENCRYPTED_SECTIONS]; // Array of rva_size_tag_iv_t
}pcl_table_t;


### Sections left plaintext
1. ELF header  - binary header
2. Sections table
3. Segments table
4. Sections' names string table pointed by e_shstrndx(e.g. .shstrtab)
5. .oeinfo section holds enclave's metadata(properties)
6. .bss and .tbss
7. sections required to construct dyn_info (.dynamic)
8. sections holds the content provided by entries with index DT_SYMTAB, DT_STRTAB and DT_REL in
   dyn_info (e.g. .dynsym, .dynstr, .rela.dyn)
9. sections containing PCL code and data:
   a. section ".pcltbl"  // Designated section for PCL table
   b. .nipx, .nipd, .niprod, .nipd_rel, .nipd_rel_ro_local(******to be verified*****)
10. sections for debugging
   .comment, .debug_abbrev, .debug_aranges, .debug_info, .debug_line, .debug_lc, .debug_ranges,
   .debug_str
   compiler.version_d?(****** to be verified ******)

## Encryption Algorithms in Protected Code Loader
Using AES-128-GCM as the encryption/decryption algorithm, currently from openssl lib,
upon enclave loading, may consider switch to mbedtls lib in OE SDK.

## Deliver the Encryption Key in a secure way
On protecting the IP sections in enclave image, a key is required for encryption in the host and for 
decryption in enclave. The key should be delivered in a secure way using sealing/unsealing functions 
in host(sealing), in enclave(unsealing). ISV should be responsible for this part by themselves or obtain
the encryption/decryption key by Open Enclave's Remote Attestation. For Protected Code Loader itself,
we can provide an open feed for the ISVs to feed their own sealing/unsealing functions in host 
encryption tool and decryption part in enclave. This need to be considered in another seperate topic. 
We can also refer to Open Enclave's current data-sealing sample. 

## new arguments, APIs and libs
### Encryption tool
new tool for ELF image encryption - oeencrypt: placed in OESDK installation folder as the bin files
new lib for section ".pcltbl" and decryption -- liboepcl.a: placed in OESDK installation folderd
as the lib files

### Modifications to OE SDK runtime lib
No new API is needed.
A new setting is defined in include/openenclave/host.h as the argument to support
protected code loader enclave loading in API oe_create_enclave.
uint8_t *sealed_blob is defined as new member for each instance oe_enclave_t.
oe_enclave_ecall_ms_t is defined as the arg_in of ecall on the 1st time of initializing an encrypted
enclave.
new lib for section ".pcltbl" and decryption -- liboepcl.a: placed in OESDK installation folderd
as the lib files

### PCL Sample Code
A Sample Code project will be provided in samples for how to use Protected Code Loader.

## Debugging consideration when user launches an Encrypted Enclave
Debugging with oegdb should work reguarly with a minor disclaimer: you can insert break points in
the IP code but these breakpoints in IP code must be disabled while the Protected Code Loader is
running.
Problem description: When User adds a breakpoint oegdb modifies the code, if modification is
inside the cipher-text binary then when AES-GCM is applied the tag result will not match.

After PCL flow is done, breakpoints can be added and debuuging can continue regularly.

Solution: ISV should be able to choose when host attaches the debugger:
1. Default: debugger shall be attached after PCL flow is done.
2. For PCL and early trusted runtime development: debugger shall be attached before the first
instruction inside an enclave


# Alternatives
1. Open Enclave Protected Code Loader in currently implementation baked encryption into enclave image.

# Authors

- Xiangping Ji (@jixiangp)
