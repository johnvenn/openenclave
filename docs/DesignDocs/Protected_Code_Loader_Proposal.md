Open Enclave Protected Code Loader
====

Enabling Enclave Code Confidentiality in Open Enclave.

# Motivation
Current Open Enclave SDK provides code integrity and data confidentiality at
run-time but not enclave binary confidentiality on a disk. The enclave binary
is in plaintext and can be reverse engineered to reveal code logic and
secret data embedded in the enclave image. 

The Open Enclave Protected Code Loader shall enable providing confidentiality 
and integrity to the IP sections in enclave image, i.e. , the ELF file.

TODO: add an svg image here to describe the encryption and decryption process.

# User Experience
## Enclave Build-time:
### Linking "liboepcl.a" to the enclave 
On building the enclave, a static lib "liboepcl.a" should be linked to the 
enclave image with the compilation option "-Wl, whole-archive"
### Encrypt the enclave image
An encryption tool is provided as the pre-step to enclave signing process:

```bash
oeencrypt -i my_enclave -o my_enclave.enc -k keyfile
```

## Enclave Load-time:
On Enclave Loading, if the image is encrypted, it need to be decrypted 
inside enclave loader, this step is done by OE SDK runtime and invisible 
to user. 

# Specification

## Protected Code Loader Software Work Flow in Open Enclave
### Build time encryption 
    A seperate tool "oeencrypt" is provided at enclave build time to encrypt 
	the enclave image right before enclave signing process.  
### Load time decryption
    On enclave initliazation operation(EINIT operation), right before relocation, 
    the encrypted enclave image need to be decrypted and than perform the relocation
    operation.

## Encryption Algorithm in Protected Code Loader
Using openssl AES-256-GCM as the encryption/decryption algorithm.

## ELF sections Left plaintext
### PCL table entry 
A PCL table entry (a section called ".pcltbl" in ELF file)is built into the Enclave 
image by linking to PCL lib, i.e. liboepcl.a, this part contains enclave decryption
info on enclave loading and must remain plaintext.

Definition of PCL entry:
typedef struct pcl_table_t_
{
	/* Current state of PCL: initailized to PCL_PLAIN */
    pcl_status_e pcl_state;                   
    uint32_t     reserved1[3];                /* Must be 0 */
	// GUID must match GUID in Sealed blob
    uint8_t      pcl_guid[SGX_PCL_GUID_SIZE]; 
    size_t       sealed_blob_size;            
    uint32_t     reserved2[2];                /* Must be 0 */
	/* For security, sealed blob is copied into enclave */
    uint8_t      sealed_blob[PCL_SEALED_BLOB_SIZE];
	/* SHA256 digest of decryption key */
    uint8_t      decryption_key_hash[SGX_SHA256_HASH_SIZE];
	/* Number of RVAs */
    uint32_t     num_rvas;                    
    uint32_t     reserved3[3];                /* Must be 0 */
	/* Array of rva_size_tag_iv_t */
    rva_size_tag_iv_t rvas_sizes_tags_ivs[PCL_MAX_NUM_ENCRYPTED_SECTIONS]; 
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
   b. .nipx, .nipd, .niprod, .nipd_rel, .nipd_rel_ro_local
10. sections for debugging
   .comment, .debug_abbrev, .debug_aranges, .debug_info, .debug_line, .debug_lc, .debug_ranges,
   .debug_str

## Elf sections to be encrypted
Sections not mentioned above are sections containing IP information that need to be protected.
Mainly those sections are:
1. Code sections -- .text in elf file
2. Data sections -- .data in elf file (initialized local/global variables)
3. Read-only Data sections -- .rodata in elf file (const variables)
4. sections containing relocation info related with the above items

## Sealing/Unsealing the decryption key
To deliver the decryption key in a secure way, the key used to encrypt the enclave should get sealed
by key policy PRODUCT
On protecting the IP sections in enclave image, a key is required for encryption in the host and for 
decryption in enclave. The key should be delivered in a secure way using sealing/unsealing functions 
in host(sealing), in enclave(unsealing). ISV should be responsible for this part by themselves or obtain
the encryption/decryption key by Open Enclave's Remote Attestation. For Protected Code Loader itself,
we can provide an open feed for the ISVs to feed their own sealing/unsealing functions in host 
encryption tool and decryption part in enclave. This need to be considered in another seperate topic. 
We can also refer to Open Enclave's current data-sealing sample. 

## new APIs and libs
### Encryption tool
new tool for ELF image encryption - oeencrypt: placed in OESDK installation folder as the bin files
new lib for section ".pcltbl" and decryption -- liboepcl.a: placed in OESDK installation folderd
as the lib files

### Modifications to OE SDK runtime lib
No new API is needed.
1. A new setting is defined in include/openenclave/host.h as the argument to support
protected code loader enclave loading in API oe_create_enclave.
	
2. uint8_t *sealed_blob is defined as new member for each instance oe_enclave_t.
3. oe_enclave_ecall_ms_t is defined as the arg_in of ecall on the 1st time of initializing an encrypted
enclave.
4. new lib for section ".pcltbl" and decryption -- liboepcl.a: placed in OESDK installation folderd
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

# Authors

- Xiangping Ji (@jixiangp)
