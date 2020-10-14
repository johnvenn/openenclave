#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/modes.h>
#include <openenclave/internal/sgx/pcl_common.h>
#include "pcl_internal.h"
#include "pcl_crypto_internal.h"
/*
 * Porting to OpenEnclave SDK:
 * the version of openssl used in OE SDK should be upgraded to 1.1.1h
 * decryption/encryption functions here should support APIs both from
 * openssl or mbedtls lib(to be investigated)
 */

/*
 * @func pcl_gcm_decrypt applies AES-GCM-128
 * @param OUT uint8_t* plaintext, input plain text buffer
 * @param IN uint8_t* ciphertext, output cipher text buffer
 * @param size_t textlen, size of buffer in bytes
 * @param IN uint8_t* aad, aditional authenticated data
 * @param size_t aad_len, size of aditional authenticated data
 * @param IN uint8_t* key, 16 bytes decryption key
 * @param IN uint8_t* iv, 12 bytes IV
 * @param IN uint8_t* tag, 16 bytes TAG result
 * @return sgx_status_t
 * SGX_ERROR_INVALID_PARAMETER if any pointer is NULL except for aad
 * SGX_ERROR_UNEXPECTED if any of the following functions fail: 
 * pcl_vpaes_set_encrypt_key, pcl_CRYPTO_gcm128_aad or pcl_CRYPTO_gcm128_decrypt
 * SGX_ERROR_PCL_MAC_MISMATCH if MAC mismatch when calling pcl_CRYPTO_gcm128_finish
 * SGX_SUCCESS if successfull
 */
oe_result_t pcl_gcm_decrypt(
                OUT uint8_t* plaintext, 
                IN uint8_t* ciphertext, 
                size_t textlen,
                IN uint8_t* aad, 
                size_t aad_len, 
                IN uint8_t* key, 
                IN uint8_t* iv, 
                IN uint8_t* tag)
{
    oe_result_t ret_status = OE_FAILURE;
    
    if( NULL == plaintext  ||
        NULL == ciphertext ||
        NULL == key        || 
        NULL == iv         ||
        NULL == tag)
    {
        return OE_FAILURE;
    }


#if 0
    AES_KEY wide_key = {.rd_key={},.rounds=0};
    GCM128_CONTEXT gcm_ctx;

    int ret = AES_set_encrypt_key(key, PCL_AES_BLOCK_LEN_BITS, &wide_key);
    if(0 != ret)
    {
        ret_status = OE_FAILURE;
        goto Label_zero_wide_key;
    }

    CRYPTO_gcm128_init(&gcm_ctx, &wide_key, (block128_f)AES_encrypt);

    CRYPTO_gcm128_setiv(&gcm_ctx, iv, SGX_AESGCM_IV_SIZE);

    if(NULL != aad)
    {
        ret = CRYPTO_gcm128_aad(&gcm_ctx, aad, aad_len);
        if(0 != ret)
        {
            ret_status = OE_FAILURE;
            goto Label_zero_buffers;
        }
    }

    ret = CRYPTO_gcm128_decrypt(
                &gcm_ctx,
                ciphertext,
                plaintext,
                textlen);
    if(0 != ret)
    {
        ret_status = OE_FAILURE;
        goto Label_zero_buffers;
    }

    ret = CRYPTO_gcm128_finish(&gcm_ctx, tag, SGX_CMAC_MAC_SIZE);
    if(0 != ret)
    {
        ret_status =  OE_ERROR_PCL_MAC_MISMATCH;
        goto Label_zero_buffers;
    }

	
    ret_status = OE_OK;

    // Scrab secrets from stack:
Label_zero_buffers:
    pcl_volatile_memset((volatile void*)(&gcm_ctx), 0, sizeof(gcm_ctx));
Label_zero_wide_key:
    pcl_volatile_memset((volatile void*)(&wide_key), 0, sizeof(wide_key));

    return ret_status;










#endif // legacy functions






#if 1  // using EVP cipher
	EVP_CIPHER_CTX *ctx;
    int len;

	if (!(ctx = EVP_CIPHER_CTX_new()))
	{
    	ret_status = OE_FAILURE;
		goto Label_zero_wide_key;
	}
   
	/* initialize decryption operation */
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
   	{
    	ret_status = OE_FAILURE;
		goto Label_zero_wide_key;
	}
  
	/* set IV length, not necessary if this is 12 bytes(96 bits) */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 
					SGX_AESGCM_IV_SIZE, NULL))
  	{
    	ret_status = OE_FAILURE;
		goto Label_zero_wide_key;
	}

	/* initialize key and iv */
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) 
	{
    	ret_status = OE_FAILURE;
		goto Label_zero_wide_key;
	}

	/* provide any AAD data. This can be called zero or 
	 * more times as required
	 */
	if (NULL != aad) 
	{
		if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) 
		{
			ret_status = OE_FAILURE;
			goto Label_zero_wide_key;
		}
	}

	/* provide the message to be decrypted, obtain the plaintext output
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, textlen))
    {
        ret_status = OE_FAILURE;
        goto Label_zero_buffers;
    }
   
	/* set expected tag value, works in openssl 1.0.1d and later */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 
					SGX_CMAC_MAC_SIZE, tag))
    {
        ret_status =  OE_ERROR_PCL_MAC_MISMATCH;
        goto Label_zero_buffers;
    }
   
	/* Finalize the decryption. A positive return value indicates 
	 * success, anything else is a failure -- the plaintext is not
	 * trustworthy
	 */
	if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0)
	{
        ret_status =  OE_ERROR_PCL_MAC_MISMATCH;
        goto Label_zero_buffers;
    }

    ret_status = OE_OK;
    
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

    // Scrab secrets from stack:
Label_zero_buffers:
    //pcl_volatile_memset((volatile void*)(&gcm_ctx), 0, sizeof(gcm_ctx));
Label_zero_wide_key:
    //pcl_volatile_memset((volatile void*)(&wide_key), 0, sizeof(wide_key));

    return ret_status;
#endif // Using EVP cipher
}

/*
 * @func pcl_sha256 calculates the payload SHA256
 * @param IN uint8_t* buf, payload buffer
 * @param size_t buflen, buffer size in bytes
 * @param OUT uint8_t* hash, SHA256 result
 */
oe_result_t pcl_sha256(IN uint8_t* buf, size_t buflen, OUT uint8_t* hash)
{
    if(NULL == buf || NULL == hash)
    {
        return OE_FAILURE;
    }
    
    SHA256_CTX sha256;
    
    SHA256_Init(&sha256);
    
    SHA256_Update(&sha256, buf, buflen);
    
    SHA256_Final(hash, &sha256);
    
    pcl_volatile_memset((volatile void*)(&sha256), 0, sizeof(SHA256_CTX));
    
    return OE_OK;
}

#ifdef SE_SIM

/*
 * @func pcl_cmac calcualtes CMAC-128 on payload
 * @param IN const sgx_cmac_128bit_key_t *p_key, CMAC key
 * @param IN const uint8_t *p_src, input buffer
 * @param uint32_t src_len, buffer size in bytes
 * @param OUT sgx_cmac_128bit_tag_t *p_mac, 16 bytes resulting MAC
 * @return int, -1 if p_key, p_src or p_mac are NULL, 0 if success
 */
int pcl_cmac(
    const sgx_cmac_128bit_key_t *p_key, 
    const uint8_t *p_src,
    uint32_t src_len,
    sgx_cmac_128bit_tag_t *p_mac)
{
    if(NULL == p_key || NULL == p_src || NULL == p_mac)
    {
        return -1;
    }
    unsigned char iv[PCL_COUNTER_SIZE] = { 0 };
    unsigned char aux[PCL_AES_BLOCK_LEN] = { 0 };
    unsigned char k1[PCL_AES_BLOCK_LEN] = { 0 };

    AES_KEY wide_key = {.rd_key={},.rounds=0};
    pcl_vpaes_set_encrypt_key((const unsigned char *)p_key, PCL_AES_BLOCK_LEN_BITS, &wide_key);
    
    // Apply AES-CBC encrypt on input = 0^16 and IV = 0^16: 
    pcl_vpaes_cbc_encrypt(iv, aux, PCL_AES_BLOCK_LEN, &wide_key, iv, 1);
    
    // Use result to generate K1:
    make_kn(k1, aux, PCL_AES_BLOCK_LEN);
    
    // Digest message except for last block:
    pcl_memset(iv, 0, PCL_COUNTER_SIZE);
    while(src_len >  PCL_AES_BLOCK_LEN)
    {
        pcl_vpaes_cbc_encrypt((uint8_t *)p_src, aux, PCL_AES_BLOCK_LEN, &wide_key, iv, 1);
        src_len -= PCL_AES_BLOCK_LEN;
        p_src += PCL_AES_BLOCK_LEN;
    }
    
    
    // XOR K1 with last block of message: 
    for (int i = 0; i < PCL_AES_BLOCK_LEN; i++)aux[i] = p_src[i] ^ k1[i];
        
    // Apply AES-CBC encrypt on result and IV
    pcl_vpaes_cbc_encrypt(aux, (uint8_t*)p_mac, PCL_AES_BLOCK_LEN, &wide_key, iv, 1);
    return 0;
}

#endif // #ifdef SE_SIM

