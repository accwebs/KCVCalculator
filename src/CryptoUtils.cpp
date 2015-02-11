//----------------------------------------------------------------------
// See CryptoUtils.h
//----------------------------------------------------------------------

#include "CryptoUtils.h"

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <cstring>

//----------------------------------------------------------------------

const byte CryptoUtils::padding[8] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //!< Applied padding pattern.
const byte CryptoUtils::icv[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}; //!< First initial chaining vector.

//----------------------------------------------------------------------
// PUBLIC STATIC
// Encrypts a block of ciphertext with the specified key.
// Copied from GlobalPlatform library's crypto.c and modified.
/**
 * Calculates the encryption of a message in ECB mode with two key triple DES.
 * Pads the message with 0x80 and additional 0x00 if message length is not a multiple of 8.
 * \param key [in] A 3DES key used to encrypt.
 * \param *message [in] The message to encrypt.
 * \param messageLength [in] The length of the message.
 * \param *encryption [out] The encryption.
 * \param *encryptionLength [out] The length of the encryption.
 * \return bool:  true if success, false if failure
 */
bool CryptoUtils::calculate_enc_ecb_two_key_triple_des(byte key[16], byte *message, int messageLength, byte *encryption, int *encryptionLength){
    int result;
    bool status = false;
    int i,outl;
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    *encryptionLength = 0;

    result = EVP_EncryptInit_ex(&ctx, EVP_des_ede(), NULL, key, icv);
    if (result != 1) {
        goto end;
    }
    EVP_CIPHER_CTX_set_padding(&ctx, 0);
    for (i=0; i<messageLength/8; i++) {
        result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
            &outl, message+i*8, 8);
        if (result != 1) {
            goto end;
        }
        *encryptionLength+=outl;
    }
    if (messageLength%8 != 0) {
        result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
            &outl, message+i*8, messageLength%8);
        if (result != 1) {
            goto end;
        }
        *encryptionLength+=outl;

        result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
            &outl, padding, 8 - (messageLength%8));
        if (result != 1) {
            goto end;
        }
        *encryptionLength+=outl;
    }
    result = EVP_EncryptFinal_ex(&ctx, encryption+*encryptionLength,
        &outl);
    if (result != 1) {
        goto end;
    }
    *encryptionLength+=outl;
    status = true;
end:

    if (EVP_CIPHER_CTX_cleanup(&ctx) != 1) {
        status = false;
    }
    return status;
}

//----------------------------------------------------------------------
// PUBLIC STATIC
// Decrypts a block of ciphertext with the specified key.
// Copied from GlobalPlatform library's crypto.c - calculate_enc_ecb_two_key_triple_des() and modified.
/**
 * Calculates the decryption of a message in ECB mode with two key triple DES.
 * Pads the message with 0x80 and additional 0x00 if message length is not a multiple of 8.
 * \param key[16] [in] A 3DES key used to decrypt.
 * \param *message [in] The message to decrypt.
 * \param messageLength [in] The length of the message.
 * \param *decryption [out] The decryption.
 * \param *decryptionLength [out] The length of the decryption.
 * \return bool:  true if success, false if failure
 */
bool CryptoUtils::calculate_dec_ecb_two_key_triple_des(byte key[16], byte *message, int messageLength, byte *decryption, int *decryptionLength){
    const byte icv[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}; //!< First initial chaining vector.
    
    int result;
    bool status = false;
    int i,outl;
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    *decryptionLength = 0;

    result = EVP_DecryptInit_ex(&ctx, EVP_des_ede(), NULL, key, icv);
    if (result != 1) {
        goto end;
    }
    EVP_CIPHER_CTX_set_padding(&ctx, 0);
    for (i=0; i<messageLength/8; i++) {
        result = EVP_DecryptUpdate(&ctx, decryption+*decryptionLength,
            &outl, message+i*8, 8);
        if (result != 1) {
            goto end;
        }
        *decryptionLength+=outl;
    }
    if (messageLength%8 != 0) {
        result = EVP_DecryptUpdate(&ctx, decryption+*decryptionLength,
            &outl, message+i*8, messageLength%8);
        if (result != 1) {
            goto end;
        }
        *decryptionLength+=outl;

        result = EVP_DecryptUpdate(&ctx, decryption+*decryptionLength,
            &outl, padding, 8 - (messageLength%8));
        if (result != 1) {
            goto end;
        }
        *decryptionLength+=outl;
    }
    result = EVP_DecryptFinal_ex(&ctx, decryption+*decryptionLength,
        &outl);
    if (result != 1) {
        goto end;
    }
    *decryptionLength+=outl;
    status = true;
end:

    if (EVP_CIPHER_CTX_cleanup(&ctx) != 1) {
        status = false;
    }
    return status;
}

//----------------------------------------------------------------------
// PUBLIC STATIC
// Decrypts a block of ciphertext with the specified key.
// Copied from GlobalPlatform library's crypto.c - calculate_enc_cbc() and modified.
//
/**
 * Calculates the decryption of a message in CBC mode.
 * Pads the message with 0x80 and additional 0x00 if message length is not a multiple of 8.
 * \param key[16] [in] A 3DES key used to decrypt.
 * \param *message [in] The message to decrypt.
 * \param messageLength [in] The length of the message.
 * \param *decryption [out] The decryption.
 * \param *decryptionLength [out] The length of the decryption.
 * \return bool:  true if success, false if failure
 */
bool CryptoUtils::calculate_dec_cbc(byte key[16], byte message[], int messageLength, byte *decryption, int *decryptionLength) {
    int result;
    bool status = false;
    int i,outl;
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    *decryptionLength = 0;

    result = EVP_DecryptInit_ex(&ctx, EVP_des_ede_cbc(), NULL, key, icv);
    if (result != 1) {
        goto end;
    }
    EVP_CIPHER_CTX_set_padding(&ctx, 0);
    for (i=0; i<messageLength/8; i++) {
        result = EVP_DecryptUpdate(&ctx, decryption+*decryptionLength,
            &outl, message+i*8, 8);
        if (result != 1) {
            goto end;
        }
        *decryptionLength+=outl;
    }
    if (messageLength%8 != 0) {
        result = EVP_DecryptUpdate(&ctx, decryption+*decryptionLength,
            &outl, message+i*8, messageLength%8);
        if (result != 1) {
            goto end;
        }
        *decryptionLength+=outl;

        result = EVP_DecryptUpdate(&ctx, decryption+*decryptionLength,
            &outl, padding, 8 - (messageLength%8));
        if (result != 1) {
            goto end;
        }
        *decryptionLength+=outl;
    }
    result = EVP_DecryptFinal_ex(&ctx, decryption+*decryptionLength,
        &outl);
    if (result != 1) {
        goto end;
    }
    *decryptionLength+=outl;
    status = true;
end:
    if (EVP_CIPHER_CTX_cleanup(&ctx) != 1) {
        status = false;
    }
    return status;
}

//----------------------------------------------------------------------
// PUBLIC STATIC
// Decrypts a block of ciphertext with the specified key and IV.
// Copied from GlobalPlatform library's crypto.c - calculate_enc_ecb_two_key_triple_des() and modified.
/**
 * Calculates the decryption of a message in CBC mode with two key triple DES.
 * Pads the message with 0x80 and additional 0x00 if message length is not a multiple of 8.
 * \param key[16] [in] A 3DES key used to decrypt.
 * \param *message [in] The message to decrypt.
 * \param messageLength [in] The length of the message.
 * \param *decryption [out] The decryption.
 * \param *decryptionLength [out] The length of the decryption.
 * \return bool:  true if success, false if failure
 */
bool CryptoUtils::calculate_dec_cbc_two_key_triple_des(byte key[16], byte IV[8], byte *message, int messageLength, byte *decryption, int *decryptionLength){
    
    int result;
    bool status = false;
    int i,outl;
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    *decryptionLength = 0;

    result = EVP_DecryptInit_ex(&ctx, EVP_des_ede_cbc(), NULL, key, IV);
    if (result != 1) {
        goto end;
    }
    EVP_CIPHER_CTX_set_padding(&ctx, 0);
    for (i=0; i<messageLength/8; i++) {
        result = EVP_DecryptUpdate(&ctx, decryption+*decryptionLength,
            &outl, message+i*8, 8);
        if (result != 1) {
            goto end;
        }
        *decryptionLength+=outl;
    }
    if (messageLength%8 != 0) {
        result = EVP_DecryptUpdate(&ctx, decryption+*decryptionLength,
            &outl, message+i*8, messageLength%8);
        if (result != 1) {
            goto end;
        }
        *decryptionLength+=outl;

        result = EVP_DecryptUpdate(&ctx, decryption+*decryptionLength,
            &outl, padding, 8 - (messageLength%8));
        if (result != 1) {
            goto end;
        }
        *decryptionLength+=outl;
    }
    result = EVP_DecryptFinal_ex(&ctx, decryption+*decryptionLength,
        &outl);
    if (result != 1) {
        goto end;
    }
    *decryptionLength+=outl;
    status = true;
end:

    if (EVP_CIPHER_CTX_cleanup(&ctx) != 1) {
        status = false;
    }
    return status;
}

//----------------------------------------------------------------------
