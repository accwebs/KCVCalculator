//----------------------------------------------------------------------
// Defines a class "CryptoUtils" containing various static crypto methods.
//----------------------------------------------------------------------

#ifndef CryptoUtilsH_Included
#define CryptoUtilsH_Included

//----------------------------------------------------------------------

class CryptoUtils;

//----------------------------------------------------------------------

typedef unsigned char byte;

//----------------------------------------------------------------------

class CryptoUtils{
    private:
        // prevent instantiation, copying, and assignment
        CryptoUtils();
        virtual ~CryptoUtils();
        CryptoUtils(const CryptoUtils& src);
        CryptoUtils operator=(const CryptoUtils& rhs);

    public:
        static const byte padding[8];
        static const byte icv[8];

        // Encrypts a block of ciphertext with the specified key.
        // Copied from GlobalPlatform library's crypto.c
        static bool calculate_enc_ecb_two_key_triple_des(byte key[16], byte *message, int messageLength, byte *encryption, int *encryptionLength);

        // Decrypts a block of ciphertext with the specified key.
        // Copied from GlobalPlatform library's crypto.c - calculate_enc_ecb_two_key_triple_des() and modified.
        static bool calculate_dec_ecb_two_key_triple_des(byte key[16], byte *message, int messageLength, byte *decryption, int *decryptionLength);

        // Decrypts a block of ciphertext with the specified key.
        // Copied from GlobalPlatform library's crypto.c - calculate_enc_cbc() and modified.
        static bool calculate_dec_cbc(byte key[16], byte message[], int messageLength, byte *decryption, int *decryptionLength);

        // Decrypts a block of ciphertext with the specified key.
        // Copied from GlobalPlatform library's crypto.c - calculate_enc_ecb_two_key_triple_des() and modified.
        static bool calculate_dec_cbc_two_key_triple_des(byte key[16], byte IV[8], byte *message, int messageLength, byte *decryption, int *decryptionLength);
};

//----------------------------------------------------------------------

#endif 
