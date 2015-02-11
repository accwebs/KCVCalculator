//----------------------------------------------------------------------
// See KeyUtils.h
//----------------------------------------------------------------------

#include "KeyUtils.h"

#include "CryptoUtils.h"

#include <stdexcept>
#include <sstream>

//----------------------------------------------------------------------
// PUBLIC STATIC
// Computes the "Key Check" value for a 16-byte 3DES key.
// (Computes the GP KCV.)
VKey KeyUtils::ComputeKeyCheck(VKey key){
    if (key.size() != 16){
        throw std::runtime_error("VKey is incorrect size.");
    }
    
    byte keyCheckValue_calculated_bytes[KEY_SIZE + 8];
    int keyCheckValue_calculated_length = KEY_SIZE + 8;
    byte keyCheckTest[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    
    // calculate key check value for decrypted key
    bool status = CryptoUtils::calculate_enc_ecb_two_key_triple_des(&key.at(0), keyCheckTest, 8, keyCheckValue_calculated_bytes, &keyCheckValue_calculated_length);
    if (status == false){
        throw std::runtime_error("Unable to calculate key check value.");
    }

    // convert to vector and return
    VKey keyCheckValue_calculated(keyCheckValue_calculated_bytes, keyCheckValue_calculated_bytes + 3);
    return keyCheckValue_calculated;
}

//----------------------------------------------------------------------
// PUBLIC STATIC
// Computes the "Key Check" value for a 16-byte 3DES key.
// (Computes the "tkstool" KCV.)
VKey KeyUtils::ComputeKeyCheck_Tkstool(VKey key){
  if (key.size() != 16){
    throw std::runtime_error("VKey is incorrect size.");
  }

  byte keyCheckValue_calculated_bytes[KEY_SIZE + 8];
  int keyCheckValue_calculated_length = KEY_SIZE + 8;
  byte keyCheckTest[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  // calculate key check value for decrypted key
  bool status = CryptoUtils::calculate_enc_ecb_two_key_triple_des(&key.at(0), keyCheckTest, 8, keyCheckValue_calculated_bytes, &keyCheckValue_calculated_length);
  if (status == false){
    throw std::runtime_error("Unable to calculate key check value.");
  }

  // convert to vector and return
  VKey keyCheckValue_calculated(keyCheckValue_calculated_bytes, keyCheckValue_calculated_bytes + 4);
  return keyCheckValue_calculated;
}

//----------------------------------------------------------------------
