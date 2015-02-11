//----------------------------------------------------------------------
// Defines a class "KeyUtils" containing various static key utilility methods.
//----------------------------------------------------------------------

#ifndef KeyUtilsH_Included
#define KeyUtilsH_Included

//----------------------------------------------------------------------

class KeyUtils;

//----------------------------------------------------------------------

#include <cstddef>
#include "VKey.h"

//----------------------------------------------------------------------

class KeyUtils{
    public:
      // size of the various GP master keys
      static const size_t KEY_SIZE = 16;
    
    private:
        // prevent instantiation, copying, and assignment
        KeyUtils();
        virtual ~KeyUtils();
        KeyUtils(const KeyUtils& src);
        KeyUtils operator=(const KeyUtils& rhs);

    public:
        // Computes the "Key Check" value for a 16-byte 3DES key.
        // (Computes the GP KCV.)
        static VKey ComputeKeyCheck(VKey key);
        
        // Computes the "Key Check" value for a 16-byte 3DES key.
        // (Computes the "tkstool" KCV.)
        static VKey ComputeKeyCheck_Tkstool(VKey key);
};

//----------------------------------------------------------------------

#endif 
