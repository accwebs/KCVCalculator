//----------------------------------------------------------------------
// KCVCalculator - A simple command line tool that calculates the Key Check Values (KCVs)
//                 for Global Platform and Red Hat Certificate System's \'tkstool\'.
//
// Written by Aaron Curley
//----------------------------------------------------------------------

#ifndef KCVCalculator_H_Included
#define KCVCalculator_H_Included

//----------------------------------------------------------------------
// includes
#include <string>
#include <vector>
#include "VKey.h"

//----------------------------------------------------------------------
// program constants
const std::string PROGRAM_NAME("KCVCalculator");
const std::string PROGRAM_EXECUTABLE("KCVCalculator.exe");
const std::string PROGRAM_VERSION("1.1");
const std::string PROGRAM_DESCRIPTION(std::string("A simple command line tool that calculates the Key Check Values (KCVs)\n") + 
                                                  "for Global Platform and Red Hat Certificate System's \'tkstool\'.");

//----------------------------------------------------------------------
// prototypes
int main(int argc, const char** const argv);

// Converts a string of ASCII-encoded hex to a byte array.
std::vector<byte> Convert_ASCIIHex_To_Byte(std::string str);

// removes any comments from a string of text
//   only searches for // comments
void Strip_Comments(std::string& line);

// replaces all instances of a string with a new string
void StringReplaceAll(std::string& str, const std::string& from, const std::string& to);

// converts a byte vector to a hexadecimal string in the form of AA:BB:CC:etc
std::string Bytes_To_String(const std::vector<byte>& v);

//----------------------------------------------------------------------

#endif