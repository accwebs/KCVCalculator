//----------------------------------------------------------------------
// See comments in KCVCalculator.h
//----------------------------------------------------------------------

#include "KCVCalculator.h"

//----------------------------------------------------------------------

#include <stdexcept>
#include <iostream>
#include <algorithm>
#include <sstream>
#include <iomanip>

#include "KeyUtils.h"

//----------------------------------------------------------------------
// entry point
int main(int argc, const char** const argv){
    int retcode;
    
    // if not 1 command line arguments
    if (argc != 2){
        std::cout << PROGRAM_NAME << "  -  " << PROGRAM_VERSION << std::endl;
        std::cout << PROGRAM_DESCRIPTION << std::endl;
        std::cout << std::endl;
        std::cout << "Usage:  " << PROGRAM_EXECUTABLE << " <key bytes (ASCII-hex)>" << std::endl;
        std::cout << std::endl;
        retcode = 1;
    }else{
        // print program name and version
        std::cout << PROGRAM_NAME << "  -  " << PROGRAM_VERSION << "\n" << std::endl;
        
        // convert input filename to string
        const std::string key_bytes_str(argv[1]);
        
        try{
          // try to convert input characters to byte array (the key)
          const std::vector<byte> key_bytes = Convert_ASCIIHex_To_Byte(key_bytes_str);
          
          try{
            // compute Global Platform kcv
            const std::vector<byte> gpkcv = KeyUtils::ComputeKeyCheck(key_bytes);
            
            // convert Global Platform kcv to string
            const std::string gpkcv_str = Bytes_To_String(gpkcv);
            
            // compute tkstook kcv
            const std::vector<byte> tkstoolkcv = KeyUtils::ComputeKeyCheck_Tkstool(key_bytes);
            
            // convert tkstool kcv to string
            const std::string tkstoolkcv_str = Bytes_To_String(tkstoolkcv);

            // print out kcvs
            std::cout << "GP KCV:      " << gpkcv_str << std::endl;
            std::cout << "tkstool KCV: " << tkstoolkcv_str << std::endl;
            retcode = 0;
            
          // error computing KCV
          } catch (std::runtime_error& ex){
            std::cout << "Exception thrown while computing KCV: " << ex.what();
            std::cout << std::endl;
            
            retcode = 50;
          } catch (...){
            std::cout << "Unknown exception thrown while computing KCV.";
            std::cout << std::endl;
            
            retcode = 50;
          }
          
        // error converting ASCII-hex to byte vector
        } catch (std::runtime_error& ex){
          std::cout << "Exception thrown while converting key text to bytes: " << ex.what();
          std::cout << std::endl;
          
          retcode = 1;
        } catch (...){
          std::cout << L"Unknown exception thrown while converting key text to bytes.";
          std::cout << std::endl;
          
          retcode = 1;
        }
        
    } // endif arguments are correct

    return retcode;
}

//----------------------------------------------------------------------
// Converts a string of ASCII-encoded hex to a byte array.
std::vector<byte> Convert_ASCIIHex_To_Byte(std::string str){
  // strip out any separator characters from this string
  StringReplaceAll(str, ":", "");
  StringReplaceAll(str, " ", "");
  
  std::vector<byte> result;
  
  std::stringstream converter;
  size_t pos = 1;
  while (pos < str.length()){
    // get two characters from string
    std::string twoChars(str.substr(pos - 1, 2));

    // convert two characters to int
    converter.clear();
    converter << std::hex << twoChars;
    int temp;
    converter >> temp;

    // check for conversion error
    if ((converter.fail() || converter.bad()) == true){
      std::ostringstream ss;
      ss << "Unable to convert ASCII-hex string \"" << str << "\" to byte array; failed on bytes " << (pos - 1) << "-" << pos << ": \"" << twoChars << "\". Is the input valid?";
      throw std::runtime_error(ss.str());
    }

    // save result
    result.push_back(static_cast<byte>(temp));

    // skip forward two characters
    pos += 2;
  }

  return result;
}

//----------------------------------------------------------------------
// removes any comments from a string of text
//   only searches for // comments
void Strip_Comments(std::string& line){

  // remove comments from line
  size_t commentStart = line.find("//");
  if (commentStart != std::string::npos){
    line = line.substr(0, commentStart);
  }

  // trim string
    {
      size_t pos = line.find_last_not_of(' ');
      if (pos != std::string::npos) {
        line.erase(pos + 1);  // erase to end of string

        pos = line.find_first_not_of(' ');
        if (pos != std::string::npos) line.erase(0, pos);
      } else{
        line.erase(line.begin(), line.end()); // erase entire string if could not find non-whitespace
      }
    }
}

//----------------------------------------------------------------------
// replaces all instances of a string with a new string
void StringReplaceAll(std::string& str, const std::string& from, const std::string& to){
  if (from.empty() == true){
    return;
  }
  size_t start_pos = 0;
  while ((start_pos = str.find(from, start_pos)) != std::string::npos){
    str.replace(start_pos, from.length(), to);
    start_pos += to.length();
  }
}

//----------------------------------------------------------------------
// converts a byte vector to a hexadecimal string in the form of AA:BB:CC:etc
std::string Bytes_To_String(const std::vector<byte>& v){
  std::stringstream ss;
  for (std::vector<byte>::const_iterator it = v.begin(); it != v.end(); it++){
    int thisNum = *it;
    ss << std::setfill('0') << std::setw(2) << std::hex << thisNum << ":";
  }

  std::string result = ss.str();
  if (result.size() > 0){
    result.erase(result.length() - 1);
  }
  return result;
}

//----------------------------------------------------------------------
