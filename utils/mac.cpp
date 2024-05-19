#ifndef MAC
#define MAC

#include <cstdint>
#include <iomanip>
#include <vector>

#include "../libs/streebog.h"
#include "../utils/bytes.cpp"

using namespace std;

#define C_in 0x36   // 00110110
#define C_out 0x5c  // 01011100


vector<uint8_t> HMAC(const vector<uint8_t>& masterKey, const vector<uint8_t>& message) {
  
    size_t kLen = KEY_LEN(masterKey.size());
    if (kLen != k32 && kLen != k64)
        throw runtime_error("Key should be 256/512 bits.");

  
    vector<uint8_t> ipad(kLen, 0x00), opad(kLen, 0x00);
    ipad[kLen - 1] = C_in;
    opad[kLen - 1] = C_out;

 
    vector<uint8_t> inner(kLen + message.size());
    vector<uint8_t> xoredIpad = XOR(masterKey, ipad);
    copy(xoredIpad.begin(), xoredIpad.end(), inner.begin());
    copy(message.begin(), message.end(), inner.begin() + kLen);

    vector<uint8_t> hashedInner = streebog(inner, KEY_LEN(kLen));  

    
    vector<uint8_t> outer(kLen + hashedInner.size());
    vector<uint8_t> xoredOpad = XOR(masterKey, opad);
    copy(xoredOpad.begin(), xoredOpad.end(), outer.begin());
    copy(hashedInner.begin(), hashedInner.end(), outer.begin() + kLen);

    vector<uint8_t> hashedOuter = streebog(outer, KEY_LEN(kLen));  

    return hashedOuter;
}


#endif