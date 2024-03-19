#pragma once
#include <string>
#include <vector>
class RSACipher {
public:
    static std::string KeyString2PemString(const std::string& keystr, bool isPrivateKey);
public:
    RSACipher(const std::string& pemKey, bool isPrivateKey = true);
    int Encrypt(const unsigned char* in, size_t inlen, std::vector<uint8_t>& out);
    int Decrypt(const unsigned char* in, size_t inlen, std::vector<uint8_t>& out);
    std::string GetLastError() { return mLastErrorMsg; }
private:
    int PublicEncrypt(const unsigned char* in, size_t inlen, std::vector<uint8_t>& out);
    int PublicDecrypt(const unsigned char* in, size_t inlen, std::vector<uint8_t>& out);
    int PrivateEncrypt(const unsigned char* in, size_t inlen, std::vector<uint8_t>& out);
    int PrivateDecrypt(const unsigned char* in, size_t inlen, std::vector<uint8_t>& out);
private:
    std::string mPemKey;
    bool privateKey;
    std::string mLastErrorMsg;
};

class RSAPrivate : public RSACipher {
public:
    RSAPrivate(const std::string& pemKey) : RSACipher(pemKey, true) {}
    ~RSAPrivate() {}
};

class RSAPublic : public RSACipher {
public:
    RSAPublic(const std::string& pemKey) : RSACipher(pemKey, false) {}
    ~RSAPublic() {}
};

