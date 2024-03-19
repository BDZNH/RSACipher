# Example
just copy `RSACipher.h` `RSACipher.cpp` into your source tree. and include `RSACipher.h`.
sample call just as
```cpp
    RSAPrivate privateKey(<your private pem key string>);
    std::vector<unsigned char> encrypted;
    if(private.Encrypt(plaintext,plaintext_len,encrypted) <= 0)
    {
        std::cout<<"some error occured:" << privateKey.GetLastError() <<std::endl;
    }
    else
    {
        // use the encrypted as you like
    }
```
build your project and link openssl.
