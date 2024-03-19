#include "RSACipher.h"
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <memory>

static std::string GetLastSSLError()
{
    char err[256] = { 0 };
    ERR_error_string_n(ERR_get_error(), err, sizeof(err));
    return std::string(err);
}

std::string RSACipher::KeyString2PemString(const std::string& keystr, bool isPrivateKey)
{
    size_t len = keystr.size();
    std::string ret;
    for (size_t i = 0; i < len; i++)
    {
        if (i % 64 == 0)
        {
            ret.push_back('\n');
        }
        ret.push_back(keystr[i]);
    }
    if (ret.back() != '\n')
    {
        ret.push_back('\n');
    }
    if (isPrivateKey)
    {
        ret.insert(0, "-----BEGIN RSA PRIVATE KEY-----");
        ret.append("-----END RSA PRIVATE KEY-----\n");
    }
    else
    {
        ret.insert(0, "-----BEGIN RSA PUBLIC KEY-----");
        ret.append("-----END RSA PUBLIC KEY-----\n");
    }
    return ret;
}

RSACipher::RSACipher(const std::string& pemKey, bool isPrivateKey) :mPemKey(pemKey), privateKey(isPrivateKey)
{
}

int RSACipher::Encrypt(const unsigned char* in, size_t inlen, std::vector<uint8_t>& out)
{
    mLastErrorMsg.clear();
    if (privateKey)
    {
        return PrivateEncrypt(in, inlen, out);
    }
    else
    {
        return PublicEncrypt(in, inlen, out);
    }
}

int RSACipher::Decrypt(const unsigned char* in, size_t inlen, std::vector<uint8_t>& out)
{
    mLastErrorMsg.clear();
    if (privateKey)
    {
        return PrivateDecrypt(in, inlen, out);
    }
    else
    {
        return PublicDecrypt(in, inlen, out);
    }
}

int RSACipher::PublicEncrypt(const unsigned char* in, size_t inlen, std::vector<uint8_t>& out)
{
    int ret = 0;
    std::shared_ptr<BIO> keybio(BIO_new_mem_buf(mPemKey.c_str(), (int)mPemKey.size()), BIO_free);
    if (keybio == nullptr)
    {
        mLastErrorMsg.assign("BIO_new_mem_buf failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return -1;
    }
    std::shared_ptr<EVP_PKEY> key(PEM_read_bio_PUBKEY(keybio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    if (key == nullptr)
    {
        mLastErrorMsg.assign("PEM_read_bio_PUBKEY failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return -1;
    }
    std::shared_ptr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new(key.get(), nullptr), EVP_PKEY_CTX_free);
    if (ctx == nullptr)
    {
        mLastErrorMsg.assign("EVP_PKEY_CTX_new failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return -1;
    }
    ret = EVP_PKEY_encrypt_init(ctx.get());
    if (ret <= 0)
    {
        mLastErrorMsg.assign("EVP_PKEY_encrypt_init failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return ret;
    }
    ret = EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING);
    if (ret <= 0)
    {
        mLastErrorMsg.assign("EVP_PKEY_CTX_set_rsa_padding failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return ret;
    }
    size_t outlen = 0;
    ret = EVP_PKEY_encrypt(ctx.get(), nullptr, &outlen, in, inlen);
    if (ret <= 0)
    {
        mLastErrorMsg.assign("EVP_PKEY_encrypt failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return ret;
    }
    out.resize(outlen);
    ret = EVP_PKEY_encrypt(ctx.get(), out.data(), &outlen, in, inlen);
    if (ret <= 0)
    {
        mLastErrorMsg.assign("EVP_PKEY_encrypt failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return ret;
    }
    return ret;
}

int RSACipher::PublicDecrypt(const unsigned char* in, size_t inlen, std::vector<uint8_t>& out)
{
    //verify_recover
    int ret = 0;
    std::shared_ptr<BIO> keybio(BIO_new_mem_buf(mPemKey.c_str(), (int)mPemKey.size()), BIO_free);
    if (keybio == nullptr)
    {
        mLastErrorMsg.assign("BIO_new_mem_buf failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return -1;
    }
    std::shared_ptr<EVP_PKEY> key(PEM_read_bio_PUBKEY(keybio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    if (key == nullptr)
    {
        mLastErrorMsg.assign("PEM_read_bio_PUBKEY failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return -1;
    }
    std::shared_ptr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new(key.get(), nullptr), EVP_PKEY_CTX_free);
    if (ctx == nullptr)
    {
        mLastErrorMsg.assign("EVP_PKEY_CTX_new failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return -1;
    }
    ret = EVP_PKEY_verify_recover_init(ctx.get());
    if (ret <= 0)
    {
        mLastErrorMsg.assign("EVP_PKEY_verify_recover_init failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return ret;
    }
    ret = EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING);
    if (ret <= 0)
    {
        mLastErrorMsg.assign("EVP_PKEY_CTX_set_rsa_padding failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return ret;
    }
    size_t outlen = 0;
    ret = EVP_PKEY_verify_recover(ctx.get(), nullptr, &outlen, in, inlen);
    if (ret <= 0)
    {
        mLastErrorMsg.assign("EVP_PKEY_verify_recover failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return ret;
    }
    out.resize(outlen);
    ret = EVP_PKEY_verify_recover(ctx.get(), out.data(), &outlen, in, inlen);
    if (ret <= 0)
    {
        mLastErrorMsg.assign("EVP_PKEY_verify_recover failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return ret;
    }
    return ret;
}

int RSACipher::PrivateEncrypt(const unsigned char* in, size_t inlen, std::vector<uint8_t>& out)
{
    //sign
    int ret = 0;
    std::shared_ptr<BIO> keybio(BIO_new_mem_buf(mPemKey.c_str(), (int)mPemKey.size()), BIO_free);
    if (keybio == nullptr)
    {
        mLastErrorMsg.assign("BIO_new_mem_buf failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return -1;
    }
    std::shared_ptr<EVP_PKEY> key(PEM_read_bio_PrivateKey(keybio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    if (key == nullptr)
    {
        mLastErrorMsg.assign("PEM_read_bio_PrivateKey failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return -1;
    }
    std::shared_ptr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new(key.get(), nullptr), EVP_PKEY_CTX_free);
    if (ctx == nullptr)
    {
        mLastErrorMsg.assign("EVP_PKEY_CTX_new failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return -1;
    }
    ret = EVP_PKEY_sign_init(ctx.get());
    if (ret <= 0)
    {
        mLastErrorMsg.assign("EVP_PKEY_sign_init failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return ret;
    }
    ret = EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING);
    if (ret <= 0)
    {
        mLastErrorMsg.assign("EVP_PKEY_CTX_set_rsa_padding failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return ret;
    }
    size_t outlen = 0;
    ret = EVP_PKEY_sign(ctx.get(), nullptr, &outlen, in, inlen);
    if (ret <= 0)
    {
        mLastErrorMsg.assign("EVP_PKEY_sign failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return ret;
    }
    out.resize(outlen);
    ret = EVP_PKEY_sign(ctx.get(), out.data(), &outlen, in, inlen);
    if (ret <= 0)
    {
        mLastErrorMsg.assign("EVP_PKEY_sign failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return ret;
    }
    return ret;
}

int RSACipher::PrivateDecrypt(const unsigned char* in, size_t inlen, std::vector<uint8_t>& out)
{
    //decrypt
    int ret = 0;
    std::shared_ptr<BIO> keybio(BIO_new_mem_buf(mPemKey.c_str(), (int)mPemKey.size()), BIO_free);
    if (keybio == nullptr)
    {
        mLastErrorMsg.assign("BIO_new_mem_buf failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return -1;
    }
    std::shared_ptr<EVP_PKEY> key(PEM_read_bio_PrivateKey(keybio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    if (key == nullptr)
    {
        mLastErrorMsg.assign("PEM_read_bio_PrivateKey failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return -1;
    }
    std::shared_ptr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new(key.get(), nullptr), EVP_PKEY_CTX_free);
    if (ctx == nullptr)
    {
        mLastErrorMsg.assign("EVP_PKEY_CTX_new failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return -1;
    }
    ret = EVP_PKEY_decrypt_init(ctx.get());
    if (ret <= 0)
    {
        mLastErrorMsg.assign("EVP_PKEY_decrypt_init failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return ret;
    }
    ret = EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING);
    if (ret <= 0)
    {
        mLastErrorMsg.assign("EVP_PKEY_CTX_set_rsa_padding failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return ret;
    }
    size_t outlen = 0;
    ret = EVP_PKEY_decrypt(ctx.get(), nullptr, &outlen, in, inlen);
    if (ret <= 0)
    {
        mLastErrorMsg.assign("EVP_PKEY_decrypt failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return ret;
    }
    out.resize(outlen);
    ret = EVP_PKEY_decrypt(ctx.get(), out.data(), &outlen, in, inlen);
    if (ret <= 0)
    {
        mLastErrorMsg.assign("EVP_PKEY_decrypt failed: ");
        mLastErrorMsg.append(GetLastSSLError());
        return ret;
    }
    return ret;
}
