#include <vanetza/security/pqc/fndsa512.hpp>
#include <oqs/oqs.h>
#include <memory>
#include <stdexcept>

namespace vanetza
{
namespace security
{
namespace pqc
{

namespace
{

using OqsSignature = std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)>;

OqsSignature create_signature_context()
{
    OqsSignature context { OQS_SIG_new(OQS_SIG_alg_falcon_padded_512), OQS_SIG_free };
    if (!context) {
        throw std::runtime_error("liboqs does not provide Falcon-padded-512");
    }

    if (context->length_public_key != fndsa512_public_key_size ||
            context->length_secret_key != fndsa512_private_key_size ||
            context->length_signature != fndsa512_signature_size) {
        throw std::runtime_error("liboqs Falcon-padded-512 parameters do not match the ASN.1 profile");
    }

    return context;
}

class OqsBackend final : public Backend
{
public:
    KeyPair generate_key_pair() override
    {
        auto context = create_signature_context();
        KeyPair key_pair;
        key_pair.public_key.bytes.resize(fndsa512_public_key_size);
        key_pair.private_key.bytes.resize(fndsa512_private_key_size);

        const auto result = OQS_SIG_keypair(
            context.get(), key_pair.public_key.bytes.data(), key_pair.private_key.bytes.data());
        if (result != OQS_SUCCESS) {
            throw std::runtime_error("liboqs failed to generate an FN-DSA-512 key pair");
        }

        return key_pair;
    }

    Signature sign(const PrivateKey& private_key, const ByteBuffer& data) override
    {
        if (private_key.bytes.size() != fndsa512_private_key_size) {
            throw std::invalid_argument("FN-DSA-512 private key has an invalid size");
        }

        auto context = create_signature_context();
        Signature signature;
        signature.bytes.resize(fndsa512_signature_size);
        std::size_t signature_size = 0;
        const auto result = OQS_SIG_sign(
            context.get(), signature.bytes.data(), &signature_size,
            data.data(), data.size(), private_key.bytes.data());
        if (result != OQS_SUCCESS) {
            throw std::runtime_error("liboqs failed to create an FN-DSA-512 signature");
        }
        if (signature_size != fndsa512_signature_size) {
            throw std::runtime_error("liboqs returned a non-padded FN-DSA-512 signature");
        }

        return signature;
    }

    bool verify(const PublicKey& public_key, const ByteBuffer& data, const Signature& signature) override
    {
        if (public_key.bytes.size() != fndsa512_public_key_size ||
                signature.bytes.size() != fndsa512_signature_size) {
            return false;
        }

        auto context = create_signature_context();
        return OQS_SIG_verify(
            context.get(), data.data(), data.size(), signature.bytes.data(),
            signature.bytes.size(), public_key.bytes.data()) == OQS_SUCCESS;
    }
};

} // namespace

std::unique_ptr<Backend> create_fndsa512_backend()
{
    return std::unique_ptr<Backend> { new OqsBackend() };
}

} // namespace pqc
} // namespace security
} // namespace vanetza
