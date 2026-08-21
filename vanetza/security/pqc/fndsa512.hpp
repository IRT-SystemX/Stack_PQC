#pragma once

#include <vanetza/common/byte_buffer.hpp>
#include <cstddef>
#include <memory>

namespace vanetza
{
namespace security
{
namespace pqc
{

constexpr std::size_t fndsa512_public_key_size = 897;
constexpr std::size_t fndsa512_private_key_size = 1281;
constexpr std::size_t fndsa512_signature_size = 666;

struct PublicKey
{
    ByteBuffer bytes;
};

struct PrivateKey
{
    ByteBuffer bytes;
};

struct Signature
{
    ByteBuffer bytes;
};

struct KeyPair
{
    PublicKey public_key;
    PrivateKey private_key;
};

/**
 * Cryptographic operations for the experimental FN-DSA-512 profile.
 *
 * The interface is intentionally separate from security::Backend. Enabling
 * the experimental profile therefore does not alter the established ECC
 * backend contract or its key types.
 */
class Backend
{
public:
    virtual KeyPair generate_key_pair() = 0;
    virtual Signature sign(const PrivateKey&, const ByteBuffer& data) = 0;
    virtual bool verify(const PublicKey&, const ByteBuffer& data, const Signature&) = 0;
    virtual ~Backend() = default;
};

/**
 * Create the liboqs-backed implementation used by the experimental profile.
 */
std::unique_ptr<Backend> create_fndsa512_backend();

} // namespace pqc
} // namespace security
} // namespace vanetza
