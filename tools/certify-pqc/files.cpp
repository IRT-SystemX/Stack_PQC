#include "files.hpp"
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/v2/persistence.hpp>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <sys/stat.h>

namespace
{

using vanetza::ByteBuffer;

ByteBuffer read_file(const std::string& path)
{
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw std::runtime_error("cannot open file for reading: " + path);
    }
    return ByteBuffer(std::istreambuf_iterator<char>(stream), {});
}

void write_file(const std::string& path, const ByteBuffer& data)
{
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream || !stream.write(
            reinterpret_cast<const char*>(data.data()), data.size())) {
        throw std::runtime_error("cannot write file: " + path);
    }
}

template<typename T>
T load_exact(const std::string& path, std::size_t expected_size, const char* description)
{
    T output { read_file(path) };
    if (output.bytes.size() != expected_size) {
        throw std::runtime_error(
            std::string(description) + " has an invalid size in: " + path);
    }
    return output;
}

} // namespace

vanetza::security::ecdsa256::KeyPair load_ecc_key_pair(const std::string& path)
{
    return vanetza::security::v2::load_private_key_from_file(path);
}

vanetza::security::pqc::KeyPair load_pqc_key_pair(const std::string& base_path)
{
    using namespace vanetza::security::pqc;
    KeyPair key_pair;
    key_pair.private_key = load_exact<PrivateKey>(
        base_path + ".pqc.key", fndsa512_private_key_size, "FN-DSA-512 private key");
    key_pair.public_key = load_exact<PublicKey>(
        base_path + ".pqc.pub", fndsa512_public_key_size, "FN-DSA-512 public key");
    return key_pair;
}

vanetza::security::pqc::PrivateKey load_pqc_private_key(const std::string& base_path)
{
    using namespace vanetza::security::pqc;
    return load_exact<PrivateKey>(
        base_path + ".pqc.key", fndsa512_private_key_size, "FN-DSA-512 private key");
}

void save_pqc_key_pair(
    const std::string& base_path, const vanetza::security::pqc::KeyPair& key_pair)
{
    using namespace vanetza::security::pqc;
    if (key_pair.private_key.bytes.size() != fndsa512_private_key_size ||
            key_pair.public_key.bytes.size() != fndsa512_public_key_size) {
        throw std::invalid_argument("cannot save malformed FN-DSA-512 key pair");
    }

    const std::string private_path = base_path + ".pqc.key";
    write_file(private_path, key_pair.private_key.bytes);
    if (::chmod(private_path.c_str(), S_IRUSR | S_IWUSR) != 0) {
        throw std::runtime_error("cannot restrict private-key permissions: " + private_path);
    }
    write_file(base_path + ".pqc.pub", key_pair.public_key.bytes);
}

vanetza::security::v3::Certificate load_v3_certificate(const std::string& path)
{
    vanetza::security::v3::Certificate certificate;
    const auto encoded = read_file(path);
    if (encoded.empty() || !certificate.decode(encoded)) {
        throw std::runtime_error("cannot decode V3 certificate: " + path);
    }
    return certificate;
}

void save_v3_certificate(
    const std::string& path, const vanetza::security::v3::Certificate& certificate)
{
    std::string error;
    if (!certificate.validate(error)) {
        throw std::runtime_error("refusing to save invalid V3 certificate: " + error);
    }
    write_file(path, certificate.encode());
}
