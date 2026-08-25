#pragma once

#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/pqc/fndsa512.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <string>

vanetza::security::ecdsa256::KeyPair load_ecc_key_pair(const std::string& path);
vanetza::security::pqc::KeyPair load_pqc_key_pair(const std::string& base_path);
vanetza::security::pqc::PrivateKey load_pqc_private_key(const std::string& base_path);

void save_pqc_key_pair(
    const std::string& base_path, const vanetza::security::pqc::KeyPair&);

vanetza::security::v3::Certificate load_v3_certificate(const std::string& path);
void save_v3_certificate(
    const std::string& path, const vanetza::security::v3::Certificate&);
