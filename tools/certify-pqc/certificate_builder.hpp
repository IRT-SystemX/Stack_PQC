#pragma once

#include <vanetza/common/clock.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/pqc/fndsa512.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <string>
#include <vector>

namespace vanetza
{
namespace security
{

class Backend;

namespace pqc
{
namespace certificate_builder
{

struct CertificateParameters
{
    std::string subject_name;
    int validity_days = 1;
    std::vector<ItsAid> application_ids;
};

v3::Certificate build_ecc_root_certificate(
    ::vanetza::security::Backend&, const ecdsa256::KeyPair&,
    const CertificateParameters&, Clock::time_point now);

v3::Certificate build_hybrid_root_certificate(
    ::vanetza::security::Backend&, Backend&, const ecdsa256::KeyPair&, const KeyPair&,
    const CertificateParameters&, Clock::time_point now);

v3::Certificate build_ecc_authorization_authority_certificate(
    ::vanetza::security::Backend&, const ecdsa256::KeyPair& issuer_key,
    const v3::Certificate& issuer_certificate,
    const ecdsa256::PublicKey& subject_key,
    const CertificateParameters&, Clock::time_point now);

v3::Certificate build_hybrid_authorization_authority_certificate(
    ::vanetza::security::Backend&, Backend&,
    const ecdsa256::KeyPair& issuer_key, const PrivateKey& issuer_pqc_key,
    const v3::Certificate& issuer_certificate,
    const ecdsa256::PublicKey& subject_key, const PublicKey& subject_pqc_key,
    const CertificateParameters&, Clock::time_point now);

v3::Certificate build_ecc_authorization_ticket(
    ::vanetza::security::Backend&, const ecdsa256::KeyPair& issuer_key,
    const v3::Certificate& issuer_certificate,
    const ecdsa256::PublicKey& subject_key,
    const CertificateParameters&, Clock::time_point now);

v3::Certificate build_hybrid_authorization_ticket(
    ::vanetza::security::Backend&, Backend&,
    const ecdsa256::KeyPair& issuer_key, const PrivateKey& issuer_pqc_key,
    const v3::Certificate& issuer_certificate,
    const ecdsa256::PublicKey& subject_key,
    const CertificateParameters&, Clock::time_point now);

} // namespace certificate_builder
} // namespace pqc
} // namespace security
} // namespace vanetza
