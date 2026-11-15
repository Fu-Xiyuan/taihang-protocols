/****************************************************************************
 * @file      ciphertext_homomorphism_proof.hpp
 * @brief     APGC ciphertext homomorphism proof from AmorHom_Wellform.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_APGC_CIPHERTEXT_HOMOMORPHISM_PROOF_HPP
#define TAIHANG_PROTOCOLS_APGC_CIPHERTEXT_HOMOMORPHISM_PROOF_HPP

#include <taihang/pke/twisted_elgamal.hpp>
#include <taihang/zkp/sigma_protocols/homomorphism_evaluation_proof.hpp>

namespace taihang::zkp::apgc::ciphertext_homomorphism {

struct PublicParameters {
    pke::twisted_elgamal::PublicParameters encryption;
    std::size_t participant_count;
    nizk::homomorphism_evaluation::PublicParameters commitment;
};

struct Statement {
    ECPoint p;
    std::vector<ECPoint> public_keys;
    std::vector<pke::twisted_elgamal::Ciphertext> transfers;
};

using Witness = nizk::homomorphism_evaluation::Witness;
using Proof = nizk::homomorphism_evaluation::Proof;

PublicParameters setup(const pke::twisted_elgamal::PublicParameters& encryption,
                       std::size_t participant_count);
Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});
bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});
Proof initialize_proof(const PublicParameters& pp);

} // namespace taihang::zkp::apgc::ciphertext_homomorphism

#endif // TAIHANG_PROTOCOLS_APGC_CIPHERTEXT_HOMOMORPHISM_PROOF_HPP
