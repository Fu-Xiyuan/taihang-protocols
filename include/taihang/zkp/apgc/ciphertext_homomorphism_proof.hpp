/****************************************************************************
 * @file      ciphertext_homomorphism_proof.hpp
 * @brief     APGC ciphertext homomorphism proof from AmorHom_Wellform.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_APGC_CIPHERTEXT_HOMOMORPHISM_PROOF_HPP
#define TAIHANG_PROTOCOLS_APGC_CIPHERTEXT_HOMOMORPHISM_PROOF_HPP

#include <taihang/pke/twisted_elgamal.hpp>
#include <taihang/zkp/sigma_protocols/homomorphism_evaluation_proof.hpp>

namespace taihang::zkp::apgc::ciphertext_homomorphism {

/** @brief Encryption and commitment bases for the batched ciphertext relation. */
struct PublicParameters {
    /// Encryption bases used in each transfer ciphertext.
    pke::twisted_elgamal::PublicParameters encryption;

    /// Number of public keys and transfer ciphertexts.
    std::size_t participant_count;

    /// Bases for committing to the randomness and plaintext vectors.
    nizk::homomorphism_evaluation::PublicParameters commitment;
};

/** @brief A vector commitment and the public transfer ciphertext relation. */
struct Statement {
    /// Commitment to n randomness scalars followed by n transfer amounts.
    ECPoint p;

    /// Ordered encryption public keys for the n entries.
    std::vector<ECPoint> public_keys;

    /// Ciphertexts c1_i = pk_i*r_i and c2_i = g*r_i + h*v_i.
    std::vector<pke::twisted_elgamal::Ciphertext> transfers;
};

/** @brief Concatenated randomness and amount vectors, with commitment blinding. */
using Witness = nizk::homomorphism_evaluation::Witness;

/** @brief Masking commitments, blinding response, and shared-vector equality proof. */
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
