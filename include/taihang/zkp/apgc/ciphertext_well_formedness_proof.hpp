/****************************************************************************
 * @file      ciphertext_well_formedness_proof.hpp
 * @brief     Proof of correct formation of all APGC transfer ciphertexts.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_APGC_CIPHERTEXT_WELL_FORMEDNESS_PROOF_HPP
#define TAIHANG_PROTOCOLS_APGC_CIPHERTEXT_WELL_FORMEDNESS_PROOF_HPP

#include <taihang/zkp/apgc/ciphertext_homomorphism_proof.hpp>

namespace taihang::zkp::apgc::ciphertext_well_formedness {

using PublicParameters = ciphertext_homomorphism::PublicParameters;

/** @brief Public keys and transfer ciphertexts in anonymous-set order. */
struct Statement {
    /// Encryption public key for each transfer ciphertext.
    std::vector<ECPoint> public_keys;

    /// Transfer ciphertexts whose formation is proved.
    std::vector<pke::twisted_elgamal::Ciphertext> transfers;
};

/** @brief Plaintexts and randomness opening the transfer ciphertexts. */
struct Witness {
    /// Signed transfer amounts, one per anonymous-set entry.
    std::vector<ZnElement> values;

    /// Encryption randomness in the same order as values.
    std::vector<ZnElement> randomness;
};

/** @brief Vector commitment and its batched ciphertext homomorphism proof. */
struct Proof {
    /// Commitment to the concatenated randomness and amount vectors.
    ECPoint p;

    /// Masked equality proof for the batched ciphertext relation.
    ciphertext_homomorphism::Proof evaluation;

    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }
    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

PublicParameters setup(const pke::twisted_elgamal::PublicParameters& encryption,
                       std::size_t count);

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});
/** @brief Allocate only the expected contexts and dimensions before stream decoding. */
Proof initialize_proof(const PublicParameters& pp);

} // namespace taihang::zkp::apgc::ciphertext_well_formedness

#endif // TAIHANG_PROTOCOLS_APGC_CIPHERTEXT_WELL_FORMEDNESS_PROOF_HPP
