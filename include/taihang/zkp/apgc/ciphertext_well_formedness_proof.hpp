/****************************************************************************
 * @file      ciphertext_well_formedness_proof.hpp
 * @brief     Proof of correct formation of all APGC transfer ciphertexts.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_APGC_CIPHERTEXT_WELL_FORMEDNESS_PROOF_HPP
#define TAIHANG_PROTOCOLS_APGC_CIPHERTEXT_WELL_FORMEDNESS_PROOF_HPP

#include <taihang/zkp/apgc/ciphertext_homomorphism_proof.hpp>

namespace taihang::zkp::apgc::ciphertext_well_formedness {

using PublicParameters = ciphertext_homomorphism::PublicParameters;
struct Statement {
    std::vector<ECPoint> public_keys;
    std::vector<pke::twisted_elgamal::Ciphertext> transfers;
};

struct Witness {
    std::vector<ZnElement> values;
    std::vector<ZnElement> randomness;
};

struct Proof {
    ECPoint p;
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
