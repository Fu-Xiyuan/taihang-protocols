/****************************************************************************
 * @file      zero_sum_proof.hpp
 * @brief     Original APGC Sigma proof that transfer amounts sum to zero.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_APGC_ZERO_SUM_PROOF_HPP
#define TAIHANG_PROTOCOLS_APGC_ZERO_SUM_PROOF_HPP

#include <taihang/pke/twisted_elgamal.hpp>

namespace taihang::zkp::apgc::zero_sum {

/** @brief Encryption base and dimension for the zero-sum relation. */
struct PublicParameters {
    /// Encryption parameters; g is the randomness base.
    pke::twisted_elgamal::PublicParameters encryption;

    /// Number of transfer randomness scalars in the witness.
    std::size_t participant_count;
};

/** @brief Sum of the transfer ciphertexts' second components. */
struct Statement {
    /// Sum_i c2_i; for a zero-sum transfer, c = g*sum_i r_i.
    ECPoint c;
};

/** @brief Randomness opening the zero-sum commitment. */
struct Witness {
    /// Encryption randomness for all anonymous-set entries.
    std::vector<ZnElement> randomness;
};

/** @brief Schnorr commitment and response for the aggregate randomness. */
struct Proof {
    /// First message A = g*alpha for a fresh mask alpha.
    ECPoint a;

    /// Response z = alpha + x*sum_i r_i.
    ZnElement z;

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

Proof initialize_proof(const PublicParameters& pp);

} // namespace taihang::zkp::apgc::zero_sum

#endif // TAIHANG_PROTOCOLS_APGC_ZERO_SUM_PROOF_HPP
