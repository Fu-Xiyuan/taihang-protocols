/****************************************************************************
 * @file      inactive_participant_proof.hpp
 * @brief     Original ZGSX23 proof for inactive APGC participant entries.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_APGC_INACTIVE_PARTICIPANT_PROOF_HPP
#define TAIHANG_PROTOCOLS_APGC_INACTIVE_PARTICIPANT_PROOF_HPP

#include <taihang/pke/twisted_elgamal.hpp>
#include <taihang/zkp/range_proofs/inner_product_proof.hpp>

namespace taihang::zkp::apgc::inactive_participant {

/** @brief Bases for the inactive-entry selector and inner-product argument. */
struct PublicParameters {
    /// Transfer commitment bases g and h.
    pke::twisted_elgamal::PublicParameters encryption;

    /// Power-of-two number of anonymous-set entries.
    std::size_t participant_count;

    /// Selector blinding base and unscaled inner-product base.
    ECPoint u;

    /// Generator basis for the left selector vector.
    std::vector<ECPoint> vector_g;

    /// Generator basis for the right selector vector.
    std::vector<ECPoint> vector_h;
};

/** @brief Transfer commitments and the number of inactive entries. */
struct Statement {
    /// Second ciphertext components c2_i = g*r_i + h*v_i.
    std::vector<ECPoint> commitments;

    /// Required number of selected entries with zero transfer amounts.
    std::size_t count;
};

/** @brief Selector bits and randomness for the selected inactive entries. */
struct Witness {
    /// One bit per entry; one selects an inactive participant.
    std::vector<ZnElement> bits;

    /// Randomness for one entries, in ascending anonymous-set index order.
    std::vector<ZnElement> randomness;
};

/** @brief Selector constraints and the zero-transfer inner-product relation. */
struct Proof {
    /// Commitment to the selector bits and their complements.
    ECPoint a;

    /// Commitment to independent masking vectors.
    ECPoint s;

    /// Commitment to the linear coefficient of the range-style polynomial.
    ECPoint t1;

    /// Commitment to its quadratic coefficient.
    ECPoint t2;

    /// Commitment linking the masking vector to the public ciphertexts.
    ECPoint e;

    /// Combined blinding response for T1 and T2.
    ZnElement taux;

    /// Combined blinding response for A and S.
    ZnElement mu;

    /// Evaluated inner product at challenge x.
    ZnElement t;

    /// Response combining the selected encryption randomness and its mask.
    ZnElement f_s;

    /// Logarithmic argument for the final vector relation.
    range_proofs::inner_product::Proof inner_product;

    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }
    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

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

} // namespace taihang::zkp::apgc::inactive_participant

#endif // TAIHANG_PROTOCOLS_APGC_INACTIVE_PARTICIPANT_PROOF_HPP
