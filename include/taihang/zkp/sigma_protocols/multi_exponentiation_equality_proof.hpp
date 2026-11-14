/****************************************************************************
 * @file      multi_exponentiation_equality_proof.hpp
 * @brief     Logarithmic-size argument for multi-exponentiation equality.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_ZKP_SIGMA_MULTI_EXPONENTIATION_EQUALITY_PROOF_HPP
#define TAIHANG_PROTOCOLS_ZKP_SIGMA_MULTI_EXPONENTIATION_EQUALITY_PROOF_HPP

#include <iosfwd>
#include <memory>
#include <string_view>
#include <vector>

#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>

namespace taihang::zkp::nizk::multi_exponentiation_equality {

/**
 * @brief Two generator bases and their shared arithmetic contexts.
 *
 * Both bases have the same positive power-of-two length. Standalone setup
 * derives deterministic generators; composed proofs reuse their parent's
 * bases and contexts, including identity points used for zero padding.
 */
struct PublicParameters {
    /// OpenSSL curve identifier.
    int curve_id;

    /// Number of generators in each basis and scalars in the witness.
    std::size_t vector_length;

    /// Number of folding rounds, equal to log2(vector_length).
    std::size_t rounds;

    /// Shared elliptic-curve context.
    std::shared_ptr<ECGroup> group_ctx;

    /// Scalar field modulo the group order.
    std::shared_ptr<Zn> ring_ctx;

    /// Generator basis for G.
    std::vector<ECPoint> g;

    /// Generator basis for P.
    std::vector<ECPoint> p;
};

/** @brief Public results G = sum_i g_i*a_i and P = sum_i p_i*a_i. */
struct Statement {
    ECPoint g;
    ECPoint p;
};

/** @brief Common scalar vector; masking is the composing protocol's responsibility. */
struct Witness {
    std::vector<ZnElement> a;
};

/** @brief Four cross commitments per round and the final shared scalar. */
struct Proof {
    /// L commitments for the g basis.
    std::vector<ECPoint> left_g;

    /// R commitments for the g basis.
    std::vector<ECPoint> right_g;

    /// L commitments for the p basis.
    std::vector<ECPoint> left_p;

    /// R commitments for the p basis.
    std::vector<ECPoint> right_p;

    /// Public scalar remaining after both relations have been folded.
    ZnElement a;

    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }

    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    /** @note Initialize point/scalar contexts and resize all four vectors to pp.rounds before reading. */
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

/** @brief Derive two deterministic bases for a positive power-of-two length. */
PublicParameters setup(int curve_id, std::size_t vector_length);

/**
 * @brief Reuse a composing protocol's contexts and two generator bases.
 * @note Both bases must have the same positive power-of-two length and use
 * group_ctx. The scalar modulus must equal the group order. No independent
 * generator requirement is imposed here; the composing relation determines it.
 */
PublicParameters setup(const std::shared_ptr<ECGroup>& group_ctx,
                       const std::shared_ptr<Zn>& ring_ctx,
                       const std::vector<ECPoint>& generators_g,
                       const std::vector<ECPoint>& generators_p);

/**
 * @brief Generate a compression argument for multi-exponentiation equality.
 * @param context Optional associated data that must also be supplied to verify().
 * @note The caller must provide compatible parameter, statement, and witness
 * contexts. This function does not add zero-knowledge masking.
 */
Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});

/**
 * @brief Verify both folded relations, returning false for invalid lengths or equations.
 * @param context Associated data used by the prover.
 * @note The caller must provide compatible parameter, statement, and proof contexts.
 */
bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});

} // namespace taihang::zkp::nizk::multi_exponentiation_equality

#endif // TAIHANG_PROTOCOLS_ZKP_SIGMA_MULTI_EXPONENTIATION_EQUALITY_PROOF_HPP
