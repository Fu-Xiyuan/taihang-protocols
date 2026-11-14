/****************************************************************************
 * @file      multi_exponentiation_proof.hpp
 * @brief     Logarithmic-size argument for a multi-exponentiation relation.
 *
 * For G = sum_i g_i*a_i, each round publishes L = g_L*a_R and R = g_R*a_L
 * and folds g' = x*g_L + g_R, a' = a_L + x*a_R, G' = x^2*L + x*G + R.
 * A length-n relation uses 2*log2(n) points and one final scalar.
 *
 * This argument is not independently zero knowledge. A composing protocol
 * must mask its secret witness before using it. Length one reveals the input
 * scalar and checks only G = g_0*a_0, without a context-dependent challenge.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_ZKP_SIGMA_MULTI_EXPONENTIATION_PROOF_HPP
#define TAIHANG_PROTOCOLS_ZKP_SIGMA_MULTI_EXPONENTIATION_PROOF_HPP

#include <iosfwd>
#include <memory>
#include <string_view>
#include <vector>

#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>

namespace taihang::zkp::nizk::multi_exponentiation {

/**
 * @brief Generator basis and arithmetic contexts for the relation.
 *
 * The vector length is a positive power of two. Standalone setup derives a
 * deterministic basis; composed proofs reuse their parent's basis and contexts.
 */
struct PublicParameters {
    /// OpenSSL curve identifier.
    int curve_id;

    /// Number of generators and witness scalars.
    std::size_t vector_length;

    /// Number of folding rounds, equal to log2(vector_length).
    std::size_t rounds;

    /// Shared elliptic-curve context.
    std::shared_ptr<ECGroup> group_ctx;

    /// Scalar field modulo the group order.
    std::shared_ptr<Zn> ring_ctx;

    /// Generator basis for the scalar representation.
    std::vector<ECPoint> g;
};

/** @brief Public result G = sum_i g_i*a_i. */
struct Statement {
    ECPoint g;
};

/** @brief Scalar representation; masking is the composing protocol's responsibility. */
struct Witness {
    std::vector<ZnElement> a;
};

/** @brief Two cross commitments per round and the final folded scalar. */
struct Proof {
    /// L commitments, one for each folding round.
    std::vector<ECPoint> left;

    /// R commitments, one for each folding round.
    std::vector<ECPoint> right;

    /// Public scalar remaining after all folds.
    ZnElement a;

    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }

    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    /** @note Initialize point/scalar contexts and resize both vectors to pp.rounds before reading. */
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

/** @brief Create deterministic, curve-bound generators for a positive power-of-two length. */
PublicParameters setup(int curve_id, std::size_t vector_length);

/**
 * @brief Reuse a composing protocol's contexts and generator basis.
 * @note The basis length must be a positive power of two. Points must belong
 * to group_ctx, and the scalar modulus must equal the group order.
 */
PublicParameters setup(const std::shared_ptr<ECGroup>& group_ctx,
                       const std::shared_ptr<Zn>& ring_ctx,
                       const std::vector<ECPoint>& generators);

/**
 * @brief Generate a compression argument for the scalar representation.
 * @param context Optional associated data that must also be supplied to verify().
 * @note The caller must provide compatible parameter, statement, and witness
 * contexts. This function does not add zero-knowledge masking.
 */
Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});

/**
 * @brief Verify the folded relation, returning false for invalid proof lengths or equations.
 * @param context Associated data used by the prover.
 * @note The caller must provide compatible parameter, statement, and proof contexts.
 */
bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});

} // namespace taihang::zkp::nizk::multi_exponentiation

#endif // TAIHANG_PROTOCOLS_ZKP_SIGMA_MULTI_EXPONENTIATION_PROOF_HPP
