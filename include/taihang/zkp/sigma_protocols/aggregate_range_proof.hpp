/****************************************************************************
 * @file      aggregate_range_proof.hpp
 * @brief     Range proof for a weighted or delayed aggregate commitment.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_ZKP_SIGMA_AGGREGATE_RANGE_PROOF_HPP
#define TAIHANG_PROTOCOLS_ZKP_SIGMA_AGGREGATE_RANGE_PROOF_HPP

#include <iosfwd>
#include <memory>
#include <string_view>
#include <vector>

#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>
#include <taihang/zkp/range_proofs/inner_product_proof.hpp>

namespace taihang::zkp::nizk::aggregate_range {

/** @brief Range bases and dimensions; bit vectors are padded to a power of two. */
struct PublicParameters {
    int curve_id;
    std::size_t range_bits;
    std::size_t value_count;
    std::size_t vector_length;
    std::size_t rounds;
    std::shared_ptr<ECGroup> group_ctx;
    std::shared_ptr<Zn> ring_ctx;
    ECPoint g; ///< Blinding base in the aggregate.
    ECPoint h; ///< Value base in the aggregate.
    ECPoint u; ///< Inner-product base.
    std::vector<ECPoint> vector_g;
    std::vector<ECPoint> vector_h;
};

/** @brief V = g*r + h*sum_i weights[i]*values[i], with all weights nonzero. */
struct Statement {
    ECPoint aggregate;
    std::vector<ZnElement> weights;
};

struct Witness {
    std::vector<ZnElement> values;
    ZnElement randomness; ///< Aggregate blinding, not per-value randomness.
};

struct Proof {
    ECPoint a;
    ECPoint s;
    ECPoint aggregate; ///< In delayed mode this is sent after y and z.
    ECPoint t1;
    ECPoint t2;
    ZnElement taux;
    ZnElement mu;
    ZnElement t;
    range_proofs::inner_product::Proof inner_product;
    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }
    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    /** @note Preinitialize contexts and inner-product vectors to pp.rounds. */
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

PublicParameters setup(int curve_id, std::size_t range_bits, std::size_t value_count);
/** @note The parent supplies independent bases with compatible contexts. */
PublicParameters setup(const std::shared_ptr<ECGroup>& group_ctx,
                       const std::shared_ptr<Zn>& ring_ctx,
                       std::size_t range_bits, std::size_t value_count,
                       const ECPoint& g, const ECPoint& h, const ECPoint& u);
Proof prove(const PublicParameters& pp, const Statement& statement,
            const Witness& witness, std::string_view context = {});
bool verify(const PublicParameters& pp, const Statement& statement,
            const Proof& proof, std::string_view context = {});

/**
 * @brief Commit to bits before deriving weights z^(i+2), then send one aggregate.
 * @note The parent must prove the bridge linking this aggregate to its opening.
 * Unselected values and their bridge randomness are normally zero.
 */
Proof prove_delayed(const PublicParameters& pp, const std::vector<ZnElement>& values,
                    const std::vector<ZnElement>& randomness, std::string_view context = {});
bool verify_delayed(const PublicParameters& pp, const Proof& proof, std::string_view context = {});
/** @brief Recover the same delayed weights for the parent's aggregate bridge. */
std::vector<ZnElement> delayed_weights(const PublicParameters& pp,
                                      const Proof& proof, std::string_view context = {});

namespace detail {
/** @brief Private single-use masks; the parent publishes only a and s before choosing weights. */
struct ProverState {
    std::vector<ZnElement> values;
    std::vector<ZnElement> a_left;
    std::vector<ZnElement> a_right;
    std::vector<ZnElement> s_left;
    std::vector<ZnElement> s_right;
    ZnElement alpha;
    ZnElement rho;
    ECPoint a;
    ECPoint s;
};

ProverState prepare(const PublicParameters& pp, const std::vector<ZnElement>& values);
/** @note Consume state exactly once. Weights are derived after its a/s were fixed by the parent. */
Proof prove_prepared(const PublicParameters& pp, const Statement& statement,
                     const ZnElement& randomness, ProverState&& state, std::string_view context);
} // namespace detail

} // namespace taihang::zkp::nizk::aggregate_range
#endif // TAIHANG_PROTOCOLS_ZKP_SIGMA_AGGREGATE_RANGE_PROOF_HPP
