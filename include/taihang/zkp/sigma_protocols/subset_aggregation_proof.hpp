/****************************************************************************
 * @file      subset_aggregation_proof.hpp
 * @brief     Hidden subset aggregation for a composed GK range proof.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_ZKP_SIGMA_SUBSET_AGGREGATION_PROOF_HPP
#define TAIHANG_PROTOCOLS_ZKP_SIGMA_SUBSET_AGGREGATION_PROOF_HPP

#include <iosfwd>
#include <memory>
#include <string_view>
#include <vector>

#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>
#include <taihang/zkp/sigma_protocols/linear_binary_vector_proof.hpp>
#include <taihang/zkp/sigma_protocols/logarithmic_binary_vector_proof.hpp>

namespace taihang::zkp::nizk::subset_aggregation {

/** @brief Reuse the GK commitment and selector bases. */
struct PublicParameters {
    int curve_id;
    std::size_t statement_count;
    std::size_t threshold;
    std::size_t index_bits;

    std::shared_ptr<ECGroup> group_ctx;
    std::shared_ptr<Zn> ring_ctx;

    /// Public commitments have the form c_j = g*r_j + h*v_j.
    ECPoint g;
    ECPoint h;

    /// Blinding and inner-product bases for the binary-vector subprotocols.
    ECPoint u;
    ECPoint inner_product_u;
    std::vector<ECPoint> vector_g;
    std::vector<ECPoint> vector_h;
    std::vector<ECPoint> index_g;
};

/** @brief Ordered list of n public commitments. */
struct Statement {
    std::vector<ECPoint> commitments;
};

/** @brief Hidden distinct indices and their aggregate blinding contributions. */
struct Witness {
    std::vector<std::size_t> indices;
    std::vector<ZnElement> randomness;
};

/** @brief Committed indices and selection vector, polynomial messages, and subproofs. */
struct Proof {
    ECPoint b;
    ECPoint p;
    linear_binary_vector::Proof linear_binary;
    std::vector<ECPoint> c_c;
    std::vector<ECPoint> c_p;
    ZnElement z_g;
    ZnElement z_p;
    logarithmic_binary_vector::Proof logarithmic_binary;

    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }

    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    /**
     * @note Preinitialize contexts, c_c/c_p to index_bits, linear_binary.f to
     * threshold*index_bits, and inner-product left/right vectors to index_bits.
     */
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

/** @brief Derive selector bases for a power-of-two n>=2 and 1<=k<=n. */
PublicParameters setup(int curve_id,
                       std::size_t statement_count,
                       std::size_t threshold);

/**
 * @brief Aggregate a hidden subset for a parent range proof.
 * @note This proves selector consistency, not knowledge of the selected openings.
 * The parent must validate the returned aggregate with its range proof.
 */
Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});

/** @brief Verify selector consistency; the parent must also verify the range bridge. */
bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});

namespace detail {
struct Aggregate {
    ECPoint commitment;
    std::vector<ZnElement> weights;
    ZnElement normalization;
};
/** @note Call verify() first when processing untrusted proof data. */
Aggregate aggregate(const PublicParameters& pp, const Statement& statement,
                     const Proof& proof, std::string_view context = {});
} // namespace detail

} // namespace taihang::zkp::nizk::subset_aggregation

#endif // TAIHANG_PROTOCOLS_ZKP_SIGMA_SUBSET_AGGREGATION_PROOF_HPP
