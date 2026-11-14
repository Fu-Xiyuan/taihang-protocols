/****************************************************************************
 * @file      groth_kohlweiss_proof.hpp
 * @brief     GK-based k-out-of-n proof of knowledge of commitment openings.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_ZKP_K_OUT_OF_N_GROTH_KOHLWEISS_PROOF_HPP
#define TAIHANG_PROTOCOLS_ZKP_K_OUT_OF_N_GROTH_KOHLWEISS_PROOF_HPP

#include <iosfwd>
#include <memory>
#include <string_view>
#include <vector>

#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>
#include <taihang/zkp/sigma_protocols/linear_binary_vector_proof.hpp>
#include <taihang/zkp/sigma_protocols/logarithmic_binary_vector_proof.hpp>

namespace taihang::zkp::k_out_of_n::groth_kohlweiss {

/** @brief Commitment bases and dimensions for the GK-based construction. */
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

/**
 * @brief Openings of k distinct commitments, with zero-based hidden indices.
 * @note values[i] and randomness[i] open commitments[indices[i]]. Their order
 * follows indices; callers do not supply openings for unselected commitments.
 */
struct Witness {
    std::vector<std::size_t> indices;
    std::vector<ZnElement> values;
    std::vector<ZnElement> randomness;
};

/** @brief Committed indices and selection vector, polynomial messages, and subproofs. */
struct Proof {
    ECPoint b;
    ECPoint p;
    nizk::linear_binary_vector::Proof linear_binary;
    std::vector<ECPoint> c_c;
    std::vector<ECPoint> c_p;
    ZnElement z_g;
    ZnElement z_h;
    ZnElement z_p;
    nizk::logarithmic_binary_vector::Proof logarithmic_binary;

    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }

    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    /**
     * @note Preinitialize contexts, c_c/c_p to index_bits, linear_binary.f to
     * threshold*index_bits, and inner-product left/right vectors to index_bits.
     */
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

/**
 * @brief Derive deterministic bases for a power-of-two n >= 2 and 1 <= k <= n.
 * @note This is the k-out-of-n construction based on the GK technique, using
 * the linear and logarithmic binary-vector subprotocols. It does not include
 * the range-proof or heterogeneous extensions from the original project.
 */
PublicParameters setup(int curve_id,
                       std::size_t statement_count,
                       std::size_t threshold);

/**
 * @brief Prove knowledge of openings of k distinct entries in the public list.
 * @note Witness dimensions and indices must satisfy the parameter contract.
 * All points and scalars must use compatible arithmetic contexts.
 */
Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});

/** @brief Verify all four relations; invalid public dimensions or equations return false. */
bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});

} // namespace taihang::zkp::k_out_of_n::groth_kohlweiss

#endif // TAIHANG_PROTOCOLS_ZKP_K_OUT_OF_N_GROTH_KOHLWEISS_PROOF_HPP
