/****************************************************************************
 * @file      fixed_weight_binary_vector_proof.hpp
 * @brief     Logarithmic-size proof for a binary vector of prescribed weight.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_ZKP_SIGMA_FIXED_WEIGHT_BINARY_VECTOR_PROOF_HPP
#define TAIHANG_PROTOCOLS_ZKP_SIGMA_FIXED_WEIGHT_BINARY_VECTOR_PROOF_HPP

#include <iosfwd>
#include <memory>
#include <string_view>
#include <vector>

#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>
#include <taihang/zkp/range_proofs/inner_product_proof.hpp>

namespace taihang::zkp::nizk::fixed_weight_binary_vector {

/** @brief Generator bases and contexts for a positive power-of-two vector length. */
struct PublicParameters {
    int curve_id;
    std::size_t vector_length;
    std::size_t rounds;

    std::shared_ptr<ECGroup> group_ctx;
    std::shared_ptr<Zn> ring_ctx;

    /// Value and blinding bases in T_j = g*t_j + h*tau_j.
    ECPoint g;
    ECPoint h;

    /// Blinding base in the vector commitment P.
    ECPoint u;

    /// Independent base carrying the inner product after challenge scaling.
    ECPoint inner_product_u;

    std::vector<ECPoint> vector_g;
    std::vector<ECPoint> vector_h;
};

/** @brief Public commitment P = sum_i (g_i*a_i + h_i*b_i) + u*r. */
struct Statement {
    ECPoint p;
    std::size_t weight; ///< Exact number of one entries, in [0, vector_length].
};

/** @brief Opening of P, with a_i in {0,1} and b_i = a_i - 1. */
struct Witness {
    std::vector<ZnElement> a;
    std::vector<ZnElement> b;
    ZnElement r;
};

/** @brief Mask commitment, polynomial commitments and responses, and an inner-product proof. */
struct Proof {
    ECPoint a;
    ECPoint t1;
    ECPoint t2;
    ZnElement t;
    ZnElement tau;
    ZnElement mu;
    range_proofs::inner_product::Proof inner_product;

    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }

    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    /** @note Preinitialize contexts and both inner-product vectors to pp.rounds. */
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

/** @brief Derive deterministic generator bases for a positive power-of-two length. */
PublicParameters setup(int curve_id, std::size_t vector_length);

/**
 * @brief Reuse a parent protocol's contexts and generator bases.
 * @note Vector bases have equal positive power-of-two lengths. All bases use
 * group_ctx and are nonidentity points; the scalar modulus is the group order.
 * The caller ensures no known discrete-log relations between these bases.
 */
PublicParameters setup(const std::shared_ptr<ECGroup>& group_ctx,
                       const std::shared_ptr<Zn>& ring_ctx,
                       const ECPoint& g,
                       const ECPoint& h,
                       const ECPoint& u,
                       const ECPoint& inner_product_u,
                       const std::vector<ECPoint>& vector_g,
                       const std::vector<ECPoint>& vector_h);

/** @brief Mask the opening and prove both the Boolean and complement constraints. */
Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});

/**
 * @brief Verify the polynomial identity and the logarithmic inner-product proof.
 * @note Callers supply compatible arithmetic contexts. Invalid public dimensions
 * or equations return false. The public weight is bound before all challenges.
 */
bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});

} // namespace taihang::zkp::nizk::fixed_weight_binary_vector

#endif // TAIHANG_PROTOCOLS_ZKP_SIGMA_FIXED_WEIGHT_BINARY_VECTOR_PROOF_HPP
