/****************************************************************************
 * @file      amortized_homomorphism_proof.hpp
 * @brief     Amortized homomorphism proof for ACF partial knowledge.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_ZKP_SIGMA_AMORTIZED_HOMOMORPHISM_PROOF_HPP
#define TAIHANG_PROTOCOLS_ZKP_SIGMA_AMORTIZED_HOMOMORPHISM_PROOF_HPP

#include <iosfwd>
#include <memory>
#include <string_view>
#include <vector>

#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>
#include <taihang/zkp/sigma_protocols/multi_exponentiation_equality_proof.hpp>

namespace taihang::zkp::nizk::amortized_homomorphism {

/** @brief Commitment bases and dimensions for n statements and threshold k. */
struct PublicParameters {
    int curve_id;
    std::size_t statement_count;
    std::size_t threshold;

    /// Padded witness length 2*n and its logarithmic folding depth.
    std::size_t vector_length;
    std::size_t rounds;

    std::shared_ptr<ECGroup> group_ctx;
    std::shared_ptr<Zn> ring_ctx;

    /// Discrete-log base for the public statements c_j.
    ECPoint g;

    /// Blinding base in P = sum_i vector_g[i]*y_i + u*r.
    ECPoint u;
    std::vector<ECPoint> vector_g;
};

/** @brief Public commitment to a vector satisfying all n homomorphism relations. */
struct Statement {
    ECPoint p;
    std::vector<ECPoint> c;
};

/**
 * @brief Opening of P, with y = (a_1,...,a_(n-k),b_1,...,b_n,0^k).
 *
 * Each relation is c_j*(1 + sum_i a_i*j^i) = g*b_j, for j = 1,...,n.
 * The final k coordinates are padding and do not enter these relations.
 */
struct Witness {
    std::vector<ZnElement> y;
    ZnElement r;
};

/** @brief Mask commitments, blinding response, and a folded equality proof. */
struct Proof {
    ECPoint a_p;
    ECPoint a_f;
    ZnElement f;
    multi_exponentiation_equality::Proof equality_proof;

    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }

    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    /** @note Preinitialize contexts and all embedded point vectors to pp.rounds. */
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

/**
 * @brief Derive commitment bases for a positive power-of-two n and 1 <= k <= n.
 * @note The last k commitment bases are identities, matching the padded witness.
 */
PublicParameters setup(int curve_id,
                       std::size_t statement_count,
                       std::size_t threshold);

/**
 * @brief Reuse a parent protocol's contexts, bases, and padded commitment basis.
 * @note vector_g has length 2*n. Identity points are allowed for padding;
 * g and u must be nonidentity points. The caller ensures that commitment
 * bases have no known discrete-log relations, apart from padding identities.
 */
PublicParameters setup(const std::shared_ptr<ECGroup>& group_ctx,
                       const std::shared_ptr<Zn>& ring_ctx,
                       std::size_t statement_count,
                       std::size_t threshold,
                       const ECPoint& g,
                       const ECPoint& u,
                       const std::vector<ECPoint>& vector_g);

/** @brief Mask the opening and compress the batched homomorphism relation. */
Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});

/**
 * @brief Verify the masked commitment opening and batched homomorphism relation.
 * @note Parameter, statement, witness, and proof contexts must be compatible.
 * Invalid public dimensions or equations return false.
 */
bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});

} // namespace taihang::zkp::nizk::amortized_homomorphism

#endif // TAIHANG_PROTOCOLS_ZKP_SIGMA_AMORTIZED_HOMOMORPHISM_PROOF_HPP
