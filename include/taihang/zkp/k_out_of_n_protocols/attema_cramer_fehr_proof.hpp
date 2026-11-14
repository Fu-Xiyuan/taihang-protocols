/****************************************************************************
 * @file      attema_cramer_fehr_proof.hpp
 * @brief     ACF k-out-of-n proof of knowledge of discrete logarithms.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_ZKP_K_OUT_OF_N_ATTEMA_CRAMER_FEHR_PROOF_HPP
#define TAIHANG_PROTOCOLS_ZKP_K_OUT_OF_N_ATTEMA_CRAMER_FEHR_PROOF_HPP

#include <iosfwd>
#include <memory>
#include <string_view>
#include <vector>

#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>
#include <taihang/zkp/sigma_protocols/amortized_homomorphism_proof.hpp>

namespace taihang::zkp::k_out_of_n::attema_cramer_fehr {

/** @brief Commitment basis and dimensions for the ACF construction. */
struct PublicParameters {
    int curve_id;
    std::size_t statement_count;
    std::size_t threshold;

    /// Folding depth for the padded witness length 2*n.
    std::size_t rounds;

    std::shared_ptr<ECGroup> group_ctx;
    std::shared_ptr<Zn> ring_ctx;

    /// Common discrete-log base for the public points c_j = g*x_j.
    ECPoint g;

    /// Blinding base and 2*n-k independent vector-commitment bases.
    ECPoint h;
    std::vector<ECPoint> vector_g;
};

/** @brief Ordered list of n public points sharing the discrete-log base g. */
struct Statement {
    std::vector<ECPoint> points;
};

/**
 * @brief Discrete logarithms of k distinct points, with zero-based hidden indices.
 * @note secrets[i] satisfies points[indices[i]] = g*secrets[i]. Openings for
 * unselected points are not needed. Polynomial evaluation uses indices[i]+1.
 */
struct Witness {
    std::vector<std::size_t> indices;
    std::vector<ZnElement> secrets;
};

/** @brief Commitment to the polynomial witness and a compressed homomorphism proof. */
struct Proof {
    ECPoint p;
    nizk::amortized_homomorphism::Proof amortized_homomorphism;

    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }

    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    /** @note Preinitialize contexts and all embedded point vectors to pp.rounds. */
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

/** @brief Derive deterministic bases for a positive power-of-two n and 1 <= k <= n. */
PublicParameters setup(int curve_id,
                       std::size_t statement_count,
                       std::size_t threshold);

/**
 * @brief Prove knowledge of discrete logarithms at k distinct positions.
 * @note Witness dimensions and indices satisfy the parameter contract. All
 * points and scalars must use compatible arithmetic contexts.
 */
Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});

/** @brief Verify the ACF proof; invalid public dimensions or equations return false. */
bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});

} // namespace taihang::zkp::k_out_of_n::attema_cramer_fehr

#endif // TAIHANG_PROTOCOLS_ZKP_K_OUT_OF_N_ATTEMA_CRAMER_FEHR_PROOF_HPP
