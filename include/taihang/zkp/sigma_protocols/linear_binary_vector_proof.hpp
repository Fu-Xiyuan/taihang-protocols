/****************************************************************************
 * @file      linear_binary_vector_proof.hpp
 * @brief     Linear-size proof for a committed binary vector.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_ZKP_SIGMA_LINEAR_BINARY_VECTOR_PROOF_HPP
#define TAIHANG_PROTOCOLS_ZKP_SIGMA_LINEAR_BINARY_VECTOR_PROOF_HPP

#include <iosfwd>
#include <memory>
#include <string_view>
#include <vector>

#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>

namespace taihang::zkp::nizk::linear_binary_vector {

/** @brief Generator basis and arithmetic contexts for a positive vector length. */
struct PublicParameters {
    int curve_id;
    std::size_t vector_length;
    std::shared_ptr<ECGroup> group_ctx;
    std::shared_ptr<Zn> ring_ctx;

    /// Blinding base and vector bases in P = sum_i vector_g[i]*a_i + h*r.
    ECPoint h;
    std::vector<ECPoint> vector_g;
};

/** @brief Public commitment P to a binary vector. */
struct Statement {
    ECPoint p;
};

/** @brief Opening of P with a_i in {0,1}. */
struct Witness {
    std::vector<ZnElement> a;
    ZnElement r;
};

/** @brief Three commitments, a vector response, and two blinding responses. */
struct Proof {
    ECPoint a;
    ECPoint c;
    ECPoint d;
    std::vector<ZnElement> f;
    ZnElement z_a;
    ZnElement z_c;

    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }

    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    /** @note Preinitialize contexts and resize f to pp.vector_length before reading. */
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

/** @brief Derive deterministic bases for any positive vector length. */
PublicParameters setup(int curve_id, std::size_t vector_length);

/**
 * @brief Reuse a parent protocol's contexts and commitment basis.
 * @note All bases are nonidentity points in group_ctx. The scalar modulus must
 * equal the group order. The caller ensures no known discrete-log relations
 * between the bases. A power-of-two length is not required.
 */
PublicParameters setup(const std::shared_ptr<ECGroup>& group_ctx,
                       const std::shared_ptr<Zn>& ring_ctx,
                       const ECPoint& h,
                       const std::vector<ECPoint>& vector_g);

/** @brief Prove the binary-vector relation with a Fiat-Shamir challenge. */
Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});

/** @brief Verify both response equations; invalid dimensions or equations return false. */
bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});

namespace detail {

/**
 * @brief Secret, single-use prover state for composing the GK protocol.
 * @note Keep alpha and the three blindings private. They are not proof data
 * and must never be serialized. Reusing masks for different challenges reveals
 * the witness. respond() consumes the state; callers must not copy it for reuse.
 */
struct ProverState {
    ECPoint a;
    ECPoint c;
    ECPoint d;
    std::vector<ZnElement> alpha;
    ZnElement r_a;
    ZnElement r_c;
    ZnElement r_d;
};

/** @brief Prepare commitments and private masks before the parent's challenge. */
ProverState commit(const PublicParameters& pp, const Witness& witness);

/**
 * @brief Respond using the same witness and a nonzero parent challenge.
 * @note The parent binds its parameters, statement, associated data, and all
 * first messages before deriving the challenge. Use each state exactly once.
 */
Proof respond(const PublicParameters& pp,
              const Witness& witness,
              ProverState&& state,
              const ZnElement& challenge);

/**
 * @brief Check the response equations under a nonzero parent challenge.
 * @note The parent must reconstruct and validate the challenge's transcript.
 * For standalone non-interactive verification, use verify().
 */
bool verify_with_challenge(const PublicParameters& pp,
                           const Statement& statement,
                           const Proof& proof,
                           const ZnElement& challenge);

} // namespace detail

} // namespace taihang::zkp::nizk::linear_binary_vector

#endif // TAIHANG_PROTOCOLS_ZKP_SIGMA_LINEAR_BINARY_VECTOR_PROOF_HPP
