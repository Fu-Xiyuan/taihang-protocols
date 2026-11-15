/****************************************************************************
 * @file      homomorphism_evaluation_proof.hpp
 * @brief     Compressed proof of a homomorphism on a committed vector.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_ZKP_SIGMA_HOMOMORPHISM_EVALUATION_PROOF_HPP
#define TAIHANG_PROTOCOLS_ZKP_SIGMA_HOMOMORPHISM_EVALUATION_PROOF_HPP

#include <iosfwd>
#include <memory>
#include <string_view>
#include <vector>

#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>
#include <taihang/zkp/sigma_protocols/multi_exponentiation_equality_proof.hpp>

namespace taihang::zkp::nizk::homomorphism_evaluation {

/** @brief Commitment bases with positive power-of-two length; padding identities are allowed. */
struct PublicParameters {
    int curve_id;
    std::size_t vector_length;
    std::size_t rounds;
    std::shared_ptr<ECGroup> group_ctx;
    std::shared_ptr<Zn> ring_ctx;
    ECPoint u;
    std::vector<ECPoint> vector_g;
};

/** @brief P = <vector_g,a> + u*r and Q = <bases,a> for the same secret a. */
struct Statement {
    ECPoint p;
    ECPoint q;
    std::vector<ECPoint> bases;
};

struct Witness {
    std::vector<ZnElement> a;
    ZnElement r;
};

/** @brief Random mask commitments and a compressed shared response. */
struct Proof {
    ECPoint a_p;
    ECPoint a_q;
    ZnElement f;
    multi_exponentiation_equality::Proof equality_proof;
    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }
    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    /** @note Preinitialize contexts and all four embedded vectors to pp.rounds. */
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

PublicParameters setup(int curve_id, std::size_t vector_length);
/** @note The parent ensures independent nonpadding bases and a nonidentity blinding base. */
PublicParameters setup(const std::shared_ptr<ECGroup>& group_ctx,
                       const std::shared_ptr<Zn>& ring_ctx,
                       const ECPoint& u,
                       const std::vector<ECPoint>& vector_g);
Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});
/** @note Arithmetic contexts must be compatible. Invalid dimensions/equations return false. */
bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});

namespace detail {

Proof initialize_proof(const PublicParameters& pp);
/** @brief Parent supplies the original mask-challenge transcript and suffix. */
Proof prove_with_transcript(const PublicParameters& pp,
                            const Statement& statement,
                            const Witness& witness,
                            std::string& transcript,
                            bool reset_equality_context,
                            std::string_view suffix = {});
bool verify_with_transcript(const PublicParameters& pp,
                            const Statement& statement,
                            const Proof& proof,
                            std::string& transcript,
                            bool reset_equality_context,
                            std::string_view suffix = {});

} // namespace detail

} // namespace taihang::zkp::nizk::homomorphism_evaluation
#endif // TAIHANG_PROTOCOLS_ZKP_SIGMA_HOMOMORPHISM_EVALUATION_PROOF_HPP
