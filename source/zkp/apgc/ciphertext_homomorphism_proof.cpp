/****************************************************************************
 * @file      ciphertext_homomorphism_proof.cpp
 * @brief     Original APGC ciphertext batching and masked equality proof.
 *****************************************************************************/

#include <taihang/zkp/apgc/ciphertext_homomorphism_proof.hpp>

#include <openssl/obj_mac.h>

#include <limits>
#include <sstream>

#include <taihang/common/check.hpp>
#include <taihang/utility/arithmetic.hpp>

namespace taihang::zkp::apgc::ciphertext_homomorphism {
namespace {

std::vector<ZnElement> powers(std::size_t length, const ZnElement& base) {
    std::vector<ZnElement> result(length, base.ring_ctx->get_one());
    for (std::size_t i = 1; i < length; ++i) {
        result[i] = result[i - 1] * base;
    }
    return result;
}

std::vector<ECPoint> generators(const std::shared_ptr<ECGroup>& group,
                                std::size_t length,
                                const std::string& label) {
    std::vector<ECPoint> result(length, ECPoint(group));
    for (std::size_t i = 0; i < length; ++i) {
        const std::string name = label + std::to_string(i);
        result[i] = group->curve_id == NID_X9_62_prime256v1
                        ? hash_to_curve_standard(
                              name,
                              "TAIHANG-PROTOCOLS-V01-P256_XMD:SHA-256_SSWU_RO_",
                              *group)
                        : hash_to_curve_fast(name, *group);
    }
    return result;
}

namespace evaluation = taihang::zkp::nizk::homomorphism_evaluation;
namespace equality = taihang::zkp::nizk::multi_exponentiation_equality;

bool valid_statement(const PublicParameters& pp, const Statement& statement) {
    return pp.participant_count > 0 &&
           pp.participant_count <=
               std::numeric_limits<std::size_t>::max() / 2 &&
           pp.commitment.vector_length == 2 * pp.participant_count &&
           pp.commitment.vector_g.size() == pp.commitment.vector_length &&
           statement.public_keys.size() == pp.participant_count &&
           statement.transfers.size() == pp.participant_count;
}

evaluation::Statement relation(const PublicParameters& pp,
                               const Statement& statement,
                               std::string& transcript) {
    std::ostringstream input;
    input << transcript << statement.p;
    for (std::size_t i = 0; i < pp.participant_count; ++i) {
        input << statement.public_keys[i] << statement.transfers[i].c1
              << statement.transfers[i].c2;
    }
    transcript = input.str();
    const std::vector<ZnElement> rho =
        powers(2 * pp.participant_count,
               hash_to_zn(transcript, *pp.encryption.ring_ctx));
    evaluation::Statement result{
        statement.p,
        pp.encryption.group_ctx->get_infinity(),
        std::vector<ECPoint>(2 * pp.participant_count,
                             ECPoint(pp.encryption.group_ctx))
    };
    std::vector<const ECPoint*> points(2 * pp.participant_count, nullptr);
    for (std::size_t i = 0; i < pp.participant_count; ++i) {
        result.bases[i] = ec_point_msm(statement.public_keys[i],
                                       rho[i],
                                       pp.encryption.g,
                                       rho[pp.participant_count + i]);
        result.bases[pp.participant_count + i] =
            pp.encryption.h * rho[pp.participant_count + i];
        points[i] = &statement.transfers[i].c1;
        points[pp.participant_count + i] = &statement.transfers[i].c2;
    }
    result.q = ec_point_msm(points, rho);
    return result;
}

} // namespace

PublicParameters setup(const pke::twisted_elgamal::PublicParameters& encryption,
                       std::size_t participant_count) {
    TAIHANG_ASSERT(
        taihang::arithmetic::is_pow2(participant_count) &&
            participant_count <= std::numeric_limits<std::size_t>::max() / 4,
        "ciphertext homomorphism requires a power-of-two participant count");
    const std::vector<ECPoint> bases =
        generators(encryption.group_ctx,
                   2 * participant_count,
                   "taihang/apgc/well-formedness/vector-g/");
    const ECPoint u = generators(
        encryption.group_ctx, 1, "taihang/apgc/well-formedness/u/")[0];
    return {
        encryption,
        participant_count,
        evaluation::setup(encryption.group_ctx, encryption.ring_ctx, u, bases)
    };
}

Proof initialize_proof(const PublicParameters& pp) {
    return nizk::homomorphism_evaluation::detail::initialize_proof(
        pp.commitment);
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    TAIHANG_ASSERT(valid_statement(pp, statement),
                   "ciphertext homomorphism dimensions mismatch");
    std::string transcript(context);
    const evaluation::Statement batched = relation(pp, statement, transcript);
    return nizk::homomorphism_evaluation::detail::prove_with_transcript(
        pp.commitment, batched, witness, transcript, true);
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
    if (!valid_statement(pp, statement)) {
        return false;
    }
    std::string transcript(context);
    const evaluation::Statement batched = relation(pp, statement, transcript);
    return nizk::homomorphism_evaluation::detail::verify_with_transcript(
        pp.commitment, batched, proof, transcript, true);
}

} // namespace taihang::zkp::apgc::ciphertext_homomorphism
