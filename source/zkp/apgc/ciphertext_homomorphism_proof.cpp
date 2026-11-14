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

namespace evaluation = taihang::zkp::nizk::homomorphism_evaluation;
namespace equality = taihang::zkp::nizk::multi_exponentiation_equality;

bool valid_statement(const PublicParameters& pp, const Statement& statement) {
    return pp.participant_count > 0 &&
        pp.participant_count <= std::numeric_limits<std::size_t>::max() / 2 &&
        pp.commitment.vector_length == 2 * pp.participant_count &&
        pp.commitment.vector_g.size() == pp.commitment.vector_length &&
        statement.public_keys.size() == pp.participant_count &&
        statement.transfers.size() == pp.participant_count;
}

evaluation::Statement relation(const PublicParameters& pp,
                                const Statement& statement, std::string& transcript) {
    std::ostringstream input;
    input << transcript << statement.p;
    for (std::size_t i = 0; i < pp.participant_count; ++i) {
        input << statement.public_keys[i] << statement.transfers[i].c1 << statement.transfers[i].c2;
    }
    transcript = input.str();
    const std::vector<ZnElement> rho = detail::powers(2 * pp.participant_count,
        hash_to_zn(transcript, *pp.encryption.ring_ctx));
    evaluation::Statement result{statement.p, pp.encryption.group_ctx->get_infinity(),
        std::vector<ECPoint>(2 * pp.participant_count, ECPoint(pp.encryption.group_ctx))};
    for (std::size_t i = 0; i < pp.participant_count; ++i) {
        result.bases[i] = ec_point_msm(statement.public_keys[i], rho[i],
                                      pp.encryption.g, rho[pp.participant_count + i]);
        result.bases[pp.participant_count + i] = pp.encryption.h * rho[pp.participant_count + i];
        result.q = result.q + ec_point_msm(statement.transfers[i].c1, rho[i],
                            statement.transfers[i].c2, rho[pp.participant_count + i]);
    }
    return result;
}

} // namespace

PublicParameters setup(const pke::twisted_elgamal::PublicParameters& encryption,
                       std::size_t participant_count) {
    TAIHANG_ASSERT(taihang::arithmetic::is_pow2(participant_count) &&
        participant_count <= std::numeric_limits<std::size_t>::max() / 4,
        "ciphertext homomorphism requires a power-of-two participant count");
    const std::vector<ECPoint> bases = detail::generators(encryption.group_ctx,
        2 * participant_count, "taihang/apgc/well-formedness/vector-g/");
    const ECPoint u = detail::generators(encryption.group_ctx, 1,
                                         "taihang/apgc/well-formedness/u/")[0];
    return {encryption, participant_count,
        evaluation::setup(encryption.group_ctx, encryption.ring_ctx, u, bases)};
}

Proof initialize_proof(const PublicParameters& pp) {
    return detail::initialize_evaluation(pp.commitment);
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    TAIHANG_ASSERT(valid_statement(pp, statement), "ciphertext homomorphism dimensions mismatch");
    std::string transcript(context);
    const evaluation::Statement batched = relation(pp, statement, transcript);
    return detail::prove_evaluation(pp.commitment, batched, witness, transcript, true);
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
    return detail::verify_evaluation(pp.commitment, batched, proof, transcript, true);
}

namespace detail {

std::size_t folding_rounds(std::size_t length) {
    std::size_t rounds = 0;
    for (; length > 1; length /= 2) {
        ++rounds;
    }
    return rounds;
}

std::vector<ZnElement> powers(std::size_t length, const ZnElement& base) {
    std::vector<ZnElement> result(length, base.ring_ctx->get_one());
    for (std::size_t i = 1; i < length; ++i) {
        result[i] = result[i - 1] * base;
    }
    return result;
}

ZnElement dot(const std::vector<ZnElement>& a, const std::vector<ZnElement>& b) {
    TAIHANG_ASSERT(!a.empty() && a.size() == b.size(), "APGC inner-product dimensions mismatch");
    ZnElement result = a.front().ring_ctx->get_zero();
    for (std::size_t i = 0; i < a.size(); ++i) {
        result += a[i] * b[i];
    }
    return result;
}

std::vector<ECPoint> generators(const std::shared_ptr<ECGroup>& group,
                                std::size_t length, const std::string& label) {
    std::vector<ECPoint> result(length, ECPoint(group));
    for (std::size_t i = 0; i < length; ++i) {
        const std::string name = label + std::to_string(i);
        result[i] = group->curve_id == NID_X9_62_prime256v1 ?
            hash_to_curve_standard(name, "TAIHANG-PROTOCOLS-V01-P256_XMD:SHA-256_SSWU_RO_", *group) :
            hash_to_curve_fast(name, *group);
    }
    return result;
}

Proof initialize_evaluation(const evaluation::PublicParameters& pp) {
    return {ECPoint(pp.group_ctx), ECPoint(pp.group_ctx), ZnElement(pp.ring_ctx),
        {std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
         std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
         std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
         std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)), ZnElement(pp.ring_ctx)}};
}

void append_equality(std::ostringstream& transcript, const equality::Proof& proof) {
    for (std::size_t i = 0; i < proof.left_g.size(); ++i) {
        transcript << proof.left_g[i] << proof.right_g[i] << proof.left_p[i] << proof.right_p[i];
    }
}

Proof prove_evaluation(const evaluation::PublicParameters& pp,
                       const evaluation::Statement& statement,
                       const Witness& witness, std::string& transcript,
                       bool reset_equality_context) {
    TAIHANG_ASSERT(witness.a.size() == pp.vector_length, "APGC homomorphism witness length mismatch");
    const std::vector<ZnElement> alpha = gen_random_znelement_vector(pp.ring_ctx, pp.vector_length);
    const ZnElement beta = pp.ring_ctx->gen_random();
    Proof proof = initialize_evaluation(pp);
    proof.a_p = ec_point_msm(pp.vector_g, alpha) + pp.u * beta;
    proof.a_q = ec_point_msm(statement.bases, alpha);
    std::ostringstream input;
    input << transcript << proof.a_p << proof.a_q;
    const ZnElement e = hash_to_zn(input.str(), *pp.ring_ctx);
    proof.f = beta + e * witness.r;
    std::vector<ZnElement> response(pp.vector_length, pp.ring_ctx->get_zero());
    for (std::size_t i = 0; i < response.size(); ++i) {
        response[i] = alpha[i] + e * witness.a[i];
    }
    const equality::PublicParameters eq = equality::setup(pp.group_ctx, pp.ring_ctx,
                                                          statement.bases, pp.vector_g);
    const equality::Statement target{proof.a_q + ec_point_msm(statement.bases, witness.a) * e,
        statement.p * e + proof.a_p - pp.u * proof.f};
    transcript = reset_equality_context ? std::string{} : input.str();
    // Reuse the already migrated Eqmdl argument. The parent keeps the original
    // sequence of GL, GR, PL, PR messages when continuing its own transcript.
    proof.equality_proof = equality::prove(eq, target, {response}, transcript);
    std::ostringstream final;
    final << transcript;
    append_equality(final, proof.equality_proof);
    transcript = final.str();
    return proof;
}

bool verify_evaluation(const evaluation::PublicParameters& pp,
                       const evaluation::Statement& statement,
                       const Proof& proof, std::string& transcript,
                       bool reset_equality_context) {
    if (statement.bases.size() != pp.vector_length || pp.vector_g.size() != pp.vector_length ||
        proof.equality_proof.left_g.size() != pp.rounds ||
        proof.equality_proof.right_g.size() != pp.rounds ||
        proof.equality_proof.left_p.size() != pp.rounds ||
        proof.equality_proof.right_p.size() != pp.rounds) {
        return false;
    }
    std::ostringstream input;
    input << transcript << proof.a_p << proof.a_q;
    const ZnElement e = hash_to_zn(input.str(), *pp.ring_ctx);
    const equality::PublicParameters eq = equality::setup(pp.group_ctx, pp.ring_ctx,
                                                          statement.bases, pp.vector_g);
    const equality::Statement target{proof.a_q + statement.q * e,
        statement.p * e + proof.a_p - pp.u * proof.f};
    transcript = reset_equality_context ? std::string{} : input.str();
    const bool valid = equality::verify(eq, target, proof.equality_proof, transcript);
    std::ostringstream final;
    final << transcript;
    append_equality(final, proof.equality_proof);
    transcript = final.str();
    return valid;
}

range_proofs::inner_product::PublicParameters inner_parameters(
    const pke::twisted_elgamal::PublicParameters& encryption,
    const std::vector<ECPoint>& g, const std::vector<ECPoint>& h, const ECPoint& u) {
    return {encryption.curve_id, g.size(), folding_rounds(g.size()), encryption.group_ctx,
             encryption.ring_ctx, g, h, u};
}

range_proofs::inner_product::Proof initialize_inner(
    const pke::twisted_elgamal::PublicParameters& encryption, std::size_t length) {
    const std::size_t rounds = folding_rounds(length);
    return {std::vector<ECPoint>(rounds, ECPoint(encryption.group_ctx)),
        std::vector<ECPoint>(rounds, ECPoint(encryption.group_ctx)),
        ZnElement(encryption.ring_ctx), ZnElement(encryption.ring_ctx)};
}

range_proofs::bulletproof::PublicParameters range_parameters(
    const pke::twisted_elgamal::PublicParameters& encryption,
    std::size_t range_bits, std::size_t count, const ECPoint& u, const std::string& label) {
    TAIHANG_ASSERT(taihang::arithmetic::is_pow2(range_bits) && taihang::arithmetic::is_pow2(count),
                   "original APGC range dimensions must be powers of two");
    const std::size_t length = range_bits * count;
    return {encryption.curve_id, range_bits, count, length, encryption.group_ctx,
        encryption.ring_ctx, encryption.g, encryption.h, u,
        generators(encryption.group_ctx, length, label + "/g/"),
        generators(encryption.group_ctx, length, label + "/h/")};
}

range_proofs::bulletproof::Proof initialize_range(const range_proofs::bulletproof::PublicParameters& pp) {
    const std::size_t rounds = folding_rounds(pp.vector_length);
    return {ECPoint(pp.group_ctx), ECPoint(pp.group_ctx), ECPoint(pp.group_ctx), ECPoint(pp.group_ctx),
        ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx),
        {std::vector<ECPoint>(rounds, ECPoint(pp.group_ctx)),
         std::vector<ECPoint>(rounds, ECPoint(pp.group_ctx)), ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx)}};
}

} // namespace detail

} // namespace taihang::zkp::apgc::ciphertext_homomorphism
