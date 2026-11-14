/****************************************************************************
 * @file      homomorphism_evaluation_proof.cpp
 * @brief     Committed homomorphism evaluation proof implementation.
 *****************************************************************************/

#include <taihang/zkp/sigma_protocols/homomorphism_evaluation_proof.hpp>

#include <cstdint>
#include <istream>
#include <ostream>
#include <sstream>
#include <utility>

#include <taihang/common/check.hpp>

namespace taihang::zkp::nizk::homomorphism_evaluation {
namespace {

bool valid_dimensions(const PublicParameters& pp, const Statement& statement) {
    return pp.vector_length > 0 && (pp.vector_length & (pp.vector_length - 1)) == 0 &&
           pp.rounds < sizeof(std::size_t) * 8 &&
           (std::size_t{1} << pp.rounds) == pp.vector_length &&
           pp.vector_g.size() == pp.vector_length && statement.bases.size() == pp.vector_length;
}

std::string initial_transcript(const PublicParameters& pp,
                               const Statement& statement, std::string_view context) {
    std::ostringstream transcript;
    transcript << "taihang/homomorphism-evaluation/v1" << BigInt(uint64_t{context.size()});
    transcript.write(context.data(), static_cast<std::streamsize>(context.size()));
    transcript << BigInt(static_cast<uint64_t>(pp.curve_id))
               << BigInt(uint64_t{pp.vector_length}) << pp.u << statement.p << statement.q;
    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        transcript << pp.vector_g[i] << statement.bases[i];
    }
    return transcript.str();
}

} // namespace

PublicParameters setup(int curve_id, std::size_t vector_length) {
    const auto bases = multi_exponentiation_equality::setup(curve_id, vector_length);
    // The independently derived second basis supplies the blinding point.
    return {curve_id, vector_length, bases.rounds, bases.group_ctx, bases.ring_ctx,
            bases.p[0], bases.g};
}

PublicParameters setup(const std::shared_ptr<ECGroup>& group_ctx,
                       const std::shared_ptr<Zn>& ring_ctx,
                       const ECPoint& u, const std::vector<ECPoint>& vector_g) {
    const auto bases = multi_exponentiation_equality::setup(group_ctx, ring_ctx, vector_g, vector_g);
    TAIHANG_ASSERT(u.group_ctx == group_ctx.get() && !u.is_at_infinity(),
                   "homomorphism-evaluation invalid blinding base");
    return {group_ctx->curve_id, vector_g.size(), bases.rounds, group_ctx, ring_ctx, u, vector_g};
}

bool Proof::operator==(const Proof& other) const {
    return a_p == other.a_p && a_q == other.a_q && f == other.f &&
           equality_proof == other.equality_proof;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    return os << proof.a_p << proof.a_q << proof.f << proof.equality_proof;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    is >> proof.a_p >> proof.a_q >> proof.f;
    if (is) {
        is >> proof.equality_proof;
    }
    return is;
}

Proof prove(const PublicParameters& pp, const Statement& statement,
            const Witness& witness, std::string_view context) {
    TAIHANG_ASSERT(valid_dimensions(pp, statement), "homomorphism-evaluation dimensions mismatch");
    TAIHANG_ASSERT(witness.a.size() == pp.vector_length, "homomorphism-evaluation witness length");
    const auto alpha = gen_random_znelement_vector(pp.ring_ctx, pp.vector_length);
    const ZnElement beta = pp.ring_ctx->gen_random();
    Proof proof{ec_point_msm(pp.vector_g, alpha) + pp.u * beta,
                ec_point_msm(statement.bases, alpha), ZnElement(pp.ring_ctx), {}};
    std::ostringstream transcript;
    transcript << initial_transcript(pp, statement, context) << proof.a_p << proof.a_q;
    ZnElement e = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (e.value.is_zero()) {
        e = pp.ring_ctx->get_one();
    }
    proof.f = beta + e * witness.r;
    transcript << proof.f;
    std::vector<ZnElement> z(pp.vector_length, pp.ring_ctx->get_zero());
    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        z[i] = alpha[i] + e * witness.a[i];
    }
    const auto equality_pp = multi_exponentiation_equality::setup(
        pp.group_ctx, pp.ring_ctx, statement.bases, pp.vector_g);
    const multi_exponentiation_equality::Statement relation{
        proof.a_q + ec_point_msm(statement.bases, witness.a) * e,
        proof.a_p + statement.p * e - pp.u * proof.f};
    proof.equality_proof = multi_exponentiation_equality::prove(
        equality_pp, relation, {std::move(z)}, transcript.str());
    return proof;
}

bool verify(const PublicParameters& pp, const Statement& statement,
            const Proof& proof, std::string_view context) {
    if (!valid_dimensions(pp, statement) || proof.equality_proof.left_g.size() != pp.rounds ||
        proof.equality_proof.right_g.size() != pp.rounds ||
        proof.equality_proof.left_p.size() != pp.rounds ||
        proof.equality_proof.right_p.size() != pp.rounds) {
        return false;
    }
    std::ostringstream transcript;
    transcript << initial_transcript(pp, statement, context) << proof.a_p << proof.a_q;
    ZnElement e = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (e.value.is_zero()) {
        e = pp.ring_ctx->get_one();
    }
    transcript << proof.f;
    const auto equality_pp = multi_exponentiation_equality::setup(
        pp.group_ctx, pp.ring_ctx, statement.bases, pp.vector_g);
    const multi_exponentiation_equality::Statement relation{
        proof.a_q + statement.q * e, proof.a_p + statement.p * e - pp.u * proof.f};
    return multi_exponentiation_equality::verify(
        equality_pp, relation, proof.equality_proof, transcript.str());
}

} // namespace taihang::zkp::nizk::homomorphism_evaluation
