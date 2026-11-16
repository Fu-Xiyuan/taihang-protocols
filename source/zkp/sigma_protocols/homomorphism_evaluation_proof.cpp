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

/** Include the blinding term in the vector MSM. */
ECPoint commit_vector(const std::vector<ECPoint>& g,
                      const ECPoint& u,
                      const std::vector<ZnElement>& a,
                      const ZnElement& r) {
    std::vector<const ECPoint*> points(g.size() + 1, nullptr);
    std::vector<ZnElement> scalars = a;
    for (std::size_t i = 0; i < g.size(); ++i) {
        points[i] = &g[i];
    }
    points.back() = &u;
    scalars.push_back(r);
    return ec_point_msm(points, scalars);
}

namespace equality = taihang::zkp::nizk::multi_exponentiation_equality;

bool valid_dimensions(const PublicParameters& pp, const Statement& statement) {
    return pp.vector_length > 0 && (pp.vector_length & (pp.vector_length - 1)) == 0 &&
           pp.rounds < sizeof(std::size_t) * 8 &&
           (std::size_t{1} << pp.rounds) == pp.vector_length &&
           pp.vector_g.size() == pp.vector_length && statement.bases.size() == pp.vector_length;
}

void append_equality(std::ostringstream& transcript, const equality::Proof& proof) {
    for (std::size_t i = 0; i < proof.left_g.size(); ++i) {
        transcript << proof.left_g[i] << proof.right_g[i] << proof.left_p[i] << proof.right_p[i];
    }
}

} // namespace

PublicParameters setup(int curve_id, std::size_t vector_length) {
    const multi_exponentiation_equality::PublicParameters bases =
        multi_exponentiation_equality::setup(curve_id, vector_length);
    // The independently derived second basis supplies the blinding point.
    return {curve_id, vector_length, bases.rounds, bases.group_ctx, bases.ring_ctx,
            bases.p[0], bases.g};
}

PublicParameters setup(const std::shared_ptr<ECGroup>& group_ctx,
                       const std::shared_ptr<Zn>& ring_ctx,
                       const ECPoint& u,
                       const std::vector<ECPoint>& vector_g) {
    const multi_exponentiation_equality::PublicParameters bases =
        multi_exponentiation_equality::setup(group_ctx, ring_ctx, vector_g, vector_g);
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

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    TAIHANG_ASSERT(valid_dimensions(pp, statement),
                   "homomorphism-evaluation dimensions mismatch");
    std::string transcript(context);
    return detail::prove_with_transcript(pp, statement, witness, transcript, true);
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
    if (!valid_dimensions(pp, statement)) {
        return false;
    }
    std::string transcript(context);
    return detail::verify_with_transcript(pp, statement, proof, transcript, true);
}

namespace detail {

Proof initialize_proof(const PublicParameters& pp) {
    return {ECPoint(pp.group_ctx), ECPoint(pp.group_ctx), ZnElement(pp.ring_ctx),
        {std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
         std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
         std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
         std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)), ZnElement(pp.ring_ctx)}};
}

Proof prove_with_transcript(const PublicParameters& pp,
                            const Statement& statement,
                            const Witness& witness,
                            std::string& transcript,
                            bool reset_equality_context,
                            std::string_view suffix) {
    TAIHANG_ASSERT(witness.a.size() == pp.vector_length,
        "homomorphism evaluation witness length mismatch");
    const std::vector<ZnElement> alpha = gen_random_znelement_vector(pp.ring_ctx, pp.vector_length);
    const ZnElement beta = pp.ring_ctx->gen_random();
    Proof proof = detail::initialize_proof(pp);
    proof.a_p = commit_vector(pp.vector_g, pp.u, alpha, beta);
    proof.a_q = ec_point_msm(statement.bases, alpha);
    std::ostringstream input;
    input << transcript << proof.a_p << proof.a_q;
    input.write(suffix.data(), static_cast<std::streamsize>(suffix.size()));
    const ZnElement e = hash_to_zn(input.str(), *pp.ring_ctx);
    proof.f = beta + e * witness.r;
    std::vector<ZnElement> response(pp.vector_length, pp.ring_ctx->get_zero());
    for (std::size_t i = 0; i < response.size(); ++i) {
        response[i] = alpha[i] + e * witness.a[i];
    }
    const equality::PublicParameters eq = equality::setup(pp.group_ctx, pp.ring_ctx,
                                                          statement.bases, pp.vector_g);
    std::vector<ZnElement> target_scalars = witness.a;
    for (ZnElement& value : target_scalars) {
        value *= e;
    }
    const equality::Statement target{
        commit_vector(
            statement.bases, proof.a_q, target_scalars, pp.ring_ctx->get_one()),
        ec_point_msm({statement.p, proof.a_p, pp.u},
                     {e, pp.ring_ctx->get_one(), -proof.f})
    };
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

bool verify_with_transcript(const PublicParameters& pp,
                            const Statement& statement,
                            const Proof& proof,
                            std::string& transcript,
                            bool reset_equality_context,
                            std::string_view suffix) {
    if (statement.bases.size() != pp.vector_length || pp.vector_g.size() != pp.vector_length ||
        proof.equality_proof.left_g.size() != pp.rounds ||
        proof.equality_proof.right_g.size() != pp.rounds ||
        proof.equality_proof.left_p.size() != pp.rounds ||
        proof.equality_proof.right_p.size() != pp.rounds) {
        return false;
    }
    std::ostringstream input;
    input << transcript << proof.a_p << proof.a_q;
    input.write(suffix.data(), static_cast<std::streamsize>(suffix.size()));
    const ZnElement e = hash_to_zn(input.str(), *pp.ring_ctx);
    const equality::PublicParameters eq = equality::setup(pp.group_ctx, pp.ring_ctx,
                                                          statement.bases, pp.vector_g);
    const equality::Statement target{
        ec_point_msm(proof.a_q, pp.ring_ctx->get_one(), statement.q, e),
        ec_point_msm({statement.p, proof.a_p, pp.u},
                     {e, pp.ring_ctx->get_one(), -proof.f})
    };
    transcript = reset_equality_context ? std::string{} : input.str();
    const bool valid = equality::verify(eq, target, proof.equality_proof, transcript);
    std::ostringstream final;
    final << transcript;
    append_equality(final, proof.equality_proof);
    transcript = final.str();
    return valid;
}

} // namespace detail

} // namespace taihang::zkp::nizk::homomorphism_evaluation
