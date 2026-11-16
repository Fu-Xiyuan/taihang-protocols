/****************************************************************************
 * @file      sender_balance_proof.cpp
 * @brief     Direct migration of SdrBalance commitments and subproof relations.
 *****************************************************************************/

#include <taihang/zkp/apgc/sender_balance_proof.hpp>

#include <openssl/obj_mac.h>

#include <istream>
#include <ostream>
#include <sstream>

#include <taihang/common/check.hpp>
#include <taihang/utility/arithmetic.hpp>

namespace taihang::zkp::apgc::sender_balance {
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

/** Commit both vectors and the blinding scalar in one MSM. */
ECPoint commit_vectors(const std::vector<ECPoint>& g,
                       const std::vector<ECPoint>& h,
                       const ECPoint& u,
                       const std::vector<ZnElement>& a,
                       const std::vector<ZnElement>& b,
                       const ZnElement& r) {
    const std::size_t length = g.size();
    std::vector<const ECPoint*> points(2 * length + 1, nullptr);
    std::vector<ZnElement> scalars(points.size(), r.ring_ctx->get_zero());
    for (std::size_t i = 0; i < length; ++i) {
        points[i] = &g[i];
        scalars[i] = a[i];
        points[length + i] = &h[i];
        scalars[length + i] = b[i];
    }
    points.back() = &u;
    scalars.back() = r;
    return ec_point_msm(points, scalars);
}

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

range_proofs::inner_product::Proof initialize_inner(
    const pke::twisted_elgamal::PublicParameters& encryption,
    std::size_t length) {
    const std::size_t rounds = folding_rounds(length);
    return {
        std::vector<ECPoint>(rounds, ECPoint(encryption.group_ctx)),
        std::vector<ECPoint>(rounds, ECPoint(encryption.group_ctx)),
        ZnElement(encryption.ring_ctx),
        ZnElement(encryption.ring_ctx)
    };
}

range_proofs::bulletproof::PublicParameters range_parameters(
    const pke::twisted_elgamal::PublicParameters& encryption,
    std::size_t range_bits,
    std::size_t count,
    const ECPoint& u,
    const std::string& label) {
    TAIHANG_ASSERT(taihang::arithmetic::is_pow2(range_bits) &&
                       taihang::arithmetic::is_pow2(count),
                   "original APGC range dimensions must be powers of two");
    const std::size_t length = range_bits * count;
    return {
        encryption.curve_id,
        range_bits,
        count,
        length,
        encryption.group_ctx,
        encryption.ring_ctx,
        encryption.g,
        encryption.h,
        u,
        generators(encryption.group_ctx, length, label + "/g/"),
        generators(encryption.group_ctx, length, label + "/h/")
    };
}

range_proofs::bulletproof::Proof initialize_range(
    const range_proofs::bulletproof::PublicParameters& pp) {
    const std::size_t rounds = folding_rounds(pp.vector_length);
    return {
        ECPoint(pp.group_ctx),
        ECPoint(pp.group_ctx),
        ECPoint(pp.group_ctx),
        ECPoint(pp.group_ctx),
        ZnElement(pp.ring_ctx),
        ZnElement(pp.ring_ctx),
        ZnElement(pp.ring_ctx),
        {std::vector<ECPoint>(rounds, ECPoint(pp.group_ctx)),
         std::vector<ECPoint>(rounds, ECPoint(pp.group_ctx)),
         ZnElement(pp.ring_ctx),
         ZnElement(pp.ring_ctx)}
    };
}

namespace binary = taihang::zkp::nizk::fixed_weight_binary_vector;
namespace representation = taihang::zkp::nizk::multi_exponentiation;
namespace evaluation = taihang::zkp::nizk::homomorphism_evaluation;
namespace range = taihang::zkp::range_proofs::bulletproof;
using ScalarVector = std::vector<ZnElement>;

std::vector<ECPoint> commitment_bases(const PublicParameters& pp,
                                      bool complement) {
    std::vector<ECPoint> bases = complement ? pp.vector_h : pp.vector_g;
    bases.insert(bases.end(), pp.vector_u.begin(), pp.vector_u.end());
    return bases;
}

evaluation::PublicParameters commitment_parameters(const PublicParameters& pp) {
    return evaluation::setup(pp.encryption.group_ctx,
                             pp.encryption.ring_ctx,
                             pp.u,
                             commitment_bases(pp, false));
}

binary::PublicParameters binary_parameters(const PublicParameters& pp) {
    return binary::setup(pp.encryption.group_ctx,
                         pp.encryption.ring_ctx,
                         pp.encryption.g,
                         pp.encryption.h,
                         pp.u,
                         pp.inner_product_u,
                         pp.vector_g,
                         pp.vector_h);
}

std::string initial_homomorphism_transcript(const PublicParameters& pp,
                                            const Statement& statement,
                                            const Proof& proof,
                                            std::string_view context) {
    std::ostringstream transcript;
    transcript << context << proof.p << proof.v;
    for (std::size_t j = 0; j < pp.participant_count; ++j) {
        transcript << statement.transfers[j].c1 + statement.balances[j].c1
                   << statement.transfers[j].c2 + statement.balances[j].c2
                   << statement.public_keys[j];
    }
    return transcript.str();
}

evaluation::Statement homomorphism_relation(const PublicParameters& pp,
                                            const Statement& statement,
                                            const Proof& proof,
                                            std::string& transcript) {
    transcript =
        initial_homomorphism_transcript(pp, statement, proof, transcript);
    const std::size_t n = pp.participant_count;
    const ScalarVector rho =
        powers(3 * n, hash_to_zn(transcript, *pp.encryption.ring_ctx));
    evaluation::Statement result{
        proof.p,
        pp.encryption.group_ctx->get_infinity(),
        std::vector<ECPoint>(4 * n, ECPoint(pp.encryption.group_ctx))
    };
    for (std::size_t j = 0; j < n; ++j) {
        const ECPoint left =
            statement.transfers[j].c1 + statement.balances[j].c1;
        const ECPoint right =
            statement.transfers[j].c2 + statement.balances[j].c2;
        result.bases[j] =
            ec_point_msm({pp.encryption.g, right, proof.v},
                         {-rho[3 * j], -rho[3 * j + 1], -rho[3 * j + 2]});
        result.bases[n + 2 * j] = ec_point_msm(
            statement.public_keys[j], rho[3 * j], left, rho[3 * j + 1]);
        result.bases[n + 2 * j + 1] =
            pp.encryption.h * (rho[3 * j + 1] + rho[3 * j + 2]);
        result.bases[3 * n + j] = pp.encryption.g * rho[3 * j + 2];
    }
    return result;
}

} // namespace

PublicParameters setup(const pke::twisted_elgamal::PublicParameters& encryption,
                       std::size_t participant_count) {
    TAIHANG_ASSERT(taihang::arithmetic::is_pow2(participant_count),
                   "sender-balance participant count must be a power of two");
    PublicParameters pp;
    pp.encryption = encryption;
    pp.participant_count = participant_count;
    pp.u = generators(
        encryption.group_ctx, 1, "taihang/apgc/sender-balance/u/")[0];
    pp.inner_product_u = generators(
        encryption.group_ctx, 1, "taihang/apgc/sender-balance/ip-u/")[0];
    pp.vector_g = generators(encryption.group_ctx,
                             participant_count,
                             "taihang/apgc/sender-balance/g/");
    pp.vector_h = generators(encryption.group_ctx,
                             participant_count,
                             "taihang/apgc/sender-balance/h/");
    pp.vector_u = generators(encryption.group_ctx,
                             3 * participant_count,
                             "taihang/apgc/sender-balance/vector-u/");
    pp.range = range_parameters(
        encryption, 32, 1, pp.u, "taihang/apgc/sender-balance/range");
    return pp;
}

bool Proof::operator==(const Proof& other) const {
    return p == other.p && s == other.s && v == other.v && z_s == other.z_s &&
           k == other.k && f == other.f && a_x == other.a_x &&
           homomorphism == other.homomorphism && binary == other.binary &&
           representation == other.representation && range == other.range;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    return os << proof.p << proof.s << proof.v << proof.z_s << proof.k
              << proof.f << proof.a_x << proof.homomorphism << proof.binary
              << proof.representation << proof.range;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    is >> proof.p >> proof.s >> proof.v >> proof.z_s >> proof.k >> proof.f >>
        proof.a_x;
    if (is) {
        is >> proof.homomorphism;
    }
    if (is) {
        is >> proof.binary;
    }
    if (is) {
        is >> proof.representation;
    }
    if (is) {
        is >> proof.range;
    }
    return is;
}

Proof initialize_proof(const PublicParameters& pp) {
    const std::shared_ptr<ECGroup> group = pp.encryption.group_ctx;
    const std::shared_ptr<Zn> ring = pp.encryption.ring_ctx;
    const std::size_t rounds = folding_rounds(4 * pp.participant_count);
    return {
        ECPoint(group),
        ECPoint(group),
        ECPoint(group),
        ZnElement(ring),
        ZnElement(ring),
        ZnElement(ring),
        ECPoint(group),
        nizk::homomorphism_evaluation::detail::initialize_proof(
            commitment_parameters(pp)),
        {ECPoint(group),
         ECPoint(group),
         ECPoint(group),
         ZnElement(ring),
         ZnElement(ring),
         ZnElement(ring),
         initialize_inner(pp.encryption, pp.participant_count)},
        {std::vector<ECPoint>(rounds, ECPoint(group)),
         std::vector<ECPoint>(rounds, ECPoint(group)),
         ZnElement(ring)},
        initialize_range(pp.range)
    };
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    detail::ProverState state{ZnElement(pp.encryption.ring_ctx)};
    return detail::prove_with_state(pp, statement, witness, state, context);
}

Proof detail::prove_with_state(const PublicParameters& pp,
                               const Statement& statement,
                               const Witness& witness,
                               ProverState& state,
                               std::string_view context) {
    TAIHANG_ASSERT(detail::valid_statement(pp, statement) &&
                       witness.index < pp.participant_count,
                   "sender-balance dimensions mismatch");
    const std::size_t n = pp.participant_count;
    const std::shared_ptr<Zn> ring = pp.encryption.ring_ctx;
    const ZnElement one = ring->get_one();
    const ZnElement r_p = ring->gen_random();
    const ZnElement r_s = ring->gen_random();
    const ZnElement r_v = ring->gen_random();
    ScalarVector selection(n, ring->get_zero());
    selection[witness.index] = one;
    ScalarVector complement(n, -one);
    complement[witness.index] = ring->get_zero();
    ScalarVector y(4 * n, ring->get_zero());
    y[witness.index] = one;
    y[n + 2 * witness.index] = witness.inverse_secret_key;
    y[n + 2 * witness.index + 1] = witness.post_balance;
    y[3 * n + witness.index] = r_v;
    Proof proof = initialize_proof(pp);
    state.r_s = r_s;
    proof.v = ec_point_msm(
        pp.encryption.g, r_v, pp.encryption.h, witness.post_balance);
    proof.p = commit_vector(commitment_bases(pp, false), pp.u, y, r_p);
    proof.s = commit_vectors(
        pp.vector_g, pp.vector_h, pp.u, selection, complement, r_s);
    proof.range =
        range::prove(pp.range, {{proof.v}}, {{r_v}, {witness.post_balance}});
    proof.binary = binary::prove(
        binary_parameters(pp), {proof.s, 1}, {selection, complement, r_s});

    const std::vector<ECPoint> bases = commitment_bases(pp, true);
    const representation::PublicParameters exp =
        representation::setup(pp.encryption.group_ctx, ring, bases);
    const ScalarVector alpha = gen_random_znelement_vector(ring, 4 * n);
    const ZnElement beta = ring->gen_random();
    proof.a_x = commit_vector(bases, pp.u, alpha, beta);
    std::ostringstream input;
    input << proof.a_x;
    const ZnElement e = hash_to_zn(input.str(), *ring);
    proof.f = beta + e * (r_p - r_s);
    ScalarVector response(4 * n, ring->get_zero());
    for (std::size_t i = 0; i < 4 * n; ++i) {
        const ZnElement value = i < n ? one - selection[i] : y[i];
        response[i] = alpha[i] + e * value;
    }
    proof.representation = representation::prove(
        exp,
        {ec_point_msm({proof.p, proof.s, proof.a_x, pp.u},
                      {e, -e, pp.encryption.ring_ctx->get_one(), -proof.f})},
        {response});
    std::string transcript(context);
    const evaluation::Statement relation =
        homomorphism_relation(pp, statement, proof, transcript);
    proof.homomorphism =
        nizk::homomorphism_evaluation::detail::prove_with_transcript(
            commitment_parameters(pp), relation, {y, r_p}, transcript, false);
    return proof;
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
    if (!detail::valid_statement(pp, statement)) {
        return false;
    }
    if (!range::verify(pp.range, {{proof.v}}, proof.range) ||
        !binary::verify(binary_parameters(pp), {proof.s, 1}, proof.binary)) {
        return false;
    }
    std::ostringstream input;
    input << proof.a_x;
    const ZnElement e = hash_to_zn(input.str(), *pp.encryption.ring_ctx);
    const representation::PublicParameters exp =
        representation::setup(pp.encryption.group_ctx,
                              pp.encryption.ring_ctx,
                              commitment_bases(pp, true));
    if (!representation::verify(
            exp,
            {ec_point_msm(
                {proof.p, proof.s, proof.a_x, pp.u},
                {e, -e, pp.encryption.ring_ctx->get_one(), -proof.f})},
            proof.representation)) {
        return false;
    }
    std::string transcript(context);
    const evaluation::Statement relation =
        homomorphism_relation(pp, statement, proof, transcript);
    return nizk::homomorphism_evaluation::detail::verify_with_transcript(
        commitment_parameters(pp),
        relation,
        proof.homomorphism,
        transcript,
        false);
}

namespace detail {

bool valid_statement(const PublicParameters& pp, const Statement& statement) {
    const std::size_t n = pp.participant_count;
    return taihang::arithmetic::is_pow2(n) && pp.vector_g.size() == n &&
           pp.vector_h.size() == n && pp.vector_u.size() == 3 * n &&
           statement.public_keys.size() == n &&
           statement.transfers.size() == n && statement.balances.size() == n;
}

std::string homomorphism_transcript(const PublicParameters& pp,
                                    const Statement& statement,
                                    const Proof& proof,
                                    std::string_view context) {
    std::ostringstream transcript;
    transcript << initial_homomorphism_transcript(pp, statement, proof, context)
               << proof.homomorphism.a_p << proof.homomorphism.a_q;
    const nizk::multi_exponentiation_equality::Proof& equality =
        proof.homomorphism.equality_proof;
    for (std::size_t i = 0; i < equality.left_g.size(); ++i) {
        transcript << equality.left_g[i] << equality.right_g[i]
                   << equality.left_p[i] << equality.right_p[i];
    }
    return transcript.str();
}

} // namespace detail

} // namespace taihang::zkp::apgc::sender_balance
