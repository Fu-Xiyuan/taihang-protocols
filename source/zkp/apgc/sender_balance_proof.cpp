/****************************************************************************
 * @file      sender_balance_proof.cpp
 * @brief     Direct migration of SdrBalance commitments and subproof relations.
 *****************************************************************************/

#include <taihang/zkp/apgc/sender_balance_proof.hpp>

#include <istream>
#include <ostream>
#include <sstream>

#include <taihang/common/check.hpp>
#include <taihang/utility/arithmetic.hpp>

namespace taihang::zkp::apgc::sender_balance {
namespace {

namespace common = taihang::zkp::apgc::ciphertext_homomorphism::detail;
namespace binary = taihang::zkp::nizk::fixed_weight_binary_vector;
namespace representation = taihang::zkp::nizk::multi_exponentiation;
namespace evaluation = taihang::zkp::nizk::homomorphism_evaluation;
namespace range = taihang::zkp::range_proofs::bulletproof;
using ScalarVector = std::vector<ZnElement>;

std::vector<ECPoint> commitment_bases(const PublicParameters& pp, bool complement) {
    std::vector<ECPoint> bases = complement ? pp.vector_h : pp.vector_g;
    bases.insert(bases.end(), pp.vector_u.begin(), pp.vector_u.end());
    return bases;
}

evaluation::PublicParameters commitment_parameters(const PublicParameters& pp) {
    return evaluation::setup(pp.encryption.group_ctx, pp.encryption.ring_ctx, pp.u, commitment_bases(pp, false));
}

binary::PublicParameters binary_parameters(const PublicParameters& pp) {
    return binary::setup(pp.encryption.group_ctx, pp.encryption.ring_ctx,
        pp.encryption.g, pp.encryption.h, pp.u, pp.inner_product_u, pp.vector_g, pp.vector_h);
}

std::string initial_homomorphism_transcript(const PublicParameters& pp,
    const Statement& statement, const Proof& proof, std::string_view context) {
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
    const Statement& statement, const Proof& proof, std::string& transcript) {
    transcript = initial_homomorphism_transcript(pp, statement, proof, transcript);
    const std::size_t n = pp.participant_count;
    const ScalarVector rho = common::powers(3 * n, hash_to_zn(transcript, *pp.encryption.ring_ctx));
    evaluation::Statement result{proof.p, pp.encryption.group_ctx->get_infinity(),
        std::vector<ECPoint>(4 * n, ECPoint(pp.encryption.group_ctx))};
    for (std::size_t j = 0; j < n; ++j) {
        const ECPoint left = statement.transfers[j].c1 + statement.balances[j].c1;
        const ECPoint right = statement.transfers[j].c2 + statement.balances[j].c2;
        result.bases[j] = pp.encryption.g * (-rho[3 * j]) + right * (-rho[3 * j + 1]) + proof.v * (-rho[3 * j + 2]);
        result.bases[n + 2 * j] = ec_point_msm(statement.public_keys[j], rho[3 * j], left, rho[3 * j + 1]);
        result.bases[n + 2 * j + 1] = pp.encryption.h * (rho[3 * j + 1] + rho[3 * j + 2]);
        result.bases[3 * n + j] = pp.encryption.g * rho[3 * j + 2];
    }
    return result;
}

} // namespace

PublicParameters setup(const pke::twisted_elgamal::PublicParameters& encryption,
                       std::size_t participant_count) {
    TAIHANG_ASSERT(taihang::arithmetic::is_pow2(participant_count), "sender-balance participant count must be a power of two");
    PublicParameters pp;
    pp.encryption = encryption;
    pp.participant_count = participant_count;
    pp.u = common::generators(encryption.group_ctx, 1, "taihang/apgc/sender-balance/u/")[0];
    pp.inner_product_u = common::generators(encryption.group_ctx, 1, "taihang/apgc/sender-balance/ip-u/")[0];
    pp.vector_g = common::generators(encryption.group_ctx, participant_count, "taihang/apgc/sender-balance/g/");
    pp.vector_h = common::generators(encryption.group_ctx, participant_count, "taihang/apgc/sender-balance/h/");
    pp.vector_u = common::generators(encryption.group_ctx, 3 * participant_count, "taihang/apgc/sender-balance/vector-u/");
    pp.range = common::range_parameters(encryption, 32, 1, pp.u, "taihang/apgc/sender-balance/range");
    return pp;
}

bool Proof::operator==(const Proof& other) const {
    return p == other.p && s == other.s && v == other.v && z_s == other.z_s && k == other.k &&
        f == other.f && a_x == other.a_x && homomorphism == other.homomorphism &&
        binary == other.binary && representation == other.representation && range == other.range;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    return os << proof.p << proof.s << proof.v << proof.z_s << proof.k << proof.f << proof.a_x
              << proof.homomorphism << proof.binary << proof.representation << proof.range;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    is >> proof.p >> proof.s >> proof.v >> proof.z_s >> proof.k >> proof.f >> proof.a_x;
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
    const std::size_t rounds = common::folding_rounds(4 * pp.participant_count);
    return {ECPoint(group), ECPoint(group), ECPoint(group), ZnElement(ring), ZnElement(ring),
        ZnElement(ring), ECPoint(group), common::initialize_evaluation(commitment_parameters(pp)),
        {ECPoint(group), ECPoint(group), ECPoint(group), ZnElement(ring), ZnElement(ring), ZnElement(ring),
         common::initialize_inner(pp.encryption, pp.participant_count)},
        {std::vector<ECPoint>(rounds, ECPoint(group)), std::vector<ECPoint>(rounds, ECPoint(group)), ZnElement(ring)},
        common::initialize_range(pp.range)};
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
    TAIHANG_ASSERT(detail::valid_statement(pp, statement) && witness.index < pp.participant_count,
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
    proof.v = ec_point_msm(pp.encryption.g, r_v, pp.encryption.h, witness.post_balance);
    proof.p = ec_point_msm(commitment_bases(pp, false), y) + pp.u * r_p;
    proof.s = ec_point_msm(pp.vector_g, selection) + ec_point_msm(pp.vector_h, complement) + pp.u * r_s;
    proof.range = range::prove(pp.range, {{proof.v}}, {{r_v}, {witness.post_balance}});
    proof.binary = binary::prove(binary_parameters(pp), {proof.s, 1}, {selection, complement, r_s});

    const std::vector<ECPoint> bases = commitment_bases(pp, true);
    const representation::PublicParameters exp = representation::setup(pp.encryption.group_ctx, ring, bases);
    const ScalarVector alpha = gen_random_znelement_vector(ring, 4 * n);
    const ZnElement beta = ring->gen_random();
    proof.a_x = ec_point_msm(bases, alpha) + pp.u * beta;
    std::ostringstream input;
    input << proof.a_x;
    const ZnElement e = hash_to_zn(input.str(), *ring);
    proof.f = beta + e * (r_p - r_s);
    ScalarVector response(4 * n, ring->get_zero());
    for (std::size_t i = 0; i < 4 * n; ++i) {
        const ZnElement value = i < n ? one - selection[i] : y[i];
        response[i] = alpha[i] + e * value;
    }
    proof.representation = representation::prove(exp,
        {(proof.p - proof.s) * e + proof.a_x - pp.u * proof.f}, {response});
    std::string transcript(context);
    const evaluation::Statement relation = homomorphism_relation(pp, statement, proof, transcript);
    proof.homomorphism = common::prove_evaluation(commitment_parameters(pp), relation, {y, r_p}, transcript);
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
    const representation::PublicParameters exp = representation::setup(
        pp.encryption.group_ctx, pp.encryption.ring_ctx, commitment_bases(pp, true));
    if (!representation::verify(exp, {(proof.p - proof.s) * e + proof.a_x - pp.u * proof.f}, proof.representation)) {
        return false;
    }
    std::string transcript(context);
    const evaluation::Statement relation = homomorphism_relation(pp, statement, proof, transcript);
    return common::verify_evaluation(commitment_parameters(pp), relation, proof.homomorphism, transcript);
}

namespace detail {

bool valid_statement(const PublicParameters& pp, const Statement& statement) {
    const std::size_t n = pp.participant_count;
    return taihang::arithmetic::is_pow2(n) && pp.vector_g.size() == n && pp.vector_h.size() == n &&
        pp.vector_u.size() == 3 * n && statement.public_keys.size() == n &&
        statement.transfers.size() == n && statement.balances.size() == n;
}

std::string homomorphism_transcript(const PublicParameters& pp, const Statement& statement,
                                   const Proof& proof, std::string_view context) {
    std::ostringstream transcript;
    transcript << initial_homomorphism_transcript(pp, statement, proof, context)
               << proof.homomorphism.a_p << proof.homomorphism.a_q;
    common::append_equality(transcript, proof.homomorphism.equality_proof);
    return transcript.str();
}

} // namespace detail

} // namespace taihang::zkp::apgc::sender_balance
