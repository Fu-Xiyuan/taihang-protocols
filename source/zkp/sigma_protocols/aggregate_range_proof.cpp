/****************************************************************************
 * @file      aggregate_range_proof.cpp
 * @brief     Weighted and delayed aggregate range proof implementation.
 *****************************************************************************/

#include <taihang/zkp/sigma_protocols/aggregate_range_proof.hpp>

#include <openssl/bn.h>
#include <openssl/obj_mac.h>

#include <cstdint>
#include <istream>
#include <limits>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>

#include <taihang/common/check.hpp>
#include <taihang/utility/arithmetic.hpp>

namespace taihang::zkp::nizk::aggregate_range {
namespace {

using ScalarVector = std::vector<ZnElement>;
using taihang::arithmetic::is_pow2;
namespace inner_product = taihang::zkp::range_proofs::inner_product;

ECPoint derive_generator(const std::string& label, const ECGroup& group) {
    static const std::string kP256Dst = "TAIHANG-PROTOCOLS-V01-P256_XMD:SHA-256_SSWU_RO_";
    if (group.curve_id == NID_X9_62_prime256v1) {
        return hash_to_curve_standard(label, kP256Dst, group);
    }
    return hash_to_curve_fast(label, group);
}

std::size_t padded_length(std::size_t bits, std::size_t count) {
    if (!is_pow2(bits) || count == 0 ||
        bits > std::numeric_limits<std::size_t>::max() / count) {
        return 0;
    }
    std::size_t length = 1;
    while (length < bits * count) {
        if (length > (std::numeric_limits<std::size_t>::max() - 4) / 4) {
            return 0;
        }
        length *= 2;
    }
    return length;
}

bool valid_dimensions(const PublicParameters& pp) {
    return pp.vector_length > 0 && pp.vector_length == padded_length(pp.range_bits,
        pp.value_count) &&
           pp.rounds < sizeof(std::size_t) * 8 &&
           (std::size_t{1} << pp.rounds) == pp.vector_length &&
           pp.vector_g.size() == pp.vector_length && pp.vector_h.size() == pp.vector_length;
}

ScalarVector powers(std::size_t count, const ZnElement& base) {
    ScalarVector result(count, base.ring_ctx->get_one());
    for (std::size_t i = 1; i < count; ++i) {
        result[i] = result[i - 1] * base;
    }
    return result;
}

ZnElement dot(const ScalarVector& a, const ScalarVector& b) {
    ZnElement result = a.front().ring_ctx->get_zero();
    for (std::size_t i = 0; i < a.size(); ++i) {
        result += a[i] * b[i];
    }
    return result;
}

ZnElement challenge(const std::string& transcript, const Zn& ring) {
    ZnElement result = hash_to_zn(transcript, ring);
    if (result.value.is_zero()) {
        result = ring.get_one();
    }
    return result;
}

std::string initial_transcript(std::string_view context) {
    std::ostringstream transcript;
    transcript.write(context.data(),
                     static_cast<std::streamsize>(context.size()));
    return transcript.str();
}

bool valid_weights(const PublicParameters& pp, const Statement& statement) {
    if (statement.weights.size() != pp.value_count) {
        return false;
    }
    for (const ZnElement& weight : statement.weights) {
        if (weight.value.is_zero()) {
            return false;
        }
    }
    return true;
}

/** Expand the aggregate coefficients into per-bit polynomial coefficients. */
ScalarVector bit_coefficients(const PublicParameters& pp,
                              const ScalarVector& weights,
                              const ZnElement& factor) {
    ScalarVector result(pp.vector_length, pp.ring_ctx->get_zero());
    const ScalarVector two = powers(pp.range_bits, ZnElement(pp.ring_ctx, BigInt(uint64_t{2})));
    for (std::size_t j = 0; j < pp.value_count; ++j) {
        for (std::size_t bit = 0; bit < pp.range_bits; ++bit) {
            result[j * pp.range_bits + bit] = factor * weights[j] * two[bit];
        }
    }
    return result;
}

inner_product::PublicParameters inner_parameters(
    const PublicParameters& pp,
    const ScalarVector& inverse_y,
    const ZnElement& e) {
    inner_product::PublicParameters ip;
    ip.curve_id = pp.curve_id;
    ip.vector_length = pp.vector_length;
    ip.rounds = pp.rounds;
    ip.group_ctx = pp.group_ctx;
    ip.ring_ctx = pp.ring_ctx;
    ip.g = pp.vector_g;
    ip.h = std::vector<ECPoint>(pp.vector_length, ECPoint(pp.group_ctx));
    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        ip.h[i] = pp.vector_h[i] * inverse_y[i];
    }
    ip.u = pp.u * e;
    return ip;
}

ECPoint inner_statement(const PublicParameters& pp,
                        const Proof& proof,
                        const inner_product::PublicParameters& ip,
                        const ScalarVector& y,
                        const ScalarVector& coefficients,
                        const ZnElement& z,
                        const ZnElement& x) {
    ScalarVector left(pp.vector_length, -z);
    ScalarVector right(pp.vector_length, pp.ring_ctx->get_zero());
    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        right[i] = z * y[i] + coefficients[i];
    }
    return proof.a + proof.s * x + ec_point_msm(ip.g, left) + ec_point_msm(ip.h, right) -
           pp.h * proof.mu + ip.u * proof.t;
}

struct ProverState {
    std::vector<ZnElement> values;
    ScalarVector a_left;
    ScalarVector a_right;
    ScalarVector s_left;
    ScalarVector s_right;
    ZnElement alpha;
    ZnElement rho;
    ECPoint a;
    ECPoint s;
};

ProverState prepare(const PublicParameters& pp, const ScalarVector& values);

DelayedProof prove_impl(const PublicParameters& pp,
                        const Statement* statement,
                        const ScalarVector& values,
                        const ZnElement& randomness,
                        const ScalarVector* per_value_randomness,
                        std::string_view context) {
    TAIHANG_ASSERT(valid_dimensions(pp), "aggregate-range parameter dimensions mismatch");
    TAIHANG_ASSERT(values.size() == pp.value_count, "aggregate-range witness length mismatch");
    TAIHANG_ASSERT(!statement || valid_weights(pp, *statement), "aggregate-range invalid weights");
    const ZnElement zero = pp.ring_ctx->get_zero();
    const ZnElement one = pp.ring_ctx->get_one();
    ProverState state = prepare(pp, values);
    const ScalarVector& a_left = state.a_left;
    const ScalarVector& a_right = state.a_right;
    const ScalarVector& s_left = state.s_left;
    const ScalarVector& s_right = state.s_right;
    DelayedProof proof{{state.a, state.s,
        ECPoint(pp.group_ctx), ECPoint(pp.group_ctx),
        ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx), {}},
        ECPoint(pp.group_ctx)};
    std::ostringstream transcript;
    transcript << initial_transcript(context) << proof.a;
    const ZnElement y = challenge(transcript.str(), *pp.ring_ctx);
    transcript << proof.s;
    const ZnElement z = challenge(transcript.str(), *pp.ring_ctx);
    const ScalarVector y_power = powers(pp.vector_length, y);
    ScalarVector weights;
    ZnElement aggregate_r = randomness;
    const ZnElement factor = statement ? z * z : one;
    if (statement) {
        weights = statement->weights;
        proof.aggregate = statement->aggregate;
    } else {
        weights = powers(pp.value_count, z);
        for (ZnElement& weight : weights) {
            weight *= z * z;
        }
        aggregate_r = dot(weights, *per_value_randomness);
        proof.aggregate = ec_point_msm(pp.g, aggregate_r, pp.h, dot(weights, values));
    }
    if (!statement) {
        transcript << proof.aggregate;
    }
    const ScalarVector coefficients = bit_coefficients(pp, weights, factor);
    ScalarVector l0(pp.vector_length, zero);
    ScalarVector r0(pp.vector_length, zero);
    ScalarVector r1(pp.vector_length, zero);
    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        l0[i] = a_left[i] - z;
        r0[i] = y_power[i] * (a_right[i] + z) + coefficients[i];
        r1[i] = y_power[i] * s_right[i];
    }
    const ZnElement tau1 = pp.ring_ctx->gen_random();
    const ZnElement tau2 = pp.ring_ctx->gen_random();
    proof.t1 = ec_point_msm(pp.g, tau1, pp.h, dot(s_left, r0) + dot(l0, r1));
    proof.t2 = ec_point_msm(pp.g, tau2, pp.h, dot(s_left, r1));
    transcript << proof.t1 << proof.t2;
    const ZnElement x = challenge(transcript.str(), *pp.ring_ctx);
    ScalarVector l_x(pp.vector_length, zero);
    ScalarVector r_x(pp.vector_length, zero);
    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        l_x[i] = l0[i] + s_left[i] * x;
        r_x[i] = r0[i] + r1[i] * x;
    }
    proof.t = dot(l_x, r_x);
    proof.taux = tau1 * x + tau2 * x * x + factor * aggregate_r;
    proof.mu = state.alpha + state.rho * x;
    transcript << x;
    const ZnElement e = challenge(transcript.str(), *pp.ring_ctx);
    const inner_product::PublicParameters ip = inner_parameters(pp, powers(pp.vector_length,
        y.inv()), e);
    const ECPoint p = inner_statement(pp, proof, ip, y_power, coefficients, z, x);
    proof.inner_product = inner_product::prove(ip, {p}, {std::move(l_x), std::move(r_x)},
        transcript.str());
    return proof;
}

bool verify_impl(const PublicParameters& pp,
                 const Statement* statement,
                 const Proof& proof,
                 std::string_view context,
                 const ECPoint* delayed_aggregate = nullptr) {
    if (!valid_dimensions(pp) || proof.inner_product.left.size() != pp.rounds ||
        proof.inner_product.right.size() != pp.rounds ||
        (statement && !valid_weights(pp, *statement)) || (!statement && !delayed_aggregate)) {
        return false;
    }
    std::ostringstream transcript;
    transcript << initial_transcript(context) << proof.a;
    const ZnElement y = challenge(transcript.str(), *pp.ring_ctx);
    transcript << proof.s;
    const ZnElement z = challenge(transcript.str(), *pp.ring_ctx);
    ScalarVector weights = statement ? statement->weights : powers(pp.value_count, z);
    if (!statement) {
        for (ZnElement& weight : weights) {
            weight *= z * z;
        }
    }
    const ZnElement factor = statement ? z * z : pp.ring_ctx->get_one();
    const ScalarVector coefficients = bit_coefficients(pp, weights, factor);
    const ScalarVector y_power = powers(pp.vector_length, y);
    ZnElement sum_y = pp.ring_ctx->get_zero();
    ZnElement sum_coefficients = pp.ring_ctx->get_zero();
    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        sum_y += y_power[i];
        sum_coefficients += coefficients[i];
    }
    const ZnElement delta = (z - z * z) * sum_y - z * sum_coefficients;
    const ECPoint& aggregate = statement ? statement->aggregate : *delayed_aggregate;
    if (!statement) {
        transcript << aggregate;
    }
    transcript << proof.t1 << proof.t2;
    const ZnElement x = challenge(transcript.str(), *pp.ring_ctx);
    const ECPoint left = ec_point_msm(pp.g, proof.taux, pp.h, proof.t);
    const ECPoint right = aggregate * factor + pp.h * delta +
                          ec_point_msm(proof.t1, x, proof.t2, x * x);
    if (left != right) {
        return false;
    }
    transcript << x;
    const ZnElement e = challenge(transcript.str(), *pp.ring_ctx);
    const inner_product::PublicParameters ip = inner_parameters(pp, powers(pp.vector_length,
        y.inv()), e);
    const ECPoint p = inner_statement(pp, proof, ip, y_power, coefficients, z, x);
    return inner_product::verify(ip, {p}, proof.inner_product, transcript.str());
}

} // namespace

PublicParameters setup(int curve_id, std::size_t range_bits, std::size_t value_count) {
    std::shared_ptr<ECGroup> group = std::make_shared<ECGroup>(curve_id);
    std::shared_ptr<Zn> ring = std::make_shared<Zn>(group->order);
    const ECPoint h = derive_generator("taihang/aggregate-range/base-h", *group);
    const ECPoint u = derive_generator("taihang/aggregate-range/base-u", *group);
    return setup(group, ring, range_bits, value_count, group->get_generator(), h, u);
}

PublicParameters setup(const std::shared_ptr<ECGroup>& group_ctx,
                       const std::shared_ptr<Zn>& ring_ctx,
                       std::size_t range_bits,
                       std::size_t value_count,
                       const ECPoint& g,
                       const ECPoint& h,
                       const ECPoint& u) {
    TAIHANG_ASSERT(group_ctx && ring_ctx && ring_ctx->modulus == group_ctx->order,
                   "aggregate-range invalid contexts");
    const std::size_t length = padded_length(range_bits, value_count);
    TAIHANG_ASSERT(length > 0 && range_bits < ring_ctx->modulus.get_bit_length(),
                   "aggregate-range invalid dimensions or range width");
    for (const ECPoint* base : {&g, &h, &u}) {
        TAIHANG_ASSERT(base->group_ctx == group_ctx.get() && !base->is_at_infinity(),
                       "aggregate-range invalid base");
    }
    PublicParameters pp{group_ctx->curve_id, range_bits, value_count, length, 0,
        group_ctx, ring_ctx, g, h, u, std::vector<ECPoint>(length, ECPoint(group_ctx)),
        std::vector<ECPoint>(length, ECPoint(group_ctx))};
    for (std::size_t n = length; n > 1; n /= 2) {
        ++pp.rounds;
    }
    for (std::size_t i = 0; i < length; ++i) {
        pp.vector_g[i] = derive_generator("taihang/aggregate-range/vector-g/" +
            std::to_string(i), *group_ctx);
        pp.vector_h[i] = derive_generator("taihang/aggregate-range/vector-h/" +
            std::to_string(i), *group_ctx);
    }
    return pp;
}

bool Proof::operator==(const Proof& other) const {
    return a == other.a && s == other.s &&
           t1 == other.t1 && t2 == other.t2 && taux == other.taux && mu == other.mu &&
           t == other.t && inner_product == other.inner_product;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    return os << proof.a << proof.s << proof.t1 << proof.t2 <<
        proof.taux << proof.mu << proof.t << proof.inner_product;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    is >> proof.a >> proof.s >> proof.t1 >> proof.t2 >> proof.taux >> proof.mu >> proof.t;
    if (is) {
        is >> proof.inner_product;
    }
    return is;
}

bool DelayedProof::operator==(const DelayedProof& other) const {
    return Proof::operator==(other) && aggregate == other.aggregate;
}

std::ostream& operator<<(std::ostream& os, const DelayedProof& proof) {
    return os << proof.a << proof.s << proof.aggregate << proof.t1 << proof.t2
              << proof.taux << proof.mu << proof.t << proof.inner_product;
}

std::istream& operator>>(std::istream& is, DelayedProof& proof) {
    is >> proof.a >> proof.s >> proof.aggregate >> proof.t1 >> proof.t2
       >> proof.taux >> proof.mu >> proof.t;
    if (is) {
        is >> proof.inner_product;
    }
    return is;
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    return prove_impl(pp, &statement, witness.values, witness.randomness, nullptr, context);
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
    return verify_impl(pp, &statement, proof, context);
}

DelayedProof prove_delayed(const PublicParameters& pp,
                           const ScalarVector& values,
                           const ScalarVector& randomness,
                           std::string_view context) {
    TAIHANG_ASSERT(randomness.size() == pp.value_count,
        "aggregate-range randomness length mismatch");
    return prove_impl(pp, nullptr, values, pp.ring_ctx->get_zero(), &randomness, context);
}

bool verify_delayed(const PublicParameters& pp,
                    const DelayedProof& proof,
                    std::string_view context) {
    return verify_impl(pp, nullptr, proof, context, &proof.aggregate);
}

ScalarVector delayed_weights(const PublicParameters& pp,
                             const DelayedProof& proof,
                             std::string_view context) {
    TAIHANG_ASSERT(valid_dimensions(pp), "aggregate-range parameter dimensions mismatch");
    std::ostringstream transcript;
    transcript << initial_transcript(context) << proof.a << proof.s;
    const ZnElement z = challenge(transcript.str(), *pp.ring_ctx);
    ScalarVector result = powers(pp.value_count, z);
    for (ZnElement& weight : result) {
        weight *= z * z;
    }
    return result;
}

namespace {
ProverState prepare(const PublicParameters& pp, const ScalarVector& values) {
    TAIHANG_ASSERT(valid_dimensions(pp) && values.size() == pp.value_count,
                   "aggregate-range preparation dimensions mismatch");
    const ZnElement zero = pp.ring_ctx->get_zero();
    const ZnElement one = pp.ring_ctx->get_one();
    ProverState state{values, ScalarVector(pp.vector_length, zero),
        ScalarVector(pp.vector_length, -one),
        gen_random_znelement_vector(pp.ring_ctx, pp.vector_length),
        gen_random_znelement_vector(pp.ring_ctx, pp.vector_length),
        pp.ring_ctx->gen_random(), pp.ring_ctx->gen_random(), ECPoint(pp.group_ctx),
            ECPoint(pp.group_ctx)};
    for (std::size_t j = 0; j < pp.value_count; ++j) {
        for (std::size_t bit = 0; bit < pp.range_bits; ++bit) {
            const std::size_t index = j * pp.range_bits + bit;
            state.a_left[index] = BN_is_bit_set(values[j].value.bn_ptr,
                static_cast<int>(bit)) ? one : zero;
            state.a_right[index] = state.a_left[index] - one;
        }
    }
    state.a = ec_point_msm(pp.vector_g, state.a_left) +
              ec_point_msm(pp.vector_h, state.a_right) + pp.h * state.alpha;
    state.s = ec_point_msm(pp.vector_g, state.s_left) +
              ec_point_msm(pp.vector_h, state.s_right) + pp.h * state.rho;
    return state;
}

} // namespace

} // namespace taihang::zkp::nizk::aggregate_range
