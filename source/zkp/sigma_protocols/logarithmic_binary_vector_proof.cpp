/****************************************************************************
 * @file      logarithmic_binary_vector_proof.cpp
 * @brief     Logarithmic-size binary-vector proof implementation.
 *****************************************************************************/

#include <taihang/zkp/sigma_protocols/logarithmic_binary_vector_proof.hpp>

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

namespace taihang::zkp::nizk::logarithmic_binary_vector {
namespace {

using taihang::arithmetic::is_pow2;
using ScalarVector = std::vector<ZnElement>;
namespace inner_product = taihang::zkp::range_proofs::inner_product;

ECPoint derive_generator(const std::string& label, const ECGroup& group) {
    static const std::string kP256Dst =
        "TAIHANG-PROTOCOLS-V01-P256_XMD:SHA-256_SSWU_RO_";

    if (group.curve_id == NID_X9_62_prime256v1) {
        return hash_to_curve_standard(label, kP256Dst, group);
    }
    return hash_to_curve_fast(label, group);
}

std::size_t folding_rounds(std::size_t vector_length) {
    std::size_t rounds = 0;
    for (std::size_t n = vector_length; n > 1; n /= 2) {
        ++rounds;
    }
    return rounds;
}

bool valid_dimensions(const PublicParameters& pp) {
    return is_pow2(pp.vector_length) &&
           pp.vector_length <= (std::numeric_limits<std::size_t>::max() - 3) / 2 &&
           pp.vector_g.size() == pp.vector_length &&
           pp.vector_h.size() == pp.vector_length &&
           pp.rounds == folding_rounds(pp.vector_length);
}

/** Generate (1, base, ..., base^(length-1)). */
ScalarVector powers(std::size_t length, const ZnElement& base) {
    ScalarVector result(length, base.ring_ctx->get_one());
    for (std::size_t i = 1; i < length; ++i) {
        result[i] = result[i - 1] * base;
    }
    return result;
}

ZnElement inner_product_value(const ScalarVector& a, const ScalarVector& b) {
    TAIHANG_ASSERT(a.size() == b.size() && !a.empty(),
                   "binary-vector inner-product dimensions mismatch");
    ZnElement result = a.front().ring_ctx->get_zero();
    for (std::size_t i = 0; i < a.size(); ++i) {
        result += a[i] * b[i];
    }
    return result;
}

/** Start the transcript with the caller-supplied context. */
std::string initial_transcript(std::string_view context) {
    std::ostringstream transcript;
    transcript.write(context.data(),
                     static_cast<std::streamsize>(context.size()));
    return transcript.str();
}

/** Remove the combined blinding from B = P + A*x + z*sum_i(h_i-g_i). */
ECPoint unblinded_commitment(const PublicParameters& pp,
                             const Statement& statement,
                             const Proof& proof,
                             const ZnElement& x,
                             const ZnElement& z) {
    const std::size_t length = pp.vector_length;
    std::vector<const ECPoint*> points(2 * length + 3, nullptr);
    ScalarVector scalars(2 * length + 3, pp.ring_ctx->get_zero());
    for (std::size_t i = 0; i < length; ++i) {
        points[i] = &pp.vector_g[i];
        scalars[i] = -z;
        points[length + i] = &pp.vector_h[i];
        scalars[length + i] = z;
    }
    points[2 * length] = &statement.p;
    scalars[2 * length] = pp.ring_ctx->get_one();
    points[2 * length + 1] = &proof.a;
    scalars[2 * length + 1] = x;
    points[2 * length + 2] = &pp.u;
    scalars[2 * length + 2] = -proof.mu;
    return ec_point_msm(points, scalars);
}

/** Reuse parent contexts with h'_i = h_i*y^-i and u' = u_ip*e. */
inner_product::PublicParameters make_inner_product_parameters(
    const PublicParameters& pp,
    const ScalarVector& y_inverse_power,
    const ZnElement& e) {
    inner_product::PublicParameters ip_pp;
    ip_pp.curve_id = pp.curve_id;
    ip_pp.vector_length = pp.vector_length;
    ip_pp.rounds = pp.rounds;
    ip_pp.group_ctx = pp.group_ctx;
    ip_pp.ring_ctx = pp.ring_ctx;
    ip_pp.g = pp.vector_g;
    ip_pp.h = std::vector<ECPoint>(pp.vector_length, ECPoint(pp.group_ctx));
    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        ip_pp.h[i] = pp.vector_h[i] * y_inverse_power[i];
    }
    ip_pp.u = pp.inner_product_u * e;
    return ip_pp;
}

} // namespace

PublicParameters setup(int curve_id, std::size_t vector_length) {
    TAIHANG_ASSERT(is_pow2(vector_length) &&
                       vector_length <= (std::numeric_limits<std::size_t>::max() - 3) / 2,
                   "binary-vector length must be a positive power of two");

    PublicParameters pp;
    pp.curve_id = curve_id;
    pp.vector_length = vector_length;
    pp.rounds = folding_rounds(vector_length);
    pp.group_ctx = std::make_shared<ECGroup>(curve_id);
    pp.ring_ctx = std::make_shared<Zn>(pp.group_ctx->order);
    pp.g = pp.group_ctx->get_generator();
    pp.h = derive_generator("taihang/logarithmic-binary-vector/base-h", *pp.group_ctx);
    pp.u = derive_generator("taihang/logarithmic-binary-vector/base-u", *pp.group_ctx);
    pp.inner_product_u = derive_generator(
        "taihang/logarithmic-binary-vector/inner-product-u", *pp.group_ctx);
    pp.vector_g = std::vector<ECPoint>(vector_length, ECPoint(pp.group_ctx));
    pp.vector_h = std::vector<ECPoint>(vector_length, ECPoint(pp.group_ctx));
    for (std::size_t i = 0; i < vector_length; ++i) {
        pp.vector_g[i] = derive_generator(
            "taihang/logarithmic-binary-vector/vector-g/" + std::to_string(i),
            *pp.group_ctx);
        pp.vector_h[i] = derive_generator(
            "taihang/logarithmic-binary-vector/vector-h/" + std::to_string(i),
            *pp.group_ctx);
    }
    return pp;
}

PublicParameters setup(const std::shared_ptr<ECGroup>& group_ctx,
                       const std::shared_ptr<Zn>& ring_ctx,
                       const ECPoint& g,
                       const ECPoint& h,
                       const ECPoint& u,
                       const ECPoint& inner_product_u,
                       const std::vector<ECPoint>& vector_g,
                       const std::vector<ECPoint>& vector_h) {
    TAIHANG_ASSERT(group_ctx != nullptr && ring_ctx != nullptr,
                   "binary-vector contexts cannot be null");
    TAIHANG_ASSERT(ring_ctx->modulus == group_ctx->order,
                   "binary-vector scalar modulus mismatch");
    for (const ECPoint* base : {&g, &h, &u, &inner_product_u}) {
        TAIHANG_ASSERT(base->group_ctx == group_ctx.get(),
                       "binary-vector base context mismatch");
        TAIHANG_ASSERT(!base->is_at_infinity(),
                       "binary-vector bases cannot be identities");
    }
    for (const std::vector<ECPoint>* generators : {&vector_g, &vector_h}) {
        for (const ECPoint& generator : *generators) {
            TAIHANG_ASSERT(generator.group_ctx == group_ctx.get(),
                           "binary-vector generator context mismatch");
            TAIHANG_ASSERT(!generator.is_at_infinity(),
                           "binary-vector generators cannot be identities");
        }
    }

    PublicParameters pp;
    pp.curve_id = group_ctx->curve_id;
    pp.vector_length = vector_g.size();
    pp.rounds = folding_rounds(pp.vector_length);
    pp.group_ctx = group_ctx;
    pp.ring_ctx = ring_ctx;
    pp.g = g;
    pp.h = h;
    pp.u = u;
    pp.inner_product_u = inner_product_u;
    pp.vector_g = vector_g;
    pp.vector_h = vector_h;
    TAIHANG_ASSERT(valid_dimensions(pp), "binary-vector parameter dimensions mismatch");
    return pp;
}

bool Proof::operator==(const Proof& other) const {
    return a == other.a && t1 == other.t1 && t2 == other.t2 &&
           t == other.t && tau == other.tau && mu == other.mu &&
           inner_product == other.inner_product;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    return os << proof.a << proof.t1 << proof.t2 << proof.t << proof.tau
              << proof.mu << proof.inner_product;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    is >> proof.a >> proof.t1 >> proof.t2 >> proof.t >> proof.tau >> proof.mu;
    if (is) {
        is >> proof.inner_product;
    }
    return is;
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    TAIHANG_ASSERT(valid_dimensions(pp), "binary-vector parameter dimensions mismatch");
    TAIHANG_ASSERT(witness.a.size() == pp.vector_length &&
                       witness.b.size() == pp.vector_length,
                   "binary-vector witness length mismatch");

    const std::size_t length = pp.vector_length;
    const ZnElement zero = pp.ring_ctx->get_zero();
    const ZnElement one = pp.ring_ctx->get_one();
    const ScalarVector alpha = gen_random_znelement_vector(pp.ring_ctx, length);
    const ScalarVector beta = gen_random_znelement_vector(pp.ring_ctx, length);
    const ZnElement rho = pp.ring_ctx->gen_random();
    Proof proof{
        ec_point_msm(pp.vector_g, alpha) + ec_point_msm(pp.vector_h, beta) + pp.u * rho,
        ECPoint(pp.group_ctx), ECPoint(pp.group_ctx),
        ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx), {}
    };

    std::ostringstream transcript;
    transcript << initial_transcript(context) << proof.a;
    ZnElement y = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (y.value.is_zero()) {
        y = one;
    }
    transcript << proof.a;
    ZnElement z = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (z.value.is_zero()) {
        z = one;
    }
    const ScalarVector y_power = powers(length, y);
    const ScalarVector y_inverse_power = powers(length, y.inv());

    // l(X) = a-z*1 + alpha*X and r(X) = y^n o (b+z*1+beta*X).
    ScalarVector l0(length, zero);
    ScalarVector r0(length, zero);
    ScalarVector r1(length, zero);
    for (std::size_t i = 0; i < length; ++i) {
        l0[i] = witness.a[i] - z;
        r0[i] = y_power[i] * (witness.b[i] + z);
        r1[i] = y_power[i] * beta[i];
    }
    const ZnElement t1 = inner_product_value(alpha, r0) + inner_product_value(l0, r1);
    const ZnElement t2 = inner_product_value(alpha, r1);
    const ZnElement tau1 = pp.ring_ctx->gen_random();
    const ZnElement tau2 = pp.ring_ctx->gen_random();
    proof.t1 = ec_point_msm(pp.g, t1, pp.h, tau1);
    proof.t2 = ec_point_msm(pp.g, t2, pp.h, tau2);

    // Commit to the nonconstant coefficients before fixing the evaluation x.
    transcript << proof.t1 << proof.t2;
    ZnElement x = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (x.value.is_zero()) {
        x = one;
    }
    ScalarVector l_x(length, zero);
    ScalarVector r_x(length, zero);
    for (std::size_t i = 0; i < length; ++i) {
        l_x[i] = l0[i] + alpha[i] * x;
        r_x[i] = r0[i] + r1[i] * x;
    }
    proof.t = inner_product_value(l_x, r_x);
    proof.tau = tau1 * x + tau2 * x * x;
    proof.mu = witness.r + rho * x;

    // Hash the unblinded commitment and inner product before scaling u_ip.
    const ECPoint p = unblinded_commitment(pp, statement, proof, x, z);
    transcript << p << proof.t;
    ZnElement e = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (e.value.is_zero()) {
        e = one;
    }
    const inner_product::PublicParameters ip_pp = make_inner_product_parameters(pp,
        y_inverse_power, e);
    const inner_product::Statement ip_statement{p + ip_pp.u * proof.t};
    proof.inner_product = inner_product::prove(
        ip_pp, ip_statement, {std::move(l_x), std::move(r_x)}, transcript.str());
    return proof;
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
    if (!valid_dimensions(pp) || proof.inner_product.left.size() != pp.rounds ||
        proof.inner_product.right.size() != pp.rounds) {
        return false;
    }
    const ZnElement one = pp.ring_ctx->get_one();
    std::ostringstream transcript;
    transcript << initial_transcript(context) << proof.a;
    ZnElement y = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (y.value.is_zero()) {
        y = one;
    }
    transcript << proof.a;
    ZnElement z = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (z.value.is_zero()) {
        z = one;
    }
    const ScalarVector y_power = powers(pp.vector_length, y);
    const ScalarVector y_inverse_power = powers(pp.vector_length, y.inv());
    ZnElement sum_y = pp.ring_ctx->get_zero();
    for (const ZnElement& value : y_power) {
        sum_y += value;
    }

    // The Boolean and complement constraints a_i*b_i=0 and a_i-b_i=1
    // give the constant coefficient delta = (z-z^2)*sum_i y^i.
    transcript << proof.t1 << proof.t2;
    ZnElement x = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (x.value.is_zero()) {
        x = one;
    }
    const ZnElement delta = (z - z * z) * sum_y;
    const ECPoint left = ec_point_msm(pp.g, proof.t, pp.h, proof.tau);
    const ECPoint right = ec_point_msm(
        {pp.g, proof.t1, proof.t2}, {delta, x, x * x});
    if (left != right) {
        return false;
    }

    const ECPoint p = unblinded_commitment(pp, statement, proof, x, z);
    transcript << p << proof.t;
    ZnElement e = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (e.value.is_zero()) {
        e = one;
    }
    const inner_product::PublicParameters ip_pp = make_inner_product_parameters(pp,
        y_inverse_power, e);
    const inner_product::Statement ip_statement{p + ip_pp.u * proof.t};
    return inner_product::verify(ip_pp, ip_statement, proof.inner_product, transcript.str());
}

} // namespace taihang::zkp::nizk::logarithmic_binary_vector
