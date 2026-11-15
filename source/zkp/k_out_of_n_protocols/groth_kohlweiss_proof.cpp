/****************************************************************************
 * @file      groth_kohlweiss_proof.cpp
 * @brief     GK-based k-out-of-n proof implementation.
 *****************************************************************************/

#include <taihang/zkp/k_out_of_n_protocols/groth_kohlweiss_proof.hpp>

#include <openssl/obj_mac.h>

#include <cstdint>
#include <ios>
#include <istream>
#include <limits>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>

#include <taihang/common/check.hpp>
#include <taihang/utility/arithmetic.hpp>

namespace taihang::zkp::k_out_of_n::groth_kohlweiss {
namespace {

using taihang::arithmetic::is_pow2;
using ScalarVector = std::vector<ZnElement>;
namespace linear_binary = taihang::zkp::nizk::linear_binary_vector;
namespace logarithmic_binary = taihang::zkp::nizk::logarithmic_binary_vector;

ECPoint derive_generator(const std::string& label, const ECGroup& group) {
    static const std::string kP256Dst =
        "TAIHANG-PROTOCOLS-V01-P256_XMD:SHA-256_SSWU_RO_";

    if (group.curve_id == NID_X9_62_prime256v1) {
        return hash_to_curve_standard(label, kP256Dst, group);
    }
    return hash_to_curve_fast(label, group);
}

std::size_t index_bits(std::size_t count) {
    std::size_t bits = 0;
    for (std::size_t n = count; n > 1; n /= 2) {
        ++bits;
    }
    return bits;
}

bool valid_dimensions(const PublicParameters& pp) {
    return pp.statement_count >= 2 && is_pow2(pp.statement_count) &&
           pp.statement_count <= (std::numeric_limits<std::size_t>::max() - 3) / 2 &&
           pp.threshold > 0 && pp.threshold <= pp.statement_count &&
           pp.index_bits == index_bits(pp.statement_count) &&
           pp.threshold < std::numeric_limits<std::size_t>::max() / pp.index_bits &&
           pp.vector_g.size() == pp.statement_count &&
           pp.vector_h.size() == pp.statement_count &&
           pp.index_g.size() == pp.threshold * pp.index_bits;
}

ScalarVector powers(std::size_t length, const ZnElement& base) {
    ScalarVector result(length, base.ring_ctx->get_one());
    for (std::size_t i = 1; i < length; ++i) {
        result[i] = result[i - 1] * base;
    }
    return result;
}

ZnElement nonzero_challenge(const std::string& transcript, const Zn& ring) {
    ZnElement result = hash_to_zn(transcript, ring);
    if (result.value.is_zero()) {
        result = ring.get_one();
    }
    return result;
}

ZnElement selection_challenge(const PublicParameters& pp,
                              const ECPoint& a,
                              const ECPoint& c,
                              const ECPoint& d,
                              std::string_view context) {
    std::ostringstream transcript;
    transcript << context << a << c << d;
    return nonzero_challenge(transcript.str(), *pp.ring_ctx);
}

ZnElement aggregation_challenge(const PublicParameters& pp,
                                const ECPoint& a,
                                const ECPoint& b,
                                const ECPoint& c,
                                const ECPoint& d,
                                const ECPoint& p,
                                std::string_view context) {
    std::ostringstream transcript;
    transcript << context << a << b << c << d << p;
    return nonzero_challenge(transcript.str(), *pp.ring_ctx);
}

logarithmic_binary::PublicParameters logarithmic_parameters(const PublicParameters& pp) {
    return logarithmic_binary::setup(
        pp.group_ctx, pp.ring_ctx, pp.g, pp.h, pp.u, pp.inner_product_u,
        pp.vector_g, pp.vector_h);
}

/** Compute product_b (alpha_ib + l_ib*X) or its complement per public index bit. */
ScalarVector selection_polynomial(const PublicParameters& pp,
                                  const ScalarVector& bits,
                                  const ScalarVector& alpha,
                                  std::size_t selected,
                                  std::size_t index) {
    const ZnElement zero = pp.ring_ctx->get_zero();
    const ZnElement one = pp.ring_ctx->get_one();
    ScalarVector coefficients(pp.index_bits + 1, zero);
    coefficients[0] = one;
    for (std::size_t bit = 0; bit < pp.index_bits; ++bit) {
        const std::size_t offset = selected * pp.index_bits + bit;
        const bool right = ((index >> bit) & 1U) != 0;
        const ZnElement constant = right ? alpha[offset] : -alpha[offset];
        const ZnElement linear = right ? bits[offset] : one - bits[offset];
        for (std::size_t degree = bit + 1; degree > 0; --degree) {
            coefficients[degree] = coefficients[degree] * constant +
                                   coefficients[degree - 1] * linear;
        }
        coefficients[0] *= constant;
    }
    return coefficients;
}

} // namespace

PublicParameters setup(int curve_id,
                       std::size_t statement_count,
                       std::size_t threshold) {
    TAIHANG_ASSERT(statement_count >= 2 && is_pow2(statement_count) &&
                       statement_count <= (std::numeric_limits<std::size_t>::max() - 3) / 2,
                   "GK statement count must be a power of two at least two");
    TAIHANG_ASSERT(threshold > 0 && threshold <= statement_count,
                   "GK threshold out of range");
    const std::size_t bits = index_bits(statement_count);
    TAIHANG_ASSERT(threshold < std::numeric_limits<std::size_t>::max() / bits,
                   "GK index vector length overflow");

    PublicParameters pp;
    pp.curve_id = curve_id;
    pp.statement_count = statement_count;
    pp.threshold = threshold;
    pp.index_bits = bits;
    pp.group_ctx = std::make_shared<ECGroup>(curve_id);
    pp.ring_ctx = std::make_shared<Zn>(pp.group_ctx->order);
    pp.g = pp.group_ctx->get_generator();
    pp.h = derive_generator("taihang/groth-kohlweiss/base-h", *pp.group_ctx);
    pp.u = derive_generator("taihang/groth-kohlweiss/base-u", *pp.group_ctx);
    pp.inner_product_u = derive_generator(
        "taihang/groth-kohlweiss/inner-product-u", *pp.group_ctx);
    pp.vector_g = std::vector<ECPoint>(statement_count, ECPoint(pp.group_ctx));
    pp.vector_h = std::vector<ECPoint>(statement_count, ECPoint(pp.group_ctx));
    pp.index_g = std::vector<ECPoint>(threshold * bits, ECPoint(pp.group_ctx));
    for (std::size_t i = 0; i < statement_count; ++i) {
        pp.vector_g[i] = derive_generator(
            "taihang/groth-kohlweiss/vector-g/" + std::to_string(i), *pp.group_ctx);
        pp.vector_h[i] = derive_generator(
            "taihang/groth-kohlweiss/vector-h/" + std::to_string(i), *pp.group_ctx);
    }
    for (std::size_t i = 0; i < pp.index_g.size(); ++i) {
        pp.index_g[i] = derive_generator(
            "taihang/groth-kohlweiss/index-g/" + std::to_string(i), *pp.group_ctx);
    }
    return pp;
}

bool Proof::operator==(const Proof& other) const {
    return b == other.b && p == other.p && linear_binary == other.linear_binary &&
           c_c == other.c_c && c_p == other.c_p && z_g == other.z_g &&
           z_h == other.z_h && z_p == other.z_p &&
           logarithmic_binary == other.logarithmic_binary;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    os << proof.b << proof.p << proof.linear_binary;
    const std::uint64_t count = static_cast<std::uint64_t>(proof.c_c.size());
    os.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (const ECPoint& point : proof.c_c) {
        os << point;
    }
    for (const ECPoint& point : proof.c_p) {
        os << point;
    }
    return os << proof.z_g << proof.z_h << proof.z_p << proof.logarithmic_binary;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    is >> proof.b >> proof.p;
    if (is) {
        is >> proof.linear_binary;
    }
    std::uint64_t count = 0;
    if (!is.read(reinterpret_cast<char*>(&count), sizeof(count))) {
        return is;
    }
    if (count != proof.c_c.size() || count != proof.c_p.size()) {
        is.setstate(std::ios::failbit);
        return is;
    }
    for (std::vector<ECPoint>* points : {&proof.c_c, &proof.c_p}) {
        for (ECPoint& point : *points) {
            if (!(is >> point)) {
                return is;
            }
        }
    }
    is >> proof.z_g >> proof.z_h >> proof.z_p;
    if (is) {
        is >> proof.logarithmic_binary;
    }
    return is;
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    TAIHANG_ASSERT(valid_dimensions(pp), "GK parameter dimensions mismatch");
    TAIHANG_ASSERT(statement.commitments.size() == pp.statement_count,
                   "GK statement length mismatch");
    TAIHANG_ASSERT(witness.indices.size() == pp.threshold &&
                       witness.values.size() == pp.threshold &&
                       witness.randomness.size() == pp.threshold,
                   "GK witness length mismatch");

    const ZnElement zero = pp.ring_ctx->get_zero();
    const ZnElement one = pp.ring_ctx->get_one();
    ScalarVector bits(pp.index_g.size(), zero);
    ScalarVector selection(pp.statement_count, zero);
    ScalarVector complement(pp.statement_count, -one);
    std::vector<bool> used(pp.statement_count, false);
    for (std::size_t i = 0; i < pp.threshold; ++i) {
        const std::size_t index = witness.indices[i];
        TAIHANG_ASSERT(index < pp.statement_count, "GK witness index out of range");
        TAIHANG_ASSERT(!used[index], "GK witness indices must be distinct");
        used[index] = true;
        selection[index] = one;
        complement[index] = zero;
        for (std::size_t bit = 0; bit < pp.index_bits; ++bit) {
            bits[i * pp.index_bits + bit] = ((index >> bit) & 1U) ? one : zero;
        }
    }
    const ZnElement r_b = pp.ring_ctx->gen_random();
    const ZnElement r_p = pp.ring_ctx->gen_random();
    Proof proof{
        ec_point_msm(pp.index_g, bits) + pp.u * r_b,
        ec_point_msm(pp.vector_g, selection) + ec_point_msm(pp.vector_h, complement) + pp.u * r_p,
        {ECPoint(pp.group_ctx), ECPoint(pp.group_ctx), ECPoint(pp.group_ctx),
         {}, ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx)},
        std::vector<ECPoint>(pp.index_bits, ECPoint(pp.group_ctx)),
        std::vector<ECPoint>(pp.index_bits, ECPoint(pp.group_ctx)),
        ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx),
        {ECPoint(pp.group_ctx), ECPoint(pp.group_ctx), ECPoint(pp.group_ctx),
         ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx),
         {{}, {}, ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx)}}
    };
    const linear_binary::PublicParameters linear_pp = linear_binary::setup(pp.group_ctx,
        pp.ring_ctx, pp.u, pp.index_g);
    const linear_binary::Witness linear_witness{bits, r_b};
    linear_binary::detail::ProverState state = linear_binary::detail::commit(linear_pp,
        linear_witness);

    const ZnElement x = selection_challenge(pp, state.a, state.c, state.d, context);
    const ZnElement e = aggregation_challenge(
        pp, state.a, proof.b, state.c, state.d, proof.p, context);
    const ScalarVector e_power = powers(pp.threshold, e);

    // Accumulate the lower coefficients by degree and public index, avoiding
    // storage of the full k*n*(m+1) polynomial tensor from the original code.
    std::vector<ScalarVector> weighted(pp.index_bits, ScalarVector(pp.statement_count, zero));
    std::vector<ScalarVector> unweighted(pp.index_bits, ScalarVector(pp.statement_count, zero));
    for (std::size_t i = 0; i < pp.threshold; ++i) {
        for (std::size_t j = 0; j < pp.statement_count; ++j) {
            const ScalarVector polynomial = selection_polynomial(pp, bits, state.alpha, i, j);
            for (std::size_t degree = 0; degree < pp.index_bits; ++degree) {
                weighted[degree][j] += e_power[i] * polynomial[degree];
                unweighted[degree][j] += polynomial[degree];
            }
        }
    }
    const ScalarVector rho = gen_random_znelement_vector(pp.ring_ctx, pp.index_bits);
    const ScalarVector alpha = gen_random_znelement_vector(pp.ring_ctx, pp.index_bits);
    const ScalarVector beta = gen_random_znelement_vector(pp.ring_ctx, pp.index_bits);
    std::vector<ECPoint> selection_bases(pp.statement_count, ECPoint(pp.group_ctx));
    for (std::size_t j = 0; j < pp.statement_count; ++j) {
        selection_bases[j] = pp.vector_g[j] + pp.vector_h[j];
    }
    for (std::size_t degree = 0; degree < pp.index_bits; ++degree) {
        proof.c_c[degree] = ec_point_msm(statement.commitments, weighted[degree]) +
                            ec_point_msm(pp.g, rho[degree], pp.h, beta[degree]);
        proof.c_p[degree] = ec_point_msm(selection_bases, unweighted[degree]) +
                            pp.u * alpha[degree];
    }

    // Preserve the original selector challenge fixed before coefficient messages.
    const ScalarVector x_power = powers(pp.index_bits + 1, x);
    proof.linear_binary = linear_binary::detail::respond(
        linear_pp, linear_witness, std::move(state), x);
    proof.z_g = zero;
    proof.z_h = zero;
    proof.z_p = r_p * x_power[pp.index_bits];
    for (std::size_t i = 0; i < pp.threshold; ++i) {
        proof.z_g += e_power[i] * witness.randomness[i];
        proof.z_h += e_power[i] * witness.values[i];
    }
    proof.z_g *= x_power[pp.index_bits];
    proof.z_h *= x_power[pp.index_bits];
    for (std::size_t degree = 0; degree < pp.index_bits; ++degree) {
        proof.z_g -= rho[degree] * x_power[degree];
        proof.z_h -= beta[degree] * x_power[degree];
        proof.z_p += alpha[degree] * x_power[degree];
    }

    // Binary selection entries prevent repeated indices from counting twice.
    const logarithmic_binary::PublicParameters log_pp = logarithmic_parameters(pp);
    proof.logarithmic_binary = logarithmic_binary::prove(
        log_pp, {proof.p}, {std::move(selection), std::move(complement), r_p}, context);
    return proof;
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
    if (!valid_dimensions(pp) || statement.commitments.size() != pp.statement_count ||
        proof.linear_binary.f.size() != pp.index_g.size() ||
        proof.c_c.size() != pp.index_bits || proof.c_p.size() != pp.index_bits ||
        proof.logarithmic_binary.inner_product.left.size() != pp.index_bits ||
        proof.logarithmic_binary.inner_product.right.size() != pp.index_bits) {
        return false;
    }
    const ZnElement e = aggregation_challenge(pp, proof.linear_binary.a,
        proof.b, proof.linear_binary.c, proof.linear_binary.d, proof.p, context);
    const ScalarVector e_power = powers(pp.threshold, e);
    const ZnElement x = selection_challenge(pp, proof.linear_binary.a,
        proof.linear_binary.c, proof.linear_binary.d, context);
    const ScalarVector x_power = powers(pp.index_bits + 1, x);
    const linear_binary::PublicParameters linear_pp = linear_binary::setup(pp.group_ctx,
        pp.ring_ctx, pp.u, pp.index_g);
    if (!linear_binary::detail::verify_with_challenge(linear_pp, {proof.b}, proof.linear_binary,
        x)) {
        return false;
    }

    // Evaluate all selector polynomials directly from f and x-f.
    const ZnElement zero = pp.ring_ctx->get_zero();
    ScalarVector weighted(pp.statement_count, zero);
    ScalarVector unweighted(pp.statement_count, zero);
    for (std::size_t i = 0; i < pp.threshold; ++i) {
        for (std::size_t j = 0; j < pp.statement_count; ++j) {
            ZnElement value = pp.ring_ctx->get_one();
            for (std::size_t bit = 0; bit < pp.index_bits; ++bit) {
                const ZnElement& f = proof.linear_binary.f[i * pp.index_bits + bit];
                value *= ((j >> bit) & 1U) ? f : x - f;
            }
            weighted[j] += e_power[i] * value;
            unweighted[j] += value;
        }
    }

    // sum_j c_j*sum_i e^i*p_ij(x) - sum_d C_c,d*x^d = g*z_g+h*z_h.
    ScalarVector negative_x(pp.index_bits, zero);
    for (std::size_t degree = 0; degree < pp.index_bits; ++degree) {
        negative_x[degree] = -x_power[degree];
    }
    const ECPoint opening = ec_point_msm(statement.commitments, weighted) +
                            ec_point_msm(proof.c_c, negative_x);
    if (opening != ec_point_msm(pp.g, proof.z_g, pp.h, proof.z_h)) {
        return false;
    }

    // P*x^m - sum_j (g_j+h_j)*sum_i p_ij(x) + sum_j h_j*x^m
    //        + sum_d C_p,d*x^d = u*z_p.
    ScalarVector coefficients_g(pp.statement_count, zero);
    ScalarVector coefficients_h(pp.statement_count, zero);
    for (std::size_t j = 0; j < pp.statement_count; ++j) {
        coefficients_g[j] = -unweighted[j];
        coefficients_h[j] = x_power[pp.index_bits] - unweighted[j];
    }
    ScalarVector lower_x(x_power.begin(), x_power.end() - 1);
    const ECPoint selection = proof.p * x_power[pp.index_bits] +
        ec_point_msm(pp.vector_g, coefficients_g) + ec_point_msm(pp.vector_h, coefficients_h) +
        ec_point_msm(proof.c_p, lower_x);
    if (selection != pp.u * proof.z_p) {
        return false;
    }
    const logarithmic_binary::PublicParameters log_pp = logarithmic_parameters(pp);
    return logarithmic_binary::verify(log_pp, {proof.p}, proof.logarithmic_binary, context);
}

} // namespace taihang::zkp::k_out_of_n::groth_kohlweiss
