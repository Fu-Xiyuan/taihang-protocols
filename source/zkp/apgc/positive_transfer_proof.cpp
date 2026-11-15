/****************************************************************************
 * @file      positive_transfer_proof.cpp
 * @brief     Direct migration of the Koon selector and weighted half-open ranges.
 *****************************************************************************/

#include <taihang/zkp/apgc/positive_transfer_proof.hpp>

#include <openssl/obj_mac.h>

#include <openssl/bn.h>

#include <cstdint>
#include <istream>
#include <ostream>
#include <sstream>

#include <taihang/common/check.hpp>
#include <taihang/utility/arithmetic.hpp>

namespace taihang::zkp::apgc::positive_transfer {
namespace {

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
                                std::size_t length,
                                const std::string& label) {
    std::vector<ECPoint> result(length, ECPoint(group));
    for (std::size_t i = 0; i < length; ++i) {
        const std::string name = label + std::to_string(i);
        result[i] = group->curve_id == NID_X9_62_prime256v1 ?
            hash_to_curve_standard(name, "TAIHANG-PROTOCOLS-V01-P256_XMD:SHA-256_SSWU_RO_",
                *group) :
            hash_to_curve_fast(name, *group);
    }
    return result;
}

range_proofs::inner_product::Proof initialize_inner(
    const pke::twisted_elgamal::PublicParameters& encryption,
    std::size_t length) {
    const std::size_t rounds = folding_rounds(length);
    return {std::vector<ECPoint>(rounds, ECPoint(encryption.group_ctx)),
        std::vector<ECPoint>(rounds, ECPoint(encryption.group_ctx)),
        ZnElement(encryption.ring_ctx), ZnElement(encryption.ring_ctx)};
}

range_proofs::bulletproof::PublicParameters range_parameters(
    const pke::twisted_elgamal::PublicParameters& encryption,
    std::size_t range_bits,
    std::size_t count,
    const ECPoint& u,
    const std::string& label) {
    TAIHANG_ASSERT(taihang::arithmetic::is_pow2(range_bits) && taihang::arithmetic::is_pow2(count),
                   "original APGC range dimensions must be powers of two");
    const std::size_t length = range_bits * count;
    return {encryption.curve_id, range_bits, count, length, encryption.group_ctx,
        encryption.ring_ctx, encryption.g, encryption.h, u,
        generators(encryption.group_ctx, length, label + "/g/"),
        generators(encryption.group_ctx, length, label + "/h/")};
}

range_proofs::bulletproof::Proof initialize_range(
    const range_proofs::bulletproof::PublicParameters& pp) {
    const std::size_t rounds = folding_rounds(pp.vector_length);
    return {ECPoint(pp.group_ctx), ECPoint(pp.group_ctx), ECPoint(pp.group_ctx),
        ECPoint(pp.group_ctx),
        ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx),
        {std::vector<ECPoint>(rounds, ECPoint(pp.group_ctx)),
         std::vector<ECPoint>(rounds, ECPoint(pp.group_ctx)), ZnElement(pp.ring_ctx),
             ZnElement(pp.ring_ctx)}};
}

namespace logarithmic = taihang::zkp::nizk::logarithmic_binary_vector;
namespace range = taihang::zkp::range_proofs::bulletproof;
namespace inner = taihang::zkp::range_proofs::inner_product;
using ScalarVector = std::vector<ZnElement>;

template<class T>
std::ostream& write_vector(
    std::ostream& os,
    const std::vector<T>& vector) {
    const std::uint64_t size = vector.size();
    os.write(reinterpret_cast<const char*>(&size), sizeof(size));
    for (const T& value : vector) {
        os << value;
    }
    return os;
}

template<class T>
std::istream& read_vector(std::istream& is, std::vector<T>& vector) {
    std::uint64_t size = 0;
    if (!is.read(reinterpret_cast<char*>(&size), sizeof(size)) || size != vector.size()) {
        is.setstate(std::ios::failbit);
        return is;
    }
    for (T& value : vector) {
        if (!(is >> value)) {
            break;
        }
    }
    return is;
}

logarithmic::PublicParameters logarithmic_parameters(const PublicParameters& pp) {
    return logarithmic::setup(pp.encryption.group_ctx, pp.encryption.ring_ctx,
        pp.encryption.g, pp.encryption.h, pp.u, pp.inner_product_u, pp.vector_g, pp.vector_h);
}

bool valid_dimensions(const PublicParameters& pp, const Statement& statement) {
    return taihang::arithmetic::is_pow2(pp.participant_count) && pp.participant_count >= 2 &&
        pp.receiver_count > 0 && pp.receiver_count <= pp.participant_count &&
        pp.index_bits == folding_rounds(pp.participant_count) &&
        pp.vector_g.size() == pp.participant_count && pp.vector_h.size() == pp.participant_count &&
        pp.index_g.size() == pp.receiver_count * pp.index_bits &&
        statement.commitments.size() == pp.participant_count;
}

ZnElement selection_x(const PublicParameters& pp,
                      const SelectionProof& proof,
                      std::string_view context) {
    std::ostringstream transcript;
    transcript << context << proof.a << proof.c << proof.d;
    return hash_to_zn(transcript.str(), *pp.encryption.ring_ctx);
}

ZnElement selection_e(const PublicParameters& pp, const SelectionProof& proof) {
    std::ostringstream transcript;
    transcript << proof.a << proof.b << proof.c << proof.d << proof.p;
    return hash_to_zn(transcript.str(), *pp.encryption.ring_ctx);
}

ScalarVector polynomial(const ScalarVector& bits,
                        const ScalarVector& alpha,
                        std::size_t offset,
                        std::size_t m,
                        std::size_t index) {
    const ZnElement zero = bits.front().ring_ctx->get_zero();
    const ZnElement one = bits.front().ring_ctx->get_one();
    ScalarVector result(1, one);
    for (std::size_t b = 0; b < m; ++b) {
        const bool bit = (index >> b) & 1U;
        const ZnElement constant = bit ? alpha[offset + b] : -alpha[offset + b];
        const ZnElement linear = bit ? bits[offset + b] : one - bits[offset + b];
        ScalarVector next(result.size() + 1, zero);
        for (std::size_t d = 0; d < result.size(); ++d) {
            next[d] += result[d] * constant;
            next[d + 1] += result[d] * linear;
        }
        result = std::move(next);
    }
    return result;
}

SelectionProof prove_selection(const PublicParameters& pp,
                               const Statement& statement,
                               const Witness& witness,
                               std::string_view context) {
    const std::shared_ptr<Zn> ring = pp.encryption.ring_ctx;
    const ZnElement zero = ring->get_zero();
    const ZnElement one = ring->get_one();
    const std::size_t n = pp.participant_count;
    const std::size_t m = pp.index_bits;
    const std::size_t k = pp.receiver_count;
    ScalarVector bits(k * m, zero);
    ScalarVector selected(n, zero);
    ScalarVector complement(n, -one);
    std::vector<bool> used(n, false);
    for (std::size_t i = 0; i < k; ++i) {
        TAIHANG_ASSERT(witness.indices[i] < n && !used[witness.indices[i]],
            "Positive indices must be distinct and in range");
        used[witness.indices[i]] = true;
        selected[witness.indices[i]] = one;
        complement[witness.indices[i]] = zero;
        for (std::size_t b = 0; b < m; ++b) {
            bits[i * m + b] = ((witness.indices[i] >> b) & 1U) ? one : zero;
        }
    }
    SelectionProof proof = initialize_proof(pp).subset;
    const ZnElement r_b = ring->gen_random();
    const ZnElement r_p = ring->gen_random();
    const ZnElement r_a = ring->gen_random();
    const ZnElement r_c = ring->gen_random();
    const ZnElement r_d = ring->gen_random();
    const ScalarVector alpha = gen_random_znelement_vector(ring, k * m);
    ScalarVector c(k * m, zero);
    ScalarVector d(k * m, zero);
    for (std::size_t i = 0; i < k * m; ++i) {
        c[i] = alpha[i] * (one - bits[i] - bits[i]);
        d[i] = -alpha[i] * alpha[i];
    }
    proof.b = ec_point_msm(pp.index_g, bits) + pp.u * r_b;
    proof.p = ec_point_msm(pp.vector_g, selected) + ec_point_msm(pp.vector_h,
        complement) + pp.u * r_p;
    proof.a = ec_point_msm(pp.index_g, alpha) + pp.u * r_a;
    proof.c = ec_point_msm(pp.index_g, c) + pp.u * r_c;
    proof.d = ec_point_msm(pp.index_g, d) + pp.u * r_d;
    const ZnElement x = selection_x(pp, proof, context);
    for (std::size_t i = 0; i < k * m; ++i) {
        proof.f[i] = bits[i] * x + alpha[i];
    }
    proof.z_a = r_b * x + r_a;
    proof.z_c = r_c * x + r_d;
    const ScalarVector e_power = powers(k, selection_e(pp, proof));
    const ScalarVector rho = gen_random_znelement_vector(ring, m);
    const ScalarVector beta = gen_random_znelement_vector(ring, m);
    std::vector<ScalarVector> weighted(m, ScalarVector(n, zero));
    std::vector<ScalarVector> unweighted(m, ScalarVector(n, zero));
    for (std::size_t i = 0; i < k; ++i) {
        for (std::size_t j = 0; j < n; ++j) {
            const ScalarVector coefficients = polynomial(bits, alpha, i * m, m, j);
            for (std::size_t degree = 0; degree < m; ++degree) {
                weighted[degree][j] += e_power[i] * coefficients[degree];
                unweighted[degree][j] += coefficients[degree];
            }
        }
    }
    std::vector<ECPoint> selection_bases(n, ECPoint(pp.encryption.group_ctx));
    for (std::size_t j = 0; j < n; ++j) {
        selection_bases[j] = pp.vector_g[j] + pp.vector_h[j];
    }
    const ScalarVector x_power = powers(m + 1, x);
    proof.z_g = zero;
    for (std::size_t i = 0; i < k; ++i) {
        proof.z_g += e_power[i] * witness.randomness[i];
    }
    proof.z_g *= x_power[m];
    proof.z_p = r_p * x_power[m];
    for (std::size_t degree = 0; degree < m; ++degree) {
        proof.c_c[degree] = pp.encryption.g * rho[degree] + ec_point_msm(statement.commitments,
            weighted[degree]);
        proof.c_p[degree] = pp.u * beta[degree] + ec_point_msm(selection_bases, unweighted[degree]);
        proof.z_g -= rho[degree] * x_power[degree];
        proof.z_p += beta[degree] * x_power[degree];
    }
    proof.binary = logarithmic::prove(logarithmic_parameters(pp), {proof.p}, {selected,
        complement, r_p});
    return proof;
}

struct Aggregate {
    ECPoint commitment;
    ScalarVector weights;
    ZnElement normalization;
};

Aggregate aggregate(const PublicParameters& pp,
                    const Statement& statement,
                    const SelectionProof& proof,
                    std::string_view context) {
    const std::shared_ptr<Zn> ring = pp.encryption.ring_ctx;
    const ZnElement x = selection_x(pp, proof, context);
    const ScalarVector x_power = powers(pp.index_bits + 1, x);
    const ScalarVector e_power = powers(pp.receiver_count, selection_e(pp, proof));
    ScalarVector weighted(pp.participant_count, ring->get_zero());
    for (std::size_t i = 0; i < pp.receiver_count; ++i) {
        for (std::size_t j = 0; j < pp.participant_count; ++j) {
            ZnElement value = ring->get_one();
            for (std::size_t b = 0; b < pp.index_bits; ++b) {
                const ZnElement& f = proof.f[i * pp.index_bits + b];
                value *= ((j >> b) & 1U) ? f : x - f;
            }
            weighted[j] += e_power[i] * value;
        }
    }
    ECPoint g = ec_point_msm(statement.commitments, weighted);
    for (std::size_t degree = 0; degree < pp.index_bits; ++degree) {
        g = g - proof.c_c[degree] * x_power[degree];
    }
    const ZnElement normalization = x_power.back().inv();
    return {g * normalization, e_power, normalization};
}

bool verify_selection(const PublicParameters& pp,
                      const SelectionProof& proof,
                      std::string_view context) {
    if (proof.f.size() != pp.index_g.size() || proof.c_c.size() != pp.index_bits ||
        proof.c_p.size() != pp.index_bits || !selection_x(pp, proof, context).is_unit()) {
        return false;
    }
    const ZnElement x = selection_x(pp, proof, context);
    ScalarVector quadratic(proof.f.size(), pp.encryption.ring_ctx->get_zero());
    for (std::size_t i = 0; i < quadratic.size(); ++i) {
        quadratic[i] = proof.f[i] * (x - proof.f[i]);
    }
    if (proof.b * x + proof.a != ec_point_msm(pp.index_g, proof.f) + pp.u * proof.z_a ||
        proof.c * x + proof.d != ec_point_msm(pp.index_g, quadratic) + pp.u * proof.z_c) {
        return false;
    }
    const ScalarVector x_power = powers(pp.index_bits + 1, x);
    ECPoint s = pp.encryption.group_ctx->get_infinity();
    for (std::size_t j = 0; j < pp.participant_count; ++j) {
        ZnElement sum = pp.encryption.ring_ctx->get_zero();
        for (std::size_t i = 0; i < pp.receiver_count; ++i) {
            ZnElement value = pp.encryption.ring_ctx->get_one();
            for (std::size_t b = 0; b < pp.index_bits; ++b) {
                const ZnElement& f = proof.f[i * pp.index_bits + b];
                value *= ((j >> b) & 1U) ? f : x - f;
            }
            sum += value;
        }
        s = s + (pp.vector_g[j] + pp.vector_h[j]) * sum - pp.vector_h[j] * x_power.back();
    }
    for (std::size_t degree = 0; degree < pp.index_bits; ++degree) {
        s = s - proof.c_p[degree] * x_power[degree];
    }
    return proof.p * x_power.back() - s == pp.u * proof.z_p &&
        logarithmic::verify(logarithmic_parameters(pp), {proof.p}, proof.binary);
}

range::Proof prove_range(const range::PublicParameters& pp,
                         const ScalarVector& weights,
                         const ScalarVector& values,
                         const ZnElement& randomness) {
    const std::size_t length = pp.vector_length;
    const std::shared_ptr<Zn> ring = pp.ring_ctx;
    const ZnElement zero = ring->get_zero();
    const ZnElement one = ring->get_one();
    ScalarVector a_left(length, zero);
    ScalarVector a_right(length, zero);
    for (std::size_t i = 0; i < values.size(); ++i) {
        for (std::size_t b = 0; b < pp.range_bits; ++b) {
            a_left[i * pp.range_bits + b] = BN_is_bit_set(values[i].value.bn_ptr,
                static_cast<int>(b)) ? one : zero;
            a_right[i * pp.range_bits + b] = a_left[i * pp.range_bits + b] - one;
        }
    }
    const ScalarVector s_left = gen_random_znelement_vector(ring, length);
    const ScalarVector s_right = gen_random_znelement_vector(ring, length);
    const ZnElement alpha = ring->gen_random();
    const ZnElement rho = ring->gen_random();
    range::Proof proof = initialize_range(pp);
    proof.a = ec_point_msm(pp.vector_g, a_left) + ec_point_msm(pp.vector_h, a_right) + pp.h * alpha;
    proof.s = ec_point_msm(pp.vector_g, s_left) + ec_point_msm(pp.vector_h, s_right) + pp.h * rho;
    std::ostringstream transcript;
    transcript << proof.a;
    const ZnElement y = hash_to_zn(transcript.str(), *ring);
    transcript << proof.s;
    const ZnElement z = hash_to_zn(transcript.str(), *ring);
    const ScalarVector y_power = powers(length, y);
    const ScalarVector inverse_y = powers(length, y.inv());
    const ScalarVector two = powers(pp.range_bits, ZnElement(ring, BigInt(uint64_t{2})));
    ScalarVector l0(length, zero);
    ScalarVector r0(length, zero);
    ScalarVector r1(length, zero);
    for (std::size_t i = 0; i < length; ++i) {
        l0[i] = a_left[i] - z;
        r0[i] = y_power[i] * (a_right[i] + z) + z * z * weights[i / pp.range_bits] *
            two[i % pp.range_bits];
        r1[i] = y_power[i] * s_right[i];
    }
    const ZnElement tau1 = ring->gen_random();
    const ZnElement tau2 = ring->gen_random();
    proof.t1 = ec_point_msm(pp.g, tau1, pp.h, dot(s_left, r0) + dot(l0, r1));
    proof.t2 = ec_point_msm(pp.g, tau2, pp.h, dot(s_left, r1));
    transcript << proof.t1 << proof.t2;
    const ZnElement x = hash_to_zn(transcript.str(), *ring);
    ScalarVector l(length, zero);
    ScalarVector r(length, zero);
    std::vector<ECPoint> h(length, ECPoint(pp.group_ctx));
    for (std::size_t i = 0; i < length; ++i) {
        l[i] = l0[i] + s_left[i] * x;
        r[i] = r0[i] + r1[i] * x;
        h[i] = pp.vector_h[i] * inverse_y[i];
    }
    proof.t = dot(l, r);
    proof.taux = tau1 * x + tau2 * x * x + z * z * randomness;
    proof.mu = alpha + rho * x;
    transcript << x;
    const ZnElement e = hash_to_zn(transcript.str(), *ring);
    const inner::PublicParameters ip{pp.curve_id, length, folding_rounds(length),
        pp.group_ctx, ring, pp.vector_g, h, pp.u * e};
    const ECPoint p = ec_point_msm(ip.g, l) + ec_point_msm(ip.h, r) + ip.u * proof.t;
    proof.inner_product = inner::prove(ip, {p}, {l, r}, transcript.str());
    return proof;
}

bool verify_range(const range::PublicParameters& pp,
                  const ECPoint& commitment,
                  const ScalarVector& weights,
                  const range::Proof& proof) {
    const std::size_t length = pp.vector_length;
    if (pp.vector_g.size() != length || pp.vector_h.size() != length ||
        proof.inner_product.left.size() != folding_rounds(length) ||
        proof.inner_product.right.size() != folding_rounds(length)) {
        return false;
    }
    const std::shared_ptr<Zn> ring = pp.ring_ctx;
    std::ostringstream transcript;
    transcript << proof.a;
    const ZnElement y = hash_to_zn(transcript.str(), *ring);
    if (!y.is_unit()) {
        return false;
    }
    transcript << proof.s;
    const ZnElement z = hash_to_zn(transcript.str(), *ring);
    transcript << proof.t1 << proof.t2;
    const ZnElement x = hash_to_zn(transcript.str(), *ring);
    transcript << x;
    const ZnElement e = hash_to_zn(transcript.str(), *ring);
    const ScalarVector y_power = powers(length, y);
    const ScalarVector inverse_y = powers(length, y.inv());
    const ScalarVector two = powers(pp.range_bits, ZnElement(ring, BigInt(uint64_t{2})));
    ZnElement sum_y = ring->get_zero();
    ZnElement sum_coefficients = ring->get_zero();
    ScalarVector coefficients(length, ring->get_zero());
    for (std::size_t i = 0; i < length; ++i) {
        coefficients[i] = z * z * weights[i / pp.range_bits] * two[i % pp.range_bits];
        sum_y += y_power[i];
        sum_coefficients += coefficients[i];
    }
    const ZnElement delta = (z - z * z) * sum_y - z * sum_coefficients;
    if (ec_point_msm(pp.g, proof.taux, pp.h, proof.t) != commitment * (z * z) + pp.h * delta +
        ec_point_msm(proof.t1, x, proof.t2, x * x)) {
        return false;
    }
    std::vector<ECPoint> h(length, ECPoint(pp.group_ctx));
    ECPoint p = proof.a + proof.s * x - pp.h * proof.mu;
    for (std::size_t i = 0; i < length; ++i) {
        h[i] = pp.vector_h[i] * inverse_y[i];
        p = p - pp.vector_g[i] * z + h[i] * (y_power[i] * z + coefficients[i]);
    }
    const inner::PublicParameters ip{pp.curve_id, length, folding_rounds(length),
        pp.group_ctx, ring, pp.vector_g, h, pp.u * e};
    return inner::verify(ip, {p + ip.u * proof.t}, proof.inner_product, transcript.str());
}

} // namespace

PublicParameters setup(const pke::twisted_elgamal::PublicParameters& encryption,
                       std::size_t participant_count,
                       std::size_t receiver_count) {
    TAIHANG_ASSERT(taihang::arithmetic::is_pow2(participant_count) && participant_count >= 2 &&
        receiver_count > 0 && receiver_count <= participant_count,
            "Positive invalid participant or receiver count");
    PublicParameters pp;
    pp.encryption = encryption;
    pp.participant_count = participant_count;
    pp.receiver_count = receiver_count;
    pp.index_bits = folding_rounds(participant_count);
    pp.u = generators(encryption.group_ctx, 1, "taihang/apgc/positive/u/")[0];
    pp.inner_product_u = generators(encryption.group_ctx, 1, "taihang/apgc/positive/ip-u/")[0];
    pp.vector_g = generators(encryption.group_ctx, participant_count, "taihang/apgc/positive/g/");
    pp.vector_h = generators(encryption.group_ctx, participant_count, "taihang/apgc/positive/h/");
    pp.index_g = generators(encryption.group_ctx, receiver_count * pp.index_bits,
        "taihang/apgc/positive/index/");
    pp.values_range = range_parameters(encryption, 32, receiver_count, pp.u,
        "taihang/apgc/positive/values");
    pp.shifted_range = range_parameters(encryption, 32, receiver_count, pp.u,
        "taihang/apgc/positive/shifted");
    return pp;
}

bool SelectionProof::operator==(const SelectionProof& other) const {
    return a == other.a && b == other.b && c == other.c && d == other.d && p == other.p &&
        c_c == other.c_c && c_p == other.c_p && f == other.f && z_a == other.z_a &&
        z_c == other.z_c && z_g == other.z_g && z_p == other.z_p && binary == other.binary;
}

std::ostream& operator<<(std::ostream& os, const SelectionProof& proof) {
    os << proof.a << proof.b << proof.c << proof.d << proof.p;
    write_vector(os, proof.c_c);
    write_vector(os, proof.c_p);
    write_vector(os, proof.f);
    return os << proof.z_a << proof.z_c << proof.z_g << proof.z_p << proof.binary;
}

std::istream& operator>>(std::istream& is, SelectionProof& proof) {
    is >> proof.a >> proof.b >> proof.c >> proof.d >> proof.p;
    if (is) {
        read_vector(is, proof.c_c);
    }
    if (is) {
        read_vector(is, proof.c_p);
    }
    if (is) {
        read_vector(is, proof.f);
    }
    if (is) {
        is >> proof.z_a >> proof.z_c >> proof.z_g >> proof.z_p >> proof.binary;
    }
    return is;
}

bool Proof::operator==(const Proof& other) const {
    return subset == other.subset && values == other.values && shifted == other.shifted;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    return os << proof.subset << proof.values << proof.shifted;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    is >> proof.subset;
    if (is) {
        is >> proof.values;
    }
    if (is) {
        is >> proof.shifted;
    }
    return is;
}

Proof initialize_proof(const PublicParameters& pp) {
    const std::shared_ptr<ECGroup> group = pp.encryption.group_ctx;
    const std::shared_ptr<Zn> ring = pp.encryption.ring_ctx;
    return {{ECPoint(group), ECPoint(group), ECPoint(group), ECPoint(group), ECPoint(group),
        std::vector<ECPoint>(pp.index_bits, ECPoint(group)), std::vector<ECPoint>(pp.index_bits,
            ECPoint(group)),
        ScalarVector(pp.index_g.size(), ZnElement(ring)), ZnElement(ring), ZnElement(ring),
            ZnElement(ring), ZnElement(ring),
        {ECPoint(group), ECPoint(group), ECPoint(group), ZnElement(ring), ZnElement(ring),
            ZnElement(ring),
         initialize_inner(pp.encryption, pp.participant_count)}},
        initialize_range(pp.values_range), initialize_range(pp.shifted_range)};
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    TAIHANG_ASSERT(valid_dimensions(pp, statement) && witness.indices.size() == pp.receiver_count &&
        witness.values.size() == pp.receiver_count &&
            witness.randomness.size() == pp.receiver_count,
        "Positive statement or witness dimensions mismatch");
    Proof proof = initialize_proof(pp);
    proof.subset = prove_selection(pp, statement, witness, context);
    const Aggregate selected = aggregate(pp, statement, proof.subset, context);
    const ZnElement tau = proof.subset.z_g * selected.normalization;
    proof.values = prove_range(pp.values_range, selected.weights, witness.values, tau);
    ScalarVector shifted = witness.values;
    for (ZnElement& value : shifted) {
        value -= pp.encryption.ring_ctx->get_one();
    }
    proof.shifted = prove_range(pp.shifted_range, selected.weights, shifted, tau);
    return proof;
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
    if (!valid_dimensions(pp, statement) || !verify_selection(pp, proof.subset, context)) {
        return false;
    }
    const Aggregate selected = aggregate(pp, statement, proof.subset, context);
    ZnElement sum = pp.encryption.ring_ctx->get_zero();
    for (const ZnElement& weight : selected.weights) {
        sum += weight;
    }
    return verify_range(pp.values_range, selected.commitment, selected.weights, proof.values) &&
        verify_range(pp.shifted_range, selected.commitment - pp.encryption.h * sum,
            selected.weights, proof.shifted);
}

} // namespace taihang::zkp::apgc::positive_transfer
