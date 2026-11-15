/****************************************************************************
 * @file      inactive_participant_proof.cpp
 * @brief     ZGSX23 construction migrated from APGC Null.
 *****************************************************************************/

#include <taihang/zkp/apgc/inactive_participant_proof.hpp>

#include <openssl/obj_mac.h>

#include <istream>
#include <ostream>
#include <sstream>

#include <taihang/common/check.hpp>
#include <taihang/utility/arithmetic.hpp>

namespace taihang::zkp::apgc::inactive_participant {
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

range_proofs::inner_product::PublicParameters inner_parameters(
    const pke::twisted_elgamal::PublicParameters& encryption,
    const std::vector<ECPoint>& g,
    const std::vector<ECPoint>& h,
    const ECPoint& u) {
    return {encryption.curve_id, g.size(), folding_rounds(g.size()), encryption.group_ctx,
             encryption.ring_ctx, g, h, u};
}

range_proofs::inner_product::Proof initialize_inner(
    const pke::twisted_elgamal::PublicParameters& encryption,
    std::size_t length) {
    const std::size_t rounds = folding_rounds(length);
    return {std::vector<ECPoint>(rounds, ECPoint(encryption.group_ctx)),
        std::vector<ECPoint>(rounds, ECPoint(encryption.group_ctx)),
        ZnElement(encryption.ring_ctx), ZnElement(encryption.ring_ctx)};
}

namespace inner = taihang::zkp::range_proofs::inner_product;
using ScalarVector = std::vector<ZnElement>;

bool valid_dimensions(const PublicParameters& pp, const Statement& statement) {
    return taihang::arithmetic::is_pow2(pp.participant_count) &&
        pp.vector_g.size() == pp.participant_count && pp.vector_h.size() == pp.participant_count &&
        statement.commitments.size() == pp.participant_count &&
            statement.count <= pp.participant_count;
}

inner::PublicParameters inner_parameters(
    const PublicParameters& pp,
    const Statement& statement,
    const ScalarVector& inverse_y,
    const ZnElement& e) {
    std::vector<ECPoint> g(pp.participant_count, ECPoint(pp.encryption.group_ctx));
    for (std::size_t i = 0; i < pp.participant_count; ++i) {
        g[i] = pp.vector_g[i] * inverse_y[i] + statement.commitments[i];
    }
    return inner_parameters(pp.encryption, g, pp.vector_h, pp.u * e);
}

} // namespace

PublicParameters setup(const pke::twisted_elgamal::PublicParameters& encryption,
                       std::size_t participant_count) {
    TAIHANG_ASSERT(taihang::arithmetic::is_pow2(participant_count),
        "inactive participant count must be a power of two");
    return {encryption, participant_count,
        generators(encryption.group_ctx, 1, "taihang/apgc/inactive/u/")[0],
        generators(encryption.group_ctx, participant_count, "taihang/apgc/inactive/g/"),
        generators(encryption.group_ctx, participant_count, "taihang/apgc/inactive/h/")};
}

bool Proof::operator==(const Proof& other) const {
    return a == other.a && s == other.s && t1 == other.t1 && t2 == other.t2 && e == other.e &&
        taux == other.taux && mu == other.mu && t == other.t && f_s == other.f_s &&
        inner_product == other.inner_product;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    return os << proof.a << proof.s << proof.t1 << proof.t2 << proof.e
              << proof.taux << proof.mu << proof.t << proof.f_s << proof.inner_product;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    is >> proof.a >> proof.s >> proof.t1 >> proof.t2 >> proof.e
       >> proof.taux >> proof.mu >> proof.t >> proof.f_s;
    if (is) {
        is >> proof.inner_product;
    }
    return is;
}

Proof initialize_proof(const PublicParameters& pp) {
    const std::shared_ptr<ECGroup> group = pp.encryption.group_ctx;
    const std::shared_ptr<Zn> ring = pp.encryption.ring_ctx;
    return {ECPoint(group), ECPoint(group), ECPoint(group), ECPoint(group), ECPoint(group),
        ZnElement(ring), ZnElement(ring), ZnElement(ring), ZnElement(ring),
        initialize_inner(pp.encryption, pp.participant_count)};
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    TAIHANG_ASSERT(valid_dimensions(pp, statement) && witness.bits.size() == pp.participant_count,
                   "inactive participant dimensions mismatch");
    const std::size_t n = pp.participant_count;
    const std::shared_ptr<Zn> ring = pp.encryption.ring_ctx;
    const ZnElement one = ring->get_one();
    const ZnElement alpha = ring->gen_random();
    const ZnElement beta = ring->gen_random();
    const ScalarVector s_left = gen_random_znelement_vector(ring, n);
    const ScalarVector s_right = gen_random_znelement_vector(ring, n);
    ScalarVector a_right(n, ring->get_zero());
    for (std::size_t i = 0; i < n; ++i) {
        a_right[i] = witness.bits[i] - one;
    }
    Proof proof = initialize_proof(pp);
    proof.a = ec_point_msm(pp.vector_g, witness.bits) + ec_point_msm(pp.vector_h,
        a_right) + pp.u * alpha;
    proof.s = ec_point_msm(pp.vector_g, s_left) + ec_point_msm(pp.vector_h, s_right) + pp.u * beta;
    std::ostringstream transcript;
    transcript << context << proof.a;
    const ZnElement y = hash_to_zn(transcript.str(), *ring);
    transcript << proof.s;
    const ZnElement z = hash_to_zn(transcript.str(), *ring);
    const ScalarVector y_power = powers(n, y);
    const ScalarVector inverse_y = powers(n, y.inv());
    ScalarVector l0(n, ring->get_zero());
    ScalarVector l1(n, ring->get_zero());
    ScalarVector r0(n, ring->get_zero());
    for (std::size_t i = 0; i < n; ++i) {
        l0[i] = y_power[i] * (witness.bits[i] - z);
        l1[i] = y_power[i] * s_left[i];
        r0[i] = a_right[i] + z + z * z * inverse_y[i];
    }
    const ZnElement t1 = dot(l1, r0) + dot(l0, s_right);
    const ZnElement t2 = dot(l1, s_right);
    const ZnElement tau1 = ring->gen_random();
    const ZnElement tau2 = ring->gen_random();
    proof.t1 = ec_point_msm(pp.encryption.g, t1, pp.encryption.h, tau1);
    proof.t2 = ec_point_msm(pp.encryption.g, t2, pp.encryption.h, tau2);
    const ZnElement r_s = ring->gen_random();
    proof.e = ec_point_msm(statement.commitments, l1) - pp.encryption.g * r_s;
    transcript << proof.t1 << proof.t2 << proof.e;
    const ZnElement x = hash_to_zn(transcript.str(), *ring);
    ScalarVector l(n, ring->get_zero());
    ScalarVector r(n, ring->get_zero());
    for (std::size_t i = 0; i < n; ++i) {
        l[i] = l0[i] + l1[i] * x;
        r[i] = r0[i] + s_right[i] * x;
    }
    proof.t = dot(l, r);
    proof.taux = tau1 * x + tau2 * x * x;
    proof.mu = alpha + beta * x;
    proof.f_s = r_s * x;
    std::size_t selected = 0;
    for (std::size_t i = 0; i < n; ++i) {
        if (witness.bits[i] == one) {
            TAIHANG_ASSERT(selected < witness.randomness.size(),
                "inactive participant randomness length mismatch");
            proof.f_s += witness.randomness[selected++] * y_power[i];
        }
    }
    TAIHANG_ASSERT(selected == witness.randomness.size(),
        "inactive participant randomness length mismatch");
    transcript << x;
    const ZnElement e = hash_to_zn(transcript.str(), *ring);
    const inner::PublicParameters ip = inner_parameters(pp, statement, inverse_y, e);
    const ECPoint p = ec_point_msm(ip.g, l) + ec_point_msm(ip.h, r) + ip.u * proof.t;
    proof.inner_product = inner::prove(ip, {p}, {l, r}, transcript.str());
    return proof;
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
    if (!valid_dimensions(pp, statement) ||
        proof.inner_product.left.size() != folding_rounds(pp.participant_count) ||
        proof.inner_product.right.size() != folding_rounds(pp.participant_count)) {
        return false;
    }
    const std::shared_ptr<Zn> ring = pp.encryption.ring_ctx;
    std::ostringstream transcript;
    transcript << context << proof.a;
    const ZnElement y = hash_to_zn(transcript.str(), *ring);
    if (!y.is_unit()) {
        return false;
    }
    transcript << proof.s;
    const ZnElement z = hash_to_zn(transcript.str(), *ring);
    transcript << proof.t1 << proof.t2 << proof.e;
    const ZnElement x = hash_to_zn(transcript.str(), *ring);
    transcript << x;
    const ZnElement e = hash_to_zn(transcript.str(), *ring);
    const ScalarVector y_power = powers(pp.participant_count, y);
    const ScalarVector inverse_y = powers(pp.participant_count, y.inv());
    ZnElement sum_y = ring->get_zero();
    for (const ZnElement& power : y_power) {
        sum_y += power;
    }
    const ZnElement n(ring, BigInt(uint64_t{pp.participant_count}));
    const ZnElement count(ring, BigInt(uint64_t{statement.count}));
    const ZnElement delta = (z - z * z) * sum_y - z * z * z * n;
    const ECPoint left = ec_point_msm(pp.encryption.g, proof.t, pp.encryption.h, proof.taux);
    const ECPoint right = pp.encryption.g * (delta + z * z * count) +
        ec_point_msm(proof.t1, x, proof.t2, x * x);
    if (left != right) {
        return false;
    }
    const inner::PublicParameters ip = inner_parameters(pp, statement, inverse_y, e);
    ECPoint p = proof.a + proof.s * x + pp.encryption.g * proof.f_s - pp.u * proof.mu + proof.e * x;
    for (std::size_t i = 0; i < pp.participant_count; ++i) {
        p = p - pp.vector_g[i] * z + pp.vector_h[i] * (z + z * z * inverse_y[i]) -
            statement.commitments[i] * (z * y_power[i]);
    }
    p = p + ip.u * proof.t;
    return inner::verify(ip, {p}, proof.inner_product, transcript.str());
}

} // namespace taihang::zkp::apgc::inactive_participant
