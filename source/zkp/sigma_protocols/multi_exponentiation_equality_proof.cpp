/****************************************************************************
 * @file      multi_exponentiation_equality_proof.cpp
 * @brief     Multi-exponentiation equality folding argument implementation.
 *****************************************************************************/

#include <taihang/zkp/sigma_protocols/multi_exponentiation_equality_proof.hpp>

#include <openssl/obj_mac.h>

#include <cstdint>
#include <ios>
#include <istream>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>

#include <taihang/common/check.hpp>
#include <taihang/utility/arithmetic.hpp>

namespace taihang::zkp::nizk::multi_exponentiation_equality {
namespace {

using taihang::arithmetic::is_pow2;
using ScalarVector = std::vector<ZnElement>;

ECPoint derive_generator(const std::string& label, const ECGroup& group) {
    static const std::string kP256Dst =
        "TAIHANG-PROTOCOLS-V01-P256_XMD:SHA-256_SSWU_RO_";

    if (group.curve_id == NID_X9_62_prime256v1) {
        return hash_to_curve_standard(label, kP256Dst, group);
    }
    return hash_to_curve_fast(label, group);
}

/** Number of folding rounds for a power-of-two vector length. */
std::size_t folding_rounds(std::size_t vector_length) {
    std::size_t rounds = 0;
    for (std::size_t n = vector_length; n > 1; n /= 2) {
        ++rounds;
    }
    return rounds;
}

} // namespace

PublicParameters setup(int curve_id, std::size_t vector_length) {
    TAIHANG_ASSERT(is_pow2(vector_length),
                   "multi-exponentiation-equality length must be a positive power of two");

    PublicParameters pp;
    pp.curve_id = curve_id;
    pp.vector_length = vector_length;
    pp.rounds = folding_rounds(vector_length);
    pp.group_ctx = std::make_shared<ECGroup>(curve_id);
    pp.ring_ctx = std::make_shared<Zn>(pp.group_ctx->order);
    pp.g = std::vector<ECPoint>(vector_length, ECPoint(pp.group_ctx));
    pp.p = std::vector<ECPoint>(vector_length, ECPoint(pp.group_ctx));

    // Distinct labels derive a reproducible basis in the selected group.
    for (std::size_t i = 0; i < vector_length; ++i) {
        pp.g[i] = derive_generator(
            "taihang/multi-exponentiation-equality/g/" + std::to_string(i),
            *pp.group_ctx);
        pp.p[i] = derive_generator(
            "taihang/multi-exponentiation-equality/p/" + std::to_string(i),
            *pp.group_ctx);
    }

    return pp;
}

PublicParameters setup(const std::shared_ptr<ECGroup>& group_ctx,
                       const std::shared_ptr<Zn>& ring_ctx,
                       const std::vector<ECPoint>& generators_g,
                       const std::vector<ECPoint>& generators_p) {
    TAIHANG_ASSERT(group_ctx != nullptr && ring_ctx != nullptr,
                   "multi-exponentiation-equality contexts cannot be null");
    TAIHANG_ASSERT(ring_ctx->modulus == group_ctx->order,
                   "multi-exponentiation-equality scalar modulus mismatch");
    TAIHANG_ASSERT(is_pow2(generators_g.size()) &&
                       generators_g.size() == generators_p.size(),
                   "multi-exponentiation-equality length must be a positive power of two");
    for (const ECPoint& generator : generators_g) {
        TAIHANG_ASSERT(generator.group_ctx == group_ctx.get(),
                       "multi-exponentiation-equality generator context mismatch");
    }

    for (const ECPoint& generator : generators_p) {
        TAIHANG_ASSERT(generator.group_ctx == group_ctx.get(),
                       "multi-exponentiation-equality generator context mismatch");
    }

    PublicParameters pp;
    pp.curve_id = group_ctx->curve_id;
    pp.vector_length = generators_g.size();
    pp.rounds = folding_rounds(pp.vector_length);
    pp.group_ctx = group_ctx;
    pp.ring_ctx = ring_ctx;
    pp.g = generators_g;
    pp.p = generators_p;
    return pp;
}

bool Proof::operator==(const Proof& other) const {
    return left_g == other.left_g && right_g == other.right_g &&
           left_p == other.left_p && right_p == other.right_p && a == other.a;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    const std::uint64_t count = static_cast<std::uint64_t>(proof.left_g.size());
    os.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (const ECPoint& point : proof.left_g) {
        os << point;
    }
    for (const ECPoint& point : proof.right_g) {
        os << point;
    }
    for (const ECPoint& point : proof.left_p) {
        os << point;
    }
    for (const ECPoint& point : proof.right_p) {
        os << point;
    }
    return os << proof.a;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    std::uint64_t count = 0;
    if (!is.read(reinterpret_cast<char*>(&count), sizeof(count))) {
        return is;
    }
    // The caller preinitializes the expected round count and contexts.
    if (count != proof.left_g.size() || count != proof.right_g.size() ||
        count != proof.left_p.size() || count != proof.right_p.size()) {
        is.setstate(std::ios::failbit);
        return is;
    }
    for (std::size_t i = 0; i < proof.left_g.size() && is; ++i) {
        is >> proof.left_g[i];
    }
    for (std::size_t i = 0; i < proof.right_g.size() && is; ++i) {
        is >> proof.right_g[i];
    }
    for (std::size_t i = 0; i < proof.left_p.size() && is; ++i) {
        is >> proof.left_p[i];
    }
    for (std::size_t i = 0; i < proof.right_p.size() && is; ++i) {
        is >> proof.right_p[i];
    }
    if (is) {
        is >> proof.a;
    }
    return is;
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    const std::size_t rounds = folding_rounds(pp.vector_length);
    TAIHANG_ASSERT(is_pow2(pp.vector_length) &&
                       pp.g.size() == pp.vector_length &&
                       pp.p.size() == pp.vector_length &&
                       pp.rounds == rounds,
                   "multi-exponentiation-equality parameter dimensions mismatch");
    TAIHANG_ASSERT(witness.a.size() == pp.vector_length,
                   "multi-exponentiation-equality witness length mismatch");

    const ZnElement zero = pp.ring_ctx->get_zero();
    const ZnElement one = pp.ring_ctx->get_one();
    Proof proof{
        std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
        std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
        std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
        std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
        ZnElement(pp.ring_ctx)
    };

    std::vector<ECPoint> current_g = pp.g;
    std::vector<ECPoint> current_p = pp.p;
    ScalarVector current_a = witness.a;

    // Bind the generator basis and public result before any folding messages.
    // The context length separates associated data from parameter encodings.
    std::ostringstream transcript;
    transcript.write(context.data(),
                     static_cast<std::streamsize>(context.size()));

    for (std::size_t round = 0; round < pp.rounds; ++round) {
        const std::size_t half = current_g.size() / 2;
        std::vector<const ECPoint*> points(half, nullptr);
        ScalarVector scalars(half, zero);

        // Both relations use cross terms from the same scalar vector.
        // L_g = g_L*a_R, R_g = g_R*a_L, and likewise for the p basis.
        for (std::size_t i = 0; i < half; ++i) {
            points[i] = &current_g[i];
            scalars[i] = current_a[half + i];
        }
        proof.left_g[round] = ec_point_msm(points, scalars);
        for (std::size_t i = 0; i < half; ++i) {
            points[i] = &current_g[half + i];
            scalars[i] = current_a[i];
        }
        proof.right_g[round] = ec_point_msm(points, scalars);
        for (std::size_t i = 0; i < half; ++i) {
            points[i] = &current_p[i];
            scalars[i] = current_a[half + i];
        }
        proof.left_p[round] = ec_point_msm(points, scalars);
        for (std::size_t i = 0; i < half; ++i) {
            points[i] = &current_p[half + i];
            scalars[i] = current_a[i];
        }
        proof.right_p[round] = ec_point_msm(points, scalars);

        transcript << proof.left_g[round] << proof.right_g[round]
                   << proof.left_p[round] << proof.right_p[round];
        ZnElement x = hash_to_zn(transcript.str(), *pp.ring_ctx);
        if (x.value.is_zero()) {
            x = one;
        }

        // g' = x*g_L + g_R and a' = a_L + x*a_R halve the dimension.
        std::vector<ECPoint> next_g(half, ECPoint(pp.group_ctx));
        std::vector<ECPoint> next_p(half, ECPoint(pp.group_ctx));
        ScalarVector next_a(half, zero);
        for (std::size_t i = 0; i < half; ++i) {
            next_g[i] = ec_point_msm(
                current_g[i], x, current_g[half + i], one);
            next_p[i] = ec_point_msm(
                current_p[i], x, current_p[half + i], one);
            next_a[i] = current_a[i] + x * current_a[half + i];
        }
        current_g = std::move(next_g);
        current_p = std::move(next_p);
        current_a = std::move(next_a);
    }
    // The remaining scalar is public; the caller supplies any ZK masking.
    proof.a = current_a[0];
    return proof;
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
    const std::size_t rounds = folding_rounds(pp.vector_length);
    if (!is_pow2(pp.vector_length) ||
        pp.g.size() != pp.vector_length ||
        pp.p.size() != pp.vector_length ||
        pp.rounds != rounds ||
        proof.left_g.size() != pp.rounds || proof.right_g.size() != pp.rounds ||
        proof.left_p.size() != pp.rounds || proof.right_p.size() != pp.rounds) {
        return false;
    }

    std::ostringstream transcript;
    transcript.write(context.data(),
                     static_cast<std::streamsize>(context.size()));

    ECPoint result_g = statement.g;
    ECPoint result_p = statement.p;
    std::vector<ECPoint> current_g = pp.g;
    std::vector<ECPoint> current_p = pp.p;
    const ZnElement one = pp.ring_ctx->get_one();
    for (std::size_t round = 0; round < pp.rounds; ++round) {
        transcript << proof.left_g[round] << proof.right_g[round]
                   << proof.left_p[round] << proof.right_p[round];
        ZnElement x = hash_to_zn(transcript.str(), *pp.ring_ctx);
        if (x.value.is_zero()) {
            x = one;
        }

        // G' = x^2*L_g + x*G + R_g and P' = x^2*L_p + x*P + R_p
        // share the same x, preserving the common scalar representation.
        const ScalarVector scalars{x * x, x, one};
        result_g = ec_point_msm(
            {proof.left_g[round], result_g, proof.right_g[round]}, scalars);
        result_p = ec_point_msm(
            {proof.left_p[round], result_p, proof.right_p[round]}, scalars);
        const std::size_t half = current_g.size() / 2;
        std::vector<ECPoint> next_g(half, ECPoint(pp.group_ctx));
        std::vector<ECPoint> next_p(half, ECPoint(pp.group_ctx));
        for (std::size_t i = 0; i < half; ++i) {
            next_g[i] = ec_point_msm(current_g[i], x, current_g[half + i], one);
            next_p[i] = ec_point_msm(current_p[i], x, current_p[half + i], one);
        }
        current_g = std::move(next_g);
        current_p = std::move(next_p);
    }
    // This also handles length one, where no folding messages are present.
    return current_g[0] * proof.a == result_g &&
           current_p[0] * proof.a == result_p;
}

} // namespace taihang::zkp::nizk::multi_exponentiation_equality
