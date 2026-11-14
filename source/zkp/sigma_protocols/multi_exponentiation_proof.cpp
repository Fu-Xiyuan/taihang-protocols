/****************************************************************************
 * @file      multi_exponentiation_proof.cpp
 * @brief     Multi-exponentiation folding argument implementation.
 *****************************************************************************/

#include <taihang/zkp/sigma_protocols/multi_exponentiation_proof.hpp>

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

namespace taihang::zkp::nizk::multi_exponentiation {
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
                   "multi-exponentiation length must be a positive power of two");

    PublicParameters pp;
    pp.curve_id = curve_id;
    pp.vector_length = vector_length;
    pp.rounds = folding_rounds(vector_length);
    pp.group_ctx = std::make_shared<ECGroup>(curve_id);
    pp.ring_ctx = std::make_shared<Zn>(pp.group_ctx->order);
    pp.g = std::vector<ECPoint>(vector_length, ECPoint(pp.group_ctx));

    // Distinct labels derive a reproducible basis in the selected group.
    for (std::size_t i = 0; i < vector_length; ++i) {
        pp.g[i] = derive_generator(
            "taihang/multi-exponentiation/g/" + std::to_string(i),
            *pp.group_ctx);
    }

    return pp;
}

PublicParameters setup(const std::shared_ptr<ECGroup>& group_ctx,
                       const std::shared_ptr<Zn>& ring_ctx,
                       const std::vector<ECPoint>& generators) {
    TAIHANG_ASSERT(group_ctx != nullptr && ring_ctx != nullptr,
                   "multi-exponentiation contexts cannot be null");
    TAIHANG_ASSERT(ring_ctx->modulus == group_ctx->order,
                   "multi-exponentiation scalar modulus mismatch");
    TAIHANG_ASSERT(is_pow2(generators.size()),
                   "multi-exponentiation length must be a positive power of two");
    for (const ECPoint& generator : generators) {
        TAIHANG_ASSERT(generator.group_ctx == group_ctx.get(),
                       "multi-exponentiation generator context mismatch");
    }

    PublicParameters pp;
    pp.curve_id = group_ctx->curve_id;
    pp.vector_length = generators.size();
    pp.rounds = folding_rounds(pp.vector_length);
    pp.group_ctx = group_ctx;
    pp.ring_ctx = ring_ctx;
    pp.g = generators;
    return pp;
}

bool Proof::operator==(const Proof& other) const {
    return left == other.left && right == other.right && a == other.a;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    const std::uint64_t count = static_cast<std::uint64_t>(proof.left.size());
    os.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (const ECPoint& point : proof.left) {
        os << point;
    }
    for (const ECPoint& point : proof.right) {
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
    if (count != proof.left.size() || count != proof.right.size()) {
        is.setstate(std::ios::failbit);
        return is;
    }
    for (std::size_t i = 0; i < proof.left.size() && is; ++i) {
        is >> proof.left[i];
    }
    for (std::size_t i = 0; i < proof.right.size() && is; ++i) {
        is >> proof.right[i];
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
                       pp.rounds == rounds,
                   "multi-exponentiation parameter dimensions mismatch");
    TAIHANG_ASSERT(witness.a.size() == pp.vector_length,
                   "multi-exponentiation witness length mismatch");

    const ZnElement zero = pp.ring_ctx->get_zero();
    const ZnElement one = pp.ring_ctx->get_one();
    Proof proof{
        std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
        std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
        ZnElement(pp.ring_ctx)
    };

    std::vector<ECPoint> current_g = pp.g;
    ScalarVector current_a = witness.a;

    // Bind the generator basis and public result before any folding messages.
    // The context length separates associated data from parameter encodings.
    std::ostringstream transcript;
    transcript << "taihang/multi-exponentiation/v1"
               << BigInt(uint64_t{context.size()});
    transcript.write(context.data(),
                     static_cast<std::streamsize>(context.size()));
    transcript << BigInt(static_cast<uint64_t>(pp.curve_id))
               << BigInt(uint64_t{pp.vector_length});
    for (const ECPoint& g : pp.g) {
        transcript << g;
    }
    transcript << statement.g;

    for (std::size_t round = 0; round < pp.rounds; ++round) {
        const std::size_t half = current_g.size() / 2;
        std::vector<const ECPoint*> points(half, nullptr);
        ScalarVector scalars(half, zero);

        // Cross terms L = g_L*a_R and R = g_R*a_L preserve the relation
        // when the generator and witness halves are folded together.
        for (std::size_t i = 0; i < half; ++i) {
            points[i] = &current_g[i];
            scalars[i] = current_a[half + i];
        }
        proof.left[round] = ec_point_msm(points, scalars);
        for (std::size_t i = 0; i < half; ++i) {
            points[i] = &current_g[half + i];
            scalars[i] = current_a[i];
        }
        proof.right[round] = ec_point_msm(points, scalars);

        transcript << proof.left[round] << proof.right[round];
        ZnElement x = hash_to_zn(transcript.str(), *pp.ring_ctx);
        if (x.value.is_zero()) {
            x = one;
        }

        // g' = x*g_L + g_R and a' = a_L + x*a_R halve the dimension.
        std::vector<ECPoint> next_g(half, ECPoint(pp.group_ctx));
        ScalarVector next_a(half, zero);
        for (std::size_t i = 0; i < half; ++i) {
            next_g[i] = ec_point_msm(
                current_g[i], x, current_g[half + i], one);
            next_a[i] = current_a[i] + x * current_a[half + i];
        }
        current_g = std::move(next_g);
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
        pp.rounds != rounds ||
        proof.left.size() != pp.rounds || proof.right.size() != pp.rounds) {
        return false;
    }

    std::ostringstream transcript;
    transcript << "taihang/multi-exponentiation/v1"
               << BigInt(uint64_t{context.size()});
    transcript.write(context.data(),
                     static_cast<std::streamsize>(context.size()));
    transcript << BigInt(static_cast<uint64_t>(pp.curve_id))
               << BigInt(uint64_t{pp.vector_length});
    for (const ECPoint& g : pp.g) {
        transcript << g;
    }
    transcript << statement.g;

    ECPoint result = statement.g;
    std::vector<ECPoint> current_g = pp.g;
    const ZnElement one = pp.ring_ctx->get_one();
    for (std::size_t round = 0; round < pp.rounds; ++round) {
        transcript << proof.left[round] << proof.right[round];
        ZnElement x = hash_to_zn(transcript.str(), *pp.ring_ctx);
        if (x.value.is_zero()) {
            x = one;
        }

        // G' = x^2*L + x*G + R matches the prover's two vector folds.
        result = ec_point_msm(
            {proof.left[round], result, proof.right[round]}, {x * x, x, one});
        const std::size_t half = current_g.size() / 2;
        std::vector<ECPoint> next_g(half, ECPoint(pp.group_ctx));
        for (std::size_t i = 0; i < half; ++i) {
            next_g[i] = ec_point_msm(current_g[i], x, current_g[half + i], one);
        }
        current_g = std::move(next_g);
    }
    // This also handles length one, where no folding messages are present.
    return current_g[0] * proof.a == result;
}

} // namespace taihang::zkp::nizk::multi_exponentiation
