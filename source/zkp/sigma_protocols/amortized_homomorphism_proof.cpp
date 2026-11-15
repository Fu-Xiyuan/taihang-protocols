/****************************************************************************
 * @file      amortized_homomorphism_proof.cpp
 * @brief     Amortized homomorphism proof implementation.
 *****************************************************************************/

#include <taihang/zkp/sigma_protocols/amortized_homomorphism_proof.hpp>

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

namespace taihang::zkp::nizk::amortized_homomorphism {
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

std::size_t folding_rounds(std::size_t vector_length) {
    std::size_t rounds = 0;
    for (std::size_t n = vector_length; n > 1; n /= 2) {
        ++rounds;
    }
    return rounds;
}

bool valid_dimensions(const PublicParameters& pp) {
    return is_pow2(pp.statement_count) &&
           pp.statement_count <= std::numeric_limits<std::size_t>::max() / 2 &&
           pp.threshold > 0 && pp.threshold <= pp.statement_count &&
           pp.vector_length == 2 * pp.statement_count &&
           pp.vector_g.size() == pp.vector_length &&
           pp.rounds == folding_rounds(pp.vector_length);
}

/** Bind the entire public input before deriving the batching challenge. */
std::string initial_transcript(const Statement& statement,
                               std::string_view context) {
    std::ostringstream transcript;
    transcript.write(context.data(),
                     static_cast<std::streamsize>(context.size()));
    transcript << statement.p;
    for (const ECPoint& c : statement.c) {
        transcript << c;
    }
    return transcript.str();
}

/** Batch c_j*(1 + sum_i a_i*j^i) = g*b_j with weights rho^(j-1). */
std::vector<ECPoint> batched_bases(const PublicParameters& pp,
                                   const Statement& statement,
                                   const ScalarVector& rho_power) {
    const std::size_t n = pp.statement_count;
    const std::size_t degree = n - pp.threshold;
    const ZnElement zero = pp.ring_ctx->get_zero();
    const ZnElement one = pp.ring_ctx->get_one();
    std::vector<ECPoint> bases(pp.vector_length, pp.group_ctx->get_infinity());
    ScalarVector evaluation_power(n, one);
    ScalarVector coefficients(n, zero);
    ScalarVector indices(n, zero);
    for (std::size_t j = 0; j < n; ++j) {
        indices[j] = ZnElement(pp.ring_ctx, BigInt(uint64_t{j + 1}));
    }
    for (std::size_t i = 0; i < degree; ++i) {
        for (std::size_t j = 0; j < n; ++j) {
            evaluation_power[j] *= indices[j];
            coefficients[j] = rho_power[j] * evaluation_power[j];
        }
        bases[i] = ec_point_msm(statement.c, coefficients);
    }
    for (std::size_t j = 0; j < n; ++j) {
        bases[degree + j] = pp.g * (-rho_power[j]);
    }
    return bases;
}

/** Generate (1, rho, ..., rho^(n-1)) for the n public relations. */
ScalarVector powers(std::size_t length, const ZnElement& rho) {
    ScalarVector result(length, rho.ring_ctx->get_one());
    for (std::size_t i = 1; i < length; ++i) {
        result[i] = result[i - 1] * rho;
    }
    return result;
}

} // namespace

PublicParameters setup(int curve_id,
                       std::size_t statement_count,
                       std::size_t threshold) {
    TAIHANG_ASSERT(is_pow2(statement_count) &&
                       statement_count <= std::numeric_limits<std::size_t>::max() / 2,
                   "amortized-homomorphism count must be a positive power of two");
    TAIHANG_ASSERT(threshold > 0 && threshold <= statement_count,
                   "amortized-homomorphism threshold out of range");

    PublicParameters pp;
    pp.curve_id = curve_id;
    pp.statement_count = statement_count;
    pp.threshold = threshold;
    pp.vector_length = 2 * statement_count;
    pp.rounds = folding_rounds(pp.vector_length);
    pp.group_ctx = std::make_shared<ECGroup>(curve_id);
    pp.ring_ctx = std::make_shared<Zn>(pp.group_ctx->order);
    pp.g = pp.group_ctx->get_generator();
    pp.u = derive_generator("taihang/amortized-homomorphism/base-u", *pp.group_ctx);
    pp.vector_g = std::vector<ECPoint>(pp.vector_length,
                                      pp.group_ctx->get_infinity());
    for (std::size_t i = 0; i < pp.vector_length - threshold; ++i) {
        pp.vector_g[i] = derive_generator(
            "taihang/amortized-homomorphism/vector-g/" + std::to_string(i),
            *pp.group_ctx);
    }
    return pp;
}

PublicParameters setup(const std::shared_ptr<ECGroup>& group_ctx,
                       const std::shared_ptr<Zn>& ring_ctx,
                       std::size_t statement_count,
                       std::size_t threshold,
                       const ECPoint& g,
                       const ECPoint& u,
                       const std::vector<ECPoint>& vector_g) {
    TAIHANG_ASSERT(group_ctx != nullptr && ring_ctx != nullptr,
                   "amortized-homomorphism contexts cannot be null");
    TAIHANG_ASSERT(ring_ctx->modulus == group_ctx->order,
                   "amortized-homomorphism scalar modulus mismatch");
    TAIHANG_ASSERT(g.group_ctx == group_ctx.get() && u.group_ctx == group_ctx.get(),
                   "amortized-homomorphism base context mismatch");
    TAIHANG_ASSERT(!g.is_at_infinity() && !u.is_at_infinity(),
                   "amortized-homomorphism bases cannot be identities");
    for (const ECPoint& generator : vector_g) {
        TAIHANG_ASSERT(generator.group_ctx == group_ctx.get(),
                       "amortized-homomorphism generator context mismatch");
    }

    PublicParameters pp;
    pp.curve_id = group_ctx->curve_id;
    pp.statement_count = statement_count;
    pp.threshold = threshold;
    pp.vector_length = vector_g.size();
    pp.rounds = folding_rounds(pp.vector_length);
    pp.group_ctx = group_ctx;
    pp.ring_ctx = ring_ctx;
    pp.g = g;
    pp.u = u;
    pp.vector_g = vector_g;
    TAIHANG_ASSERT(valid_dimensions(pp),
                   "amortized-homomorphism parameter dimensions mismatch");
    return pp;
}

bool Proof::operator==(const Proof& other) const {
    return a_p == other.a_p && a_f == other.a_f && f == other.f &&
           equality_proof == other.equality_proof;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    return os << proof.a_p << proof.a_f << proof.f << proof.equality_proof;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    is >> proof.a_p;
    if (is) {
        is >> proof.a_f;
    }
    if (is) {
        is >> proof.f;
    }
    if (is) {
        is >> proof.equality_proof;
    }
    return is;
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    TAIHANG_ASSERT(valid_dimensions(pp),
                   "amortized-homomorphism parameter dimensions mismatch");
    TAIHANG_ASSERT(statement.c.size() == pp.statement_count,
                   "amortized-homomorphism statement length mismatch");
    TAIHANG_ASSERT(witness.y.size() == pp.vector_length,
                   "amortized-homomorphism witness length mismatch");

    std::ostringstream transcript;
    transcript << initial_transcript(statement, context);
    ZnElement rho = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (rho.value.is_zero()) {
        rho = pp.ring_ctx->get_one();
    }
    const ScalarVector rho_power = powers(pp.statement_count, rho);
    const std::vector<ECPoint> bases = batched_bases(pp, statement, rho_power);

    // Fresh masks hide y and r before compressing their responses.
    const ScalarVector alpha =
        gen_random_znelement_vector(pp.ring_ctx, pp.vector_length);
    const ZnElement beta = pp.ring_ctx->gen_random();
    Proof proof{
        ec_point_msm(pp.vector_g, alpha) + pp.u * beta,
        ec_point_msm(bases, alpha),
        ZnElement(pp.ring_ctx),
        {}
    };
    transcript.str(std::string{});
    transcript << context << proof.a_p << proof.a_f;
    ZnElement e = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (e.value.is_zero()) {
        e = pp.ring_ctx->get_one();
    }

    ScalarVector z(pp.vector_length, pp.ring_ctx->get_zero());
    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        z[i] = alpha[i] + e * witness.y[i];
    }
    proof.f = beta + e * witness.r;

    // For a valid witness, <bases,y> = -sum_j rho^(j-1)*c_j.
    // Using the supplied witness here lets the verifier reject invalid openings.
    const multi_exponentiation_equality::PublicParameters equality_pp =
        multi_exponentiation_equality::setup(
        pp.group_ctx, pp.ring_ctx, bases, pp.vector_g);
    const multi_exponentiation_equality::Statement equality_statement{
        proof.a_f + ec_point_msm(bases, witness.y) * e,
        statement.p * e + proof.a_p - pp.u * proof.f
    };
    proof.equality_proof = multi_exponentiation_equality::prove(
        equality_pp, equality_statement, {std::move(z)}, context);
    return proof;
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
    if (!valid_dimensions(pp) || statement.c.size() != pp.statement_count ||
        proof.equality_proof.left_g.size() != pp.rounds ||
        proof.equality_proof.right_g.size() != pp.rounds ||
        proof.equality_proof.left_p.size() != pp.rounds ||
        proof.equality_proof.right_p.size() != pp.rounds) {
        return false;
    }

    std::ostringstream transcript;
    transcript << initial_transcript(statement, context);
    ZnElement rho = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (rho.value.is_zero()) {
        rho = pp.ring_ctx->get_one();
    }
    const ScalarVector rho_power = powers(pp.statement_count, rho);
    const std::vector<ECPoint> bases = batched_bases(pp, statement, rho_power);
    const ECPoint target = ec_point_msm(statement.c, rho_power).neg();

    transcript.str(std::string{});
    transcript << context << proof.a_p << proof.a_f;
    ZnElement e = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (e.value.is_zero()) {
        e = pp.ring_ctx->get_one();
    }

    // Both relations must open to the same masked vector z = alpha + e*y.
    const multi_exponentiation_equality::PublicParameters equality_pp =
        multi_exponentiation_equality::setup(
        pp.group_ctx, pp.ring_ctx, bases, pp.vector_g);
    const multi_exponentiation_equality::Statement equality_statement{
        proof.a_f + target * e,
        statement.p * e + proof.a_p - pp.u * proof.f
    };
    return multi_exponentiation_equality::verify(
        equality_pp, equality_statement, proof.equality_proof, context);
}

} // namespace taihang::zkp::nizk::amortized_homomorphism
