/****************************************************************************
 * @file      attema_cramer_fehr_proof.cpp
 * @brief     ACF k-out-of-n proof implementation.
 *****************************************************************************/

#include <taihang/zkp/k_out_of_n_protocols/attema_cramer_fehr_proof.hpp>

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

namespace taihang::zkp::k_out_of_n::attema_cramer_fehr {
namespace {

using taihang::arithmetic::is_pow2;
using ScalarVector = std::vector<ZnElement>;
namespace amortized = taihang::zkp::nizk::amortized_homomorphism;

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
           pp.rounds == folding_rounds(2 * pp.statement_count) &&
           pp.vector_g.size() == 2 * pp.statement_count - pp.threshold;
}

/** Pad only the final k bases with identities for the embedded folding argument. */
amortized::PublicParameters amortized_parameters(const PublicParameters& pp) {
    std::vector<ECPoint> generators = pp.vector_g;
    generators.resize(2 * pp.statement_count, pp.group_ctx->get_infinity());
    return amortized::setup(pp.group_ctx, pp.ring_ctx, pp.statement_count,
                            pp.threshold, pp.g, pp.h, generators);
}

/** Bind the ACF domain, application data, bases, and entire public statement. */
std::string parent_context(const PublicParameters& pp,
                           const Statement& statement,
                           const ECPoint& p,
                           std::string_view context) {
    std::ostringstream transcript;
    transcript << "taihang/k-out-of-n/attema-cramer-fehr/v1"
               << BigInt(uint64_t{context.size()});
    transcript.write(context.data(), static_cast<std::streamsize>(context.size()));
    transcript << BigInt(static_cast<uint64_t>(pp.curve_id))
               << BigInt(uint64_t{pp.statement_count})
               << BigInt(uint64_t{pp.threshold}) << pp.g << pp.h;
    for (const ECPoint& generator : pp.vector_g) {
        transcript << generator;
    }
    for (const ECPoint& point : statement.points) {
        transcript << point;
    }
    transcript << p;
    return transcript.str();
}

/** q(X) = product_(j not in S) (1-X/(j+1)), so q(0)=1. */
ScalarVector selection_polynomial(const PublicParameters& pp,
                                  const std::vector<bool>& selected) {
    const ZnElement zero = pp.ring_ctx->get_zero();
    const ZnElement one = pp.ring_ctx->get_one();
    const std::size_t degree = pp.statement_count - pp.threshold;
    ScalarVector coefficients(degree + 1, zero);
    coefficients[0] = one;
    std::size_t current_degree = 0;
    for (std::size_t j = 0; j < pp.statement_count; ++j) {
        if (selected[j]) {
            continue;
        }
        const ZnElement root(pp.ring_ctx, BigInt(uint64_t{j + 1}));
        const ZnElement factor = -root.inv();
        for (std::size_t i = current_degree + 1; i > 0; --i) {
            coefficients[i] += coefficients[i - 1] * factor;
        }
        ++current_degree;
    }
    // With k=n the empty product is the constant polynomial q(X)=1.
    return coefficients;
}

ZnElement evaluate_polynomial(const ScalarVector& coefficients, const ZnElement& x) {
    ZnElement result = x.ring_ctx->get_zero();
    for (std::size_t i = coefficients.size(); i > 0; --i) {
        result = result * x + coefficients[i - 1];
    }
    return result;
}

} // namespace

PublicParameters setup(int curve_id,
                       std::size_t statement_count,
                       std::size_t threshold) {
    TAIHANG_ASSERT(is_pow2(statement_count) &&
                       statement_count <= std::numeric_limits<std::size_t>::max() / 2,
                   "ACF statement count must be a positive power of two");
    TAIHANG_ASSERT(threshold > 0 && threshold <= statement_count,
                   "ACF threshold out of range");

    PublicParameters pp;
    pp.curve_id = curve_id;
    pp.statement_count = statement_count;
    pp.threshold = threshold;
    pp.rounds = folding_rounds(2 * statement_count);
    pp.group_ctx = std::make_shared<ECGroup>(curve_id);
    pp.ring_ctx = std::make_shared<Zn>(pp.group_ctx->order);
    TAIHANG_ASSERT(BigInt(uint64_t{statement_count}) < pp.ring_ctx->modulus,
                   "ACF evaluation points must be distinct and nonzero");
    pp.g = pp.group_ctx->get_generator();
    pp.h = derive_generator("taihang/attema-cramer-fehr/base-h", *pp.group_ctx);
    pp.vector_g = std::vector<ECPoint>(2 * statement_count - threshold, ECPoint(pp.group_ctx));
    for (std::size_t i = 0; i < pp.vector_g.size(); ++i) {
        pp.vector_g[i] = derive_generator(
            "taihang/attema-cramer-fehr/vector-g/" + std::to_string(i), *pp.group_ctx);
    }
    return pp;
}

bool Proof::operator==(const Proof& other) const {
    return p == other.p && amortized_homomorphism == other.amortized_homomorphism;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    return os << proof.p << proof.amortized_homomorphism;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    is >> proof.p;
    if (is) {
        is >> proof.amortized_homomorphism;
    }
    return is;
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    TAIHANG_ASSERT(valid_dimensions(pp), "ACF parameter dimensions mismatch");
    TAIHANG_ASSERT(statement.points.size() == pp.statement_count,
                   "ACF statement length mismatch");
    TAIHANG_ASSERT(witness.indices.size() == pp.threshold &&
                       witness.secrets.size() == pp.threshold,
                   "ACF witness length mismatch");

    std::vector<bool> selected(pp.statement_count, false);
    for (const std::size_t index : witness.indices) {
        TAIHANG_ASSERT(index < pp.statement_count, "ACF witness index out of range");
        TAIHANG_ASSERT(!selected[index], "ACF witness indices must be distinct");
        selected[index] = true;
    }
    const ScalarVector coefficients = selection_polynomial(pp, selected);
    const std::size_t degree = pp.statement_count - pp.threshold;
    const ZnElement zero = pp.ring_ctx->get_zero();
    ScalarVector y(2 * pp.statement_count, zero);
    for (std::size_t i = 0; i < degree; ++i) {
        y[i] = coefficients[i + 1];
    }
    for (std::size_t i = 0; i < pp.threshold; ++i) {
        const std::size_t index = witness.indices[i];
        const ZnElement x(pp.ring_ctx, BigInt(uint64_t{index + 1}));
        y[degree + index] = witness.secrets[i] * evaluate_polynomial(coefficients, x);
    }

    // q(j+1)=0 off S; on S, g*(x_j*q(j+1))=c_j*q(j+1).
    // Commit to q's nonconstant coefficients and these weighted secrets.
    const ZnElement tau = pp.ring_ctx->gen_random();
    const auto amortized_pp = amortized_parameters(pp);
    Proof proof{
        ec_point_msm(amortized_pp.vector_g, y) + pp.h * tau,
        {ECPoint(pp.group_ctx), ECPoint(pp.group_ctx), ZnElement(pp.ring_ctx),
         {{}, {}, {}, {}, ZnElement(pp.ring_ctx)}}
    };
    const amortized::Statement amortized_statement{proof.p, statement.points};
    proof.amortized_homomorphism = amortized::prove(
        amortized_pp, amortized_statement, {std::move(y), tau},
        parent_context(pp, statement, proof.p, context));
    return proof;
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
    if (!valid_dimensions(pp) || statement.points.size() != pp.statement_count ||
        proof.amortized_homomorphism.equality_proof.left_g.size() != pp.rounds ||
        proof.amortized_homomorphism.equality_proof.right_g.size() != pp.rounds ||
        proof.amortized_homomorphism.equality_proof.left_p.size() != pp.rounds ||
        proof.amortized_homomorphism.equality_proof.right_p.size() != pp.rounds) {
        return false;
    }
    const auto amortized_pp = amortized_parameters(pp);
    const amortized::Statement amortized_statement{proof.p, statement.points};
    return amortized::verify(
        amortized_pp, amortized_statement, proof.amortized_homomorphism,
        parent_context(pp, statement, proof.p, context));
}

} // namespace taihang::zkp::k_out_of_n::attema_cramer_fehr
