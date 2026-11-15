/****************************************************************************
 * @file      heterogeneous_range_proof.cpp
 * @brief     Delayed aggregate bridge construction for heterogeneous range proofs.
 *****************************************************************************/

#include <taihang/zkp/k_out_of_n_protocols/heterogeneous_range_proof.hpp>

#include <cstdint>
#include <istream>
#include <limits>
#include <ostream>
#include <sstream>
#include <string>

#include <taihang/common/check.hpp>

namespace taihang::zkp::k_out_of_n::heterogeneous_range {
namespace {
namespace range = taihang::zkp::nizk::aggregate_range;

bool compatible_parameters(const PublicParameters& pp) {
    return heterogeneous::detail::valid_parameters(pp.core) &&
        pp.core.opening_length >= 2 && pp.core.output_length > 0 &&
        pp.core.opening_length <= std::numeric_limits<std::size_t>::max() / pp.core.output_length &&
        pp.range.vector_g.size() == pp.range.vector_length &&
        pp.range.vector_h.size() == pp.range.vector_length &&
        pp.range.value_count == pp.core.statement_count &&
        pp.range.group_ctx == pp.core.selection.group_ctx &&
        pp.range.ring_ctx == pp.core.selection.ring_ctx &&
        pp.range.g == pp.core.selection.g && pp.range.h == pp.core.selection.h &&
        pp.range.u == pp.core.selection.u;
}

/** Add an identity column: bridge randomness does not change the public maps. */
bool extend_statement(const PublicParameters& pp,
                      const Statement& statement,
                      Statement& result) {
    if (!compatible_parameters(pp) || statement.bases.size() != pp.core.statement_count ||
        statement.outputs.size() != pp.core.statement_count) {
        return false;
    }
    result.outputs = statement.outputs;
    result.bases.assign(pp.core.statement_count,
        std::vector<ECPoint>(pp.core.opening_length * pp.core.output_length,
                             pp.core.selection.group_ctx->get_infinity()));
    for (std::size_t j = 0; j < pp.core.statement_count; ++j) {
        if (statement.bases[j].size() != (pp.core.opening_length - 1) * pp.core.output_length ||
            statement.outputs[j].size() != pp.core.output_length) {
            return false;
        }
        for (std::size_t q = 0; q < pp.core.output_length; ++q) {
            for (std::size_t a = 0; a + 1 < pp.core.opening_length; ++a) {
                result.bases[j][q * pp.core.opening_length + a] =
                    statement.bases[j][q * (pp.core.opening_length - 1) + a];
            }
        }
    }
    return heterogeneous::detail::valid_statement(pp.core, result);
}

std::string evaluation_context(const PublicParameters& pp,
                               const ECPoint& p,
                               const range::DelayedProof& proof,
                               std::string_view context) {
    std::ostringstream challenges;
    challenges << context << proof.a << proof.s;
    ZnElement z = hash_to_zn(challenges.str(), *pp.range.ring_ctx);
    if (z.value.is_zero()) {
        z = pp.range.ring_ctx->get_one();
    }
    std::ostringstream transcript;
    transcript << context << p << proof.aggregate << z;
    return transcript.str();
}

std::string aggregation_context(const PublicParameters& pp,
                                const Statement& statement,
                                std::string_view prefix) {
    std::ostringstream transcript;
    transcript << prefix << BigInt(uint64_t{pp.core.threshold});
    for (std::size_t j = 0; j < pp.core.statement_count; ++j) {
        for (const ECPoint& base : statement.bases[j]) {
            transcript << base;
        }
        for (const ECPoint& output : statement.outputs[j]) {
            transcript << output;
        }
    }
    return transcript.str();
}

std::vector<ECPoint> bridge_bases(const PublicParameters& pp,
                                  const std::vector<ZnElement>& weights) {
    std::vector<ECPoint> bases(pp.core.commitment.vector_length,
        pp.range.group_ctx->get_infinity());
    for (std::size_t j = 0; j < pp.core.statement_count; ++j) {
        const std::size_t index = pp.core.statement_count + j * pp.core.opening_length;
        bases[index] = pp.range.h * weights[j];
        bases[index + pp.core.opening_length - 1] = pp.range.g * weights[j];
    }
    return bases;
}
} // namespace

PublicParameters setup(int curve_id,
                       std::size_t statement_count,
                       std::size_t threshold,
                       std::size_t opening_length,
                       std::size_t output_length,
                       std::size_t range_bits) {
    TAIHANG_ASSERT(opening_length > 0 && opening_length + 1 > opening_length,
                   "heterogeneous range invalid opening length");
    PublicParameters pp;
    pp.core = heterogeneous::setup(curve_id, statement_count, threshold, opening_length + 1,
        output_length);
    const nizk::fixed_weight_binary_vector::PublicParameters& bp = pp.core.selection;
    pp.range = range::setup(bp.group_ctx, bp.ring_ctx, range_bits, statement_count, bp.g, bp.h,
        bp.u);
    return pp;
}

bool Proof::operator==(const Proof& other) const {
    return core == other.core && range == other.range;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    return os << proof.core << proof.range;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    is >> proof.core;
    if (is) {
        is >> proof.range;
    }
    return is;
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    Statement extended;
    TAIHANG_ASSERT(extend_statement(pp, statement, extended),
        "heterogeneous range statement dimensions mismatch");
    TAIHANG_ASSERT(witness.indices.size() == pp.core.threshold &&
                       witness.openings.size() == pp.core.threshold,
                   "heterogeneous range witness length mismatch");
    TAIHANG_ASSERT(witness.randomness.size() == pp.core.threshold,
                   "heterogeneous range randomness length mismatch");
    heterogeneous::Witness augmented{witness.indices, witness.openings};
    for (std::size_t i = 0; i < augmented.openings.size(); ++i) {
        TAIHANG_ASSERT(augmented.openings[i].size() + 1 == pp.core.opening_length,
                       "heterogeneous range opening length mismatch");
        augmented.openings[i].push_back(witness.randomness[i]);
    }
    const heterogeneous::detail::ProverState state = heterogeneous::detail::prepare(pp.core,
        augmented);
    std::vector<ZnElement> values(pp.core.statement_count, pp.range.ring_ctx->get_zero());
    std::vector<ZnElement> randomness(pp.core.statement_count, pp.range.ring_ctx->get_zero());
    for (std::size_t j = 0; j < pp.core.statement_count; ++j) {
        const std::size_t offset = pp.core.statement_count + j * pp.core.opening_length;
        values[j] = state.y[offset];
        randomness[j] = state.y[offset + pp.core.opening_length - 1];
    }
    Proof proof;
    proof.range = range::prove_delayed(pp.range, values, randomness, context);
    const std::vector<ZnElement> weights = range::delayed_weights(pp.range, proof.range, context);
    const std::vector<ECPoint> bases = bridge_bases(pp, weights);
    const std::string prefix = evaluation_context(pp, state.p, proof.range, context);
    const std::string parent = aggregation_context(pp, statement, prefix);
    proof.core = heterogeneous::detail::prove_prepared(pp.core, extended, state, parent,
        &bases, &proof.range.aggregate, prefix);
    return proof;
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
    Statement extended;
    if (!extend_statement(pp, statement, extended)) {
        return false;
    }
    if (!range::verify_delayed(pp.range, proof.range, context)) {
        return false;
    }
    const std::vector<ZnElement> weights = range::delayed_weights(pp.range, proof.range, context);
    const std::vector<ECPoint> bases = bridge_bases(pp, weights);
    const std::string prefix = evaluation_context(pp, proof.core.p, proof.range, context);
    const std::string parent = aggregation_context(pp, statement, prefix);
    return heterogeneous::detail::verify_extended(pp.core, extended, proof.core, parent,
        &bases, &proof.range.aggregate, prefix);
}
} // namespace taihang::zkp::k_out_of_n::heterogeneous_range
