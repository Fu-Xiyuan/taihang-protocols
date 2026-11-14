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
bool extend_statement(const PublicParameters& pp, const Statement& statement, Statement& result) {
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

std::string parent_context(const PublicParameters& pp, std::string_view context) {
    std::ostringstream transcript;
    transcript << "taihang/heterogeneous-range/v1" << BigInt(uint64_t{context.size()});
    transcript.write(context.data(), static_cast<std::streamsize>(context.size()));
    transcript << BigInt(uint64_t{pp.range.range_bits});
    for (std::size_t i = 0; i < pp.range.vector_g.size(); ++i) {
        transcript << pp.range.vector_g[i] << pp.range.vector_h[i];
    }
    return transcript.str();
}

std::vector<ECPoint> bridge_bases(const PublicParameters& pp, const std::vector<ZnElement>& weights) {
    std::vector<ECPoint> bases(pp.core.commitment.vector_length, pp.range.group_ctx->get_infinity());
    for (std::size_t j = 0; j < pp.core.statement_count; ++j) {
        const std::size_t index = pp.core.statement_count + j * pp.core.opening_length;
        bases[index] = pp.range.h * weights[j];
        bases[index + pp.core.opening_length - 1] = pp.range.g * weights[j];
    }
    return bases;
}
} // namespace

PublicParameters setup(int curve_id, std::size_t statement_count, std::size_t threshold,
                       std::size_t opening_length, std::size_t output_length, std::size_t range_bits) {
    TAIHANG_ASSERT(opening_length > 0 && opening_length + 1 > opening_length,
                   "heterogeneous range invalid opening length");
    PublicParameters pp;
    pp.core = heterogeneous::setup(curve_id, statement_count, threshold, opening_length + 1, output_length);
    const auto& bp = pp.core.selection;
    pp.range = range::setup(bp.group_ctx, bp.ring_ctx, range_bits, statement_count, bp.g, bp.h, bp.u);
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

Proof prove(const PublicParameters& pp, const Statement& statement,
            const Witness& witness, std::string_view context) {
    Statement extended;
    TAIHANG_ASSERT(extend_statement(pp, statement, extended), "heterogeneous range statement dimensions mismatch");
    Witness augmented = witness;
    for (auto& opening : augmented.openings) {
        TAIHANG_ASSERT(opening.size() + 1 == pp.core.opening_length, "heterogeneous range opening length mismatch");
        opening.push_back(pp.range.ring_ctx->gen_random());
    }
    const auto state = heterogeneous::detail::prepare(pp.core, augmented);
    const std::string parent = parent_context(pp, context);
    const auto range_parent = heterogeneous::detail::binding_context(pp.core, extended, state.p, state.s, parent);
    std::vector<ZnElement> values(pp.core.statement_count, pp.range.ring_ctx->get_zero());
    std::vector<ZnElement> randomness(pp.core.statement_count, pp.range.ring_ctx->get_zero());
    for (std::size_t j = 0; j < pp.core.statement_count; ++j) {
        const auto offset = pp.core.statement_count + j * pp.core.opening_length;
        values[j] = state.y[offset];
        randomness[j] = state.y[offset + pp.core.opening_length - 1];
    }
    Proof proof;
    proof.range = range::prove_delayed(pp.range, values, randomness, range_parent);
    const auto weights = range::delayed_weights(pp.range, proof.range, range_parent);
    const auto bases = bridge_bases(pp, weights);
    std::ostringstream full_context;
    full_context << parent << proof.range;
    proof.core = heterogeneous::detail::prove_prepared(pp.core, extended, state, full_context.str(),
                                                       &bases, &proof.range.aggregate);
    return proof;
}

bool verify(const PublicParameters& pp, const Statement& statement,
            const Proof& proof, std::string_view context) {
    Statement extended;
    if (!extend_statement(pp, statement, extended)) {
        return false;
    }
    const std::string parent = parent_context(pp, context);
    const auto range_parent = heterogeneous::detail::binding_context(pp.core, extended, proof.core.p, proof.core.s, parent);
    if (!range::verify_delayed(pp.range, proof.range, range_parent)) {
        return false;
    }
    const auto weights = range::delayed_weights(pp.range, proof.range, range_parent);
    const auto bases = bridge_bases(pp, weights);
    std::ostringstream full_context;
    full_context << parent << proof.range;
    return heterogeneous::detail::verify_extended(pp.core, extended, proof.core, full_context.str(),
                                                   &bases, &proof.range.aggregate);
}
} // namespace taihang::zkp::k_out_of_n::heterogeneous_range
