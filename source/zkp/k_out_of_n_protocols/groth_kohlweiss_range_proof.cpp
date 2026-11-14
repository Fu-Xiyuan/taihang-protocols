/****************************************************************************
 * @file      groth_kohlweiss_range_proof.cpp
 * @brief     GK range proof implementation using a hidden aggregate.
 *****************************************************************************/

#include <taihang/zkp/k_out_of_n_protocols/groth_kohlweiss_range_proof.hpp>

#include <cstdint>
#include <istream>
#include <ostream>
#include <sstream>
#include <utility>

#include <taihang/common/check.hpp>

namespace taihang::zkp::k_out_of_n::groth_kohlweiss_range {
namespace {
namespace subset = taihang::zkp::nizk::subset_aggregation;
namespace range = taihang::zkp::nizk::aggregate_range;

bool compatible_parameters(const PublicParameters& pp) {
    return pp.range.vector_g.size() == pp.range.vector_length &&
        pp.range.vector_h.size() == pp.range.vector_length &&
        pp.range.value_count == pp.subset.threshold &&
        pp.range.group_ctx == pp.subset.group_ctx && pp.range.ring_ctx == pp.subset.ring_ctx &&
        pp.range.g == pp.subset.g && pp.range.h == pp.subset.h && pp.range.u == pp.subset.u;
}

std::string parent_context(const PublicParameters& pp, std::string_view context) {
    std::ostringstream transcript;
    transcript << "taihang/groth-kohlweiss-range/v1" << BigInt(uint64_t{context.size()});
    transcript.write(context.data(), static_cast<std::streamsize>(context.size()));
    transcript << BigInt(uint64_t{pp.range.range_bits}) << BigInt(uint64_t{pp.range.value_count});
    for (std::size_t i = 0; i < pp.range.vector_g.size(); ++i) {
        transcript << pp.range.vector_g[i] << pp.range.vector_h[i];
    }
    return transcript.str();
}

std::string range_context(const subset::Proof& proof, std::string_view parent) {
    std::ostringstream transcript;
    transcript.write(parent.data(), static_cast<std::streamsize>(parent.size()));
    transcript << proof;
    return transcript.str();
}

/** The bounded values must be committed before the subset weights e^i are chosen. */
std::string subset_context(const PublicParameters& pp, const ECPoint& a,
                           const ECPoint& s, std::string_view context) {
    std::ostringstream transcript;
    transcript << parent_context(pp, context) << a << s;
    return transcript.str();
}
} // namespace

PublicParameters setup(int curve_id, std::size_t statement_count, std::size_t threshold,
                       std::size_t range_bits) {
    PublicParameters pp;
    pp.subset = subset::setup(curve_id, statement_count, threshold);
    pp.range = range::setup(pp.subset.group_ctx, pp.subset.ring_ctx, range_bits,
                            threshold, pp.subset.g, pp.subset.h, pp.subset.u);
    return pp;
}

bool Proof::operator==(const Proof& other) const {
    return subset == other.subset && range == other.range;
}
std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    return os << proof.subset << proof.range;
}
std::istream& operator>>(std::istream& is, Proof& proof) {
    is >> proof.subset;
    if (is) {
        is >> proof.range;
    }
    return is;
}

Proof prove(const PublicParameters& pp, const Statement& statement,
            const Witness& witness, std::string_view context) {
    TAIHANG_ASSERT(compatible_parameters(pp), "GK range incompatible parameters");
    TAIHANG_ASSERT(witness.values.size() == pp.subset.threshold, "GK range witness length mismatch");
    auto range_state = range::detail::prepare(pp.range, witness.values);
    const auto parent = subset_context(pp, range_state.a, range_state.s, context);
    Proof proof;
    proof.subset = subset::prove(pp.subset, {statement.commitments},
                                 {witness.indices, witness.randomness}, parent);
    const auto aggregate = subset::detail::aggregate(pp.subset, {statement.commitments}, proof.subset, parent);
    proof.range = range::detail::prove_prepared(pp.range, {aggregate.commitment, aggregate.weights},
        proof.subset.z_g * aggregate.normalization, std::move(range_state), range_context(proof.subset, parent));
    return proof;
}

bool verify(const PublicParameters& pp, const Statement& statement,
            const Proof& proof, std::string_view context) {
    if (!compatible_parameters(pp)) {
        return false;
    }
    const auto parent = subset_context(pp, proof.range.a, proof.range.s, context);
    if (!subset::verify(pp.subset, {statement.commitments}, proof.subset, parent)) {
        return false;
    }
    const auto aggregate = subset::detail::aggregate(pp.subset, {statement.commitments}, proof.subset, parent);
    return range::verify(pp.range, {aggregate.commitment, aggregate.weights}, proof.range,
                          range_context(proof.subset, parent));
}
} // namespace taihang::zkp::k_out_of_n::groth_kohlweiss_range
