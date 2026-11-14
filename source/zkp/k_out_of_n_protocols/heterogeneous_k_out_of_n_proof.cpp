/****************************************************************************
 * @file      heterogeneous_k_out_of_n_proof.cpp
 * @brief     Heterogeneous partial knowledge proof implementation.
 *****************************************************************************/

#include <taihang/zkp/k_out_of_n_protocols/heterogeneous_k_out_of_n_proof.hpp>

#include <openssl/obj_mac.h>

#include <cstdint>
#include <ios>
#include <istream>
#include <limits>
#include <ostream>
#include <sstream>
#include <string>

#include <taihang/common/check.hpp>
#include <taihang/utility/arithmetic.hpp>

namespace taihang::zkp::k_out_of_n::heterogeneous {
namespace {

using ScalarVector = std::vector<ZnElement>;
namespace binary = taihang::zkp::nizk::fixed_weight_binary_vector;
namespace evaluation = taihang::zkp::nizk::homomorphism_evaluation;

bool parameter_dimensions(const PublicParameters& pp) {
    const auto& cp = pp.commitment;
    const auto& bp = pp.selection;
    return taihang::arithmetic::is_pow2(pp.statement_count) &&
        pp.threshold > 0 && pp.threshold <= pp.statement_count &&
        pp.opening_length > 0 && pp.output_length > 0 &&
        pp.opening_length <= std::numeric_limits<std::size_t>::max() / pp.statement_count - 1 &&
        pp.output_length < std::numeric_limits<std::size_t>::max() / pp.opening_length &&
        pp.statement_count <= cp.vector_length &&
        pp.opening_length * pp.statement_count <= cp.vector_length - pp.statement_count &&
        cp.vector_length > 0 && taihang::arithmetic::is_pow2(cp.vector_length) &&
        cp.rounds < sizeof(std::size_t) * 8 && (std::size_t{1} << cp.rounds) == cp.vector_length &&
        cp.vector_g.size() == cp.vector_length &&
        bp.vector_length == pp.statement_count && bp.vector_g.size() == pp.statement_count &&
        bp.vector_h.size() == pp.statement_count && bp.rounds < sizeof(std::size_t) * 8 &&
        (std::size_t{1} << bp.rounds) == pp.statement_count &&
        bp.group_ctx == cp.group_ctx && bp.ring_ctx == cp.ring_ctx;
}

evaluation::PublicParameters consistency_parameters(const PublicParameters& pp) {
    auto bases = pp.commitment.vector_g;
    for (std::size_t j = 0; j < pp.statement_count; ++j) {
        bases[j] = pp.selection.vector_h[j];
    }
    return evaluation::setup(pp.commitment.group_ctx, pp.commitment.ring_ctx, pp.selection.u, bases);
}

/** Batch the n maps with powers of rho, keeping output coordinates separate. */
std::vector<std::vector<ECPoint>> relation_bases(const PublicParameters& pp,
                                                const Statement& statement,
                                                const std::string& transcript) {
    const auto& cp = pp.commitment;
    ZnElement rho = hash_to_zn(transcript, *cp.ring_ctx);
    if (rho.value.is_zero()) {
        rho = cp.ring_ctx->get_one();
    }
    std::vector<std::vector<ECPoint>> rows(pp.output_length,
        std::vector<ECPoint>(cp.vector_length, cp.group_ctx->get_infinity()));
    ZnElement power = cp.ring_ctx->get_one();
    for (std::size_t j = 0; j < pp.statement_count; ++j) {
        for (std::size_t q = 0; q < pp.output_length; ++q) {
            rows[q][j] = statement.outputs[j][q] * (-power);
            for (std::size_t a = 0; a < pp.opening_length; ++a) {
                rows[q][pp.statement_count + j * pp.opening_length + a] =
                    statement.bases[j][q * pp.opening_length + a] * power;
            }
        }
        power *= rho;
    }
    return rows;
}

} // namespace

PublicParameters setup(int curve_id, std::size_t statement_count, std::size_t threshold,
                       std::size_t opening_length, std::size_t output_length) {
    TAIHANG_ASSERT(taihang::arithmetic::is_pow2(statement_count) && threshold > 0 &&
                       threshold <= statement_count, "heterogeneous invalid count or threshold");
    TAIHANG_ASSERT(opening_length > 0 && output_length > 0 &&
        opening_length <= std::numeric_limits<std::size_t>::max() / statement_count - 1 &&
        output_length < std::numeric_limits<std::size_t>::max() / opening_length,
        "heterogeneous invalid map dimensions");
    const std::size_t raw = statement_count * (opening_length + 1);
    std::size_t padded = 1;
    while (padded < raw) {
        TAIHANG_ASSERT(padded <= std::numeric_limits<std::size_t>::max() / 4,
                       "heterogeneous padded length overflow");
        padded *= 2;
    }
    PublicParameters pp;
    pp.statement_count = statement_count;
    pp.threshold = threshold;
    pp.opening_length = opening_length;
    pp.output_length = output_length;
    pp.selection = binary::setup(curve_id, statement_count);
    const auto& bp = pp.selection;
    auto bases = std::vector<ECPoint>(padded, bp.group_ctx->get_infinity());
    for (std::size_t j = 0; j < statement_count; ++j) {
        bases[j] = bp.vector_g[j];
    }
    for (std::size_t i = statement_count; i < raw; ++i) {
        const std::string label = "taihang/heterogeneous/opening/" + std::to_string(i);
        if (curve_id == NID_X9_62_prime256v1) {
            bases[i] = hash_to_curve_standard(label,
                "TAIHANG-PROTOCOLS-V01-P256_XMD:SHA-256_SSWU_RO_", *bp.group_ctx);
        } else {
            bases[i] = hash_to_curve_fast(label, *bp.group_ctx);
        }
    }
    pp.commitment = evaluation::setup(bp.group_ctx, bp.ring_ctx, bp.u, bases);
    return pp;
}

bool Proof::operator==(const Proof& other) const {
    return p == other.p && s == other.s && selection == other.selection &&
           consistency == other.consistency && evaluations == other.evaluations;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    os << proof.p << proof.s << proof.selection << proof.consistency;
    const std::uint64_t count = proof.evaluations.size();
    os.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (const auto& evaluation : proof.evaluations) {
        os << evaluation;
    }
    return os;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    is >> proof.p >> proof.s;
    if (is) {
        is >> proof.selection;
    }
    if (is) {
        is >> proof.consistency;
    }
    std::uint64_t count = 0;
    if (!is.read(reinterpret_cast<char*>(&count), sizeof(count))) {
        return is;
    }
    if (count != proof.evaluations.size()) {
        is.setstate(std::ios::failbit);
        return is;
    }
    for (auto& evaluation : proof.evaluations) {
        if (!(is >> evaluation)) {
            return is;
        }
    }
    return is;
}

Proof prove(const PublicParameters& pp, const Statement& statement,
            const Witness& witness, std::string_view context) {
    TAIHANG_ASSERT(detail::valid_statement(pp, statement), "heterogeneous statement dimensions mismatch");
    const auto state = detail::prepare(pp, witness);
    return detail::prove_prepared(pp, statement, state, context);
}

bool verify(const PublicParameters& pp, const Statement& statement,
            const Proof& proof, std::string_view context) {
    return detail::verify_extended(pp, statement, proof, context);
}

namespace detail {

bool valid_parameters(const PublicParameters& pp) {
    return parameter_dimensions(pp);
}

bool valid_statement(const PublicParameters& pp, const Statement& statement) {
    if (!valid_parameters(pp) || statement.bases.size() != pp.statement_count ||
        statement.outputs.size() != pp.statement_count) {
        return false;
    }
    for (std::size_t j = 0; j < pp.statement_count; ++j) {
        if (statement.bases[j].size() != pp.output_length * pp.opening_length ||
            statement.outputs[j].size() != pp.output_length) {
            return false;
        }
    }
    return true;
}

ProverState prepare(const PublicParameters& pp, const Witness& witness) {
    TAIHANG_ASSERT(valid_parameters(pp), "heterogeneous parameter dimensions mismatch");
    TAIHANG_ASSERT(witness.indices.size() == pp.threshold && witness.openings.size() == pp.threshold,
                   "heterogeneous witness length mismatch");
    const auto& cp = pp.commitment;
    const auto zero = cp.ring_ctx->get_zero();
    const auto one = cp.ring_ctx->get_one();
    ProverState state{ScalarVector(cp.vector_length, zero), ScalarVector(pp.statement_count, zero),
        ScalarVector(pp.statement_count, -one), cp.ring_ctx->gen_random(), cp.ring_ctx->gen_random(),
        ECPoint(cp.group_ctx), ECPoint(cp.group_ctx)};
    std::vector<bool> used(pp.statement_count, false);
    for (std::size_t i = 0; i < pp.threshold; ++i) {
        const auto j = witness.indices[i];
        TAIHANG_ASSERT(j < pp.statement_count, "heterogeneous index out of range");
        TAIHANG_ASSERT(!used[j], "heterogeneous indices must be distinct");
        TAIHANG_ASSERT(witness.openings[i].size() == pp.opening_length,
                       "heterogeneous opening length mismatch");
        used[j] = true;
        state.y[j] = one;
        state.selection[j] = one;
        state.complement[j] = zero;
        for (std::size_t a = 0; a < pp.opening_length; ++a) {
            state.y[pp.statement_count + j * pp.opening_length + a] = witness.openings[i][a];
        }
    }
    state.p = ec_point_msm(cp.vector_g, state.y) + cp.u * state.r_p;
    state.s = ec_point_msm(pp.selection.vector_g, state.selection) +
        ec_point_msm(pp.selection.vector_h, state.complement) + cp.u * state.r_s;
    return state;
}

std::string binding_context(const PublicParameters& pp, const Statement& statement,
                             const ECPoint& p, const ECPoint& s, std::string_view context) {
    std::ostringstream transcript;
    transcript << "taihang/heterogeneous-k-out-of-n/v1" << BigInt(uint64_t{context.size()});
    transcript.write(context.data(), static_cast<std::streamsize>(context.size()));
    transcript << BigInt(uint64_t{pp.statement_count}) << BigInt(uint64_t{pp.threshold})
               << BigInt(uint64_t{pp.opening_length}) << BigInt(uint64_t{pp.output_length})
               << BigInt(static_cast<uint64_t>(pp.selection.curve_id))
               << pp.selection.g << pp.selection.h << pp.selection.u << pp.selection.inner_product_u;
    for (const auto* bases : {&pp.selection.vector_g, &pp.selection.vector_h, &pp.commitment.vector_g}) {
        for (const auto& base : *bases) {
            transcript << base;
        }
    }
    for (std::size_t j = 0; j < pp.statement_count; ++j) {
        for (const auto& base : statement.bases[j]) {
            transcript << base;
        }
        for (const auto& output : statement.outputs[j]) {
            transcript << output;
        }
    }
    transcript << p << s;
    return transcript.str();
}

Proof prove_prepared(const PublicParameters& pp, const Statement& statement,
                     const ProverState& state, std::string_view context,
                     const std::vector<ECPoint>* bridge_bases, const ECPoint* bridge_target) {
    TAIHANG_ASSERT(valid_statement(pp, statement), "heterogeneous statement dimensions mismatch");
    TAIHANG_ASSERT((bridge_bases == nullptr) == (bridge_target == nullptr), "heterogeneous bridge mismatch");
    const std::string parent = binding_context(pp, statement, state.p, state.s, context);
    Proof proof;
    proof.p = state.p;
    proof.s = state.s;
    proof.selection = binary::prove(pp.selection, {state.s, pp.threshold},
                                    {state.selection, state.complement, state.r_s}, parent);
    const auto projection = consistency_parameters(pp);
    auto difference = state.y;
    for (std::size_t j = 0; j < pp.statement_count; ++j) {
        difference[j] = pp.commitment.ring_ctx->get_one() - state.selection[j];
    }
    proof.consistency = evaluation::prove(projection,
        {state.p - state.s, pp.commitment.group_ctx->get_infinity(),
         std::vector<ECPoint>(projection.vector_length, pp.commitment.group_ctx->get_infinity())},
        {difference, state.r_p - state.r_s}, parent);
    auto rows = relation_bases(pp, statement, parent);
    if (bridge_bases) {
        rows.push_back(*bridge_bases);
    }
    for (std::size_t q = 0; q < rows.size(); ++q) {
        const auto target = q == pp.output_length ? *bridge_target : pp.commitment.group_ctx->get_infinity();
        proof.evaluations.push_back(evaluation::prove(pp.commitment, {state.p, target, rows[q]},
            {state.y, state.r_p}, parent + "/output/" + std::to_string(q)));
    }
    return proof;
}

bool verify_extended(const PublicParameters& pp, const Statement& statement,
                      const Proof& proof, std::string_view context,
                      const std::vector<ECPoint>* bridge_bases, const ECPoint* bridge_target) {
    if (!valid_statement(pp, statement) || (bridge_bases == nullptr) != (bridge_target == nullptr) ||
        proof.evaluations.size() != pp.output_length + (bridge_bases ? 1 : 0)) {
        return false;
    }
    const std::string parent = binding_context(pp, statement, proof.p, proof.s, context);
    if (!binary::verify(pp.selection, {proof.s, pp.threshold}, proof.selection, parent)) {
        return false;
    }
    const auto projection = consistency_parameters(pp);
    if (!evaluation::verify(projection,
        {proof.p - proof.s, pp.commitment.group_ctx->get_infinity(),
         std::vector<ECPoint>(projection.vector_length, pp.commitment.group_ctx->get_infinity())},
        proof.consistency, parent)) {
        return false;
    }
    auto rows = relation_bases(pp, statement, parent);
    if (bridge_bases) {
        rows.push_back(*bridge_bases);
    }
    for (std::size_t q = 0; q < rows.size(); ++q) {
        const auto target = q == pp.output_length ? *bridge_target : pp.commitment.group_ctx->get_infinity();
        if (!evaluation::verify(pp.commitment, {proof.p, target, rows[q]}, proof.evaluations[q],
            parent + "/output/" + std::to_string(q))) {
            return false;
        }
    }
    return true;
}

} // namespace detail
} // namespace taihang::zkp::k_out_of_n::heterogeneous
