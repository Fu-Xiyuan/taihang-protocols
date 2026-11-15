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
namespace representation = taihang::zkp::nizk::multi_exponentiation;
namespace evaluation = taihang::zkp::nizk::homomorphism_evaluation;

bool parameter_dimensions(const PublicParameters& pp) {
    const evaluation::PublicParameters& cp = pp.commitment;
    const binary::PublicParameters& bp = pp.selection;
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

representation::PublicParameters consistency_parameters(const PublicParameters& pp) {
    std::vector<ECPoint> bases;
    if (pp.opening_length == 1 && pp.output_length == 1) {
        bases = pp.selection.vector_h;
    } else {
        bases = pp.commitment.vector_g;
        for (std::size_t j = 0; j < pp.statement_count; ++j) {
            bases[j] = pp.selection.vector_h[j];
        }
    }
    return representation::setup(pp.commitment.group_ctx, pp.commitment.ring_ctx, bases);
}

/** Batch the n maps with powers of rho, keeping output coordinates separate. */
std::vector<std::vector<ECPoint>> relation_bases(
    const PublicParameters& pp,
    const Statement& statement,
    const std::string& transcript) {
    const evaluation::PublicParameters& cp = pp.commitment;
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
    if (pp.opening_length == 1 && pp.output_length == 1) {
        for (ECPoint& base : rows.front()) {
            base = -base;
        }
    }
    return rows;
}

} // namespace

PublicParameters setup(int curve_id,
                       std::size_t statement_count,
                       std::size_t threshold,
                       std::size_t opening_length,
                       std::size_t output_length) {
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
    const binary::PublicParameters& bp = pp.selection;
    std::vector<ECPoint> bases = std::vector<ECPoint>(padded, bp.group_ctx->get_infinity());
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
    if (opening_length == 1 && output_length == 1) {
        for (std::size_t j = 0; j < statement_count; ++j) {
            bases[statement_count + j] = bp.vector_h[j];
        }
    }
    pp.commitment = evaluation::setup(bp.group_ctx, bp.ring_ctx, bp.u, bases);
    return pp;
}

bool Proof::operator==(const Proof& other) const {
    return p == other.p && s == other.s && selection == other.selection && a_x == other.a_x &&
        f == other.f &&
           consistency == other.consistency && evaluations == other.evaluations;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    os << proof.p << proof.s << proof.a_x << proof.f << proof.selection << proof.consistency;
    const std::uint64_t count = proof.evaluations.size();
    os.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (const evaluation::Proof& evaluation : proof.evaluations) {
        os << evaluation;
    }
    return os;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    is >> proof.p >> proof.s >> proof.a_x >> proof.f;
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
    for (evaluation::Proof& evaluation : proof.evaluations) {
        if (!(is >> evaluation)) {
            return is;
        }
    }
    return is;
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    TAIHANG_ASSERT(detail::valid_statement(pp, statement),
        "heterogeneous statement dimensions mismatch");
    const detail::ProverState state = detail::prepare(pp, witness);
    return detail::prove_prepared(pp, statement, state, context);
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
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
    TAIHANG_ASSERT(witness.indices.size() == pp.threshold &&
        witness.openings.size() == pp.threshold,
                   "heterogeneous witness length mismatch");
    const evaluation::PublicParameters& cp = pp.commitment;
    const ZnElement zero = cp.ring_ctx->get_zero();
    const ZnElement one = cp.ring_ctx->get_one();
    ProverState state{ScalarVector(cp.vector_length, zero), ScalarVector(pp.statement_count, zero),
        ScalarVector(pp.statement_count, -one), cp.ring_ctx->gen_random(),
            cp.ring_ctx->gen_random(),
        ECPoint(cp.group_ctx), ECPoint(cp.group_ctx)};
    std::vector<bool> used(pp.statement_count, false);
    for (std::size_t i = 0; i < pp.threshold; ++i) {
        const std::size_t j = witness.indices[i];
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

std::string binding_context(const PublicParameters& pp,
                            const Statement& statement,
                            const ECPoint& p,
                            const ECPoint& s,
                            std::string_view context) {
    std::ostringstream transcript;
    transcript << context;
    if (pp.opening_length == 1 && pp.output_length == 1) {
        transcript << p;
        for (const std::vector<ECPoint>& output : statement.outputs) {
            transcript << output.front();
        }
    }
    return transcript.str();
}

Proof prove_prepared(const PublicParameters& pp,
                     const Statement& statement,
                     const ProverState& state,
                     std::string_view context,
                     const std::vector<ECPoint>* bridge_bases,
                     const ECPoint* bridge_target,
                     std::string_view evaluation_context) {
    TAIHANG_ASSERT(valid_statement(pp, statement), "heterogeneous statement dimensions mismatch");
    TAIHANG_ASSERT((bridge_bases == nullptr) == (bridge_target == nullptr),
        "heterogeneous bridge mismatch");
    const std::string parent = binding_context(pp, statement, state.p, state.s, context);
    Proof proof;
    proof.p = state.p;
    proof.s = state.s;
    proof.selection = binary::prove(pp.selection, {state.s, pp.threshold},
                                    {state.selection, state.complement, state.r_s});
    const representation::PublicParameters projection = consistency_parameters(pp);
    ScalarVector difference;
    if (pp.opening_length == 1 && pp.output_length == 1) {
        difference.resize(pp.statement_count, pp.commitment.ring_ctx->get_zero());
        for (std::size_t j = 0; j < pp.statement_count; ++j) {
            difference[j] = state.y[pp.statement_count + j] +
                pp.commitment.ring_ctx->get_one() - state.selection[j];
        }
    } else {
        difference = state.y;
        for (std::size_t j = 0; j < pp.statement_count; ++j) {
            difference[j] = pp.commitment.ring_ctx->get_one() - state.selection[j];
        }
    }
    const ScalarVector alpha = gen_random_znelement_vector(
        pp.commitment.ring_ctx, projection.vector_length);
    const ZnElement beta = pp.commitment.ring_ctx->gen_random();
    proof.a_x = ec_point_msm(projection.g, alpha) + pp.selection.u * beta;
    std::ostringstream transcript;
    transcript << proof.a_x;
    const ZnElement e = hash_to_zn(transcript.str(), *pp.commitment.ring_ctx);
    proof.f = beta + e * (state.r_p - state.r_s);
    ScalarVector response = alpha;
    for (std::size_t i = 0; i < response.size(); ++i) {
        response[i] += e * difference[i];
    }
    proof.consistency = representation::prove(projection,
        {(state.p - state.s) * e + proof.a_x - pp.selection.u * proof.f},
        {response});
    std::vector<std::vector<ECPoint>> rows = relation_bases(pp, statement, parent);
    if (bridge_bases) {
        rows.push_back(*bridge_bases);
    }
    for (std::size_t q = 0; q < rows.size(); ++q) {
        const ECPoint target =
            q == pp.output_length ? *bridge_target : pp.commitment.group_ctx->get_infinity();
        std::string mask_context(evaluation_context.empty() ? context : evaluation_context);
        std::ostringstream suffix;
        if (bridge_bases) {
            suffix << BigInt(uint64_t{q});
        }
        proof.evaluations.push_back(evaluation::detail::prove_with_transcript(
            pp.commitment, {state.p, target, rows[q]}, {state.y, state.r_p},
            mask_context, true, suffix.str()));
    }
    return proof;
}

bool verify_extended(const PublicParameters& pp,
                     const Statement& statement,
                     const Proof& proof,
                     std::string_view context,
                     const std::vector<ECPoint>* bridge_bases,
                     const ECPoint* bridge_target,
                     std::string_view evaluation_context) {
    if (!valid_statement(pp,
        statement) || (bridge_bases == nullptr) != (bridge_target == nullptr) ||
        proof.evaluations.size() != pp.output_length + (bridge_bases ? 1 : 0)) {
        return false;
    }
    const std::string parent = binding_context(pp, statement, proof.p, proof.s, context);
    if (!binary::verify(pp.selection, {proof.s, pp.threshold}, proof.selection)) {
        return false;
    }
    const representation::PublicParameters projection = consistency_parameters(pp);
    std::ostringstream transcript;
    transcript << proof.a_x;
    const ZnElement e = hash_to_zn(transcript.str(), *pp.commitment.ring_ctx);
    if (!representation::verify(projection,
        {(proof.p - proof.s) * e + proof.a_x - pp.selection.u * proof.f},
        proof.consistency)) {
        return false;
    }
    std::vector<std::vector<ECPoint>> rows = relation_bases(pp, statement, parent);
    if (bridge_bases) {
        rows.push_back(*bridge_bases);
    }
    for (std::size_t q = 0; q < rows.size(); ++q) {
        const ECPoint target =
            q == pp.output_length ? *bridge_target : pp.commitment.group_ctx->get_infinity();
        std::string mask_context(evaluation_context.empty() ? context : evaluation_context);
        std::ostringstream suffix;
        if (bridge_bases) {
            suffix << BigInt(uint64_t{q});
        }
        if (!evaluation::detail::verify_with_transcript(pp.commitment,
            {proof.p, target, rows[q]}, proof.evaluations[q], mask_context,
            true, suffix.str())) {
            return false;
        }
    }
    return true;
}

} // namespace detail
} // namespace taihang::zkp::k_out_of_n::heterogeneous
