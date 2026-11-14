/****************************************************************************
 * @file      solvency_proof.cpp
 * @brief     Original Solvent index polynomials, sender linkage and debit ranges.
 *****************************************************************************/

#include <taihang/zkp/apgc/solvency_proof.hpp>

#include <cstdint>
#include <istream>
#include <ostream>
#include <sstream>

#include <taihang/common/check.hpp>

namespace taihang::zkp::apgc::solvency {
namespace {

namespace common = taihang::zkp::apgc::ciphertext_homomorphism::detail;
namespace range = taihang::zkp::range_proofs::bulletproof;
using ScalarVector = std::vector<ZnElement>;

template<class T>
void write_vector(std::ostream& os, const std::vector<T>& values) {
    const std::uint64_t size = values.size();
    os.write(reinterpret_cast<const char*>(&size), sizeof(size));
    for (const T& value : values) {
        os << value;
    }
}

template<class T>
void read_vector(std::istream& is, std::vector<T>& values) {
    std::uint64_t size = 0;
    if (!is.read(reinterpret_cast<char*>(&size), sizeof(size)) || size != values.size()) {
        is.setstate(std::ios::failbit);
        return;
    }
    for (T& value : values) {
        if (!(is >> value)) {
            return;
        }
    }
}

ZnElement challenge(const PublicParameters& pp, const Statement& statement,
                     const Proof& proof, std::string_view context) {
    std::ostringstream transcript;
    transcript << sender_balance::detail::homomorphism_transcript(pp.sender, statement, proof.sender, context)
               << proof.a << proof.c << proof.d;
    return hash_to_zn(transcript.str(), *pp.sender.encryption.ring_ctx);
}

ScalarVector polynomial(const ScalarVector& bits, const ScalarVector& alpha, std::size_t index) {
    const ZnElement one = bits.front().ring_ctx->get_one();
    const ZnElement zero = bits.front().ring_ctx->get_zero();
    ScalarVector result(1, one);
    for (std::size_t b = 0; b < bits.size(); ++b) {
        const bool bit = (index >> b) & 1U;
        const ZnElement constant = bit ? alpha[b] : -alpha[b];
        const ZnElement linear = bit ? bits[b] : one - bits[b];
        ScalarVector next(result.size() + 1, zero);
        for (std::size_t degree = 0; degree < result.size(); ++degree) {
            next[degree] += result[degree] * constant;
            next[degree + 1] += result[degree] * linear;
        }
        result = std::move(next);
    }
    return result;
}

struct Aggregates {
    ECPoint debit;
    ECPoint selection;
    ZnElement normalization;
};

Aggregates aggregate(const PublicParameters& pp, const Statement& statement,
                      const Proof& proof, const ZnElement& x) {
    const std::size_t n = pp.sender.participant_count, m = pp.index_g.size();
    const ScalarVector x_power = common::powers(m + 1, x);
    ECPoint g = pp.sender.encryption.group_ctx->get_infinity();
    ECPoint s = pp.sender.encryption.group_ctx->get_infinity();
    for (std::size_t j = 0; j < n; ++j) {
        ZnElement value = pp.sender.encryption.ring_ctx->get_one();
        for (std::size_t b = 0; b < m; ++b) {
            value *= ((j >> b) & 1U) ? proof.f[b] : x - proof.f[b];
        }
        g = g + statement.transfers[j].c2 * value;
        s = s + (pp.sender.vector_g[j] + pp.sender.vector_h[j]) * value - pp.sender.vector_h[j] * x_power.back();
    }
    for (std::size_t degree = 0; degree < m; ++degree) {
        g = g - proof.c_c[degree] * x_power[degree];
        s = s - proof.c_s[degree] * x_power[degree];
    }
    return {g, s, x_power.back().inv()};
}

} // namespace

PublicParameters setup(const pke::twisted_elgamal::PublicParameters& encryption,
                       std::size_t participant_count) {
    PublicParameters pp;
    pp.sender = sender_balance::setup(encryption, participant_count);
    pp.index_g = common::generators(encryption.group_ctx, common::folding_rounds(participant_count),
                                    "taihang/apgc/solvency/index/");
    pp.values_range = common::range_parameters(encryption, 32, 1, pp.sender.u, "taihang/apgc/solvency/values");
    pp.shifted_range = common::range_parameters(encryption, 32, 1, pp.sender.u, "taihang/apgc/solvency/shifted");
    return pp;
}

bool Proof::operator==(const Proof& other) const {
    return a == other.a && b == other.b && c == other.c && d == other.d &&
        c_c == other.c_c && c_s == other.c_s && f == other.f && z_a == other.z_a && z_c == other.z_c &&
        z_g == other.z_g && z_s == other.z_s && sender == other.sender && values == other.values && shifted == other.shifted;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    os << proof.a << proof.b << proof.c << proof.d;
    write_vector(os, proof.c_c);
    write_vector(os, proof.c_s);
    write_vector(os, proof.f);
    return os << proof.z_a << proof.z_c << proof.z_g << proof.z_s << proof.sender << proof.values << proof.shifted;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    is >> proof.a >> proof.b >> proof.c >> proof.d;
    if (is) {
        read_vector(is, proof.c_c);
    }
    if (is) {
        read_vector(is, proof.c_s);
    }
    if (is) {
        read_vector(is, proof.f);
    }
    if (is) {
        is >> proof.z_a >> proof.z_c >> proof.z_g >> proof.z_s;
    }
    if (is) {
        is >> proof.sender;
    }
    if (is) {
        is >> proof.values;
    }
    if (is) {
        is >> proof.shifted;
    }
    return is;
}

Proof initialize_proof(const PublicParameters& pp) {
    const std::shared_ptr<ECGroup> group = pp.sender.encryption.group_ctx;
    const std::shared_ptr<Zn> ring = pp.sender.encryption.ring_ctx;
    const std::size_t m = pp.index_g.size();
    return {ECPoint(group), ECPoint(group), ECPoint(group), ECPoint(group),
        std::vector<ECPoint>(m, ECPoint(group)), std::vector<ECPoint>(m, ECPoint(group)),
        ScalarVector(m, ZnElement(ring)), ZnElement(ring), ZnElement(ring), ZnElement(ring), ZnElement(ring),
        sender_balance::initialize_proof(pp.sender), common::initialize_range(pp.values_range),
        common::initialize_range(pp.shifted_range)};
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    TAIHANG_ASSERT(sender_balance::detail::valid_statement(pp.sender, statement) &&
        witness.index < pp.sender.participant_count && !witness.secret_key.value.is_zero(),
        "Solvent invalid statement or sender witness");
    const std::size_t n = pp.sender.participant_count, m = pp.index_g.size();
    const std::shared_ptr<Zn> ring = pp.sender.encryption.ring_ctx;
    const ZnElement one = ring->get_one(), zero = ring->get_zero();
    Proof proof = initialize_proof(pp);
    sender_balance::detail::ProverState sender_state{ZnElement(ring)};
    proof.sender = sender_balance::detail::prove_with_state(pp.sender, statement,
        {witness.index, witness.secret_key.inv(), witness.post_balance}, sender_state, context);
    ScalarVector bits(m, zero);
    for (std::size_t b = 0; b < m; ++b) {
        bits[b] = ((witness.index >> b) & 1U) ? one : zero;
    }
    const ZnElement r_b = ring->gen_random(), r_a = ring->gen_random();
    const ZnElement r_c = ring->gen_random(), r_d = ring->gen_random();
    const ScalarVector alpha = gen_random_znelement_vector(ring, m);
    ScalarVector c(m, zero), d(m, zero);
    for (std::size_t b = 0; b < m; ++b) {
        c[b] = alpha[b] * (one - bits[b] - bits[b]);
        d[b] = -alpha[b] * alpha[b];
    }
    proof.b = ec_point_msm(pp.index_g, bits) + pp.sender.u * r_b;
    proof.a = ec_point_msm(pp.index_g, alpha) + pp.sender.u * r_a;
    proof.c = ec_point_msm(pp.index_g, c) + pp.sender.u * r_c;
    proof.d = ec_point_msm(pp.index_g, d) + pp.sender.u * r_d;
    const ZnElement x = challenge(pp, statement, proof, context);
    for (std::size_t b = 0; b < m; ++b) {
        proof.f[b] = bits[b] * x + alpha[b];
    }
    proof.z_a = r_b * x + r_a;
    proof.z_c = r_c * x + r_d;
    std::vector<ScalarVector> coefficients;
    for (std::size_t j = 0; j < n; ++j) {
        coefficients.push_back(polynomial(bits, alpha, j));
    }
    const ScalarVector rho = gen_random_znelement_vector(ring, m);
    const ScalarVector beta = gen_random_znelement_vector(ring, m);
    const ScalarVector x_power = common::powers(m + 1, x);
    proof.z_g = witness.transfer_randomness * x_power.back();
    proof.z_s = sender_state.r_s * x_power.back();
    for (std::size_t degree = 0; degree < m; ++degree) {
        proof.c_c[degree] = pp.sender.encryption.g * rho[degree];
        proof.c_s[degree] = pp.sender.u * beta[degree];
        for (std::size_t j = 0; j < n; ++j) {
            proof.c_c[degree] = proof.c_c[degree] + statement.transfers[j].c2 * coefficients[j][degree];
            proof.c_s[degree] = proof.c_s[degree] + (pp.sender.vector_g[j] + pp.sender.vector_h[j]) * coefficients[j][degree];
        }
        proof.z_g -= rho[degree] * x_power[degree];
        proof.z_s += beta[degree] * x_power[degree];
    }
    const Aggregates selected = aggregate(pp, statement, proof, x);
    const ECPoint commitment = selected.debit * (-selected.normalization);
    const ZnElement tau = -(proof.z_g * selected.normalization);
    proof.values = range::prove(pp.values_range, {{commitment}}, {{tau}, {-witness.transfer_value}});
    proof.shifted = range::prove(pp.shifted_range, {{commitment - pp.sender.encryption.h}},
        {{tau}, {-witness.transfer_value - one}});
    return proof;
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
    const std::size_t m = common::folding_rounds(pp.sender.participant_count);
    if (pp.index_g.size() != m || proof.f.size() != m || proof.c_c.size() != m || proof.c_s.size() != m ||
        !sender_balance::verify(pp.sender, statement, proof.sender, context)) {
        return false;
    }
    const ZnElement x = challenge(pp, statement, proof, context);
    if (!x.is_unit()) {
        return false;
    }
    ScalarVector quadratic(m, pp.sender.encryption.ring_ctx->get_zero());
    for (std::size_t b = 0; b < m; ++b) {
        quadratic[b] = proof.f[b] * (x - proof.f[b]);
    }
    if (proof.b * x + proof.a != ec_point_msm(pp.index_g, proof.f) + pp.sender.u * proof.z_a ||
        proof.c * x + proof.d != ec_point_msm(pp.index_g, quadratic) + pp.sender.u * proof.z_c) {
        return false;
    }
    const Aggregates selected = aggregate(pp, statement, proof, x);
    const ScalarVector x_power = common::powers(m + 1, x);
    if (proof.sender.s * x_power.back() - selected.selection != pp.sender.u * proof.z_s) {
        return false;
    }
    const ECPoint commitment = selected.debit * (-selected.normalization);
    return range::verify(pp.values_range, {{commitment}}, proof.values) &&
        range::verify(pp.shifted_range, {{commitment - pp.sender.encryption.h}}, proof.shifted);
}

} // namespace taihang::zkp::apgc::solvency
