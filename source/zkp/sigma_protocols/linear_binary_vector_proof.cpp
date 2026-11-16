/****************************************************************************
 * @file      linear_binary_vector_proof.cpp
 * @brief     Linear-size binary-vector proof implementation.
 *****************************************************************************/

#include <taihang/zkp/sigma_protocols/linear_binary_vector_proof.hpp>

#include <openssl/obj_mac.h>

#include <cstdint>
#include <ios>
#include <istream>
#include <limits>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>

#include <taihang/common/check.hpp>

namespace taihang::zkp::nizk::linear_binary_vector {
namespace {

using ScalarVector = std::vector<ZnElement>;

ECPoint derive_generator(const std::string& label, const ECGroup& group) {
    static const std::string kP256Dst =
        "TAIHANG-PROTOCOLS-V01-P256_XMD:SHA-256_SSWU_RO_";

    if (group.curve_id == NID_X9_62_prime256v1) {
        return hash_to_curve_standard(label, kP256Dst, group);
    }
    return hash_to_curve_fast(label, group);
}

bool valid_dimensions(const PublicParameters& pp) {
    return pp.vector_length > 0 &&
           pp.vector_length < std::numeric_limits<std::size_t>::max() &&
           pp.vector_g.size() == pp.vector_length;
}

/** Compute a vector Pedersen commitment with one MSM. */
ECPoint vector_commitment(const PublicParameters& pp,
                          const ScalarVector& values,
                          const ZnElement& randomness) {
    TAIHANG_ASSERT(values.size() == pp.vector_length,
                   "linear-binary-vector commitment length mismatch");
    std::vector<const ECPoint*> points(pp.vector_length + 1, nullptr);
    ScalarVector scalars(pp.vector_length + 1, pp.ring_ctx->get_zero());
    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        points[i] = &pp.vector_g[i];
        scalars[i] = values[i];
    }
    points[pp.vector_length] = &pp.h;
    scalars[pp.vector_length] = randomness;
    return ec_point_msm(points, scalars);
}

/** Derive x from the caller's context followed by A, C, and D. */
ZnElement derive_challenge(const PublicParameters& pp,
                           const Statement& statement,
                           const ECPoint& a,
                           const ECPoint& c,
                           const ECPoint& d,
                           std::string_view context) {
    std::ostringstream transcript;
    transcript.write(context.data(),
                     static_cast<std::streamsize>(context.size()));
    transcript << a << c << d;
    ZnElement x = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (x.value.is_zero()) {
        x = pp.ring_ctx->get_one();
    }
    return x;
}

} // namespace

PublicParameters setup(int curve_id, std::size_t vector_length) {
    TAIHANG_ASSERT(vector_length > 0 &&
                       vector_length < std::numeric_limits<std::size_t>::max(),
                   "linear-binary-vector length must be positive");

    PublicParameters pp;
    pp.curve_id = curve_id;
    pp.vector_length = vector_length;
    pp.group_ctx = std::make_shared<ECGroup>(curve_id);
    pp.ring_ctx = std::make_shared<Zn>(pp.group_ctx->order);
    pp.h = derive_generator("taihang/linear-binary-vector/base-h", *pp.group_ctx);
    pp.vector_g = std::vector<ECPoint>(vector_length, ECPoint(pp.group_ctx));
    for (std::size_t i = 0; i < vector_length; ++i) {
        pp.vector_g[i] = derive_generator(
            "taihang/linear-binary-vector/vector-g/" + std::to_string(i),
            *pp.group_ctx);
    }
    return pp;
}

PublicParameters setup(const std::shared_ptr<ECGroup>& group_ctx,
                       const std::shared_ptr<Zn>& ring_ctx,
                       const ECPoint& h,
                       const std::vector<ECPoint>& vector_g) {
    TAIHANG_ASSERT(group_ctx != nullptr && ring_ctx != nullptr,
                   "linear-binary-vector contexts cannot be null");
    TAIHANG_ASSERT(ring_ctx->modulus == group_ctx->order,
                   "linear-binary-vector scalar modulus mismatch");
    TAIHANG_ASSERT(h.group_ctx == group_ctx.get(),
                   "linear-binary-vector base context mismatch");
    TAIHANG_ASSERT(!h.is_at_infinity(),
                   "linear-binary-vector blinding base cannot be an identity");
    for ([[maybe_unused]] const ECPoint& generator : vector_g) {
        TAIHANG_ASSERT(generator.group_ctx == group_ctx.get(),
                       "linear-binary-vector generator context mismatch");
        TAIHANG_ASSERT(!generator.is_at_infinity(),
                       "linear-binary-vector generators cannot be identities");
    }

    PublicParameters pp;
    pp.curve_id = group_ctx->curve_id;
    pp.vector_length = vector_g.size();
    pp.group_ctx = group_ctx;
    pp.ring_ctx = ring_ctx;
    pp.h = h;
    pp.vector_g = vector_g;
    TAIHANG_ASSERT(valid_dimensions(pp), "linear-binary-vector parameter dimensions mismatch");
    return pp;
}

bool Proof::operator==(const Proof& other) const {
    return a == other.a && c == other.c && d == other.d &&
           f == other.f && z_a == other.z_a && z_c == other.z_c;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    os << proof.a << proof.c << proof.d;
    const std::uint64_t count = static_cast<std::uint64_t>(proof.f.size());
    os.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (const ZnElement& scalar : proof.f) {
        os << scalar;
    }
    return os << proof.z_a << proof.z_c;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    is >> proof.a >> proof.c >> proof.d;
    std::uint64_t count = 0;
    if (!is.read(reinterpret_cast<char*>(&count), sizeof(count))) {
        return is;
    }
    // Reject unexpected lengths without allocating from untrusted input.
    if (count != proof.f.size()) {
        is.setstate(std::ios::failbit);
        return is;
    }
    for (ZnElement& scalar : proof.f) {
        if (!(is >> scalar)) {
            return is;
        }
    }
    is >> proof.z_a >> proof.z_c;
    return is;
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    detail::ProverState state = detail::commit(pp, witness);
    const ZnElement x = derive_challenge(
        pp, statement, state.a, state.c, state.d, context);
    return detail::respond(pp, witness, std::move(state), x);
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
    if (!valid_dimensions(pp) || proof.f.size() != pp.vector_length) {
        return false;
    }
    const ZnElement x = derive_challenge(pp, statement, proof.a, proof.c, proof.d, context);
    return detail::verify_with_challenge(pp, statement, proof, x);
}

namespace detail {

ProverState commit(const PublicParameters& pp, const Witness& witness) {
    TAIHANG_ASSERT(valid_dimensions(pp), "linear-binary-vector parameter dimensions mismatch");
    TAIHANG_ASSERT(witness.a.size() == pp.vector_length,
                   "linear-binary-vector witness length mismatch");

    ProverState state{
        ECPoint(pp.group_ctx), ECPoint(pp.group_ctx), ECPoint(pp.group_ctx),
        gen_random_znelement_vector(pp.ring_ctx, pp.vector_length),
        pp.ring_ctx->gen_random(), pp.ring_ctx->gen_random(), pp.ring_ctx->gen_random()
    };
    const ZnElement zero = pp.ring_ctx->get_zero();
    const ZnElement one = pp.ring_ctx->get_one();
    ScalarVector coefficients_c(pp.vector_length, zero);
    ScalarVector coefficients_d(pp.vector_length, zero);
    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        // f_i*(x-f_i) = x^2*a_i*(1-a_i)
        //                  + x*alpha_i*(1-2*a_i) - alpha_i^2.
        coefficients_c[i] = state.alpha[i] * (one - witness.a[i] - witness.a[i]);
        coefficients_d[i] = -state.alpha[i] * state.alpha[i];
    }
    state.a = vector_commitment(pp, state.alpha, state.r_a);
    state.c = vector_commitment(pp, coefficients_c, state.r_c);
    state.d = vector_commitment(pp, coefficients_d, state.r_d);
    return state;
}

Proof respond(const PublicParameters& pp,
              const Witness& witness,
              ProverState&& state,
              const ZnElement& challenge) {
    TAIHANG_ASSERT(valid_dimensions(pp), "linear-binary-vector parameter dimensions mismatch");
    TAIHANG_ASSERT(witness.a.size() == pp.vector_length &&
                       state.alpha.size() == pp.vector_length,
                   "linear-binary-vector witness or state length mismatch");
    TAIHANG_ASSERT(!challenge.value.is_zero(),
                   "linear-binary-vector challenge must be nonzero");

    Proof proof{
        std::move(state.a), std::move(state.c), std::move(state.d),
        ScalarVector(pp.vector_length, pp.ring_ctx->get_zero()),
        witness.r * challenge + state.r_a,
        state.r_c * challenge + state.r_d
    };
    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        proof.f[i] = witness.a[i] * challenge + state.alpha[i];
    }
    // Invalidate the consumed state; the public proof never contains alpha.
    state.alpha.clear();
    state.r_a = pp.ring_ctx->get_zero();
    state.r_c = pp.ring_ctx->get_zero();
    state.r_d = pp.ring_ctx->get_zero();
    return proof;
}

bool verify_with_challenge(const PublicParameters& pp,
                           const Statement& statement,
                           const Proof& proof,
                           const ZnElement& challenge) {
    if (!valid_dimensions(pp) || proof.f.size() != pp.vector_length ||
        challenge.value.is_zero()) {
        return false;
    }

    // The first equation checks that f opens A + x*P under the same basis.
    const ECPoint opening_left = vector_commitment(pp, proof.f, proof.z_a);
    const ECPoint opening_right =
        ec_point_msm(statement.p, challenge, proof.a, pp.ring_ctx->get_one());
    if (opening_left != opening_right) {
        return false;
    }

    // The second equation removes the quadratic term only for Boolean a_i.
    ScalarVector products(pp.vector_length, pp.ring_ctx->get_zero());
    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        products[i] = proof.f[i] * (challenge - proof.f[i]);
    }
    const ECPoint binary_left = vector_commitment(pp, products, proof.z_c);
    const ECPoint binary_right =
        ec_point_msm(proof.c, challenge, proof.d, pp.ring_ctx->get_one());
    return binary_left == binary_right;
}

} // namespace detail

} // namespace taihang::zkp::nizk::linear_binary_vector
