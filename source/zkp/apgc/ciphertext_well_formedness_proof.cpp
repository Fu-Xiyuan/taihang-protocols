/****************************************************************************
 * @file      ciphertext_well_formedness_proof.cpp
 * @brief     APGC well-formedness proof implementation.
 *****************************************************************************/

#include <taihang/zkp/apgc/ciphertext_well_formedness_proof.hpp>

#include <istream>
#include <ostream>

#include <taihang/common/check.hpp>

namespace taihang::zkp::apgc::ciphertext_well_formedness {
namespace {

/** Include the blinding term in the vector MSM. */
ECPoint commit_vector(const std::vector<ECPoint>& g,
                      const ECPoint& u,
                      const std::vector<ZnElement>& a,
                      const ZnElement& r) {
    std::vector<const ECPoint*> points(g.size() + 1, nullptr);
    std::vector<ZnElement> scalars = a;
    for (std::size_t i = 0; i < g.size(); ++i) {
        points[i] = &g[i];
    }
    points.back() = &u;
    scalars.push_back(r);
    return ec_point_msm(points, scalars);
}

} // namespace

PublicParameters setup(const pke::twisted_elgamal::PublicParameters& encryption,
                       std::size_t count) {
    return ciphertext_homomorphism::setup(encryption, count);
}

bool Proof::operator==(const Proof& other) const {
    return p == other.p && evaluation == other.evaluation;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    return os << proof.p << proof.evaluation;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    is >> proof.p;
    if (is) {
        is >> proof.evaluation;
    }
    return is;
}

Proof initialize_proof(const PublicParameters& pp) {
    return {
        ECPoint(pp.encryption.group_ctx),
        ciphertext_homomorphism::initialize_proof(pp)
    };
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    TAIHANG_ASSERT(witness.values.size() == pp.participant_count &&
                       witness.randomness.size() == pp.participant_count,
                   "well-formedness witness length mismatch");
    std::vector<ZnElement> a = witness.randomness;
    a.insert(a.end(), witness.values.begin(), witness.values.end());
    const ZnElement r = pp.encryption.ring_ctx->gen_random();
    Proof proof = ciphertext_well_formedness::initialize_proof(pp);
    proof.p = commit_vector(pp.commitment.vector_g, pp.commitment.u, a, r);
    proof.evaluation = ciphertext_homomorphism::prove(
        pp,
        {proof.p, statement.public_keys, statement.transfers},
        {a, r},
        context);
    return proof;
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
    return ciphertext_homomorphism::verify(
        pp,
        {proof.p, statement.public_keys, statement.transfers},
        proof.evaluation,
        context);
}
} // namespace taihang::zkp::apgc::ciphertext_well_formedness
