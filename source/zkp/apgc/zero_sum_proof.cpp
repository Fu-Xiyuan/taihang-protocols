/****************************************************************************
 * @file      zero_sum_proof.cpp
 * @brief     Original APGC SumZero commitment, challenge and response.
 *****************************************************************************/

#include <taihang/zkp/apgc/zero_sum_proof.hpp>

#include <istream>
#include <ostream>
#include <sstream>

#include <taihang/common/check.hpp>

namespace taihang::zkp::apgc::zero_sum {

PublicParameters setup(const pke::twisted_elgamal::PublicParameters& encryption, std::size_t count) {
    TAIHANG_ASSERT(count > 0, "zero-sum participant count must be positive");
    return {encryption, count};
}

bool Proof::operator==(const Proof& other) const {
    return a == other.a && z == other.z;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    return os << proof.a << proof.z;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    return is >> proof.a >> proof.z;
}

Proof initialize_proof(const PublicParameters& pp) {
    return {ECPoint(pp.encryption.group_ctx), ZnElement(pp.encryption.ring_ctx)};
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    TAIHANG_ASSERT(witness.randomness.size() == pp.participant_count, "zero-sum witness length mismatch");
    const ZnElement alpha = pp.encryption.ring_ctx->gen_random();
    Proof proof{pp.encryption.g * alpha, ZnElement(pp.encryption.ring_ctx)};
    std::ostringstream transcript;
    transcript << context << statement.c << proof.a;
    const ZnElement x = hash_to_zn(transcript.str(), *pp.encryption.ring_ctx);
    ZnElement sum = pp.encryption.ring_ctx->get_zero();
    for (const ZnElement& r : witness.randomness) {
        sum += r;
    }
    proof.z = alpha + x * sum;
    return proof;
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
    std::ostringstream transcript;
    transcript << context << statement.c << proof.a;
    const ZnElement x = hash_to_zn(transcript.str(), *pp.encryption.ring_ctx);
    return pp.encryption.g * proof.z == proof.a + statement.c * x;
}

} // namespace taihang::zkp::apgc::zero_sum
