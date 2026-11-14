#include <gtest/gtest.h>

#include <sstream>
#include <openssl/obj_mac.h>

#include <taihang/zkp/apgc/inactive_participant_proof.hpp>

namespace {
using namespace taihang;
namespace protocol = taihang::zkp::apgc::inactive_participant;
namespace encryption = taihang::pke::twisted_elgamal;

class APGCInactiveParticipantTest : public ::testing::Test {
protected:
    APGCInactiveParticipantTest() : enc(encryption::setup(NID_X9_62_prime256v1, 8)), pp(protocol::setup(enc, 4)) {
        for (std::size_t j = 0; j < 4; ++j) {
            const auto key = encryption::keygen(enc);
            keys.push_back(key.first.y);
            secrets.push_back(key.second.x);
            randomness.push_back(enc.ring_ctx->gen_random());
            const auto amount = j == 0 ? -ZnElement(enc.ring_ctx, BigInt(uint64_t{9})) :
                ZnElement(enc.ring_ctx, BigInt(uint64_t{j == 1 ? 0 : j + 2}));
            values.push_back(amount);
            transfers.push_back(encryption::encrypt(enc, key.first, amount, randomness.back()));
            balances.push_back(encryption::encrypt(enc, key.first, ZnElement(enc.ring_ctx, BigInt(uint64_t{100}))));
        }
        for (const auto& ct : transfers) statement.commitments.push_back(ct.c2);
        statement.count = 1;
        witness.bits.assign(4, enc.ring_ctx->get_zero());
        witness.bits[1] = enc.ring_ctx->get_one();
        witness.randomness = {randomness[1]};
    }
    encryption::PublicParameters enc;
    protocol::PublicParameters pp;
    std::vector<ECPoint> keys;
    std::vector<ZnElement> secrets, randomness, values;
    std::vector<encryption::Ciphertext> transfers, balances;
    protocol::Statement statement;
    protocol::Witness witness;
};

TEST_F(APGCInactiveParticipantTest, AcceptsOriginalRelationAndAssociatedContext) {
    const auto proof = protocol::prove(pp, statement, witness, "payment");
    EXPECT_TRUE(protocol::verify(pp, statement, proof, "payment"));
    EXPECT_FALSE(protocol::verify(pp, statement, proof, "other-payment"));
}

TEST_F(APGCInactiveParticipantTest, RejectsChangedPublicInput) {
    const auto proof = protocol::prove(pp, statement, witness);
    statement.commitments[1] = statement.commitments[1] + enc.h;
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCInactiveParticipantTest, RejectsWrongWitness) {
    witness.bits[1] = enc.ring_ctx->get_zero();
    witness.bits[2] = enc.ring_ctx->get_one();
    witness.randomness = {randomness[2]};
    const auto proof = protocol::prove(pp, statement, witness);
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCInactiveParticipantTest, FreshMasksAndResponseTampering) {
    auto proof = protocol::prove(pp, statement, witness);
    const auto other = protocol::prove(pp, statement, witness);
    EXPECT_NE(proof, other);
    proof.f_s += enc.ring_ctx->get_one();
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCInactiveParticipantTest, SerializationRoundTripAndTruncation) {
    const auto proof = protocol::prove(pp, statement, witness);
    std::ostringstream output;
    output << proof;
    auto decoded = protocol::initialize_proof(pp);
    std::istringstream input(output.str());
    input >> decoded;
    ASSERT_TRUE(input);
    EXPECT_EQ(proof, decoded);
    EXPECT_TRUE(protocol::verify(pp, statement, decoded));
    for (const auto length : {std::size_t{0}, output.str().size() / 2, output.str().size() - 1}) {
        std::istringstream truncated(output.str().substr(0, length));
        decoded = protocol::initialize_proof(pp);
        truncated >> decoded;
        EXPECT_TRUE(truncated.fail());
    }
}

TEST_F(APGCInactiveParticipantTest, RejectsMalformedDimensions) {
    const auto proof = protocol::prove(pp, statement, witness);
    statement.commitments.pop_back();
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}


TEST_F(APGCInactiveParticipantTest, MatchesOriginalNullPolynomialAndInnerProductEquations) {
    namespace inner = taihang::zkp::range_proofs::inner_product;
    const auto proof = protocol::prove(pp, statement, witness);
    std::ostringstream transcript;
    transcript << proof.a;
    const auto y = hash_to_zn(transcript.str(), *enc.ring_ctx);
    transcript << proof.s;
    const auto z = hash_to_zn(transcript.str(), *enc.ring_ctx);
    transcript << proof.t1 << proof.t2 << proof.e;
    const auto x = hash_to_zn(transcript.str(), *enc.ring_ctx);
    transcript << x;
    const auto e = hash_to_zn(transcript.str(), *enc.ring_ctx);
    const auto one = enc.ring_ctx->get_one();
    auto power = one, inverse = one, sum_y = enc.ring_ctx->get_zero();
    std::vector<ECPoint> g(4, ECPoint(enc.group_ctx));
    auto p = proof.a + proof.s * x + enc.g * proof.f_s - pp.u * proof.mu + proof.e * x;
    for (std::size_t j = 0; j < 4; ++j) {
        g[j] = pp.vector_g[j] * inverse + statement.commitments[j];
        p = p - pp.vector_g[j] * z + pp.vector_h[j] * (z + z * z * inverse) - statement.commitments[j] * (z * power);
        sum_y += power;
        power *= y;
        inverse *= y.inv();
    }
    const auto delta = (z - z * z) * sum_y - z * z * z * ZnElement(enc.ring_ctx, BigInt(uint64_t{4}));
    EXPECT_EQ(enc.g * proof.t + enc.h * proof.taux,
        enc.g * (delta + z * z * ZnElement(enc.ring_ctx, BigInt(uint64_t{statement.count}))) + proof.t1 * x + proof.t2 * (x * x));
    const inner::PublicParameters ip{enc.curve_id, 4, 2, enc.group_ctx, enc.ring_ctx, g, pp.vector_h, pp.u * e};
    EXPECT_TRUE(inner::verify(ip, {p + ip.u * proof.t}, proof.inner_product, transcript.str()));
    std::ostringstream encoded;
    encoded << proof;
    EXPECT_EQ(encoded.str().size(), 9 * enc.g.to_bytes().size() + 6 * one.to_bytes().size() + sizeof(uint64_t));
}

TEST_F(APGCInactiveParticipantTest, PreservesZeroSelectedEntriesAndRejectsWrongCardinality) {
    statement.count = 0;
    witness.bits.assign(4, enc.ring_ctx->get_zero());
    witness.randomness.clear();
    const auto proof = protocol::prove(pp, statement, witness);
    EXPECT_TRUE(protocol::verify(pp, statement, proof));
    statement.count = 1;
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

} // namespace
