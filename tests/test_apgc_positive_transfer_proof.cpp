#include <gtest/gtest.h>

#include <sstream>
#include <openssl/obj_mac.h>

#include <taihang/zkp/apgc/positive_transfer_proof.hpp>

namespace {
using namespace taihang;
namespace protocol = taihang::zkp::apgc::positive_transfer;
namespace encryption = taihang::pke::twisted_elgamal;

class APGCPositiveTransferTest : public ::testing::Test {
protected:
    APGCPositiveTransferTest() : enc(encryption::setup(NID_X9_62_prime256v1, 8)), pp(protocol::setup(enc, 4, 2)) {
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
        witness = {{2, 3}, {values[2], values[3]}, {randomness[2], randomness[3]}};
    }
    encryption::PublicParameters enc;
    protocol::PublicParameters pp;
    std::vector<ECPoint> keys;
    std::vector<ZnElement> secrets, randomness, values;
    std::vector<encryption::Ciphertext> transfers, balances;
    protocol::Statement statement;
    protocol::Witness witness;
};

TEST_F(APGCPositiveTransferTest, AcceptsOriginalRelationAndAssociatedContext) {
    const auto proof = protocol::prove(pp, statement, witness, "payment");
    EXPECT_TRUE(protocol::verify(pp, statement, proof, "payment"));
    EXPECT_FALSE(protocol::verify(pp, statement, proof, "other-payment"));
}

TEST_F(APGCPositiveTransferTest, RejectsChangedPublicInput) {
    const auto proof = protocol::prove(pp, statement, witness);
    statement.commitments[2] = statement.commitments[2] + enc.h;
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCPositiveTransferTest, RejectsWrongWitness) {
    witness.values[0] += enc.ring_ctx->get_one();
    const auto proof = protocol::prove(pp, statement, witness);
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCPositiveTransferTest, FreshMasksAndResponseTampering) {
    auto proof = protocol::prove(pp, statement, witness);
    const auto other = protocol::prove(pp, statement, witness);
    EXPECT_NE(proof, other);
    proof.shifted.t += enc.ring_ctx->get_one();
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCPositiveTransferTest, SerializationRoundTripAndTruncation) {
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

TEST_F(APGCPositiveTransferTest, RejectsMalformedDimensions) {
    const auto proof = protocol::prove(pp, statement, witness);
    statement.commitments.pop_back();
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}


TEST_F(APGCPositiveTransferTest, MatchesOriginalKoonChallengesAndAggregateOpening) {
    const auto proof = protocol::prove(pp, statement, witness);
    const auto& q = proof.subset;
    std::ostringstream x_input, e_input;
    x_input << q.a << q.c << q.d;
    e_input << q.a << q.b << q.c << q.d << q.p;
    const auto x = hash_to_zn(x_input.str(), *enc.ring_ctx);
    const auto e = hash_to_zn(e_input.str(), *enc.ring_ctx);
    std::vector<ZnElement> quadratic(q.f.size(), enc.ring_ctx->get_zero());
    for (std::size_t i = 0; i < q.f.size(); ++i) quadratic[i] = q.f[i] * (x - q.f[i]);
    EXPECT_EQ(q.b * x + q.a, ec_point_msm(pp.index_g, q.f) + pp.u * q.z_a);
    EXPECT_EQ(q.c * x + q.d, ec_point_msm(pp.index_g, quadratic) + pp.u * q.z_c);
    auto aggregate = enc.group_ctx->get_infinity();
    for (std::size_t j = 0; j < 4; ++j) {
        auto weight = enc.ring_ctx->get_zero();
        auto e_power = enc.ring_ctx->get_one();
        for (std::size_t i = 0; i < 2; ++i) {
            auto value = enc.ring_ctx->get_one();
            for (std::size_t b = 0; b < 2; ++b) value *= ((j >> b) & 1U) ? q.f[i * 2 + b] : x - q.f[i * 2 + b];
            weight += value * e_power;
            e_power *= e;
        }
        aggregate = aggregate + statement.commitments[j] * weight;
    }
    aggregate = aggregate - q.c_c[0] - q.c_c[1] * x;
    const auto inverse = (x * x).inv();
    EXPECT_EQ(aggregate * inverse, enc.g * (q.z_g * inverse) + enc.h * (values[2] + values[3] * e));
    std::ostringstream encoded;
    encoded << proof;
    EXPECT_EQ(encoded.str().size(), 48 * enc.g.to_bytes().size() +
        23 * enc.ring_ctx->get_one().to_bytes().size() + 6 * sizeof(uint64_t));
}

TEST_F(APGCPositiveTransferTest, PreservesOriginalHalfOpenPositiveAmountRange) {
    for (const auto amount : {uint64_t{0}, uint64_t{1}, uint64_t{4294967295}, uint64_t{4294967296}}) {
        witness.values[0] = ZnElement(enc.ring_ctx, BigInt(amount));
        statement.commitments[2] = encryption::encrypt(enc, {keys[2]}, witness.values[0], randomness[2]).c2;
        EXPECT_EQ(protocol::verify(pp, statement, protocol::prove(pp, statement, witness)), amount > 0 && amount < 4294967296ULL);
    }
    witness.values[0] = -enc.ring_ctx->get_one();
    statement.commitments[2] = encryption::encrypt(enc, {keys[2]}, witness.values[0], randomness[2]).c2;
    EXPECT_FALSE(protocol::verify(pp, statement, protocol::prove(pp, statement, witness)));
}

} // namespace
