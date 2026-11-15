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
    APGCPositiveTransferTest() : enc(encryption::setup(NID_X9_62_prime256v1, 8)),
        pp(protocol::setup(enc, 4, 2)) {
        for (std::size_t j = 0; j < 4; ++j) {
            const std::pair<encryption::PublicKey, encryption::SecretKey> key =
                encryption::keygen(enc);
            keys.push_back(key.first.y);
            secrets.push_back(key.second.x);
            randomness.push_back(enc.ring_ctx->gen_random());
            const ZnElement amount = j == 0 ? -ZnElement(enc.ring_ctx, BigInt(uint64_t{9})) :
                ZnElement(enc.ring_ctx, BigInt(uint64_t{j == 1 ? 0 : j + 2}));
            values.push_back(amount);
            transfers.push_back(encryption::encrypt(enc, key.first, amount, randomness.back()));
            balances.push_back(encryption::encrypt(enc, key.first, ZnElement(enc.ring_ctx,
                BigInt(uint64_t{100}))));
        }
        for (const encryption::Ciphertext& ct : transfers) {
            statement.commitments.push_back(ct.c2);
        }
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
    const protocol::Proof proof = protocol::prove(pp, statement, witness, "payment");
    EXPECT_TRUE(protocol::verify(pp, statement, proof, "payment"));
    EXPECT_FALSE(protocol::verify(pp, statement, proof, "other-payment"));
}

TEST_F(APGCPositiveTransferTest, RejectsChangedPublicInput) {
    const protocol::Proof proof = protocol::prove(pp, statement, witness);
    statement.commitments[2] = statement.commitments[2] + enc.h;
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCPositiveTransferTest, RejectsWrongWitness) {
    witness.values[0] += enc.ring_ctx->get_one();
    const protocol::Proof proof = protocol::prove(pp, statement, witness);
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCPositiveTransferTest, FreshMasksAndResponseTampering) {
    protocol::Proof proof = protocol::prove(pp, statement, witness);
    const protocol::Proof other = protocol::prove(pp, statement, witness);
    EXPECT_NE(proof, other);
    proof.shifted.t += enc.ring_ctx->get_one();
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCPositiveTransferTest, SerializationRoundTripAndTruncation) {
    const protocol::Proof proof = protocol::prove(pp, statement, witness);
    std::ostringstream output;
    output << proof;
    protocol::Proof decoded = protocol::initialize_proof(pp);
    std::istringstream input(output.str());
    input >> decoded;
    ASSERT_TRUE(input);
    EXPECT_EQ(proof, decoded);
    EXPECT_TRUE(protocol::verify(pp, statement, decoded));
    for (const std::size_t length : {std::size_t{0}, output.str().size() / 2,
        output.str().size() - 1}) {
        std::istringstream truncated(output.str().substr(0, length));
        decoded = protocol::initialize_proof(pp);
        truncated >> decoded;
        EXPECT_TRUE(truncated.fail());
    }
}

TEST_F(APGCPositiveTransferTest, RejectsMalformedDimensions) {
    const protocol::Proof proof = protocol::prove(pp, statement, witness);
    statement.commitments.pop_back();
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCPositiveTransferTest, PreservesOriginalHalfOpenPositiveAmountRange) {
    for (const std::uint64_t amount : {uint64_t{0}, uint64_t{1}, uint64_t{4294967295},
        uint64_t{4294967296}}) {
        witness.values[0] = ZnElement(enc.ring_ctx, BigInt(amount));
        statement.commitments[2] = encryption::encrypt(enc, {keys[2]}, witness.values[0],
            randomness[2]).c2;
        EXPECT_EQ(protocol::verify(pp, statement, protocol::prove(pp, statement, witness)),
            amount > 0 && amount < 4294967296ULL);
    }
    witness.values[0] = -enc.ring_ctx->get_one();
    statement.commitments[2] = encryption::encrypt(enc, {keys[2]}, witness.values[0],
        randomness[2]).c2;
    EXPECT_FALSE(protocol::verify(pp, statement, protocol::prove(pp, statement, witness)));
}

} // namespace
