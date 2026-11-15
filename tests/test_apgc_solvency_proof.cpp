#include <gtest/gtest.h>

#include <sstream>
#include <openssl/obj_mac.h>

#include <taihang/zkp/apgc/solvency_proof.hpp>

namespace {
using namespace taihang;
namespace protocol = taihang::zkp::apgc::solvency;
namespace encryption = taihang::pke::twisted_elgamal;

class APGCSolvencyTest : public ::testing::Test {
protected:
    APGCSolvencyTest() : enc(encryption::setup(NID_X9_62_prime256v1, 8)),
        pp(protocol::setup(enc, 4)) {
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
        statement = {keys, transfers, balances};
        witness = {secrets[0], 0, ZnElement(enc.ring_ctx, BigInt(uint64_t{91})), values[0],
            randomness[0]};
    }
    encryption::PublicParameters enc;
    protocol::PublicParameters pp;
    std::vector<ECPoint> keys;
    std::vector<ZnElement> secrets, randomness, values;
    std::vector<encryption::Ciphertext> transfers, balances;
    protocol::Statement statement;
    protocol::Witness witness;
};

TEST_F(APGCSolvencyTest, AcceptsOriginalRelationAndAssociatedContext) {
    const protocol::Proof proof = protocol::prove(pp, statement, witness, "payment");
    EXPECT_TRUE(protocol::verify(pp, statement, proof, "payment"));
    EXPECT_FALSE(protocol::verify(pp, statement, proof, "other-payment"));
}

TEST_F(APGCSolvencyTest, RejectsChangedPublicInput) {
    const protocol::Proof proof = protocol::prove(pp, statement, witness);
    statement.transfers[0].c2 = statement.transfers[0].c2 + enc.h;
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCSolvencyTest, RejectsWrongWitness) {
    witness.post_balance += enc.ring_ctx->get_one();
    const protocol::Proof proof = protocol::prove(pp, statement, witness);
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCSolvencyTest, FreshMasksAndResponseTampering) {
    protocol::Proof proof = protocol::prove(pp, statement, witness);
    const protocol::Proof other = protocol::prove(pp, statement, witness);
    EXPECT_NE(proof, other);
    proof.z_s += enc.ring_ctx->get_one();
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCSolvencyTest, SerializationRoundTripAndTruncation) {
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

TEST_F(APGCSolvencyTest, RejectsMalformedDimensions) {
    const protocol::Proof proof = protocol::prove(pp, statement, witness);
    statement.transfers.pop_back();
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCSolvencyTest, PreservesOriginalStrictlyPositiveDebitRange) {
    for (const std::uint64_t amount : {uint64_t{0}, uint64_t{1}, uint64_t{4294967295},
        uint64_t{4294967296}}) {
        witness.transfer_value = -ZnElement(enc.ring_ctx, BigInt(amount));
        statement.transfers[0] = encryption::encrypt(enc, {keys[0]}, witness.transfer_value,
            witness.transfer_randomness);
        statement.balances[0] = encryption::encrypt(enc, {keys[0]},
            witness.post_balance - witness.transfer_value);
        EXPECT_EQ(protocol::verify(pp, statement, protocol::prove(pp, statement, witness)),
            amount > 0 && amount < 4294967296ULL);
    }
}

} // namespace
