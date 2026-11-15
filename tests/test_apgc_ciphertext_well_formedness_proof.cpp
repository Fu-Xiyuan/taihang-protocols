#include <gtest/gtest.h>

#include <sstream>
#include <openssl/obj_mac.h>

#include <taihang/zkp/apgc/ciphertext_well_formedness_proof.hpp>

namespace {
using namespace taihang;
namespace protocol = taihang::zkp::apgc::ciphertext_well_formedness;
namespace encryption = taihang::pke::twisted_elgamal;

class APGCWellFormednessTest : public ::testing::Test {
protected:
    APGCWellFormednessTest() : enc(encryption::setup(NID_X9_62_prime256v1, 8)),
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
        statement = {keys, transfers};
        witness = {values, randomness};
    }
    encryption::PublicParameters enc;
    protocol::PublicParameters pp;
    std::vector<ECPoint> keys;
    std::vector<ZnElement> secrets, randomness, values;
    std::vector<encryption::Ciphertext> transfers, balances;
    protocol::Statement statement;
    protocol::Witness witness;
};

TEST_F(APGCWellFormednessTest, AcceptsOriginalRelationAndAssociatedContext) {
    const protocol::Proof proof = protocol::prove(pp, statement, witness, "payment");
    EXPECT_TRUE(protocol::verify(pp, statement, proof, "payment"));
    EXPECT_FALSE(protocol::verify(pp, statement, proof, "other-payment"));
}

TEST_F(APGCWellFormednessTest, RejectsChangedPublicInput) {
    const protocol::Proof proof = protocol::prove(pp, statement, witness);
    statement.transfers[2].c1 = statement.transfers[2].c1 + enc.g;
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCWellFormednessTest, RejectsWrongWitness) {
    witness.values[2] += enc.ring_ctx->get_one();
    const protocol::Proof proof = protocol::prove(pp, statement, witness);
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCWellFormednessTest, FreshMasksAndResponseTampering) {
    protocol::Proof proof = protocol::prove(pp, statement, witness);
    const protocol::Proof other = protocol::prove(pp, statement, witness);
    EXPECT_NE(proof, other);
    proof.evaluation.f += enc.ring_ctx->get_one();
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCWellFormednessTest, SerializationRoundTripAndTruncation) {
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

TEST_F(APGCWellFormednessTest, RejectsMalformedDimensions) {
    const protocol::Proof proof = protocol::prove(pp, statement, witness);
    statement.transfers.pop_back();
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

} // namespace
