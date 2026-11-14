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
    APGCSolvencyTest() : enc(encryption::setup(NID_X9_62_prime256v1, 8)), pp(protocol::setup(enc, 4)) {
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
        statement = {keys, transfers, balances};
        witness = {secrets[0], 0, ZnElement(enc.ring_ctx, BigInt(uint64_t{91})), values[0], randomness[0]};
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
    const auto proof = protocol::prove(pp, statement, witness, "payment");
    EXPECT_TRUE(protocol::verify(pp, statement, proof, "payment"));
    EXPECT_FALSE(protocol::verify(pp, statement, proof, "other-payment"));
}

TEST_F(APGCSolvencyTest, RejectsChangedPublicInput) {
    const auto proof = protocol::prove(pp, statement, witness);
    statement.transfers[0].c2 = statement.transfers[0].c2 + enc.h;
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCSolvencyTest, RejectsWrongWitness) {
    witness.post_balance += enc.ring_ctx->get_one();
    const auto proof = protocol::prove(pp, statement, witness);
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCSolvencyTest, FreshMasksAndResponseTampering) {
    auto proof = protocol::prove(pp, statement, witness);
    const auto other = protocol::prove(pp, statement, witness);
    EXPECT_NE(proof, other);
    proof.z_s += enc.ring_ctx->get_one();
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCSolvencyTest, SerializationRoundTripAndTruncation) {
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

TEST_F(APGCSolvencyTest, RejectsMalformedDimensions) {
    const auto proof = protocol::prove(pp, statement, witness);
    statement.transfers.pop_back();
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}


TEST_F(APGCSolvencyTest, MatchesOriginalSolventSharedSelectorEquationAndProofShape) {
    const auto proof = protocol::prove(pp, statement, witness);
    const auto& sender = proof.sender;
    std::ostringstream transcript;
    transcript << sender.p << sender.v;
    for (std::size_t j = 0; j < 4; ++j) {
        transcript << statement.transfers[j].c1 + statement.balances[j].c1
                   << statement.transfers[j].c2 + statement.balances[j].c2 << statement.public_keys[j];
    }
    transcript << sender.homomorphism.a_p << sender.homomorphism.a_q;
    const auto& eq = sender.homomorphism.equality_proof;
    for (std::size_t r = 0; r < eq.left_g.size(); ++r) transcript << eq.left_g[r] << eq.right_g[r] << eq.left_p[r] << eq.right_p[r];
    transcript << proof.a << proof.c << proof.d;
    const auto x = hash_to_zn(transcript.str(), *enc.ring_ctx);
    auto s = enc.group_ctx->get_infinity();
    for (std::size_t j = 0; j < 4; ++j) {
        auto p = enc.ring_ctx->get_one();
        for (std::size_t b = 0; b < 2; ++b) p *= ((j >> b) & 1U) ? proof.f[b] : x - proof.f[b];
        s = s + (pp.sender.vector_g[j] + pp.sender.vector_h[j]) * p - pp.sender.vector_h[j] * (x * x);
    }
    s = s - proof.c_s[0] - proof.c_s[1] * x;
    EXPECT_EQ(sender.s * (x * x) - s, pp.sender.u * proof.z_s);
    std::ostringstream encoded;
    encoded << proof;
    EXPECT_EQ(encoded.str().size(), 87 * enc.g.to_bytes().size() +
        32 * enc.ring_ctx->get_one().to_bytes().size() + 9 * sizeof(uint64_t));
}

TEST_F(APGCSolvencyTest, PreservesOriginalStrictlyPositiveDebitRange) {
    for (const auto amount : {uint64_t{0}, uint64_t{1}, uint64_t{4294967295}, uint64_t{4294967296}}) {
        witness.transfer_value = -ZnElement(enc.ring_ctx, BigInt(amount));
        statement.transfers[0] = encryption::encrypt(enc, {keys[0]}, witness.transfer_value, witness.transfer_randomness);
        statement.balances[0] = encryption::encrypt(enc, {keys[0]}, witness.post_balance - witness.transfer_value);
        EXPECT_EQ(protocol::verify(pp, statement, protocol::prove(pp, statement, witness)), amount > 0 && amount < 4294967296ULL);
    }
}

} // namespace
