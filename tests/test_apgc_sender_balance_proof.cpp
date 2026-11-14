#include <gtest/gtest.h>

#include <sstream>
#include <openssl/obj_mac.h>

#include <taihang/zkp/apgc/sender_balance_proof.hpp>

namespace {
using namespace taihang;
namespace protocol = taihang::zkp::apgc::sender_balance;
namespace encryption = taihang::pke::twisted_elgamal;

template<class T>
concept ExposesSelectionRandomness = requires(const T& value) { value.r_s; };

static_assert(!ExposesSelectionRandomness<protocol::Proof>);
static_assert(ExposesSelectionRandomness<protocol::detail::ProverState>);

class APGCSenderBalanceTest : public ::testing::Test {
protected:
    APGCSenderBalanceTest() : enc(encryption::setup(NID_X9_62_prime256v1, 8)), pp(protocol::setup(enc, 4)) {
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
        witness = {0, secrets[0].inv(), ZnElement(enc.ring_ctx, BigInt(uint64_t{91}))};
    }
    encryption::PublicParameters enc;
    protocol::PublicParameters pp;
    std::vector<ECPoint> keys;
    std::vector<ZnElement> secrets, randomness, values;
    std::vector<encryption::Ciphertext> transfers, balances;
    protocol::Statement statement;
    protocol::Witness witness;
};

TEST_F(APGCSenderBalanceTest, AcceptsOriginalRelationAndAssociatedContext) {
    const auto proof = protocol::prove(pp, statement, witness, "payment");
    EXPECT_TRUE(protocol::verify(pp, statement, proof, "payment"));
    EXPECT_FALSE(protocol::verify(pp, statement, proof, "other-payment"));
}

TEST_F(APGCSenderBalanceTest, RejectsChangedPublicInput) {
    const auto proof = protocol::prove(pp, statement, witness);
    statement.balances[0].c2 = statement.balances[0].c2 + enc.h;
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCSenderBalanceTest, RejectsWrongWitness) {
    witness.inverse_secret_key += enc.ring_ctx->get_one();
    const auto proof = protocol::prove(pp, statement, witness);
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCSenderBalanceTest, FreshMasksAndResponseTampering) {
    auto proof = protocol::prove(pp, statement, witness);
    const auto other = protocol::prove(pp, statement, witness);
    EXPECT_NE(proof, other);
    proof.homomorphism.f += enc.ring_ctx->get_one();
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCSenderBalanceTest, SerializationRoundTripAndTruncation) {
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

TEST_F(APGCSenderBalanceTest, RejectsMalformedDimensions) {
    const auto proof = protocol::prove(pp, statement, witness);
    statement.transfers.pop_back();
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}


TEST_F(APGCSenderBalanceTest, PreservesOriginalSelectionCommitmentAndProofShape) {
    protocol::detail::ProverState state{ZnElement(enc.ring_ctx)};
    const auto proof = protocol::detail::prove_with_state(pp, statement, witness, state);
    auto selected = pp.vector_g[0];
    for (std::size_t j = 1; j < 4; ++j) selected = selected - pp.vector_h[j];
    EXPECT_EQ(proof.s - pp.u * state.r_s, selected);
    EXPECT_EQ(proof.homomorphism.equality_proof.left_g.size(), 4);
    EXPECT_EQ(proof.representation.left.size(), 4);
    EXPECT_EQ(proof.binary.inner_product.left.size(), 2);
    EXPECT_EQ(proof.range.inner_product.left.size(), 5);
    std::ostringstream encoded;
    encoded << proof;
    EXPECT_EQ(encoded.str().size(), 51 * enc.g.to_bytes().size() +
        16 * enc.ring_ctx->get_one().to_bytes().size() + 4 * sizeof(uint64_t));
}

TEST_F(APGCSenderBalanceTest, PreservesOriginalRangeLanguageIncludingZeroPostBalance) {
    for (const auto amount : {uint64_t{0}, uint64_t{4294967295}, uint64_t{4294967296}}) {
        witness.post_balance = ZnElement(enc.ring_ctx, BigInt(amount));
        statement.balances[0] = encryption::encrypt(enc, {keys[0]},
            witness.post_balance + ZnElement(enc.ring_ctx, BigInt(uint64_t{9})));
        EXPECT_EQ(protocol::verify(pp, statement, protocol::prove(pp, statement, witness)), amount < 4294967296ULL);
    }
    witness.post_balance = -enc.ring_ctx->get_one();
    statement.balances[0] = encryption::encrypt(enc, {keys[0]},
        witness.post_balance + ZnElement(enc.ring_ctx, BigInt(uint64_t{9})));
    EXPECT_FALSE(protocol::verify(pp, statement, protocol::prove(pp, statement, witness)));
}

TEST_F(APGCSenderBalanceTest, RejectsIndependentSubproofSplicing) {
    const auto first = protocol::prove(pp, statement, witness);
    const auto second = protocol::prove(pp, statement, witness);
    auto changed = first;
    changed.binary = second.binary;
    EXPECT_FALSE(protocol::verify(pp, statement, changed));
    changed = first;
    changed.representation = second.representation;
    EXPECT_FALSE(protocol::verify(pp, statement, changed));
    changed = first;
    changed.range = second.range;
    EXPECT_FALSE(protocol::verify(pp, statement, changed));
}

} // namespace
