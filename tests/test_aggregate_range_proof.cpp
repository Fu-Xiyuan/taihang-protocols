#include <gtest/gtest.h>

#include <sstream>
#include <openssl/obj_mac.h>

#include <taihang/zkp/sigma_protocols/aggregate_range_proof.hpp>

namespace {
using namespace taihang;
namespace range = taihang::zkp::nizk::aggregate_range;

class AggregateRangeProofTest : public ::testing::Test {
protected:
    AggregateRangeProofTest()
        : pp(range::setup(NID_X9_62_prime256v1, 8, 3)),
          witness{{ZnElement(pp.ring_ctx, BigInt(uint64_t{0})),
                    ZnElement(pp.ring_ctx, BigInt(uint64_t{17})),
                    ZnElement(pp.ring_ctx, BigInt(uint64_t{255}))}, pp.ring_ctx->gen_random()},
          statement{pp.g * witness.randomness,
                    {pp.ring_ctx->get_one(), ZnElement(pp.ring_ctx, BigInt(uint64_t{7})),
                     ZnElement(pp.ring_ctx, BigInt(uint64_t{49}))}} {
        for (std::size_t j = 0; j < 3; ++j) {
            statement.aggregate = statement.aggregate + pp.h * (statement.weights[j] *
                witness.values[j]);
        }
    }
    range::Proof empty() const {
        return {ECPoint(pp.group_ctx), ECPoint(pp.group_ctx),
            ECPoint(pp.group_ctx), ECPoint(pp.group_ctx), ZnElement(pp.ring_ctx),
            ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx),
            {std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
             std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
             ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx)}};
    }
    range::PublicParameters pp;
    range::Witness witness;
    range::Statement statement;
};

TEST_F(AggregateRangeProofTest, AcceptsWeightedAggregateWithNonPowerOfTwoCount) {
    EXPECT_EQ(pp.vector_length, 32U);
    EXPECT_TRUE(range::verify(pp, statement, range::prove(pp, statement, witness)));
}

TEST_F(AggregateRangeProofTest, AcceptsDelayedAggregateAndRecoversBridgeWeights) {
    const std::vector<ZnElement> randomness = gen_random_znelement_vector(pp.ring_ctx,
        pp.value_count);
    const range::DelayedProof proof = range::prove_delayed(pp, witness.values, randomness,
        "bridge");
    EXPECT_TRUE(range::verify_delayed(pp, proof, "bridge"));
    EXPECT_FALSE(range::verify_delayed(pp, proof, "wrong"));
    const std::vector<ZnElement> weights = range::delayed_weights(pp, proof, "bridge");
    ECPoint aggregate = pp.group_ctx->get_infinity();
    for (std::size_t j = 0; j < pp.value_count; ++j) {
        aggregate = aggregate + (pp.g * randomness[j] + pp.h * witness.values[j]) * weights[j];
    }
    EXPECT_EQ(aggregate, proof.aggregate);
    EXPECT_FALSE(range::verify(pp, {proof.aggregate, weights}, proof));
}

TEST_F(AggregateRangeProofTest, DelayedSerializationRoundTripAndTruncation) {
    const std::vector<ZnElement> randomness = gen_random_znelement_vector(
        pp.ring_ctx, pp.value_count);
    const range::DelayedProof proof = range::prove_delayed(
        pp, witness.values, randomness);
    std::ostringstream output;
    output << proof;
    range::DelayedProof decoded{empty(), ECPoint(pp.group_ctx)};
    std::istringstream input(output.str());
    input >> decoded;
    ASSERT_TRUE(input);
    EXPECT_EQ(decoded, proof);
    EXPECT_TRUE(range::verify_delayed(pp, decoded));
    const std::string bytes = output.str();
    for (std::size_t length = 0; length < bytes.size(); length += 31) {
        decoded = {empty(), ECPoint(pp.group_ctx)};
        std::istringstream truncated(bytes.substr(0, length));
        truncated >> decoded;
        ASSERT_TRUE(truncated.fail());
    }
}

TEST_F(AggregateRangeProofTest, RejectsOutOfRangeValueAndWrongBlinding) {
    range::Witness wrong = witness;
    wrong.values[0] = ZnElement(pp.ring_ctx, BigInt(uint64_t{256}));
    range::Statement changed = statement;
    changed.aggregate = changed.aggregate + pp.h * wrong.values[0];
    EXPECT_FALSE(range::verify(pp, changed, range::prove(pp, changed, wrong)));
    const std::vector<ZnElement> randomness = gen_random_znelement_vector(pp.ring_ctx,
        pp.value_count);
    EXPECT_FALSE(range::verify_delayed(pp, range::prove_delayed(pp, wrong.values, randomness)));
    wrong = witness;
    wrong.randomness += pp.ring_ctx->get_one();
    EXPECT_FALSE(range::verify(pp, statement, range::prove(pp, statement, wrong)));
}

TEST_F(AggregateRangeProofTest, BindsWeightsContextAndAggregate) {
    const range::Proof proof = range::prove(pp, statement, witness, "a");
    EXPECT_TRUE(range::verify(pp, statement, proof, "a"));
    EXPECT_FALSE(range::verify(pp, statement, proof, "b"));
    range::Statement changed = statement;
    changed.weights[1] += pp.ring_ctx->get_one();
    EXPECT_FALSE(range::verify(pp, changed, proof, "a"));
    changed = statement;
    changed.weights[1] = pp.ring_ctx->get_zero();
    EXPECT_FALSE(range::verify(pp, changed, proof, "a"));
    changed = statement;
    changed.aggregate = changed.aggregate + pp.g;
    EXPECT_FALSE(range::verify(pp, changed, proof, "a"));
}

TEST_F(AggregateRangeProofTest, RejectsEveryOuterFieldTampering) {
    const range::Proof valid = range::prove(pp, statement, witness);
    for (ECPoint range::Proof::* member :
         {&range::Proof::a,
          &range::Proof::s,
          &range::Proof::t1,
          &range::Proof::t2}) {
        range::Proof proof = valid;
        proof.*member = proof.*member + pp.g;
        EXPECT_FALSE(range::verify(pp, statement, proof));
    }
    for (ZnElement range::Proof::* member :
         {&range::Proof::taux,
          &range::Proof::mu,
          &range::Proof::t}) {
        range::Proof proof = valid;
        proof.*member += pp.ring_ctx->get_one();
        EXPECT_FALSE(range::verify(pp, statement, proof));
    }
    range::Proof proof = valid;
    proof.inner_product.a += pp.ring_ctx->get_one();
    EXPECT_FALSE(range::verify(pp, statement, proof));
    proof = valid;
    proof.inner_product.left.pop_back();
    EXPECT_FALSE(range::verify(pp, statement, proof));
}

TEST_F(AggregateRangeProofTest, SerializationAndEveryTruncation) {
    const range::Proof proof = range::prove(pp, statement, witness);
    std::stringstream stream;
    stream << proof;
    range::Proof decoded = empty();
    stream >> decoded;
    ASSERT_TRUE(stream);
    EXPECT_EQ(proof, decoded);
    const std::string bytes = stream.str();
    for (std::size_t n = 0; n < bytes.size(); ++n) {
        std::istringstream input(bytes.substr(0, n));
        decoded = empty();
        input >> decoded;
        ASSERT_TRUE(input.fail());
    }
}

TEST_F(AggregateRangeProofTest, OrdinaryAndDelayedFormatsDifferByExactlyOnePoint) {
    const range::Proof ordinary = range::prove(pp, statement, witness);
    const std::vector<ZnElement> randomness = gen_random_znelement_vector(
        pp.ring_ctx, pp.value_count);
    const range::DelayedProof delayed = range::prove_delayed(
        pp, witness.values, randomness);
    std::ostringstream ordinary_bytes;
    std::ostringstream delayed_bytes;
    ordinary_bytes << ordinary;
    delayed_bytes << delayed;
    EXPECT_EQ(delayed_bytes.str().size(), ordinary_bytes.str().size() +
        pp.g.to_bytes().size());
    EXPECT_TRUE(range::verify(pp, statement, ordinary));
    EXPECT_TRUE(range::verify_delayed(pp, delayed));
}

TEST(AggregateRangeProofStandaloneTest, HandlesSingleBitAndSingleValue) {
    const range::PublicParameters pp = range::setup(NID_X9_62_prime256v1, 1, 1);
    const range::DelayedProof proof = range::prove_delayed(pp, {pp.ring_ctx->get_one()},
        {pp.ring_ctx->get_zero()});
    EXPECT_TRUE(range::verify_delayed(pp, proof));
}
} // namespace
