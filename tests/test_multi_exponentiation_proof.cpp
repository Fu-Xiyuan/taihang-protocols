#include <gtest/gtest.h>

#include <cstdint>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <openssl/obj_mac.h>

#include <taihang/zkp/sigma_protocols/multi_exponentiation_proof.hpp>

namespace {

using namespace taihang;
namespace multi_exp = taihang::zkp::nizk::multi_exponentiation;

class MultiExponentiationProofTest : public ::testing::Test {
protected:
    MultiExponentiationProofTest()
        : pp(multi_exp::setup(NID_X9_62_prime256v1, 8)) {
        for (std::size_t i = 0; i < pp.vector_length; ++i) {
            witness.a.emplace_back(pp.ring_ctx, BigInt(uint64_t{i + 1}));
        }
        statement.g = ec_point_msm(pp.g, witness.a);
    }

    multi_exp::Proof empty_proof() const {
        return {std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
                std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
                ZnElement(pp.ring_ctx)};
    }

    multi_exp::PublicParameters pp;
    multi_exp::Witness witness;
    multi_exp::Statement statement;
};

TEST_F(MultiExponentiationProofTest, SetupCreatesDeterministicGenerators) {
    EXPECT_EQ(pp.curve_id, NID_X9_62_prime256v1);
    EXPECT_EQ(pp.vector_length, 8U);
    EXPECT_EQ(pp.rounds, 3U);
    ASSERT_EQ(pp.g.size(), pp.vector_length);
    EXPECT_EQ(pp.ring_ctx->modulus, pp.group_ctx->order);
    const auto repeated = multi_exp::setup(pp.curve_id, pp.vector_length);
    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        EXPECT_EQ(pp.g[i].group_ctx, pp.group_ctx.get());
        EXPECT_EQ(pp.g[i].to_bytes(), repeated.g[i].to_bytes());
        EXPECT_FALSE(pp.g[i].is_at_infinity());
    }
    EXPECT_NE(pp.g[0], pp.g[1]);
}

TEST_F(MultiExponentiationProofTest, SetupReusesParentContextsAndBases) {
    const auto composed = multi_exp::setup(pp.group_ctx, pp.ring_ctx, pp.g);
    EXPECT_EQ(composed.group_ctx.get(), pp.group_ctx.get());
    EXPECT_EQ(composed.ring_ctx.get(), pp.ring_ctx.get());
    EXPECT_EQ(composed.g, pp.g);
    const auto proof = multi_exp::prove(composed, statement, witness);
    EXPECT_TRUE(multi_exp::verify(pp, statement, proof));
}

TEST_F(MultiExponentiationProofTest, AcceptsValidProofAndExpectedSize) {
    const auto proof = multi_exp::prove(pp, statement, witness);
    EXPECT_TRUE(multi_exp::verify(pp, statement, proof));
    EXPECT_EQ(proof.left.size(), pp.rounds);
    EXPECT_EQ(proof.right.size(), pp.rounds);
    std::stringstream stream;
    stream << proof;
    EXPECT_EQ(stream.str().size(), sizeof(std::uint64_t) +
        2 * pp.rounds * pp.group_ctx->get_point_byte_len() +
        pp.ring_ctx->element_byte_len);
}

TEST_F(MultiExponentiationProofTest, AcceptsZeroAndModularBoundaryWitnesses) {
    multi_exp::Witness boundary = witness;
    for (auto& scalar : boundary.a) scalar = pp.ring_ctx->get_zero();
    multi_exp::Statement changed{pp.group_ctx->get_infinity()};
    EXPECT_TRUE(multi_exp::verify(
        pp, changed, multi_exp::prove(pp, changed, boundary)));

    boundary.a[0] = ZnElement(pp.ring_ctx, pp.group_ctx->order - kBigIntOne);
    changed.g = ec_point_msm(pp.g, boundary.a);
    EXPECT_TRUE(multi_exp::verify(
        pp, changed, multi_exp::prove(pp, changed, boundary)));
}

TEST_F(MultiExponentiationProofTest, RejectsWrongWitnessAndStatement) {
    auto wrong = witness;
    wrong.a[0] += pp.ring_ctx->get_one();
    EXPECT_FALSE(multi_exp::verify(
        pp, statement, multi_exp::prove(pp, statement, wrong)));
    const auto proof = multi_exp::prove(pp, statement, witness);
    const multi_exp::Statement changed{statement.g + pp.g[0]};
    EXPECT_FALSE(multi_exp::verify(pp, changed, proof));
}

TEST_F(MultiExponentiationProofTest, RejectsTamperedMessagesAndFinalScalar) {
    const auto valid = multi_exp::prove(pp, statement, witness);
    for (std::size_t round = 0; round < pp.rounds; ++round) {
        auto proof = valid;
        proof.left[round] = proof.left[round] + pp.g[0];
        EXPECT_FALSE(multi_exp::verify(pp, statement, proof));
        proof = valid;
        proof.right[round] = proof.right[round] + pp.g[0];
        EXPECT_FALSE(multi_exp::verify(pp, statement, proof));
    }
    auto proof = valid;
    proof.a += pp.ring_ctx->get_one();
    EXPECT_FALSE(multi_exp::verify(pp, statement, proof));
}

TEST_F(MultiExponentiationProofTest, BindsAssociatedContextAndGeneratorOrder) {
    const auto proof = multi_exp::prove(pp, statement, witness, "session-a");
    EXPECT_TRUE(multi_exp::verify(pp, statement, proof, "session-a"));
    EXPECT_FALSE(multi_exp::verify(pp, statement, proof, "session-b"));
    auto changed = pp;
    std::swap(changed.g[0], changed.g[1]);
    EXPECT_FALSE(multi_exp::verify(changed, statement, proof, "session-a"));
}

TEST_F(MultiExponentiationProofTest, RejectsMalformedDimensions) {
    const auto valid = multi_exp::prove(pp, statement, witness);
    auto proof = valid;
    proof.left.pop_back();
    EXPECT_FALSE(multi_exp::verify(pp, statement, proof));
    proof = valid;
    proof.right.push_back(pp.g[0]);
    EXPECT_FALSE(multi_exp::verify(pp, statement, proof));
    auto changed = pp;
    changed.g.pop_back();
    EXPECT_FALSE(multi_exp::verify(changed, statement, valid));
    changed = pp;
    changed.rounds = 0;
    EXPECT_FALSE(multi_exp::verify(changed, statement, valid));
    changed = pp;
    changed.vector_length = 0;
    EXPECT_FALSE(multi_exp::verify(changed, statement, valid));
}

TEST_F(MultiExponentiationProofTest, SerializationRoundTrip) {
    const auto proof = multi_exp::prove(pp, statement, witness, "round-trip");
    std::stringstream stream;
    stream << proof;
    auto decoded = empty_proof();
    stream >> decoded;
    ASSERT_TRUE(stream);
    EXPECT_EQ(decoded, proof);
    EXPECT_TRUE(multi_exp::verify(pp, statement, decoded, "round-trip"));
}

TEST_F(MultiExponentiationProofTest, DeserializationRejectsUnexpectedRoundCount) {
    std::stringstream stream;
    const auto count = std::numeric_limits<std::uint64_t>::max();
    stream.write(reinterpret_cast<const char*>(&count), sizeof(count));
    auto decoded = empty_proof();
    stream >> decoded;
    EXPECT_TRUE(stream.fail());
    EXPECT_EQ(decoded.left.size(), pp.rounds);
    EXPECT_EQ(decoded.right.size(), pp.rounds);
}

TEST_F(MultiExponentiationProofTest, DeserializationRejectsTruncatedProof) {
    std::stringstream stream;
    stream << multi_exp::prove(pp, statement, witness);
    const auto encoded = stream.str();
    // Cut the count, point payload, and final scalar separately.
    for (const std::size_t size : {std::size_t{0}, sizeof(std::uint64_t) - 1,
                                  sizeof(std::uint64_t) + 1, encoded.size() - 1}) {
        std::istringstream input(encoded.substr(0, size));
        auto decoded = empty_proof();
        input >> decoded;
        EXPECT_TRUE(input.fail()) << "Truncation size: " << size;
    }
}

TEST_F(MultiExponentiationProofTest, DeserializationRejectsNonCanonicalScalar) {
    std::stringstream stream;
    stream << multi_exp::prove(pp, statement, witness);
    std::string encoded = stream.str();
    const auto modulus = pp.ring_ctx->modulus.to_bytes();
    ASSERT_EQ(modulus.size(), pp.ring_ctx->element_byte_len);
    encoded.replace(encoded.size() - modulus.size(), modulus.size(),
                    reinterpret_cast<const char*>(modulus.data()), modulus.size());
    std::istringstream input(encoded);
    auto decoded = empty_proof();
    input >> decoded;
    EXPECT_TRUE(input.fail());
}

TEST(MultiExponentiationProofStandaloneTest, HandlesSingleElementAndExposesItsScalar) {
    const auto pp = multi_exp::setup(NID_X9_62_prime256v1, 1);
    const multi_exp::Witness witness{{ZnElement(pp.ring_ctx, BigInt(uint64_t{7}))}};
    const multi_exp::Statement statement{pp.g[0] * witness.a[0]};
    auto proof = multi_exp::prove(pp, statement, witness);
    EXPECT_TRUE(proof.left.empty());
    EXPECT_TRUE(proof.right.empty());
    EXPECT_EQ(proof.a, witness.a[0]); // This module does not provide standalone ZK.
    EXPECT_TRUE(multi_exp::verify(pp, statement, proof));
    proof.a += pp.ring_ctx->get_one();
    EXPECT_FALSE(multi_exp::verify(pp, statement, proof));
}

TEST(MultiExponentiationProofStandaloneTest, TwoElementFoldMatchesDirectEquation) {
    const auto pp = multi_exp::setup(NID_X9_62_prime256v1, 2);
    const multi_exp::Witness witness{{ZnElement(pp.ring_ctx, BigInt(uint64_t{3})),
                                      ZnElement(pp.ring_ctx, BigInt(uint64_t{5}))}};
    const multi_exp::Statement statement{ec_point_msm(pp.g, witness.a)};
    const auto proof = multi_exp::prove(pp, statement, witness);
    ASSERT_EQ(proof.left.size(), 1U);
    ASSERT_EQ(proof.right.size(), 1U);
    EXPECT_EQ(proof.left[0], pp.g[0] * witness.a[1]);
    EXPECT_EQ(proof.right[0], pp.g[1] * witness.a[0]);
    EXPECT_TRUE(multi_exp::verify(pp, statement, proof));
}

#ifndef NDEBUG
TEST_F(MultiExponentiationProofTest, RejectsInvalidSetupAndWitnessContracts) {
    EXPECT_DEATH(multi_exp::setup(pp.curve_id, 0), "positive power of two");
    EXPECT_DEATH(multi_exp::setup(pp.curve_id, 3), "positive power of two");
    auto wrong = witness;
    wrong.a.pop_back();
    EXPECT_DEATH(multi_exp::prove(pp, statement, wrong), "witness length");
    auto foreign_ring = std::make_shared<Zn>(BigInt(uint64_t{17}));
    EXPECT_DEATH(multi_exp::setup(pp.group_ctx, foreign_ring, pp.g), "modulus mismatch");
    const auto foreign_group = std::make_shared<ECGroup>(pp.curve_id);
    EXPECT_DEATH(multi_exp::setup(foreign_group, pp.ring_ctx, pp.g), "generator context");
}
#endif

} // namespace
