#include <gtest/gtest.h>

#include <cstdint>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <openssl/obj_mac.h>

#include <taihang/zkp/sigma_protocols/multi_exponentiation_equality_proof.hpp>

namespace {

using namespace taihang;
namespace multi_exp_eq = taihang::zkp::nizk::multi_exponentiation_equality;

class MultiExponentiationEqualityProofTest : public ::testing::Test {
protected:
    MultiExponentiationEqualityProofTest()
        : pp(multi_exp_eq::setup(NID_X9_62_prime256v1, 8)) {
        for (std::size_t i = 0; i < pp.vector_length; ++i) {
            witness.a.emplace_back(pp.ring_ctx, BigInt(uint64_t{i + 1}));
        }
        statement.g = ec_point_msm(pp.g, witness.a);
        statement.p = ec_point_msm(pp.p, witness.a);
    }

    multi_exp_eq::Proof empty_proof() const {
        return {std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
                std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
                std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
                std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
                ZnElement(pp.ring_ctx)};
    }

    multi_exp_eq::PublicParameters pp;
    multi_exp_eq::Witness witness;
    multi_exp_eq::Statement statement;
};

TEST_F(MultiExponentiationEqualityProofTest, SetupCreatesDistinctDeterministicBases) {
    EXPECT_EQ(pp.curve_id, NID_X9_62_prime256v1);
    EXPECT_EQ(pp.vector_length, 8U);
    EXPECT_EQ(pp.rounds, 3U);
    ASSERT_EQ(pp.g.size(), pp.vector_length);
    ASSERT_EQ(pp.p.size(), pp.vector_length);
    EXPECT_EQ(pp.ring_ctx->modulus, pp.group_ctx->order);
    const auto repeated = multi_exp_eq::setup(pp.curve_id, pp.vector_length);
    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        EXPECT_EQ(pp.g[i].group_ctx, pp.group_ctx.get());
        EXPECT_EQ(pp.p[i].group_ctx, pp.group_ctx.get());
        EXPECT_EQ(pp.g[i].to_bytes(), repeated.g[i].to_bytes());
        EXPECT_EQ(pp.p[i].to_bytes(), repeated.p[i].to_bytes());
        EXPECT_FALSE(pp.g[i].is_at_infinity());
        EXPECT_FALSE(pp.p[i].is_at_infinity());
        EXPECT_NE(pp.g[i], pp.p[i]);
    }
    EXPECT_NE(pp.g[0], pp.g[1]);
    EXPECT_NE(pp.p[0], pp.p[1]);
}

TEST_F(MultiExponentiationEqualityProofTest, SetupReusesParentContextsAndBases) {
    const auto composed = multi_exp_eq::setup(pp.group_ctx, pp.ring_ctx, pp.g, pp.p);
    EXPECT_EQ(composed.group_ctx.get(), pp.group_ctx.get());
    EXPECT_EQ(composed.ring_ctx.get(), pp.ring_ctx.get());
    EXPECT_EQ(composed.g, pp.g);
    EXPECT_EQ(composed.p, pp.p);
    const auto proof = multi_exp_eq::prove(composed, statement, witness);
    EXPECT_TRUE(multi_exp_eq::verify(pp, statement, proof));
}

TEST_F(MultiExponentiationEqualityProofTest, AcceptsIdentityPaddingInParentBases) {
    auto generators_g = pp.g;
    auto generators_p = pp.p;
    generators_g.back() = pp.group_ctx->get_infinity();
    generators_p.back() = pp.group_ctx->get_infinity();
    const auto composed = multi_exp_eq::setup(
        pp.group_ctx, pp.ring_ctx, generators_g, generators_p);
    const multi_exp_eq::Statement padded{ec_point_msm(composed.g, witness.a),
                                       ec_point_msm(composed.p, witness.a)};
    EXPECT_TRUE(multi_exp_eq::verify(
        composed, padded, multi_exp_eq::prove(composed, padded, witness)));
}

TEST_F(MultiExponentiationEqualityProofTest, AcceptsValidProofAndExpectedSize) {
    const auto proof = multi_exp_eq::prove(pp, statement, witness);
    EXPECT_TRUE(multi_exp_eq::verify(pp, statement, proof));
    EXPECT_EQ(proof.left_g.size(), pp.rounds);
    EXPECT_EQ(proof.right_g.size(), pp.rounds);
    EXPECT_EQ(proof.left_p.size(), pp.rounds);
    EXPECT_EQ(proof.right_p.size(), pp.rounds);
    std::stringstream stream;
    stream << proof;
    EXPECT_EQ(stream.str().size(), sizeof(std::uint64_t) +
        4 * pp.rounds * pp.group_ctx->get_point_byte_len() +
        pp.ring_ctx->element_byte_len);
}

TEST_F(MultiExponentiationEqualityProofTest, AcceptsZeroAndModularBoundaryWitnesses) {
    auto boundary = witness;
    for (auto& scalar : boundary.a) scalar = pp.ring_ctx->get_zero();
    multi_exp_eq::Statement changed{pp.group_ctx->get_infinity(),
                                  pp.group_ctx->get_infinity()};
    EXPECT_TRUE(multi_exp_eq::verify(
        pp, changed, multi_exp_eq::prove(pp, changed, boundary)));

    boundary.a[0] = ZnElement(pp.ring_ctx, pp.group_ctx->order - kBigIntOne);
    changed.g = ec_point_msm(pp.g, boundary.a);
    changed.p = ec_point_msm(pp.p, boundary.a);
    EXPECT_TRUE(multi_exp_eq::verify(
        pp, changed, multi_exp_eq::prove(pp, changed, boundary)));
}

TEST_F(MultiExponentiationEqualityProofTest, RejectsDifferentWitnessesForTheTwoRelations) {
    auto other = witness;
    other.a[0] += pp.ring_ctx->get_one();
    const multi_exp_eq::Statement changed{statement.g, ec_point_msm(pp.p, other.a)};
    // Each relation is satisfiable separately; these supplied witnesses differ.
    EXPECT_FALSE(multi_exp_eq::verify(
        pp, changed, multi_exp_eq::prove(pp, changed, witness)));
    EXPECT_FALSE(multi_exp_eq::verify(
        pp, changed, multi_exp_eq::prove(pp, changed, other)));
}

TEST_F(MultiExponentiationEqualityProofTest, RejectsWrongWitnessAndEitherChangedResult) {
    auto wrong = witness;
    wrong.a[0] += pp.ring_ctx->get_one();
    EXPECT_FALSE(multi_exp_eq::verify(
        pp, statement, multi_exp_eq::prove(pp, statement, wrong)));
    const auto proof = multi_exp_eq::prove(pp, statement, witness);
    auto changed = statement;
    changed.g = changed.g + pp.g[0];
    EXPECT_FALSE(multi_exp_eq::verify(pp, changed, proof));
    changed = statement;
    changed.p = changed.p + pp.p[0];
    EXPECT_FALSE(multi_exp_eq::verify(pp, changed, proof));
}

TEST_F(MultiExponentiationEqualityProofTest, RejectsTamperedMessagesAndFinalScalar) {
    const auto valid = multi_exp_eq::prove(pp, statement, witness);
    for (std::size_t round = 0; round < pp.rounds; ++round) {
        for (const auto member : {&multi_exp_eq::Proof::left_g,
                                  &multi_exp_eq::Proof::right_g,
                                  &multi_exp_eq::Proof::left_p,
                                  &multi_exp_eq::Proof::right_p}) {
            auto proof = valid;
            (proof.*member)[round] = (proof.*member)[round] + pp.g[0];
            EXPECT_FALSE(multi_exp_eq::verify(pp, statement, proof));
        }
    }
    auto proof = valid;
    proof.a += pp.ring_ctx->get_one();
    EXPECT_FALSE(multi_exp_eq::verify(pp, statement, proof));
}

TEST_F(MultiExponentiationEqualityProofTest, BindsAssociatedContextAndBothGeneratorOrders) {
    const auto proof = multi_exp_eq::prove(pp, statement, witness, "session-a");
    EXPECT_TRUE(multi_exp_eq::verify(pp, statement, proof, "session-a"));
    EXPECT_FALSE(multi_exp_eq::verify(pp, statement, proof, "session-b"));
    auto changed = pp;
    std::swap(changed.g[0], changed.g[1]);
    EXPECT_FALSE(multi_exp_eq::verify(changed, statement, proof, "session-a"));
    changed = pp;
    std::swap(changed.p[0], changed.p[1]);
    EXPECT_FALSE(multi_exp_eq::verify(changed, statement, proof, "session-a"));
}

TEST_F(MultiExponentiationEqualityProofTest, RejectsMalformedDimensions) {
    const auto valid = multi_exp_eq::prove(pp, statement, witness);
    for (const auto member : {&multi_exp_eq::Proof::left_g,
                              &multi_exp_eq::Proof::right_g,
                              &multi_exp_eq::Proof::left_p,
                              &multi_exp_eq::Proof::right_p}) {
        auto proof = valid;
        (proof.*member).pop_back();
        EXPECT_FALSE(multi_exp_eq::verify(pp, statement, proof));
        proof = valid;
        (proof.*member).push_back(pp.g[0]);
        EXPECT_FALSE(multi_exp_eq::verify(pp, statement, proof));
    }
    auto changed = pp;
    changed.g.pop_back();
    EXPECT_FALSE(multi_exp_eq::verify(changed, statement, valid));
    changed = pp;
    changed.p.pop_back();
    EXPECT_FALSE(multi_exp_eq::verify(changed, statement, valid));
    changed = pp;
    changed.rounds = 0;
    EXPECT_FALSE(multi_exp_eq::verify(changed, statement, valid));
    changed = pp;
    changed.vector_length = 0;
    EXPECT_FALSE(multi_exp_eq::verify(changed, statement, valid));
}

TEST_F(MultiExponentiationEqualityProofTest, SerializationPreservesAllFourMessageVectors) {
    const auto proof = multi_exp_eq::prove(pp, statement, witness, "round-trip");
    ASSERT_NE(proof.left_g, proof.left_p);
    ASSERT_NE(proof.right_g, proof.right_p);
    std::stringstream stream;
    stream << proof;
    auto decoded = empty_proof();
    stream >> decoded;
    ASSERT_TRUE(stream);
    EXPECT_EQ(decoded, proof);
    EXPECT_TRUE(multi_exp_eq::verify(pp, statement, decoded, "round-trip"));
}

TEST_F(MultiExponentiationEqualityProofTest, DeserializationRejectsUnexpectedRoundCount) {
    std::stringstream stream;
    const auto count = std::numeric_limits<std::uint64_t>::max();
    stream.write(reinterpret_cast<const char*>(&count), sizeof(count));
    auto decoded = empty_proof();
    stream >> decoded;
    EXPECT_TRUE(stream.fail());
    EXPECT_EQ(decoded.left_g.size(), pp.rounds);
    EXPECT_EQ(decoded.right_g.size(), pp.rounds);
    EXPECT_EQ(decoded.left_p.size(), pp.rounds);
    EXPECT_EQ(decoded.right_p.size(), pp.rounds);
}

TEST_F(MultiExponentiationEqualityProofTest, DeserializationRejectsTruncatedProof) {
    std::stringstream stream;
    stream << multi_exp_eq::prove(pp, statement, witness);
    const auto encoded = stream.str();
    const std::size_t points_size = pp.rounds * pp.group_ctx->get_point_byte_len();
    // Cut the count, each of the four point vectors, and the final scalar.
    for (const std::size_t size : {std::size_t{0}, sizeof(std::uint64_t) - 1,
                                  sizeof(std::uint64_t) + 1,
                                  sizeof(std::uint64_t) + points_size + 1,
                                  sizeof(std::uint64_t) + 2 * points_size + 1,
                                  sizeof(std::uint64_t) + 3 * points_size + 1,
                                  encoded.size() - 1}) {
        std::istringstream input(encoded.substr(0, size));
        auto decoded = empty_proof();
        input >> decoded;
        EXPECT_TRUE(input.fail()) << "Truncation size: " << size;
    }
}

TEST_F(MultiExponentiationEqualityProofTest, DeserializationRejectsNonCanonicalScalar) {
    std::stringstream stream;
    stream << multi_exp_eq::prove(pp, statement, witness);
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

TEST(MultiExponentiationEqualityProofStandaloneTest, HandlesSingleElementAndExposesItsScalar) {
    const auto pp = multi_exp_eq::setup(NID_X9_62_prime256v1, 1);
    const multi_exp_eq::Witness witness{{ZnElement(pp.ring_ctx, BigInt(uint64_t{7}))}};
    const multi_exp_eq::Statement statement{pp.g[0] * witness.a[0],
                                          pp.p[0] * witness.a[0]};
    const auto proof = multi_exp_eq::prove(pp, statement, witness);
    EXPECT_TRUE(proof.left_g.empty());
    EXPECT_TRUE(proof.right_g.empty());
    EXPECT_TRUE(proof.left_p.empty());
    EXPECT_TRUE(proof.right_p.empty());
    EXPECT_EQ(proof.a, witness.a[0]); // This module does not provide standalone ZK.
    EXPECT_TRUE(multi_exp_eq::verify(pp, statement, proof));
    auto changed = statement;
    changed.g = changed.g + pp.g[0];
    EXPECT_FALSE(multi_exp_eq::verify(pp, changed, proof));
    changed = statement;
    changed.p = changed.p + pp.p[0];
    EXPECT_FALSE(multi_exp_eq::verify(pp, changed, proof));

    std::stringstream stream;
    stream << proof;
    multi_exp_eq::Proof decoded{{}, {}, {}, {}, ZnElement(pp.ring_ctx)};
    stream >> decoded;
    ASSERT_TRUE(stream);
    EXPECT_EQ(decoded, proof);
}

TEST(MultiExponentiationEqualityProofStandaloneTest, TwoElementFoldMatchesBothDirectEquations) {
    const auto pp = multi_exp_eq::setup(NID_X9_62_prime256v1, 2);
    const multi_exp_eq::Witness witness{{ZnElement(pp.ring_ctx, BigInt(uint64_t{3})),
                                       ZnElement(pp.ring_ctx, BigInt(uint64_t{5}))}};
    const multi_exp_eq::Statement statement{ec_point_msm(pp.g, witness.a),
                                          ec_point_msm(pp.p, witness.a)};
    const auto proof = multi_exp_eq::prove(pp, statement, witness);
    ASSERT_EQ(proof.left_g.size(), 1U);
    ASSERT_EQ(proof.right_g.size(), 1U);
    ASSERT_EQ(proof.left_p.size(), 1U);
    ASSERT_EQ(proof.right_p.size(), 1U);
    EXPECT_EQ(proof.left_g[0], pp.g[0] * witness.a[1]);
    EXPECT_EQ(proof.right_g[0], pp.g[1] * witness.a[0]);
    EXPECT_EQ(proof.left_p[0], pp.p[0] * witness.a[1]);
    EXPECT_EQ(proof.right_p[0], pp.p[1] * witness.a[0]);
    EXPECT_TRUE(multi_exp_eq::verify(pp, statement, proof));
}

#ifndef NDEBUG
TEST_F(MultiExponentiationEqualityProofTest, RejectsInvalidSetupAndWitnessContracts) {
    EXPECT_DEATH(multi_exp_eq::setup(pp.curve_id, 0), "positive power of two");
    EXPECT_DEATH(multi_exp_eq::setup(pp.curve_id, 3), "positive power of two");
    auto wrong = witness;
    wrong.a.pop_back();
    EXPECT_DEATH(multi_exp_eq::prove(pp, statement, wrong), "witness length");
    auto shorter = pp.p;
    shorter.pop_back();
    EXPECT_DEATH(multi_exp_eq::setup(pp.group_ctx, pp.ring_ctx, pp.g, shorter),
                 "positive power of two");
    EXPECT_DEATH(multi_exp_eq::setup(nullptr, pp.ring_ctx, pp.g, pp.p),
                 "contexts cannot be null");
    const auto foreign_ring = std::make_shared<Zn>(BigInt(uint64_t{17}));
    EXPECT_DEATH(multi_exp_eq::setup(pp.group_ctx, foreign_ring, pp.g, pp.p),
                 "modulus mismatch");
    const auto foreign_group = std::make_shared<ECGroup>(pp.curve_id);
    auto foreign = pp.g;
    foreign[0] = foreign_group->get_generator();
    EXPECT_DEATH(multi_exp_eq::setup(pp.group_ctx, pp.ring_ctx, foreign, pp.p),
                 "generator context");
    EXPECT_DEATH(multi_exp_eq::setup(pp.group_ctx, pp.ring_ctx, pp.g, foreign),
                 "generator context");
}
#endif

} // namespace
