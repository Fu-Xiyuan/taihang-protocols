#include <gtest/gtest.h>

#include <cstdint>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <openssl/obj_mac.h>

#include <taihang/zkp/sigma_protocols/linear_binary_vector_proof.hpp>

namespace {

using namespace taihang;
namespace binary_vector = taihang::zkp::nizk::linear_binary_vector;

binary_vector::Statement commit(const binary_vector::PublicParameters& pp,
                                const binary_vector::Witness& witness) {
    return {ec_point_msm(pp.vector_g, witness.a) + pp.h * witness.r};
}

class LinearBinaryVectorProofTest : public ::testing::Test {
protected:
    LinearBinaryVectorProofTest()
        : pp(binary_vector::setup(NID_X9_62_prime256v1, 6)),
          witness{{}, ZnElement(pp.ring_ctx, BigInt(uint64_t{17}))} {
        for (std::size_t i = 0; i < pp.vector_length; ++i) {
            witness.a.emplace_back(pp.ring_ctx, BigInt(uint64_t{i % 2}));
        }
        statement = commit(pp, witness);
    }

    binary_vector::Proof empty_proof() const {
        return {ECPoint(pp.group_ctx), ECPoint(pp.group_ctx), ECPoint(pp.group_ctx),
                std::vector<ZnElement>(pp.vector_length, ZnElement(pp.ring_ctx)),
                ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx)};
    }

    binary_vector::PublicParameters pp;
    binary_vector::Witness witness;
    binary_vector::Statement statement;
};

TEST_F(LinearBinaryVectorProofTest, SetupCreatesDistinctDeterministicGenerators) {
    EXPECT_EQ(pp.curve_id, NID_X9_62_prime256v1);
    EXPECT_EQ(pp.vector_length, 6U);
    ASSERT_EQ(pp.vector_g.size(), pp.vector_length);
    EXPECT_EQ(pp.ring_ctx->modulus, pp.group_ctx->order);
    EXPECT_EQ(pp.h.group_ctx, pp.group_ctx.get());
    EXPECT_FALSE(pp.h.is_at_infinity());
    const auto repeated = binary_vector::setup(pp.curve_id, pp.vector_length);
    EXPECT_EQ(pp.h.to_bytes(), repeated.h.to_bytes());
    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        EXPECT_EQ(pp.vector_g[i].group_ctx, pp.group_ctx.get());
        EXPECT_EQ(pp.vector_g[i].to_bytes(), repeated.vector_g[i].to_bytes());
        EXPECT_FALSE(pp.vector_g[i].is_at_infinity());
        EXPECT_NE(pp.vector_g[i], pp.h);
    }
    EXPECT_NE(pp.vector_g[0], pp.vector_g[1]);
}

TEST_F(LinearBinaryVectorProofTest, SetupReusesParentContextsAndBases) {
    const auto composed = binary_vector::setup(
        pp.group_ctx, pp.ring_ctx, pp.h, pp.vector_g);
    EXPECT_EQ(composed.group_ctx.get(), pp.group_ctx.get());
    EXPECT_EQ(composed.ring_ctx.get(), pp.ring_ctx.get());
    EXPECT_EQ(composed.h, pp.h);
    EXPECT_EQ(composed.vector_g, pp.vector_g);
    EXPECT_TRUE(binary_vector::verify(
        pp, statement, binary_vector::prove(composed, statement, witness)));
}

TEST_F(LinearBinaryVectorProofTest, AcceptsValidProofAndLinearSize) {
    const auto proof = binary_vector::prove(pp, statement, witness);
    EXPECT_TRUE(binary_vector::verify(pp, statement, proof));
    EXPECT_EQ(proof.f.size(), pp.vector_length);
    std::stringstream stream;
    stream << proof;
    EXPECT_EQ(stream.str().size(), sizeof(std::uint64_t) +
        3 * pp.group_ctx->get_point_byte_len() +
        (pp.vector_length + 2) * pp.ring_ctx->element_byte_len);
}

TEST_F(LinearBinaryVectorProofTest, FreshMasksProduceDifferentValidProofs) {
    const auto first = binary_vector::prove(pp, statement, witness);
    const auto second = binary_vector::prove(pp, statement, witness);
    EXPECT_NE(first.a, second.a);
    EXPECT_NE(first, second);
    EXPECT_TRUE(binary_vector::verify(pp, statement, first));
    EXPECT_TRUE(binary_vector::verify(pp, statement, second));
}

TEST_F(LinearBinaryVectorProofTest, AcceptsAllZeroAndAllOneVectorsWithBoundaryBlindings) {
    for (const std::uint64_t bit : {0U, 1U}) {
        auto boundary = witness;
        boundary.r = bit == 0 ? pp.ring_ctx->get_zero() :
            ZnElement(pp.ring_ctx, pp.ring_ctx->modulus - kBigIntOne);
        for (auto& scalar : boundary.a) {
            scalar = ZnElement(pp.ring_ctx, BigInt(bit));
        }
        const auto changed = commit(pp, boundary);
        EXPECT_TRUE(binary_vector::verify(
            pp, changed, binary_vector::prove(pp, changed, boundary)));
    }
}

TEST_F(LinearBinaryVectorProofTest, RejectsNonBinaryVectorDespiteCorrectOpening) {
    for (const auto& value : {BigInt(uint64_t{2}), pp.ring_ctx->modulus - kBigIntOne}) {
        auto wrong = witness;
        wrong.a[0] = ZnElement(pp.ring_ctx, value);
        const auto changed = commit(pp, wrong);
        EXPECT_FALSE(binary_vector::verify(
            pp, changed, binary_vector::prove(pp, changed, wrong)));
    }
}

TEST_F(LinearBinaryVectorProofTest, RejectsWrongOpeningOfBinaryVectors) {
    auto wrong = witness;
    wrong.r += pp.ring_ctx->get_one();
    EXPECT_FALSE(binary_vector::verify(
        pp, statement, binary_vector::prove(pp, statement, wrong)));
    wrong = witness;
    wrong.a[0] = pp.ring_ctx->get_one();
    EXPECT_FALSE(binary_vector::verify(
        pp, statement, binary_vector::prove(pp, statement, wrong)));
}

TEST_F(LinearBinaryVectorProofTest, BindsAssociatedContextAndPublicCommitment) {
    const auto proof = binary_vector::prove(pp, statement, witness, "session-a");
    EXPECT_TRUE(binary_vector::verify(pp, statement, proof, "session-a"));
    EXPECT_FALSE(binary_vector::verify(pp, statement, proof, "session-b"));
    const binary_vector::Statement changed{statement.p + pp.h};
    EXPECT_FALSE(binary_vector::verify(pp, changed, proof, "session-a"));
}

TEST_F(LinearBinaryVectorProofTest, BindsBlindingBaseAndGeneratorOrder) {
    const auto proof = binary_vector::prove(pp, statement, witness);
    auto changed = pp;
    changed.h = changed.h + pp.vector_g[0];
    EXPECT_FALSE(binary_vector::verify(changed, statement, proof));
    changed = pp;
    std::swap(changed.vector_g[0], changed.vector_g[1]);
    EXPECT_FALSE(binary_vector::verify(changed, statement, proof));
}

TEST_F(LinearBinaryVectorProofTest, RejectsTamperedCommitmentsAndResponses) {
    const auto valid = binary_vector::prove(pp, statement, witness);
    for (const auto member : {&binary_vector::Proof::a, &binary_vector::Proof::c,
                              &binary_vector::Proof::d}) {
        auto proof = valid;
        proof.*member = proof.*member + pp.h;
        EXPECT_FALSE(binary_vector::verify(pp, statement, proof));
    }
    for (const auto member : {&binary_vector::Proof::z_a, &binary_vector::Proof::z_c}) {
        auto proof = valid;
        proof.*member += pp.ring_ctx->get_one();
        EXPECT_FALSE(binary_vector::verify(pp, statement, proof));
    }
    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        auto proof = valid;
        proof.f[i] += pp.ring_ctx->get_one();
        EXPECT_FALSE(binary_vector::verify(pp, statement, proof));
    }
}

TEST_F(LinearBinaryVectorProofTest, ComposesWithParentChallengeAndConsumesPrivateState) {
    auto state = binary_vector::detail::commit(pp, witness);
    // The parent can use alpha for its own polynomial commitments before x.
    const ECPoint parent_commitment = ec_point_msm(pp.vector_g, state.alpha);
    std::ostringstream transcript;
    transcript << "test/gk-parent" << statement.p << state.a << state.c << state.d
               << parent_commitment;
    ZnElement x = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (x.value.is_zero()) {
        x = pp.ring_ctx->get_one();
    }
    const auto proof = binary_vector::detail::respond(pp, witness, std::move(state), x);
    EXPECT_TRUE(binary_vector::detail::verify_with_challenge(pp, statement, proof, x));
    EXPECT_FALSE(binary_vector::verify(pp, statement, proof));
    EXPECT_TRUE(state.alpha.empty());
    EXPECT_EQ(state.r_a, pp.ring_ctx->get_zero());
    EXPECT_EQ(state.r_c, pp.ring_ctx->get_zero());
    EXPECT_EQ(state.r_d, pp.ring_ctx->get_zero());

    // Check the two response equations independently of standalone hashing.
    EXPECT_EQ(ec_point_msm(pp.vector_g, proof.f) + pp.h * proof.z_a,
              statement.p * x + proof.a);
    std::vector<ZnElement> products(pp.vector_length, pp.ring_ctx->get_zero());
    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        products[i] = proof.f[i] * (x - proof.f[i]);
    }
    EXPECT_EQ(ec_point_msm(pp.vector_g, products) + pp.h * proof.z_c,
              proof.c * x + proof.d);
    EXPECT_FALSE(binary_vector::detail::verify_with_challenge(
        pp, statement, proof, x + pp.ring_ctx->get_one()));
    EXPECT_FALSE(binary_vector::detail::verify_with_challenge(
        pp, statement, proof, pp.ring_ctx->get_zero()));
}

TEST_F(LinearBinaryVectorProofTest, ParentChallengeRejectsNonBinaryOpening) {
    auto wrong = witness;
    wrong.a[0] = ZnElement(pp.ring_ctx, BigInt(uint64_t{2}));
    const auto changed = commit(pp, wrong);
    auto state = binary_vector::detail::commit(pp, wrong);
    const ZnElement x(pp.ring_ctx, BigInt(uint64_t{7}));
    const auto proof = binary_vector::detail::respond(pp, wrong, std::move(state), x);
    EXPECT_FALSE(binary_vector::detail::verify_with_challenge(pp, changed, proof, x));
}

TEST_F(LinearBinaryVectorProofTest, RejectsMalformedDimensions) {
    const auto valid = binary_vector::prove(pp, statement, witness);
    auto proof = valid;
    proof.f.pop_back();
    EXPECT_FALSE(binary_vector::verify(pp, statement, proof));
    EXPECT_FALSE(binary_vector::detail::verify_with_challenge(
        pp, statement, proof, pp.ring_ctx->get_one()));
    proof = valid;
    proof.f.push_back(pp.ring_ctx->get_zero());
    EXPECT_FALSE(binary_vector::verify(pp, statement, proof));
    auto changed = pp;
    changed.vector_g.pop_back();
    EXPECT_FALSE(binary_vector::verify(changed, statement, valid));
    changed = pp;
    changed.vector_length = 0;
    EXPECT_FALSE(binary_vector::verify(changed, statement, valid));
}

TEST_F(LinearBinaryVectorProofTest, SerializationRoundTrip) {
    const auto proof = binary_vector::prove(pp, statement, witness, "round-trip");
    std::stringstream stream;
    stream << proof;
    auto decoded = empty_proof();
    stream >> decoded;
    ASSERT_TRUE(stream);
    EXPECT_EQ(decoded, proof);
    EXPECT_TRUE(binary_vector::verify(pp, statement, decoded, "round-trip"));
}

TEST_F(LinearBinaryVectorProofTest, DeserializationRejectsTruncatedProof) {
    std::stringstream stream;
    stream << binary_vector::prove(pp, statement, witness);
    const auto encoded = stream.str();
    const std::size_t point_size = pp.group_ctx->get_point_byte_len();
    const std::size_t scalar_size = pp.ring_ctx->element_byte_len;
    for (const std::size_t size : {std::size_t{0}, point_size - 1,
                                  2 * point_size - 1, 3 * point_size - 1,
                                  3 * point_size + sizeof(std::uint64_t) - 1,
                                  encoded.size() - 2 * scalar_size - 1,
                                  encoded.size() - scalar_size - 1,
                                  encoded.size() - 1}) {
        std::istringstream input(encoded.substr(0, size));
        auto decoded = empty_proof();
        input >> decoded;
        EXPECT_TRUE(input.fail()) << "Truncation size: " << size;
    }
}

TEST_F(LinearBinaryVectorProofTest, DeserializationRejectsUnexpectedResponseCount) {
    std::stringstream stream;
    stream << binary_vector::prove(pp, statement, witness);
    std::string encoded = stream.str();
    const auto count = std::numeric_limits<std::uint64_t>::max();
    const std::size_t offset = 3 * pp.group_ctx->get_point_byte_len();
    encoded.replace(offset, sizeof(count), reinterpret_cast<const char*>(&count), sizeof(count));
    std::istringstream input(encoded);
    auto decoded = empty_proof();
    input >> decoded;
    EXPECT_TRUE(input.fail());
    EXPECT_EQ(decoded.f.size(), pp.vector_length);
}

TEST_F(LinearBinaryVectorProofTest, DeserializationRejectsNonCanonicalScalars) {
    std::stringstream stream;
    stream << binary_vector::prove(pp, statement, witness);
    const auto encoded = stream.str();
    const auto modulus = pp.ring_ctx->modulus.to_bytes();
    ASSERT_EQ(modulus.size(), pp.ring_ctx->element_byte_len);
    const std::size_t offset = 3 * pp.group_ctx->get_point_byte_len() + sizeof(std::uint64_t);
    for (std::size_t i = 0; i < pp.vector_length + 2; ++i) {
        std::string invalid = encoded;
        invalid.replace(offset + i * modulus.size(), modulus.size(),
                        reinterpret_cast<const char*>(modulus.data()), modulus.size());
        std::istringstream input(invalid);
        auto decoded = empty_proof();
        input >> decoded;
        EXPECT_TRUE(input.fail());
    }
}

TEST(LinearBinaryVectorProofStandaloneTest, HandlesSingleAndNonPowerOfTwoLengths) {
    for (const std::size_t length : {1U, 2U, 3U, 5U, 7U}) {
        const auto pp = binary_vector::setup(NID_X9_62_prime256v1, length);
        for (const std::uint64_t bit : {0U, 1U}) {
            const binary_vector::Witness witness{
                std::vector<ZnElement>(length, ZnElement(pp.ring_ctx, BigInt(bit))),
                pp.ring_ctx->get_zero()
            };
            const auto statement = commit(pp, witness);
            const auto proof = binary_vector::prove(pp, statement, witness);
            EXPECT_TRUE(binary_vector::verify(pp, statement, proof)) << "Length: " << length;
        }
    }
}

#ifndef NDEBUG
TEST_F(LinearBinaryVectorProofTest, RejectsInvalidSetupAndProverContracts) {
    EXPECT_DEATH(binary_vector::setup(pp.curve_id, 0), "length must be positive");
    auto wrong = witness;
    wrong.a.pop_back();
    EXPECT_DEATH(binary_vector::prove(pp, statement, wrong), "witness length");
    EXPECT_DEATH(binary_vector::setup(pp.group_ctx, pp.ring_ctx, pp.h, {}),
                 "parameter dimensions");
    EXPECT_DEATH(binary_vector::setup(nullptr, pp.ring_ctx, pp.h, pp.vector_g),
                 "contexts cannot be null");
    const auto foreign_ring = std::make_shared<Zn>(BigInt(uint64_t{17}));
    EXPECT_DEATH(binary_vector::setup(pp.group_ctx, foreign_ring, pp.h, pp.vector_g),
                 "modulus mismatch");
    const auto foreign_group = std::make_shared<ECGroup>(pp.curve_id);
    const auto foreign_g = foreign_group->get_generator();
    EXPECT_DEATH(binary_vector::setup(pp.group_ctx, pp.ring_ctx, foreign_g, pp.vector_g),
                 "base context");
    auto foreign = pp.vector_g;
    foreign[0] = foreign_g;
    EXPECT_DEATH(binary_vector::setup(pp.group_ctx, pp.ring_ctx, pp.h, foreign),
                 "generator context");
    const auto identity = pp.group_ctx->get_infinity();
    EXPECT_DEATH(binary_vector::setup(pp.group_ctx, pp.ring_ctx, identity, pp.vector_g),
                 "blinding base cannot be an identity");
    auto padded = pp.vector_g;
    padded[0] = identity;
    EXPECT_DEATH(binary_vector::setup(pp.group_ctx, pp.ring_ctx, pp.h, padded),
                 "generators cannot be identities");
}

TEST_F(LinearBinaryVectorProofTest, RejectsZeroChallengeAndConsumedStateContracts) {
    auto state = binary_vector::detail::commit(pp, witness);
    EXPECT_DEATH(binary_vector::detail::respond(
        pp, witness, std::move(state), pp.ring_ctx->get_zero()), "challenge must be nonzero");
    const auto proof = binary_vector::detail::respond(
        pp, witness, std::move(state), pp.ring_ctx->get_one());
    EXPECT_TRUE(binary_vector::detail::verify_with_challenge(
        pp, statement, proof, pp.ring_ctx->get_one()));
    EXPECT_DEATH(binary_vector::detail::respond(
        pp, witness, std::move(state), pp.ring_ctx->get_one()), "state length mismatch");
}
#endif

} // namespace
