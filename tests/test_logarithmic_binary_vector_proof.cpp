#include <gtest/gtest.h>

#include <cstdint>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <openssl/obj_mac.h>

#include <taihang/zkp/sigma_protocols/logarithmic_binary_vector_proof.hpp>

namespace {

using namespace taihang;
namespace binary_vector = taihang::zkp::nizk::logarithmic_binary_vector;
namespace inner_product = taihang::zkp::range_proofs::inner_product;

binary_vector::Statement commit(const binary_vector::PublicParameters& pp,
                                const binary_vector::Witness& witness) {
    return {ec_point_msm(pp.vector_g, witness.a) +
            ec_point_msm(pp.vector_h, witness.b) + pp.u * witness.r};
}

class LogarithmicBinaryVectorProofTest : public ::testing::Test {
protected:
    LogarithmicBinaryVectorProofTest()
        : pp(binary_vector::setup(NID_X9_62_prime256v1, 8)),
          witness{{}, {}, ZnElement(pp.ring_ctx, BigInt(uint64_t{17}))} {
        for (std::size_t i = 0; i < pp.vector_length; ++i) {
            witness.a.emplace_back(pp.ring_ctx, BigInt(uint64_t{i % 2}));
            witness.b.push_back(witness.a.back() - pp.ring_ctx->get_one());
        }
        statement = commit(pp, witness);
    }

    binary_vector::Proof empty_proof() const {
        return {ECPoint(pp.group_ctx), ECPoint(pp.group_ctx), ECPoint(pp.group_ctx),
                ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx),
                {std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
                 std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
                 ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx)}};
    }

    binary_vector::PublicParameters pp;
    binary_vector::Witness witness;
    binary_vector::Statement statement;
};

TEST_F(LogarithmicBinaryVectorProofTest, SetupCreatesDistinctDeterministicGenerators) {
    EXPECT_EQ(pp.curve_id, NID_X9_62_prime256v1);
    EXPECT_EQ(pp.vector_length, 8U);
    EXPECT_EQ(pp.rounds, 3U);
    ASSERT_EQ(pp.vector_g.size(), pp.vector_length);
    ASSERT_EQ(pp.vector_h.size(), pp.vector_length);
    EXPECT_EQ(pp.ring_ctx->modulus, pp.group_ctx->order);
    const binary_vector::PublicParameters repeated = binary_vector::setup(pp.curve_id,
        pp.vector_length);
    EXPECT_EQ(pp.g.to_bytes(), repeated.g.to_bytes());
    EXPECT_EQ(pp.h.to_bytes(), repeated.h.to_bytes());
    EXPECT_EQ(pp.u.to_bytes(), repeated.u.to_bytes());
    EXPECT_EQ(pp.inner_product_u.to_bytes(), repeated.inner_product_u.to_bytes());
    for (const ECPoint* base : {&pp.g, &pp.h, &pp.u, &pp.inner_product_u}) {
        EXPECT_EQ(base->group_ctx, pp.group_ctx.get());
        EXPECT_FALSE(base->is_at_infinity());
    }
    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        EXPECT_EQ(pp.vector_g[i].group_ctx, pp.group_ctx.get());
        EXPECT_EQ(pp.vector_h[i].group_ctx, pp.group_ctx.get());
        EXPECT_EQ(pp.vector_g[i].to_bytes(), repeated.vector_g[i].to_bytes());
        EXPECT_EQ(pp.vector_h[i].to_bytes(), repeated.vector_h[i].to_bytes());
        EXPECT_FALSE(pp.vector_g[i].is_at_infinity());
        EXPECT_FALSE(pp.vector_h[i].is_at_infinity());
        EXPECT_NE(pp.vector_g[i], pp.vector_h[i]);
    }
    EXPECT_NE(pp.g, pp.h);
    EXPECT_NE(pp.u, pp.inner_product_u);
    EXPECT_NE(pp.vector_g[0], pp.vector_g[1]);
    EXPECT_NE(pp.vector_h[0], pp.vector_h[1]);
}

TEST_F(LogarithmicBinaryVectorProofTest, SetupReusesParentContextsAndBases) {
    const binary_vector::PublicParameters composed = binary_vector::setup(
        pp.group_ctx, pp.ring_ctx, pp.g, pp.h, pp.u, pp.inner_product_u,
        pp.vector_g, pp.vector_h);
    EXPECT_EQ(composed.group_ctx.get(), pp.group_ctx.get());
    EXPECT_EQ(composed.ring_ctx.get(), pp.ring_ctx.get());
    EXPECT_EQ(composed.vector_g, pp.vector_g);
    EXPECT_EQ(composed.vector_h, pp.vector_h);
    EXPECT_EQ(composed.g, pp.g);
    EXPECT_EQ(composed.h, pp.h);
    EXPECT_EQ(composed.u, pp.u);
    EXPECT_EQ(composed.inner_product_u, pp.inner_product_u);
    EXPECT_TRUE(binary_vector::verify(
        pp, statement, binary_vector::prove(composed, statement, witness)));
}

TEST_F(LogarithmicBinaryVectorProofTest, AcceptsValidProofAndLogarithmicSize) {
    const binary_vector::Proof proof = binary_vector::prove(pp, statement, witness);
    EXPECT_TRUE(binary_vector::verify(pp, statement, proof));
    EXPECT_EQ(proof.inner_product.left.size(), pp.rounds);
    EXPECT_EQ(proof.inner_product.right.size(), pp.rounds);
    std::stringstream stream;
    stream << proof;
    EXPECT_EQ(stream.str().size(), sizeof(std::uint64_t) +
        (3 + 2 * pp.rounds) * pp.group_ctx->get_point_byte_len() +
        5 * pp.ring_ctx->element_byte_len);
}

TEST_F(LogarithmicBinaryVectorProofTest, FreshMasksProduceDifferentValidProofs) {
    const binary_vector::Proof first = binary_vector::prove(pp, statement, witness);
    const binary_vector::Proof second = binary_vector::prove(pp, statement, witness);
    EXPECT_NE(first.a, second.a);
    EXPECT_NE(first, second);
    EXPECT_TRUE(binary_vector::verify(pp, statement, first));
    EXPECT_TRUE(binary_vector::verify(pp, statement, second));
}

TEST_F(LogarithmicBinaryVectorProofTest, AcceptsAllZeroAndAllOneVectorsWithBoundaryBlindings) {
    for (const std::uint64_t bit : {0U, 1U}) {
        binary_vector::Witness boundary = witness;
        boundary.r = bit == 0 ? pp.ring_ctx->get_zero() :
            ZnElement(pp.ring_ctx, pp.ring_ctx->modulus - kBigIntOne);
        for (std::size_t i = 0; i < pp.vector_length; ++i) {
            boundary.a[i] = ZnElement(pp.ring_ctx, BigInt(bit));
            boundary.b[i] = boundary.a[i] - pp.ring_ctx->get_one();
        }
        const binary_vector::Statement changed = commit(pp, boundary);
        EXPECT_TRUE(binary_vector::verify(
            pp, changed, binary_vector::prove(pp, changed, boundary)));
    }
}

TEST_F(LogarithmicBinaryVectorProofTest, RejectsNonBinaryVectorDespiteCorrectOpeningAndComplement) {
    for (const BigInt& value : {BigInt(uint64_t{2}), pp.ring_ctx->modulus - kBigIntOne}) {
        binary_vector::Witness wrong = witness;
        wrong.a[0] = ZnElement(pp.ring_ctx, value);
        wrong.b[0] = wrong.a[0] - pp.ring_ctx->get_one();
        const binary_vector::Statement changed = commit(pp, wrong);
        EXPECT_FALSE(binary_vector::verify(
            pp, changed, binary_vector::prove(pp, changed, wrong)));
    }
}

TEST_F(LogarithmicBinaryVectorProofTest, RejectsWrongComplementEvenWhenProductsAreZero) {
    binary_vector::Witness wrong = witness;
    wrong.b[0] = pp.ring_ctx->get_zero(); // a_0*b_0=0, but a_0-b_0 != 1.
    const binary_vector::Statement changed = commit(pp, wrong);
    EXPECT_FALSE(binary_vector::verify(
        pp, changed, binary_vector::prove(pp, changed, wrong)));
}

TEST_F(LogarithmicBinaryVectorProofTest, RejectsWrongOpeningOfValidBinaryVectors) {
    binary_vector::Witness wrong = witness;
    wrong.r += pp.ring_ctx->get_one();
    EXPECT_FALSE(binary_vector::verify(
        pp, statement, binary_vector::prove(pp, statement, wrong)));
    wrong = witness;
    wrong.a[0] = pp.ring_ctx->get_one();
    wrong.b[0] = pp.ring_ctx->get_zero();
    EXPECT_FALSE(binary_vector::verify(
        pp, statement, binary_vector::prove(pp, statement, wrong)));
}

TEST_F(LogarithmicBinaryVectorProofTest, BindsAssociatedContextAndPublicCommitment) {
    const binary_vector::Proof proof = binary_vector::prove(pp, statement, witness, "session-a");
    EXPECT_TRUE(binary_vector::verify(pp, statement, proof, "session-a"));
    EXPECT_FALSE(binary_vector::verify(pp, statement, proof, "session-b"));
    const binary_vector::Statement changed{statement.p + pp.u};
    EXPECT_FALSE(binary_vector::verify(pp, changed, proof, "session-a"));
}

TEST_F(LogarithmicBinaryVectorProofTest, BindsAllScalarBasesAndBothGeneratorOrders) {
    const binary_vector::Proof proof = binary_vector::prove(pp, statement, witness);
    for (ECPoint binary_vector::PublicParameters::* const member :
         {&binary_vector::PublicParameters::g,
          &binary_vector::PublicParameters::h,
          &binary_vector::PublicParameters::u,
          &binary_vector::PublicParameters::inner_product_u}) {
        binary_vector::PublicParameters changed = pp;
        changed.*member = changed.*member + pp.vector_g[0];
        EXPECT_FALSE(binary_vector::verify(changed, statement, proof));
    }
    for (std::vector<ECPoint> binary_vector::PublicParameters::* const member :
         {&binary_vector::PublicParameters::vector_g,
          &binary_vector::PublicParameters::vector_h}) {
        binary_vector::PublicParameters changed = pp;
        std::swap((changed.*member)[0], (changed.*member)[1]);
        EXPECT_FALSE(binary_vector::verify(changed, statement, proof));
    }
}

TEST_F(LogarithmicBinaryVectorProofTest, RejectsTamperedOuterPointsAndScalars) {
    const binary_vector::Proof valid = binary_vector::prove(pp, statement, witness);
    for (ECPoint binary_vector::Proof::* const member :
         {&binary_vector::Proof::a,
          &binary_vector::Proof::t1,
          &binary_vector::Proof::t2}) {
        binary_vector::Proof proof = valid;
        proof.*member = proof.*member + pp.g;
        EXPECT_FALSE(binary_vector::verify(pp, statement, proof));
    }
    for (ZnElement binary_vector::Proof::* const member :
         {&binary_vector::Proof::t,
          &binary_vector::Proof::tau,
          &binary_vector::Proof::mu}) {
        binary_vector::Proof proof = valid;
        proof.*member += pp.ring_ctx->get_one();
        EXPECT_FALSE(binary_vector::verify(pp, statement, proof));
    }
}

TEST_F(LogarithmicBinaryVectorProofTest, RejectsTamperedInnerProductProof) {
    const binary_vector::Proof valid = binary_vector::prove(pp, statement, witness);
    for (std::size_t round = 0; round < pp.rounds; ++round) {
        for (std::vector<ECPoint> inner_product::Proof::* const member :
             {&inner_product::Proof::left,
              &inner_product::Proof::right}) {
            binary_vector::Proof proof = valid;
            (proof.inner_product.*member)[round] =
                (proof.inner_product.*member)[round] + pp.g;
            EXPECT_FALSE(binary_vector::verify(pp, statement, proof));
        }
    }
    for (ZnElement inner_product::Proof::* const member :
         {&inner_product::Proof::a,
          &inner_product::Proof::b}) {
        binary_vector::Proof proof = valid;
        proof.inner_product.*member += pp.ring_ctx->get_one();
        EXPECT_FALSE(binary_vector::verify(pp, statement, proof));
    }
}

TEST_F(LogarithmicBinaryVectorProofTest, RejectsMalformedDimensions) {
    const binary_vector::Proof valid = binary_vector::prove(pp, statement, witness);
    for (std::vector<ECPoint> inner_product::Proof::* const member :
         {&inner_product::Proof::left,
          &inner_product::Proof::right}) {
        binary_vector::Proof proof = valid;
        (proof.inner_product.*member).pop_back();
        EXPECT_FALSE(binary_vector::verify(pp, statement, proof));
        proof = valid;
        (proof.inner_product.*member).push_back(pp.g);
        EXPECT_FALSE(binary_vector::verify(pp, statement, proof));
    }
    for (std::vector<ECPoint> binary_vector::PublicParameters::* const member :
         {&binary_vector::PublicParameters::vector_g,
          &binary_vector::PublicParameters::vector_h}) {
        binary_vector::PublicParameters changed = pp;
        (changed.*member).pop_back();
        EXPECT_FALSE(binary_vector::verify(changed, statement, valid));
    }
    binary_vector::PublicParameters changed = pp;
    changed.rounds = 0;
    EXPECT_FALSE(binary_vector::verify(changed, statement, valid));
    changed = pp;
    changed.vector_length = 0;
    EXPECT_FALSE(binary_vector::verify(changed, statement, valid));
    changed = pp;
    changed.vector_length = 3;
    EXPECT_FALSE(binary_vector::verify(changed, statement, valid));
}

TEST_F(LogarithmicBinaryVectorProofTest, SerializationRoundTrip) {
    const binary_vector::Proof proof = binary_vector::prove(pp, statement, witness, "round-trip");
    std::stringstream stream;
    stream << proof;
    binary_vector::Proof decoded = empty_proof();
    stream >> decoded;
    ASSERT_TRUE(stream);
    EXPECT_EQ(decoded, proof);
    EXPECT_TRUE(binary_vector::verify(pp, statement, decoded, "round-trip"));
}

TEST_F(LogarithmicBinaryVectorProofTest, DeserializationRejectsTruncatedProof) {
    std::stringstream stream;
    stream << binary_vector::prove(pp, statement, witness);
    const std::string encoded = stream.str();
    const std::size_t point_size = pp.group_ctx->get_point_byte_len();
    const std::size_t scalar_size = pp.ring_ctx->element_byte_len;
    for (const std::size_t size : {std::size_t{0}, point_size - 1,
                                  2 * point_size - 1, 3 * point_size - 1,
                                  3 * point_size + scalar_size - 1,
                                  3 * point_size + 2 * scalar_size - 1,
                                  3 * point_size + 3 * scalar_size + 1,
                                  encoded.size() - 1}) {
        std::istringstream input(encoded.substr(0, size));
        binary_vector::Proof decoded = empty_proof();
        input >> decoded;
        EXPECT_TRUE(input.fail()) << "Truncation size: " << size;
    }
}

TEST_F(LogarithmicBinaryVectorProofTest, DeserializationRejectsUnexpectedInnerProductCount) {
    std::stringstream stream;
    stream << binary_vector::prove(pp, statement, witness);
    std::string encoded = stream.str();
    const std::uint64_t count = std::numeric_limits<std::uint64_t>::max();
    const std::size_t offset = 3 * pp.group_ctx->get_point_byte_len() +
                               3 * pp.ring_ctx->element_byte_len;
    encoded.replace(offset, sizeof(count), reinterpret_cast<const char*>(&count), sizeof(count));
    std::istringstream input(encoded);
    binary_vector::Proof decoded = empty_proof();
    input >> decoded;
    EXPECT_TRUE(input.fail());
    EXPECT_EQ(decoded.inner_product.left.size(), pp.rounds);
    EXPECT_EQ(decoded.inner_product.right.size(), pp.rounds);
}

TEST_F(LogarithmicBinaryVectorProofTest, DeserializationRejectsNonCanonicalScalars) {
    std::stringstream stream;
    stream << binary_vector::prove(pp, statement, witness);
    const std::string encoded = stream.str();
    const std::vector<uint8_t> modulus = pp.ring_ctx->modulus.to_bytes();
    ASSERT_EQ(modulus.size(), pp.ring_ctx->element_byte_len);
    const std::size_t offset = 3 * pp.group_ctx->get_point_byte_len();
    for (const std::size_t scalar_offset : {offset, offset + modulus.size(),
                                           offset + 2 * modulus.size(),
                                           encoded.size() - 2 * modulus.size(),
                                           encoded.size() - modulus.size()}) {
        std::string invalid = encoded;
        invalid.replace(scalar_offset, modulus.size(),
                        reinterpret_cast<const char*>(modulus.data()), modulus.size());
        std::istringstream input(invalid);
        binary_vector::Proof decoded = empty_proof();
        input >> decoded;
        EXPECT_TRUE(input.fail());
    }
}

TEST(LogarithmicBinaryVectorProofStandaloneTest, HandlesSmallAndSingleElementVectors) {
    for (const std::size_t length : {1U, 2U, 4U, 16U}) {
        const binary_vector::PublicParameters pp = binary_vector::setup(NID_X9_62_prime256v1,
            length);
        for (const std::uint64_t bit : {0U, 1U}) {
            binary_vector::Witness witness{
                std::vector<ZnElement>(length, ZnElement(pp.ring_ctx, BigInt(bit))),
                std::vector<ZnElement>(length,
                    ZnElement(pp.ring_ctx, BigInt(bit)) - pp.ring_ctx->get_one()),
                pp.ring_ctx->get_zero()
            };
            const binary_vector::Statement statement = commit(pp, witness);
            const binary_vector::Proof proof = binary_vector::prove(pp, statement, witness);
            EXPECT_TRUE(binary_vector::verify(pp, statement, proof)) << "Length: " << length;
        }
    }
}

#ifndef NDEBUG
TEST_F(LogarithmicBinaryVectorProofTest, RejectsInvalidSetupAndProverContracts) {
    EXPECT_DEATH(binary_vector::setup(pp.curve_id, 0), "positive power of two");
    EXPECT_DEATH(binary_vector::setup(pp.curve_id, 3), "positive power of two");
    binary_vector::Witness wrong = witness;
    wrong.a.pop_back();
    EXPECT_DEATH(binary_vector::prove(pp, statement, wrong), "witness length");
    wrong = witness;
    wrong.b.pop_back();
    EXPECT_DEATH(binary_vector::prove(pp, statement, wrong), "witness length");
    std::vector<ECPoint> shorter = pp.vector_h;
    shorter.pop_back();
    EXPECT_DEATH(binary_vector::setup(pp.group_ctx, pp.ring_ctx, pp.g, pp.h,
                                     pp.u, pp.inner_product_u, pp.vector_g, shorter),
                 "parameter dimensions");
    EXPECT_DEATH(binary_vector::setup(nullptr, pp.ring_ctx, pp.g, pp.h,
                                     pp.u, pp.inner_product_u, pp.vector_g, pp.vector_h),
                 "contexts cannot be null");
    const std::shared_ptr<Zn> foreign_ring = std::make_shared<Zn>(BigInt(uint64_t{17}));
    EXPECT_DEATH(binary_vector::setup(pp.group_ctx, foreign_ring, pp.g, pp.h,
                                     pp.u, pp.inner_product_u, pp.vector_g, pp.vector_h),
                 "modulus mismatch");
    const std::shared_ptr<ECGroup> foreign_group = std::make_shared<ECGroup>(pp.curve_id);
    const ECPoint foreign_g = foreign_group->get_generator();
    EXPECT_DEATH(binary_vector::setup(pp.group_ctx, pp.ring_ctx, foreign_g, pp.h,
                                     pp.u, pp.inner_product_u, pp.vector_g, pp.vector_h),
                 "base context");
    std::vector<ECPoint> foreign = pp.vector_g;
    foreign[0] = foreign_g;
    EXPECT_DEATH(binary_vector::setup(pp.group_ctx, pp.ring_ctx, pp.g, pp.h,
                                     pp.u, pp.inner_product_u, foreign, pp.vector_h),
                 "generator context");
    const ECPoint identity = pp.group_ctx->get_infinity();
    EXPECT_DEATH(binary_vector::setup(pp.group_ctx, pp.ring_ctx, identity, pp.h,
                                     pp.u, pp.inner_product_u, pp.vector_g, pp.vector_h),
                 "bases cannot be identities");
    std::vector<ECPoint> padded = pp.vector_h;
    padded[0] = identity;
    EXPECT_DEATH(binary_vector::setup(pp.group_ctx, pp.ring_ctx, pp.g, pp.h,
                                     pp.u, pp.inner_product_u, pp.vector_g, padded),
                 "generators cannot be identities");
}
#endif

} // namespace
