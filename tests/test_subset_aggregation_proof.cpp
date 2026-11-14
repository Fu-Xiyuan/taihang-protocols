#include <gtest/gtest.h>

#include <sstream>
#include <openssl/obj_mac.h>

#include <taihang/zkp/sigma_protocols/subset_aggregation_proof.hpp>

namespace {
using namespace taihang;
namespace subset = taihang::zkp::nizk::subset_aggregation;

class SubsetAggregationProofTest : public ::testing::Test {
protected:
    SubsetAggregationProofTest()
        : pp(subset::setup(NID_X9_62_prime256v1, 8, 3)),
          witness{{7, 0, 3}, gen_random_znelement_vector(pp.ring_ctx, 3)},
          values(gen_random_znelement_vector(pp.ring_ctx, 3)), statement{pp.vector_g} {
        for (std::size_t i = 0; i < 3; ++i) {
            statement.commitments[witness.indices[i]] =
                pp.g * witness.randomness[i] + pp.h * values[i];
        }
    }
    subset::Proof empty() const {
        return {ECPoint(pp.group_ctx), ECPoint(pp.group_ctx),
            {ECPoint(pp.group_ctx), ECPoint(pp.group_ctx), ECPoint(pp.group_ctx),
             std::vector<ZnElement>(pp.index_g.size(), ZnElement(pp.ring_ctx)),
             ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx)},
            std::vector<ECPoint>(pp.index_bits, ECPoint(pp.group_ctx)),
            std::vector<ECPoint>(pp.index_bits, ECPoint(pp.group_ctx)),
            ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx),
            {ECPoint(pp.group_ctx), ECPoint(pp.group_ctx), ECPoint(pp.group_ctx),
             ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx),
             {std::vector<ECPoint>(pp.index_bits, ECPoint(pp.group_ctx)),
              std::vector<ECPoint>(pp.index_bits, ECPoint(pp.group_ctx)),
              ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx)}}};
    }
    subset::PublicParameters pp;
    subset::Witness witness;
    std::vector<ZnElement> values;
    subset::Statement statement;
};

TEST_F(SubsetAggregationProofTest, ExtractedAggregateHasTheSelectedWeightedValues) {
    const auto proof = subset::prove(pp, statement, witness, "parent");
    ASSERT_TRUE(subset::verify(pp, statement, proof, "parent"));
    const auto aggregate = subset::detail::aggregate(pp, statement, proof, "parent");
    auto value = pp.ring_ctx->get_zero();
    for (std::size_t i = 0; i < pp.threshold; ++i) {
        value += aggregate.weights[i] * values[i];
    }
    EXPECT_EQ(aggregate.commitment,
              pp.g * (proof.z_g * aggregate.normalization) + pp.h * value);
}

TEST_F(SubsetAggregationProofTest, BindsContextCommitmentsAndPolynomialMessages) {
    const auto valid = subset::prove(pp, statement, witness, "a");
    EXPECT_FALSE(subset::verify(pp, statement, valid, "b"));
    auto changed = statement;
    changed.commitments[0] = changed.commitments[0] + pp.h;
    EXPECT_FALSE(subset::verify(pp, changed, valid, "a"));
    for (auto member : {&subset::Proof::c_c, &subset::Proof::c_p}) {
        auto proof = valid;
        (proof.*member)[0] = (proof.*member)[0] + pp.u;
        EXPECT_FALSE(subset::verify(pp, statement, proof, "a"));
        (proof.*member).pop_back();
        EXPECT_FALSE(subset::verify(pp, statement, proof, "a"));
    }
}

TEST_F(SubsetAggregationProofTest, SerializationAndTruncation) {
    const auto proof = subset::prove(pp, statement, witness);
    std::stringstream stream;
    stream << proof;
    auto decoded = empty();
    stream >> decoded;
    ASSERT_TRUE(stream);
    EXPECT_EQ(proof, decoded);
    const auto bytes = stream.str();
    for (std::size_t n = 0; n < bytes.size(); ++n) {
        std::istringstream input(bytes.substr(0, n));
        decoded = empty();
        input >> decoded;
        ASSERT_TRUE(input.fail());
    }
}
} // namespace
