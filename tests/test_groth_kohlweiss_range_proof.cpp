#include <gtest/gtest.h>

#include <sstream>
#include <openssl/obj_mac.h>

#include <taihang/zkp/k_out_of_n_protocols/groth_kohlweiss_range_proof.hpp>

namespace {
using namespace taihang;
namespace gk = taihang::zkp::k_out_of_n::groth_kohlweiss_range;
namespace range = taihang::zkp::nizk::aggregate_range;

class GrothKohlweissRangeProofTest : public ::testing::Test {
protected:
    GrothKohlweissRangeProofTest()
        : pp(gk::setup(NID_X9_62_prime256v1, 8, 3, 8)),
          witness{{7, 0, 3}, {ZnElement(pp.subset.ring_ctx, BigInt(uint64_t{0})),
                    ZnElement(pp.subset.ring_ctx, BigInt(uint64_t{17})),
                    ZnElement(pp.subset.ring_ctx, BigInt(uint64_t{255}))},
                    gen_random_znelement_vector(pp.subset.ring_ctx, 3)}, statement{pp.subset.vector_g} {
        update_statement();
    }
    void update_statement() {
        for (std::size_t i = 0; i < pp.subset.threshold; ++i) {
            statement.commitments[witness.indices[i]] =
                pp.subset.g * witness.randomness[i] + pp.subset.h * witness.values[i];
        }
    }
    gk::Proof empty() const {
        const auto group = pp.subset.group_ctx;
        const auto ring = pp.subset.ring_ctx;
        gk::Proof proof;
        proof.subset.b = ECPoint(group);
        proof.subset.p = ECPoint(group);
        proof.subset.linear_binary = {ECPoint(group), ECPoint(group), ECPoint(group),
            std::vector<ZnElement>(pp.subset.index_g.size(), ZnElement(ring)), ZnElement(ring), ZnElement(ring)};
        proof.subset.c_c.assign(pp.subset.index_bits, ECPoint(group));
        proof.subset.c_p.assign(pp.subset.index_bits, ECPoint(group));
        proof.subset.z_g = ZnElement(ring);
        proof.subset.z_p = ZnElement(ring);
        proof.subset.logarithmic_binary = {ECPoint(group), ECPoint(group), ECPoint(group),
            ZnElement(ring), ZnElement(ring), ZnElement(ring),
            {std::vector<ECPoint>(pp.subset.index_bits, ECPoint(group)),
             std::vector<ECPoint>(pp.subset.index_bits, ECPoint(group)), ZnElement(ring), ZnElement(ring)}};
        proof.range = {ECPoint(group), ECPoint(group), ECPoint(group), ECPoint(group), ECPoint(group),
            ZnElement(ring), ZnElement(ring), ZnElement(ring),
            {std::vector<ECPoint>(pp.range.rounds, ECPoint(group)),
             std::vector<ECPoint>(pp.range.rounds, ECPoint(group)), ZnElement(ring), ZnElement(ring)}};
        return proof;
    }
    gk::PublicParameters pp;
    gk::Witness witness;
    gk::Statement statement;
};

TEST_F(GrothKohlweissRangeProofTest, AcceptsArbitraryThresholdAndBoundaryValues) {
    EXPECT_TRUE(gk::verify(pp, statement, gk::prove(pp, statement, witness)));
}

TEST_F(GrothKohlweissRangeProofTest, RejectsOutOfRangeSelectedValue) {
    witness.values[0] = ZnElement(pp.subset.ring_ctx, BigInt(uint64_t{256}));
    update_statement();
    EXPECT_FALSE(gk::verify(pp, statement, gk::prove(pp, statement, witness)));
    witness.values[0] = ZnElement(pp.subset.ring_ctx, pp.subset.ring_ctx->modulus - kBigIntOne);
    update_statement();
    EXPECT_FALSE(gk::verify(pp, statement, gk::prove(pp, statement, witness)));
}

TEST_F(GrothKohlweissRangeProofTest, RejectsWrongOpeningAndSelectedIndex) {
    auto wrong = witness;
    wrong.randomness[0] += pp.subset.ring_ctx->get_one();
    EXPECT_FALSE(gk::verify(pp, statement, gk::prove(pp, statement, wrong)));
    wrong = witness;
    wrong.values[1] += pp.subset.ring_ctx->get_one();
    EXPECT_FALSE(gk::verify(pp, statement, gk::prove(pp, statement, wrong)));
    wrong = witness;
    wrong.indices[0] = 1;
    EXPECT_FALSE(gk::verify(pp, statement, gk::prove(pp, statement, wrong)));
}

TEST_F(GrothKohlweissRangeProofTest, BindsContextAndPublicStatement) {
    const auto proof = gk::prove(pp, statement, witness, "a");
    EXPECT_TRUE(gk::verify(pp, statement, proof, "a"));
    EXPECT_FALSE(gk::verify(pp, statement, proof, "b"));
    for (std::size_t j = 0; j < pp.subset.statement_count; ++j) {
        auto changed = statement;
        changed.commitments[j] = changed.commitments[j] + pp.subset.h;
        EXPECT_FALSE(gk::verify(pp, changed, proof, "a"));
    }
}

TEST_F(GrothKohlweissRangeProofTest, RejectsSplicingAndBridgeTampering) {
    const auto first = gk::prove(pp, statement, witness);
    const auto second = gk::prove(pp, statement, witness);
    auto proof = first;
    proof.range = second.range;
    EXPECT_FALSE(gk::verify(pp, statement, proof));
    proof = first;
    proof.range.aggregate = proof.range.aggregate + pp.subset.g;
    EXPECT_FALSE(gk::verify(pp, statement, proof));
    proof = first;
    proof.subset.z_g += pp.subset.ring_ctx->get_one();
    EXPECT_FALSE(gk::verify(pp, statement, proof));
}

TEST_F(GrothKohlweissRangeProofTest, RejectsDimensionAndNestedProofTampering) {
    const auto valid = gk::prove(pp, statement, witness);
    auto proof = valid;
    proof.range.inner_product.left.pop_back();
    EXPECT_FALSE(gk::verify(pp, statement, proof));
    proof = valid;
    proof.subset.linear_binary.f.pop_back();
    EXPECT_FALSE(gk::verify(pp, statement, proof));
    auto changed = statement;
    changed.commitments.pop_back();
    EXPECT_FALSE(gk::verify(pp, changed, valid));
}

TEST_F(GrothKohlweissRangeProofTest, SerializationAndTruncation) {
    const auto proof = gk::prove(pp, statement, witness);
    std::stringstream stream;
    stream << proof;
    auto decoded = empty();
    stream >> decoded;
    ASSERT_TRUE(stream);
    EXPECT_EQ(decoded, proof);
    EXPECT_TRUE(gk::verify(pp, statement, decoded));
    const auto bytes = stream.str();
    for (std::size_t n = 0; n < bytes.size(); n += 7) {
        std::istringstream input(bytes.substr(0, n));
        decoded = empty();
        input >> decoded;
        ASSERT_TRUE(input.fail());
    }
}

TEST(GrothKohlweissRangeProofStandaloneTest, HandlesThresholdExtremes) {
    for (const auto& [n, k] : {std::pair{2U, 1U}, {2U, 2U}, {4U, 4U}}) {
        const auto pp = gk::setup(NID_X9_62_prime256v1, n, k, 4);
        gk::Witness witness;
        gk::Statement statement{pp.subset.vector_g};
        for (std::size_t j = 0; j < k; ++j) {
            witness.indices.push_back(j);
            witness.values.emplace_back(pp.subset.ring_ctx, BigInt(uint64_t{j}));
            witness.randomness.push_back(pp.subset.ring_ctx->get_zero());
            statement.commitments[j] = pp.subset.h * witness.values.back();
        }
        EXPECT_TRUE(gk::verify(pp, statement, gk::prove(pp, statement, witness)));
    }
}
} // namespace
