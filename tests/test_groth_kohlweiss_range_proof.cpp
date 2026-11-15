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
                    gen_random_znelement_vector(pp.subset.ring_ctx, 3)},
                        statement{pp.subset.vector_g} {
        update_statement();
    }
    void update_statement() {
        for (std::size_t i = 0; i < pp.subset.threshold; ++i) {
            statement.commitments[witness.indices[i]] =
                pp.subset.g * witness.randomness[i] + pp.subset.h * witness.values[i];
        }
    }
    gk::Proof empty() const {
        const std::shared_ptr<ECGroup> group = pp.subset.group_ctx;
        const std::shared_ptr<Zn> ring = pp.subset.ring_ctx;
        gk::Proof proof;
        proof.subset.b = ECPoint(group);
        proof.subset.p = ECPoint(group);
        proof.subset.linear_binary = {ECPoint(group), ECPoint(group), ECPoint(group),
            std::vector<ZnElement>(pp.subset.index_g.size(), ZnElement(ring)), ZnElement(ring),
                ZnElement(ring)};
        proof.subset.c_c.assign(pp.subset.index_bits, ECPoint(group));
        proof.subset.c_p.assign(pp.subset.index_bits, ECPoint(group));
        proof.subset.z_g = ZnElement(ring);
        proof.subset.z_p = ZnElement(ring);
        proof.subset.logarithmic_binary = {ECPoint(group), ECPoint(group), ECPoint(group),
            ZnElement(ring), ZnElement(ring), ZnElement(ring),
            {std::vector<ECPoint>(pp.subset.index_bits, ECPoint(group)),
             std::vector<ECPoint>(pp.subset.index_bits, ECPoint(group)), ZnElement(ring),
                 ZnElement(ring)}};
        proof.range = {ECPoint(group), ECPoint(group), ECPoint(group), ECPoint(group),
            ZnElement(ring), ZnElement(ring), ZnElement(ring),
            {std::vector<ECPoint>(pp.range.rounds, ECPoint(group)),
             std::vector<ECPoint>(pp.range.rounds, ECPoint(group)), ZnElement(ring),
                 ZnElement(ring)}};
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
    gk::Witness wrong = witness;
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
    const gk::Proof proof = gk::prove(pp, statement, witness, "a");
    EXPECT_TRUE(gk::verify(pp, statement, proof, "a"));
    EXPECT_FALSE(gk::verify(pp, statement, proof, "b"));
    for (std::size_t j = 0; j < pp.subset.statement_count; ++j) {
        gk::Statement changed = statement;
        changed.commitments[j] = changed.commitments[j] + pp.subset.h;
        EXPECT_FALSE(gk::verify(pp, changed, proof, "a"));
    }
}

TEST_F(GrothKohlweissRangeProofTest, RejectsSplicingAndBridgeTampering) {
    const gk::Proof first = gk::prove(pp, statement, witness);
    const gk::Proof second = gk::prove(pp, statement, witness);
    gk::Proof proof = first;
    proof.range = second.range;
    EXPECT_FALSE(gk::verify(pp, statement, proof));
    proof = first;
    proof.range.t1 = proof.range.t1 + pp.subset.g;
    EXPECT_FALSE(gk::verify(pp, statement, proof));
    proof = first;
    proof.subset.c_c[0] = proof.subset.c_c[0] + pp.subset.g;
    EXPECT_FALSE(gk::verify(pp, statement, proof));
}

TEST_F(GrothKohlweissRangeProofTest, PreservesOriginalProverOnlyAggregateBlindingResponse) {
    gk::Proof proof = gk::prove(pp, statement, witness);
    // z_g supplies the range prover's aggregate blinding. The verifier
    // reconstructs the public aggregate independently of this response.
    proof.subset.z_g += pp.subset.ring_ctx->get_one();
    EXPECT_TRUE(gk::verify(pp, statement, proof));
}

TEST_F(GrothKohlweissRangeProofTest, RejectsDimensionAndNestedProofTampering) {
    const gk::Proof valid = gk::prove(pp, statement, witness);
    gk::Proof proof = valid;
    proof.range.inner_product.left.pop_back();
    EXPECT_FALSE(gk::verify(pp, statement, proof));
    proof = valid;
    proof.subset.linear_binary.f.pop_back();
    EXPECT_FALSE(gk::verify(pp, statement, proof));
    gk::Statement changed = statement;
    changed.commitments.pop_back();
    EXPECT_FALSE(gk::verify(pp, changed, valid));
}

TEST_F(GrothKohlweissRangeProofTest, SerializationAndTruncation) {
    const gk::Proof proof = gk::prove(pp, statement, witness);
    std::stringstream stream;
    stream << proof;
    gk::Proof decoded = empty();
    stream >> decoded;
    ASSERT_TRUE(stream);
    EXPECT_EQ(decoded, proof);
    EXPECT_TRUE(gk::verify(pp, statement, decoded));
    const std::string bytes = stream.str();
    for (std::size_t n = 0; n < bytes.size(); n += 7) {
        std::istringstream input(bytes.substr(0, n));
        decoded = empty();
        input >> decoded;
        ASSERT_TRUE(input.fail());
    }
}

TEST(GrothKohlweissRangeProofStandaloneTest, HandlesThresholdExtremes) {
    for (const std::pair<std::size_t, std::size_t>& dimensions :
         {std::pair<std::size_t, std::size_t>{2U, 1U}, {2U, 2U},
        {4U, 4U}}) {
        const std::size_t n = dimensions.first;
        const std::size_t k = dimensions.second;
        const gk::PublicParameters pp = gk::setup(NID_X9_62_prime256v1, n, k, 4);
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
