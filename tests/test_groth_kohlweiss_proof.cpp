#include <gtest/gtest.h>

#include <cstdint>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <openssl/obj_mac.h>

#include <taihang/zkp/k_out_of_n_protocols/groth_kohlweiss_proof.hpp>

namespace {

using namespace taihang;
namespace gk = taihang::zkp::k_out_of_n::groth_kohlweiss;
namespace linear_binary = taihang::zkp::nizk::linear_binary_vector;
namespace logarithmic_binary = taihang::zkp::nizk::logarithmic_binary_vector;
namespace inner_product = taihang::zkp::range_proofs::inner_product;

gk::Witness make_witness(const gk::PublicParameters& pp) {
    gk::Witness witness;
    for (std::size_t i = 0; i < pp.threshold; ++i) {
        witness.indices.push_back(pp.statement_count - 1 - i);
        witness.values.emplace_back(pp.ring_ctx, BigInt(uint64_t{i + 3}));
        witness.randomness.emplace_back(pp.ring_ctx, BigInt(uint64_t{i + 11}));
    }
    return witness;
}

gk::Statement make_statement(const gk::PublicParameters& pp, const gk::Witness& witness) {
    gk::Statement statement{pp.vector_g};
    for (std::size_t i = 0; i < pp.threshold; ++i) {
        statement.commitments[witness.indices[i]] =
            ec_point_msm(pp.g, witness.randomness[i], pp.h, witness.values[i]);
    }
    return statement;
}

class GrothKohlweissProofTest : public ::testing::Test {
protected:
    GrothKohlweissProofTest()
        : pp(gk::setup(NID_X9_62_prime256v1, 8, 3)),
          witness(make_witness(pp)), statement(make_statement(pp, witness)) {}

    gk::Proof empty_proof() const {
        return {
            ECPoint(pp.group_ctx), ECPoint(pp.group_ctx),
            {ECPoint(pp.group_ctx), ECPoint(pp.group_ctx), ECPoint(pp.group_ctx),
             std::vector<ZnElement>(pp.index_g.size(), ZnElement(pp.ring_ctx)),
             ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx)},
            std::vector<ECPoint>(pp.index_bits, ECPoint(pp.group_ctx)),
            std::vector<ECPoint>(pp.index_bits, ECPoint(pp.group_ctx)),
            ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx),
            {ECPoint(pp.group_ctx), ECPoint(pp.group_ctx), ECPoint(pp.group_ctx),
             ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx),
             {std::vector<ECPoint>(pp.index_bits, ECPoint(pp.group_ctx)),
              std::vector<ECPoint>(pp.index_bits, ECPoint(pp.group_ctx)),
              ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx)}}
        };
    }

    gk::PublicParameters pp;
    gk::Witness witness;
    gk::Statement statement;
};

TEST_F(GrothKohlweissProofTest, SetupCreatesDistinctDeterministicBases) {
    EXPECT_EQ(pp.curve_id, NID_X9_62_prime256v1);
    EXPECT_EQ(pp.statement_count, 8U);
    EXPECT_EQ(pp.threshold, 3U);
    EXPECT_EQ(pp.index_bits, 3U);
    ASSERT_EQ(pp.vector_g.size(), pp.statement_count);
    ASSERT_EQ(pp.vector_h.size(), pp.statement_count);
    ASSERT_EQ(pp.index_g.size(), pp.threshold * pp.index_bits);
    EXPECT_EQ(pp.ring_ctx->modulus, pp.group_ctx->order);
    const gk::PublicParameters repeated = gk::setup(pp.curve_id, pp.statement_count, pp.threshold);
    for (ECPoint gk::PublicParameters::* const member :
         {&gk::PublicParameters::g,
          &gk::PublicParameters::h,
          &gk::PublicParameters::u,
          &gk::PublicParameters::inner_product_u}) {
        EXPECT_EQ((pp.*member).group_ctx, pp.group_ctx.get());
        EXPECT_FALSE((pp.*member).is_at_infinity());
        EXPECT_EQ((pp.*member).to_bytes(), (repeated.*member).to_bytes());
    }
    for (std::vector<ECPoint> gk::PublicParameters::* const member :
         {&gk::PublicParameters::vector_g,
          &gk::PublicParameters::vector_h,
          &gk::PublicParameters::index_g}) {
        const std::vector<ECPoint>& generators = pp.*member;
        for (std::size_t i = 0; i < generators.size(); ++i) {
            EXPECT_EQ(generators[i].group_ctx, pp.group_ctx.get());
            EXPECT_FALSE(generators[i].is_at_infinity());
            EXPECT_EQ(generators[i].to_bytes(), (repeated.*member)[i].to_bytes());
        }
        EXPECT_NE(generators[0], generators[1]);
    }
    EXPECT_NE(pp.g, pp.h);
    EXPECT_NE(pp.u, pp.inner_product_u);
    EXPECT_NE(pp.vector_g[0], pp.vector_h[0]);
    EXPECT_NE(pp.vector_g[0], pp.index_g[0]);
}

TEST_F(GrothKohlweissProofTest, AcceptsValidProofAndExpectedSize) {
    const gk::Proof proof = gk::prove(pp, statement, witness);
    EXPECT_TRUE(gk::verify(pp, statement, proof));
    EXPECT_EQ(proof.linear_binary.f.size(), pp.threshold * pp.index_bits);
    EXPECT_EQ(proof.c_c.size(), pp.index_bits);
    EXPECT_EQ(proof.c_p.size(), pp.index_bits);
    EXPECT_EQ(proof.logarithmic_binary.inner_product.left.size(), pp.index_bits);
    std::stringstream stream;
    stream << proof;
    EXPECT_EQ(stream.str().size(), 3 * sizeof(std::uint64_t) +
        (8 + 4 * pp.index_bits) * pp.group_ctx->get_point_byte_len() +
        (pp.threshold * pp.index_bits + 10) * pp.ring_ctx->element_byte_len);
}

TEST_F(GrothKohlweissProofTest, FreshMasksProduceDifferentValidProofs) {
    const gk::Proof first = gk::prove(pp, statement, witness);
    const gk::Proof second = gk::prove(pp, statement, witness);
    EXPECT_NE(first.b, second.b);
    EXPECT_NE(first.p, second.p);
    EXPECT_NE(first, second);
    EXPECT_TRUE(gk::verify(pp, statement, first));
    EXPECT_TRUE(gk::verify(pp, statement, second));
}

TEST_F(GrothKohlweissProofTest, SupportsUnsortedNoncontiguousAndBoundaryIndices) {
    gk::Witness changed = witness;
    changed.indices = {7, 0, 3};
    const gk::Statement public_input = make_statement(pp, changed);
    EXPECT_TRUE(gk::verify(pp, public_input, gk::prove(pp, public_input, changed)));
    std::swap(changed.indices[0], changed.indices[2]);
    std::swap(changed.values[0], changed.values[2]);
    std::swap(changed.randomness[0], changed.randomness[2]);
    EXPECT_TRUE(gk::verify(pp, public_input, gk::prove(pp, public_input, changed)));
}

TEST_F(GrothKohlweissProofTest, AcceptsZeroAndModularBoundaryOpenings) {
    gk::Witness changed = witness;
    changed.values[0] = pp.ring_ctx->get_zero();
    changed.randomness[0] = pp.ring_ctx->get_zero();
    changed.values[1] = ZnElement(pp.ring_ctx, pp.ring_ctx->modulus - kBigIntOne);
    changed.randomness[1] = changed.values[1];
    const gk::Statement public_input = make_statement(pp, changed);
    EXPECT_TRUE(public_input.commitments[changed.indices[0]].is_at_infinity());
    EXPECT_TRUE(gk::verify(pp, public_input, gk::prove(pp, public_input, changed)));
}

TEST_F(GrothKohlweissProofTest, RejectsWrongValuesAndRandomness) {
    for (std::size_t i = 0; i < pp.threshold; ++i) {
        gk::Witness wrong = witness;
        wrong.values[i] += pp.ring_ctx->get_one();
        EXPECT_FALSE(gk::verify(pp, statement, gk::prove(pp, statement, wrong)));
        wrong = witness;
        wrong.randomness[i] += pp.ring_ctx->get_one();
        EXPECT_FALSE(gk::verify(pp, statement, gk::prove(pp, statement, wrong)));
    }
}

TEST_F(GrothKohlweissProofTest, RejectsUnknownOpeningAtSelectedIndex) {
    gk::Witness wrong = witness;
    wrong.indices[0] = 0;
    EXPECT_FALSE(gk::verify(pp, statement, gk::prove(pp, statement, wrong)));
}

TEST_F(GrothKohlweissProofTest, BindsEveryPublicCommitmentAndItsOrder) {
    const gk::Proof proof = gk::prove(pp, statement, witness);
    for (std::size_t j = 0; j < pp.statement_count; ++j) {
        gk::Statement changed = statement;
        changed.commitments[j] = changed.commitments[j] + pp.h;
        EXPECT_FALSE(gk::verify(pp, changed, proof));
    }
    gk::Statement changed = statement;
    std::swap(changed.commitments[0], changed.commitments[1]);
    EXPECT_FALSE(gk::verify(pp, changed, proof));
    changed = statement;
    changed.commitments[witness.indices[0]] = changed.commitments[witness.indices[0]] + pp.u;
    EXPECT_FALSE(gk::verify(pp, changed, gk::prove(pp, changed, witness)));
}

TEST_F(GrothKohlweissProofTest, BindsAssociatedContext) {
    const gk::Proof proof = gk::prove(pp, statement, witness, "session-a");
    EXPECT_TRUE(gk::verify(pp, statement, proof, "session-a"));
    EXPECT_FALSE(gk::verify(pp, statement, proof, "session-b"));
}

TEST_F(GrothKohlweissProofTest, BindsScalarBasesAndAllGeneratorOrders) {
    const gk::Proof proof = gk::prove(pp, statement, witness);
    for (ECPoint gk::PublicParameters::* const member :
         {&gk::PublicParameters::g,
          &gk::PublicParameters::h,
          &gk::PublicParameters::u,
          &gk::PublicParameters::inner_product_u}) {
        gk::PublicParameters changed = pp;
        changed.*member = changed.*member + pp.vector_g[0];
        EXPECT_FALSE(gk::verify(changed, statement, proof));
    }
    for (std::vector<ECPoint> gk::PublicParameters::* const member :
         {&gk::PublicParameters::vector_g,
          &gk::PublicParameters::vector_h,
          &gk::PublicParameters::index_g}) {
        gk::PublicParameters changed = pp;
        std::swap((changed.*member)[0], (changed.*member)[1]);
        EXPECT_FALSE(gk::verify(changed, statement, proof));
    }
}

TEST_F(GrothKohlweissProofTest, RejectsTamperedCommitmentsAndOuterResponses) {
    const gk::Proof valid = gk::prove(pp, statement, witness);
    for (ECPoint gk::Proof::* const member :
         {&gk::Proof::b,
          &gk::Proof::p}) {
        gk::Proof proof = valid;
        proof.*member = proof.*member + pp.u;
        EXPECT_FALSE(gk::verify(pp, statement, proof));
    }
    for (std::vector<ECPoint> gk::Proof::* const member :
         {&gk::Proof::c_c,
          &gk::Proof::c_p}) {
        for (std::size_t degree = 0; degree < pp.index_bits; ++degree) {
            gk::Proof proof = valid;
            (proof.*member)[degree] = (proof.*member)[degree] + pp.u;
            EXPECT_FALSE(gk::verify(pp, statement, proof));
        }
    }
    for (ZnElement gk::Proof::* const member :
         {&gk::Proof::z_g,
          &gk::Proof::z_h,
          &gk::Proof::z_p}) {
        gk::Proof proof = valid;
        proof.*member += pp.ring_ctx->get_one();
        EXPECT_FALSE(gk::verify(pp, statement, proof));
    }
}

TEST_F(GrothKohlweissProofTest, PreservesOriginalPolynomialCommitmentRerandomization) {
    gk::Proof proof = gk::prove(pp, statement, witness);
    // The original x precedes the polynomial commitments. Reblinding C_p,0
    // and its response together preserves the same selector relation.
    proof.c_p[0] = proof.c_p[0] + pp.u;
    proof.z_p += pp.ring_ctx->get_one();
    EXPECT_TRUE(gk::verify(pp, statement, proof));
}

TEST_F(GrothKohlweissProofTest, RejectsTamperedLinearBinaryProof) {
    const gk::Proof valid = gk::prove(pp, statement, witness);
    for (ECPoint linear_binary::Proof::* const member :
         {&linear_binary::Proof::a,
          &linear_binary::Proof::c,
          &linear_binary::Proof::d}) {
        gk::Proof proof = valid;
        proof.linear_binary.*member = proof.linear_binary.*member + pp.u;
        EXPECT_FALSE(gk::verify(pp, statement, proof));
    }
    for (ZnElement linear_binary::Proof::* const member :
         {&linear_binary::Proof::z_a,
          &linear_binary::Proof::z_c}) {
        gk::Proof proof = valid;
        proof.linear_binary.*member += pp.ring_ctx->get_one();
        EXPECT_FALSE(gk::verify(pp, statement, proof));
    }
    for (std::size_t i = 0; i < pp.index_g.size(); ++i) {
        gk::Proof proof = valid;
        proof.linear_binary.f[i] += pp.ring_ctx->get_one();
        EXPECT_FALSE(gk::verify(pp, statement, proof));
    }
}

TEST_F(GrothKohlweissProofTest, RejectsTamperedLogarithmicBinaryProof) {
    const gk::Proof valid = gk::prove(pp, statement, witness);
    for (ECPoint logarithmic_binary::Proof::* const member :
         {&logarithmic_binary::Proof::a,
          &logarithmic_binary::Proof::t1,
          &logarithmic_binary::Proof::t2}) {
        gk::Proof proof = valid;
        proof.logarithmic_binary.*member = proof.logarithmic_binary.*member + pp.u;
        EXPECT_FALSE(gk::verify(pp, statement, proof));
    }
    for (ZnElement logarithmic_binary::Proof::* const member :
         {&logarithmic_binary::Proof::t,
          &logarithmic_binary::Proof::tau,
          &logarithmic_binary::Proof::mu}) {
        gk::Proof proof = valid;
        proof.logarithmic_binary.*member += pp.ring_ctx->get_one();
        EXPECT_FALSE(gk::verify(pp, statement, proof));
    }
    for (std::vector<ECPoint> inner_product::Proof::* const member :
         {&inner_product::Proof::left,
          &inner_product::Proof::right}) {
        gk::Proof proof = valid;
        (proof.logarithmic_binary.inner_product.*member)[0] =
            (proof.logarithmic_binary.inner_product.*member)[0] + pp.u;
        EXPECT_FALSE(gk::verify(pp, statement, proof));
    }
    for (ZnElement inner_product::Proof::* const member :
         {&inner_product::Proof::a,
          &inner_product::Proof::b}) {
        gk::Proof proof = valid;
        proof.logarithmic_binary.inner_product.*member += pp.ring_ctx->get_one();
        EXPECT_FALSE(gk::verify(pp, statement, proof));
    }
}

TEST_F(GrothKohlweissProofTest, RejectsSplicedSubproofFromAnotherExecution) {
    const gk::Proof first = gk::prove(pp, statement, witness);
    const gk::Proof second = gk::prove(pp, statement, witness);
    gk::Proof proof = first;
    proof.linear_binary = second.linear_binary;
    EXPECT_FALSE(gk::verify(pp, statement, proof));
    proof = first;
    proof.logarithmic_binary = second.logarithmic_binary;
    EXPECT_FALSE(gk::verify(pp, statement, proof));
}

TEST_F(GrothKohlweissProofTest, RejectsMalformedProofAndStatementDimensions) {
    const gk::Proof valid = gk::prove(pp, statement, witness);
    gk::Statement changed = statement;
    changed.commitments.pop_back();
    EXPECT_FALSE(gk::verify(pp, changed, valid));
    changed = statement;
    changed.commitments.push_back(pp.u);
    EXPECT_FALSE(gk::verify(pp, changed, valid));
    for (std::vector<ECPoint> gk::Proof::* const member :
         {&gk::Proof::c_c,
          &gk::Proof::c_p}) {
        gk::Proof proof = valid;
        (proof.*member).pop_back();
        EXPECT_FALSE(gk::verify(pp, statement, proof));
        proof = valid;
        (proof.*member).push_back(pp.u);
        EXPECT_FALSE(gk::verify(pp, statement, proof));
    }
    gk::Proof proof = valid;
    proof.linear_binary.f.pop_back();
    EXPECT_FALSE(gk::verify(pp, statement, proof));
    proof = valid;
    proof.linear_binary.f.push_back(pp.ring_ctx->get_zero());
    EXPECT_FALSE(gk::verify(pp, statement, proof));
    for (std::vector<ECPoint> inner_product::Proof::* const member :
         {&inner_product::Proof::left,
          &inner_product::Proof::right}) {
        proof = valid;
        (proof.logarithmic_binary.inner_product.*member).pop_back();
        EXPECT_FALSE(gk::verify(pp, statement, proof));
    }
}

TEST_F(GrothKohlweissProofTest, RejectsMalformedParameterDimensions) {
    const gk::Proof proof = gk::prove(pp, statement, witness);
    for (std::size_t gk::PublicParameters::* const member :
         {&gk::PublicParameters::statement_count,
          &gk::PublicParameters::threshold,
          &gk::PublicParameters::index_bits}) {
        gk::PublicParameters changed = pp;
        changed.*member = 0;
        EXPECT_FALSE(gk::verify(changed, statement, proof));
    }
    gk::PublicParameters changed = pp;
    changed.threshold = pp.statement_count + 1;
    EXPECT_FALSE(gk::verify(changed, statement, proof));
    changed = pp;
    changed.threshold = 2;
    EXPECT_FALSE(gk::verify(changed, statement, proof));
    for (std::vector<ECPoint> gk::PublicParameters::* const member :
         {&gk::PublicParameters::vector_g,
          &gk::PublicParameters::vector_h,
          &gk::PublicParameters::index_g}) {
        changed = pp;
        (changed.*member).pop_back();
        EXPECT_FALSE(gk::verify(changed, statement, proof));
    }
}

TEST_F(GrothKohlweissProofTest, SerializationRoundTrip) {
    const gk::Proof proof = gk::prove(pp, statement, witness, "round-trip");
    std::stringstream stream;
    stream << proof;
    gk::Proof decoded = empty_proof();
    stream >> decoded;
    ASSERT_TRUE(stream);
    EXPECT_EQ(decoded, proof);
    EXPECT_TRUE(gk::verify(pp, statement, decoded, "round-trip"));
}

TEST_F(GrothKohlweissProofTest, DeserializationRejectsTruncationAcrossEveryField) {
    std::stringstream stream;
    stream << gk::prove(pp, statement, witness);
    const std::string encoded = stream.str();
    // Cutting every byte boundary covers both nested proof encodings too.
    for (std::size_t size = 0; size < encoded.size(); ++size) {
        std::istringstream input(encoded.substr(0, size));
        gk::Proof decoded = empty_proof();
        input >> decoded;
        ASSERT_TRUE(input.fail()) << "Truncation size: " << size;
    }
}

TEST_F(GrothKohlweissProofTest, DeserializationRejectsAllUnexpectedVectorCounts) {
    std::stringstream stream;
    stream << gk::prove(pp, statement, witness);
    const std::string encoded = stream.str();
    const std::size_t point_size = pp.group_ctx->get_point_byte_len();
    const std::size_t scalar_size = pp.ring_ctx->element_byte_len;
    const std::size_t linear_count = 5 * point_size;
    const std::size_t polynomial_count = linear_count + sizeof(std::uint64_t) +
        (pp.index_g.size() + 2) * scalar_size;
    const std::size_t inner_count = polynomial_count + sizeof(std::uint64_t) +
        (2 * pp.index_bits + 3) * point_size + 6 * scalar_size;
    for (const std::size_t offset : {linear_count, polynomial_count, inner_count}) {
        for (const std::uint64_t count : {std::uint64_t{0},
                                          std::numeric_limits<std::uint64_t>::max()}) {
            std::string invalid = encoded;
            invalid.replace(offset, sizeof(count), reinterpret_cast<const char*>(&count),
                sizeof(count));
            std::istringstream input(invalid);
            gk::Proof decoded = empty_proof();
            input >> decoded;
            EXPECT_TRUE(input.fail());
            EXPECT_EQ(decoded.c_c.size(), pp.index_bits);
            EXPECT_EQ(decoded.c_p.size(), pp.index_bits);
        }
    }
}

TEST_F(GrothKohlweissProofTest, DeserializationRejectsNonCanonicalResponseScalars) {
    std::stringstream stream;
    stream << gk::prove(pp, statement, witness);
    const std::string encoded = stream.str();
    const std::vector<uint8_t> modulus = pp.ring_ctx->modulus.to_bytes();
    const std::size_t point_size = pp.group_ctx->get_point_byte_len();
    const std::size_t scalar_size = pp.ring_ctx->element_byte_len;
    const std::size_t linear_start = 5 * point_size + sizeof(std::uint64_t);
    const std::size_t outer_start = linear_start + (pp.index_g.size() + 2) * scalar_size +
        sizeof(std::uint64_t) + 2 * pp.index_bits * point_size;
    for (const std::size_t offset : {linear_start, outer_start, outer_start + scalar_size,
                              outer_start + 2 * scalar_size, encoded.size() - scalar_size}) {
        std::string invalid = encoded;
        invalid.replace(offset, modulus.size(),
                        reinterpret_cast<const char*>(modulus.data()), modulus.size());
        std::istringstream input(invalid);
        gk::Proof decoded = empty_proof();
        input >> decoded;
        EXPECT_TRUE(input.fail());
    }
}

TEST(GrothKohlweissProofStandaloneTest, HandlesSmallCountsAndThresholdBoundaries) {
    for (const std::pair<std::size_t, std::size_t>& dimensions :
         {std::pair<std::size_t, std::size_t>{2U, 1U}, {2U, 2U}, {4U, 1U}, {4U, 4U},
          {8U, 1U}, {8U, 8U}, {16U, 5U}}) {
        const std::size_t count = dimensions.first;
        const std::size_t threshold = dimensions.second;
        const gk::PublicParameters pp = gk::setup(NID_X9_62_prime256v1, count, threshold);
        const gk::Witness witness = make_witness(pp);
        const gk::Statement statement = make_statement(pp, witness);
        EXPECT_TRUE(gk::verify(pp, statement, gk::prove(pp, statement, witness)))
            << "n=" << count << ", k=" << threshold;
    }
}

#ifndef NDEBUG
TEST_F(GrothKohlweissProofTest, RejectsInvalidSetupAndWitnessContracts) {
    for (const std::size_t count : {0U, 1U, 3U}) {
        EXPECT_DEATH(gk::setup(pp.curve_id, count, 1), "power of two at least two");
    }
    EXPECT_DEATH(gk::setup(pp.curve_id, 8, 0), "threshold out of range");
    EXPECT_DEATH(gk::setup(pp.curve_id, 8, 9), "threshold out of range");
    gk::Witness wrong = witness;
    wrong.indices.pop_back();
    EXPECT_DEATH(gk::prove(pp, statement, wrong), "witness length");
    wrong = witness;
    wrong.values.pop_back();
    EXPECT_DEATH(gk::prove(pp, statement, wrong), "witness length");
    wrong = witness;
    wrong.randomness.pop_back();
    EXPECT_DEATH(gk::prove(pp, statement, wrong), "witness length");
    wrong = witness;
    wrong.indices[0] = pp.statement_count;
    EXPECT_DEATH(gk::prove(pp, statement, wrong), "index out of range");
    wrong = witness;
    wrong.indices[0] = wrong.indices[1];
    EXPECT_DEATH(gk::prove(pp, statement, wrong), "indices must be distinct");
    gk::Statement changed = statement;
    changed.commitments.pop_back();
    EXPECT_DEATH(gk::prove(pp, changed, witness), "statement length");
}
#endif

} // namespace
