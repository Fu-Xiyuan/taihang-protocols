#include <gtest/gtest.h>

#include <cstdint>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <openssl/obj_mac.h>

#include <taihang/zkp/k_out_of_n_protocols/attema_cramer_fehr_proof.hpp>

namespace {

using namespace taihang;
namespace acf = taihang::zkp::k_out_of_n::attema_cramer_fehr;
namespace amortized = taihang::zkp::nizk::amortized_homomorphism;
namespace equality = taihang::zkp::nizk::multi_exponentiation_equality;

acf::Witness make_witness(const acf::PublicParameters& pp) {
    acf::Witness witness;
    for (std::size_t i = 0; i < pp.threshold; ++i) {
        witness.indices.push_back(pp.statement_count - 1 - i);
        witness.secrets.emplace_back(pp.ring_ctx, BigInt(uint64_t{i + 7}));
    }
    return witness;
}

acf::Statement make_statement(const acf::PublicParameters& pp,
                              const acf::Witness& witness) {
    acf::Statement statement{std::vector<ECPoint>(pp.statement_count, ECPoint(pp.group_ctx))};
    for (std::size_t j = 0; j < pp.statement_count; ++j) {
        statement.points[j] = pp.vector_g[j];
    }
    for (std::size_t i = 0; i < pp.threshold; ++i) {
        statement.points[witness.indices[i]] = pp.g * witness.secrets[i];
    }
    return statement;
}

class AttemaCramerFehrProofTest : public ::testing::Test {
protected:
    AttemaCramerFehrProofTest()
        : pp(acf::setup(NID_X9_62_prime256v1, 8, 3)),
          witness(make_witness(pp)), statement(make_statement(pp, witness)) {}

    acf::Proof empty_proof() const {
        return {
            ECPoint(pp.group_ctx),
            {ECPoint(pp.group_ctx), ECPoint(pp.group_ctx), ZnElement(pp.ring_ctx),
             {std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
              std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
              std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
              std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
              ZnElement(pp.ring_ctx)}}
        };
    }

    acf::PublicParameters pp;
    acf::Witness witness;
    acf::Statement statement;
};

TEST_F(AttemaCramerFehrProofTest, SetupCreatesDistinctDeterministicBases) {
    EXPECT_EQ(pp.curve_id, NID_X9_62_prime256v1);
    EXPECT_EQ(pp.statement_count, 8U);
    EXPECT_EQ(pp.threshold, 3U);
    EXPECT_EQ(pp.rounds, 4U);
    ASSERT_EQ(pp.vector_g.size(), 2 * pp.statement_count - pp.threshold);
    EXPECT_EQ(pp.ring_ctx->modulus, pp.group_ctx->order);
    EXPECT_EQ(pp.g.group_ctx, pp.group_ctx.get());
    EXPECT_EQ(pp.h.group_ctx, pp.group_ctx.get());
    EXPECT_FALSE(pp.g.is_at_infinity());
    EXPECT_FALSE(pp.h.is_at_infinity());
    EXPECT_NE(pp.g, pp.h);
    const acf::PublicParameters repeated = acf::setup(pp.curve_id, pp.statement_count,
        pp.threshold);
    EXPECT_EQ(pp.g.to_bytes(), repeated.g.to_bytes());
    EXPECT_EQ(pp.h.to_bytes(), repeated.h.to_bytes());
    for (std::size_t i = 0; i < pp.vector_g.size(); ++i) {
        EXPECT_EQ(pp.vector_g[i].group_ctx, pp.group_ctx.get());
        EXPECT_EQ(pp.vector_g[i].to_bytes(), repeated.vector_g[i].to_bytes());
        EXPECT_FALSE(pp.vector_g[i].is_at_infinity());
        EXPECT_NE(pp.vector_g[i], pp.g);
        EXPECT_NE(pp.vector_g[i], pp.h);
    }
    EXPECT_NE(pp.vector_g[0], pp.vector_g[1]);
}

TEST_F(AttemaCramerFehrProofTest, AcceptsValidProofAndLogarithmicSize) {
    const acf::Proof proof = acf::prove(pp, statement, witness);
    EXPECT_TRUE(acf::verify(pp, statement, proof));
    const equality::Proof& folded = proof.amortized_homomorphism.equality_proof;
    EXPECT_EQ(folded.left_g.size(), pp.rounds);
    EXPECT_EQ(folded.right_g.size(), pp.rounds);
    EXPECT_EQ(folded.left_p.size(), pp.rounds);
    EXPECT_EQ(folded.right_p.size(), pp.rounds);
    std::stringstream stream;
    stream << proof;
    EXPECT_EQ(stream.str().size(), sizeof(std::uint64_t) +
        (3 + 4 * pp.rounds) * pp.group_ctx->get_point_byte_len() +
        2 * pp.ring_ctx->element_byte_len);
}

TEST_F(AttemaCramerFehrProofTest, FreshMasksProduceDifferentValidProofs) {
    const acf::Proof first = acf::prove(pp, statement, witness);
    const acf::Proof second = acf::prove(pp, statement, witness);
    EXPECT_NE(first.p, second.p);
    EXPECT_NE(first, second);
    EXPECT_TRUE(acf::verify(pp, statement, first));
    EXPECT_TRUE(acf::verify(pp, statement, second));
}

TEST_F(AttemaCramerFehrProofTest, SupportsUnsortedNoncontiguousAndBoundaryIndices) {
    acf::Witness changed = witness;
    changed.indices = {7, 0, 3};
    const acf::Statement public_input = make_statement(pp, changed);
    EXPECT_TRUE(acf::verify(pp, public_input, acf::prove(pp, public_input, changed)));
    std::swap(changed.indices[0], changed.indices[2]);
    std::swap(changed.secrets[0], changed.secrets[2]);
    EXPECT_TRUE(acf::verify(pp, public_input, acf::prove(pp, public_input, changed)));
}

TEST_F(AttemaCramerFehrProofTest, AcceptsZeroAndModularBoundarySecrets) {
    acf::Witness changed = witness;
    changed.secrets[0] = pp.ring_ctx->get_zero();
    changed.secrets[1] = ZnElement(pp.ring_ctx, pp.ring_ctx->modulus - kBigIntOne);
    const acf::Statement public_input = make_statement(pp, changed);
    EXPECT_TRUE(public_input.points[changed.indices[0]].is_at_infinity());
    EXPECT_TRUE(acf::verify(pp, public_input, acf::prove(pp, public_input, changed)));
}

TEST_F(AttemaCramerFehrProofTest, NeedsNoSecretsForUnselectedPublicPoints) {
    acf::Statement changed = statement;
    changed.points[0] = pp.group_ctx->get_infinity();
    changed.points[1] = pp.vector_g.back();
    changed.points[2] = pp.h;
    // q(j+1) vanishes at these unselected positions regardless of their points.
    EXPECT_TRUE(acf::verify(pp, changed, acf::prove(pp, changed, witness)));
}

TEST_F(AttemaCramerFehrProofTest, RejectsEveryIncorrectSelectedSecret) {
    for (std::size_t i = 0; i < pp.threshold; ++i) {
        acf::Witness wrong = witness;
        wrong.secrets[i] += pp.ring_ctx->get_one();
        EXPECT_FALSE(acf::verify(pp, statement, acf::prove(pp, statement, wrong)));
    }
}

TEST_F(AttemaCramerFehrProofTest, RejectsUnknownLogarithmAtSelectedIndex) {
    acf::Witness wrong = witness;
    wrong.indices[0] = 0;
    EXPECT_FALSE(acf::verify(pp, statement, acf::prove(pp, statement, wrong)));
}

TEST_F(AttemaCramerFehrProofTest, RejectsChangedSelectedPointBeforeProving) {
    acf::Statement changed = statement;
    changed.points[witness.indices[0]] = changed.points[witness.indices[0]] + pp.h;
    EXPECT_FALSE(acf::verify(pp, changed, acf::prove(pp, changed, witness)));
}

TEST_F(AttemaCramerFehrProofTest, BindsEveryPublicPointAndItsOrder) {
    const acf::Proof proof = acf::prove(pp, statement, witness);
    for (std::size_t j = 0; j < pp.statement_count; ++j) {
        acf::Statement changed = statement;
        changed.points[j] = changed.points[j] + pp.h;
        EXPECT_FALSE(acf::verify(pp, changed, proof));
    }
    acf::Statement changed = statement;
    std::swap(changed.points[0], changed.points[1]);
    EXPECT_FALSE(acf::verify(pp, changed, proof));
}

TEST_F(AttemaCramerFehrProofTest, BindsAssociatedContext) {
    const acf::Proof proof = acf::prove(pp, statement, witness, "session-a");
    EXPECT_TRUE(acf::verify(pp, statement, proof, "session-a"));
    EXPECT_FALSE(acf::verify(pp, statement, proof, "session-b"));
}

TEST_F(AttemaCramerFehrProofTest, BindsScalarBasesAndGeneratorOrder) {
    const acf::Proof proof = acf::prove(pp, statement, witness);
    for (ECPoint acf::PublicParameters::* const member :
         {&acf::PublicParameters::g,
          &acf::PublicParameters::h}) {
        acf::PublicParameters changed = pp;
        changed.*member = changed.*member + pp.vector_g[0];
        EXPECT_FALSE(acf::verify(changed, statement, proof));
    }
    acf::PublicParameters changed = pp;
    std::swap(changed.vector_g[0], changed.vector_g[1]);
    EXPECT_FALSE(acf::verify(changed, statement, proof));
}

TEST_F(AttemaCramerFehrProofTest, RejectsTamperedCommitmentsAndBlindingResponse) {
    const acf::Proof valid = acf::prove(pp, statement, witness);
    acf::Proof proof = valid;
    proof.p = proof.p + pp.h;
    EXPECT_FALSE(acf::verify(pp, statement, proof));
    for (ECPoint amortized::Proof::* const member :
         {&amortized::Proof::a_p,
          &amortized::Proof::a_f}) {
        proof = valid;
        proof.amortized_homomorphism.*member = proof.amortized_homomorphism.*member + pp.g;
        EXPECT_FALSE(acf::verify(pp, statement, proof));
    }
    proof = valid;
    proof.amortized_homomorphism.f += pp.ring_ctx->get_one();
    EXPECT_FALSE(acf::verify(pp, statement, proof));
}

TEST_F(AttemaCramerFehrProofTest, RejectsTamperedFoldingMessagesAndFinalScalar) {
    const acf::Proof valid = acf::prove(pp, statement, witness);
    for (std::vector<ECPoint> equality::Proof::* const member :
         {&equality::Proof::left_g,
          &equality::Proof::right_g,
          &equality::Proof::left_p,
          &equality::Proof::right_p}) {
        for (std::size_t round = 0; round < pp.rounds; ++round) {
            acf::Proof proof = valid;
            std::vector<ECPoint>& messages = proof.amortized_homomorphism.equality_proof.*member;
            messages[round] = messages[round] + pp.h;
            EXPECT_FALSE(acf::verify(pp, statement, proof));
        }
    }
    acf::Proof proof = valid;
    proof.amortized_homomorphism.equality_proof.a += pp.ring_ctx->get_one();
    EXPECT_FALSE(acf::verify(pp, statement, proof));
}

TEST_F(AttemaCramerFehrProofTest, RejectsSplicedSubproofFromAnotherExecution) {
    acf::Proof proof = acf::prove(pp, statement, witness);
    const acf::Proof other = acf::prove(pp, statement, witness);
    proof.amortized_homomorphism = other.amortized_homomorphism;
    EXPECT_FALSE(acf::verify(pp, statement, proof));
}

TEST_F(AttemaCramerFehrProofTest, RejectsMalformedProofAndStatementDimensions) {
    const acf::Proof valid = acf::prove(pp, statement, witness);
    acf::Statement changed = statement;
    changed.points.pop_back();
    EXPECT_FALSE(acf::verify(pp, changed, valid));
    changed = statement;
    changed.points.push_back(pp.h);
    EXPECT_FALSE(acf::verify(pp, changed, valid));
    for (std::vector<ECPoint> equality::Proof::* const member :
         {&equality::Proof::left_g,
          &equality::Proof::right_g,
          &equality::Proof::left_p,
          &equality::Proof::right_p}) {
        acf::Proof proof = valid;
        (proof.amortized_homomorphism.equality_proof.*member).pop_back();
        EXPECT_FALSE(acf::verify(pp, statement, proof));
        proof = valid;
        (proof.amortized_homomorphism.equality_proof.*member).push_back(pp.h);
        EXPECT_FALSE(acf::verify(pp, statement, proof));
    }
}

TEST_F(AttemaCramerFehrProofTest, RejectsMalformedParameterDimensions) {
    const acf::Proof proof = acf::prove(pp, statement, witness);
    for (std::size_t acf::PublicParameters::* const member :
         {&acf::PublicParameters::statement_count,
          &acf::PublicParameters::threshold,
          &acf::PublicParameters::rounds}) {
        acf::PublicParameters changed = pp;
        changed.*member = 0;
        EXPECT_FALSE(acf::verify(changed, statement, proof));
    }
    acf::PublicParameters changed = pp;
    changed.threshold = pp.statement_count + 1;
    EXPECT_FALSE(acf::verify(changed, statement, proof));
    changed = pp;
    changed.vector_g.pop_back();
    EXPECT_FALSE(acf::verify(changed, statement, proof));
    changed = pp;
    changed.statement_count = 3;
    EXPECT_FALSE(acf::verify(changed, statement, proof));
}

TEST_F(AttemaCramerFehrProofTest, SerializationRoundTrip) {
    const acf::Proof proof = acf::prove(pp, statement, witness, "round-trip");
    std::stringstream stream;
    stream << proof;
    acf::Proof decoded = empty_proof();
    stream >> decoded;
    ASSERT_TRUE(stream);
    EXPECT_EQ(decoded, proof);
    EXPECT_TRUE(acf::verify(pp, statement, decoded, "round-trip"));
}

TEST_F(AttemaCramerFehrProofTest, DeserializationRejectsTruncationAcrossEveryField) {
    std::stringstream stream;
    stream << acf::prove(pp, statement, witness);
    const std::string encoded = stream.str();
    for (std::size_t size = 0; size < encoded.size(); ++size) {
        std::istringstream input(encoded.substr(0, size));
        acf::Proof decoded = empty_proof();
        input >> decoded;
        ASSERT_TRUE(input.fail()) << "Truncation size: " << size;
    }
}

TEST_F(AttemaCramerFehrProofTest, DeserializationRejectsUnexpectedFoldingCount) {
    std::stringstream stream;
    stream << acf::prove(pp, statement, witness);
    const std::string encoded = stream.str();
    const std::size_t offset = 3 * pp.group_ctx->get_point_byte_len() +
                               pp.ring_ctx->element_byte_len;
    for (const std::uint64_t count : {std::uint64_t{0},
        std::numeric_limits<std::uint64_t>::max()}) {
        std::string invalid = encoded;
        invalid.replace(offset, sizeof(count), reinterpret_cast<const char*>(&count),
            sizeof(count));
        std::istringstream input(invalid);
        acf::Proof decoded = empty_proof();
        input >> decoded;
        EXPECT_TRUE(input.fail());
        EXPECT_EQ(decoded.amortized_homomorphism.equality_proof.left_g.size(), pp.rounds);
    }
}

TEST_F(AttemaCramerFehrProofTest, DeserializationRejectsNonCanonicalResponseScalars) {
    std::stringstream stream;
    stream << acf::prove(pp, statement, witness);
    const std::string encoded = stream.str();
    const std::vector<uint8_t> modulus = pp.ring_ctx->modulus.to_bytes();
    ASSERT_EQ(modulus.size(), pp.ring_ctx->element_byte_len);
    for (const std::size_t offset : {3 * pp.group_ctx->get_point_byte_len(),
                              encoded.size() - modulus.size()}) {
        std::string invalid = encoded;
        invalid.replace(offset, modulus.size(),
                        reinterpret_cast<const char*>(modulus.data()), modulus.size());
        std::istringstream input(invalid);
        acf::Proof decoded = empty_proof();
        input >> decoded;
        EXPECT_TRUE(input.fail());
    }
}

TEST(AttemaCramerFehrProofStandaloneTest, HandlesSingleStatementAndThresholdBoundaries) {
    for (const std::pair<std::size_t, std::size_t>& dimensions :
         {std::pair<std::size_t, std::size_t>{1U, 1U}, {2U, 1U}, {2U, 2U}, {4U, 1U},
          {4U, 4U}, {8U, 1U},
          {8U, 8U}, {16U, 5U}}) {
        const std::size_t count = dimensions.first;
        const std::size_t threshold = dimensions.second;
        const acf::PublicParameters pp = acf::setup(NID_X9_62_prime256v1, count, threshold);
        acf::Witness witness = make_witness(pp);
        const acf::Statement statement = make_statement(pp, witness);
        EXPECT_TRUE(acf::verify(pp, statement, acf::prove(pp, statement, witness)))
            << "n=" << count << ", k=" << threshold;
        witness.secrets[0] += pp.ring_ctx->get_one();
        EXPECT_FALSE(acf::verify(pp, statement, acf::prove(pp, statement, witness)))
            << "n=" << count << ", k=" << threshold;
    }
}

TEST(AttemaCramerFehrProofStandaloneTest, AcceptsEverySubsetOfFourStatements) {
    // Exercise every nonempty subset, not just consecutive selected positions.
    for (std::size_t mask = 1; mask < 16; ++mask) {
        std::size_t count = 0;
        for (std::size_t j = 0; j < 4; ++j) {
            count += (mask >> j) & 1U;
        }
        const acf::PublicParameters pp = acf::setup(NID_X9_62_prime256v1, 4, count);
        acf::Witness witness;
        for (std::size_t j = 0; j < 4; ++j) {
            if ((mask >> j) & 1U) {
                witness.indices.push_back(j);
                witness.secrets.emplace_back(pp.ring_ctx, BigInt(uint64_t{j + 3}));
            }
        }
        const acf::Statement statement = make_statement(pp, witness);
        EXPECT_TRUE(acf::verify(pp, statement, acf::prove(pp, statement, witness)))
            << "Subset mask: " << mask;
    }
}

#ifndef NDEBUG
TEST_F(AttemaCramerFehrProofTest, RejectsInvalidSetupAndWitnessContracts) {
    EXPECT_DEATH(acf::setup(pp.curve_id, 0, 1), "positive power of two");
    EXPECT_DEATH(acf::setup(pp.curve_id, 3, 1), "positive power of two");
    EXPECT_DEATH(acf::setup(pp.curve_id, 8, 0), "threshold out of range");
    EXPECT_DEATH(acf::setup(pp.curve_id, 8, 9), "threshold out of range");
    acf::Witness wrong = witness;
    wrong.indices.pop_back();
    EXPECT_DEATH(acf::prove(pp, statement, wrong), "witness length");
    wrong = witness;
    wrong.secrets.pop_back();
    EXPECT_DEATH(acf::prove(pp, statement, wrong), "witness length");
    wrong = witness;
    wrong.indices[0] = pp.statement_count;
    EXPECT_DEATH(acf::prove(pp, statement, wrong), "index out of range");
    wrong = witness;
    wrong.indices[0] = wrong.indices[1];
    EXPECT_DEATH(acf::prove(pp, statement, wrong), "indices must be distinct");
    acf::Statement changed = statement;
    changed.points.pop_back();
    EXPECT_DEATH(acf::prove(pp, changed, witness), "statement length");
}
#endif

} // namespace
