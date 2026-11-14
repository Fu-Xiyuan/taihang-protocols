#include <gtest/gtest.h>

#include <cstdint>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <openssl/obj_mac.h>

#include <taihang/zkp/sigma_protocols/amortized_homomorphism_proof.hpp>

namespace {

using namespace taihang;
namespace amortized = taihang::zkp::nizk::amortized_homomorphism;
namespace multi_exp_eq = taihang::zkp::nizk::multi_exponentiation_equality;

/** Build q(X) = product_(j > k) (1-X/j), so q(0)=1 and q(j)=0 off S. */
amortized::Witness make_witness(const amortized::PublicParameters& pp) {
    const ZnElement zero = pp.ring_ctx->get_zero();
    const ZnElement one = pp.ring_ctx->get_one();
    std::vector<ZnElement> polynomial{one};
    for (std::size_t j = pp.threshold + 1; j <= pp.statement_count; ++j) {
        const ZnElement root(pp.ring_ctx, BigInt(uint64_t{j}));
        const ZnElement coefficient = -root.inv();
        std::vector<ZnElement> next(polynomial.size() + 1, zero);
        for (std::size_t i = 0; i < polynomial.size(); ++i) {
            next[i] += polynomial[i];
            next[i + 1] += polynomial[i] * coefficient;
        }
        polynomial = std::move(next);
    }

    amortized::Witness witness{
        std::vector<ZnElement>(pp.vector_length, zero),
        ZnElement(pp.ring_ctx, BigInt(uint64_t{19}))
    };
    const std::size_t degree = pp.statement_count - pp.threshold;
    for (std::size_t i = 0; i < degree; ++i) {
        witness.y[i] = polynomial[i + 1];
    }
    for (std::size_t j = 1; j <= pp.threshold; ++j) {
        const ZnElement index(pp.ring_ctx, BigInt(uint64_t{j}));
        ZnElement value = zero;
        for (std::size_t i = polynomial.size(); i > 0; --i) {
            value = value * index + polynomial[i - 1];
        }
        const ZnElement secret(pp.ring_ctx, BigInt(uint64_t{j + 7}));
        witness.y[degree + j - 1] = secret * value;
    }
    return witness;
}

amortized::Statement make_statement(const amortized::PublicParameters& pp,
                                    const amortized::Witness& witness) {
    amortized::Statement statement{
        ec_point_msm(pp.vector_g, witness.y) + pp.u * witness.r,
        std::vector<ECPoint>(pp.statement_count, ECPoint(pp.group_ctx))
    };
    for (std::size_t j = 1; j <= pp.statement_count; ++j) {
        if (j <= pp.threshold) {
            const ZnElement secret(pp.ring_ctx, BigInt(uint64_t{j + 7}));
            statement.c[j - 1] = pp.g * secret;
        } else {
            statement.c[j - 1] = pp.vector_g[j - 1];
        }
    }
    return statement;
}

class AmortizedHomomorphismProofTest : public ::testing::Test {
protected:
    AmortizedHomomorphismProofTest()
        : pp(amortized::setup(NID_X9_62_prime256v1, 4, 2)),
          witness(make_witness(pp)),
          statement(make_statement(pp, witness)) {}

    amortized::Proof empty_proof() const {
        return {ECPoint(pp.group_ctx), ECPoint(pp.group_ctx), ZnElement(pp.ring_ctx),
                {std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
                 std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
                 std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
                 std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
                 ZnElement(pp.ring_ctx)}};
    }

    amortized::PublicParameters pp;
    amortized::Witness witness;
    amortized::Statement statement;
};

TEST_F(AmortizedHomomorphismProofTest, SetupCreatesDeterministicBasesAndPadding) {
    EXPECT_EQ(pp.curve_id, NID_X9_62_prime256v1);
    EXPECT_EQ(pp.statement_count, 4U);
    EXPECT_EQ(pp.threshold, 2U);
    EXPECT_EQ(pp.vector_length, 8U);
    EXPECT_EQ(pp.rounds, 3U);
    ASSERT_EQ(pp.vector_g.size(), pp.vector_length);
    EXPECT_EQ(pp.ring_ctx->modulus, pp.group_ctx->order);
    EXPECT_FALSE(pp.g.is_at_infinity());
    EXPECT_FALSE(pp.u.is_at_infinity());
    EXPECT_NE(pp.g, pp.u);
    const auto repeated = amortized::setup(pp.curve_id, pp.statement_count, pp.threshold);
    EXPECT_EQ(pp.g.to_bytes(), repeated.g.to_bytes());
    EXPECT_EQ(pp.u.to_bytes(), repeated.u.to_bytes());
    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        EXPECT_EQ(pp.vector_g[i].group_ctx, pp.group_ctx.get());
        EXPECT_EQ(pp.vector_g[i].to_bytes(), repeated.vector_g[i].to_bytes());
        EXPECT_EQ(pp.vector_g[i].is_at_infinity(),
                  i >= pp.vector_length - pp.threshold);
    }
    EXPECT_NE(pp.vector_g[0], pp.vector_g[1]);
    EXPECT_NE(pp.vector_g[0], pp.u);
}

TEST_F(AmortizedHomomorphismProofTest, SetupReusesParentContextsAndPaddedBases) {
    const auto composed = amortized::setup(
        pp.group_ctx, pp.ring_ctx, pp.statement_count, pp.threshold,
        pp.g, pp.u, pp.vector_g);
    EXPECT_EQ(composed.group_ctx.get(), pp.group_ctx.get());
    EXPECT_EQ(composed.ring_ctx.get(), pp.ring_ctx.get());
    EXPECT_EQ(composed.g, pp.g);
    EXPECT_EQ(composed.u, pp.u);
    EXPECT_EQ(composed.vector_g, pp.vector_g);
    EXPECT_TRUE(amortized::verify(
        pp, statement, amortized::prove(composed, statement, witness)));
}

TEST_F(AmortizedHomomorphismProofTest, WitnessSatisfiesEachUnbatchedRelation) {
    const std::size_t degree = pp.statement_count - pp.threshold;
    for (std::size_t j = 1; j <= pp.statement_count; ++j) {
        const ZnElement index(pp.ring_ctx, BigInt(uint64_t{j}));
        ZnElement evaluation = pp.ring_ctx->get_zero();
        for (std::size_t i = degree; i > 0; --i) {
            evaluation = (evaluation + witness.y[i - 1]) * index;
        }
        evaluation += pp.ring_ctx->get_one();
        EXPECT_EQ(statement.c[j - 1] * evaluation,
                  pp.g * witness.y[degree + j - 1]);
    }
}

TEST_F(AmortizedHomomorphismProofTest, AcceptsValidProofAndExpectedSize) {
    const auto proof = amortized::prove(pp, statement, witness);
    EXPECT_TRUE(amortized::verify(pp, statement, proof));
    EXPECT_EQ(proof.equality_proof.left_g.size(), pp.rounds);
    std::stringstream stream;
    stream << proof;
    EXPECT_EQ(stream.str().size(), sizeof(std::uint64_t) +
        (2 + 4 * pp.rounds) * pp.group_ctx->get_point_byte_len() +
        2 * pp.ring_ctx->element_byte_len);
}

TEST_F(AmortizedHomomorphismProofTest, FreshMasksProduceDifferentValidProofs) {
    const auto first = amortized::prove(pp, statement, witness);
    const auto second = amortized::prove(pp, statement, witness);
    EXPECT_NE(first.a_p, second.a_p);
    EXPECT_NE(first.a_f, second.a_f);
    EXPECT_NE(first, second);
    EXPECT_TRUE(amortized::verify(pp, statement, first));
    EXPECT_TRUE(amortized::verify(pp, statement, second));
}

TEST_F(AmortizedHomomorphismProofTest, AcceptsZeroWitnessAndIdentityStatements) {
    auto zero = witness;
    for (auto& scalar : zero.y) scalar = pp.ring_ctx->get_zero();
    zero.r = pp.ring_ctx->get_zero();
    const amortized::Statement identity{
        pp.group_ctx->get_infinity(),
        std::vector<ECPoint>(pp.statement_count, pp.group_ctx->get_infinity())
    };
    EXPECT_TRUE(amortized::verify(
        pp, identity, amortized::prove(pp, identity, zero)));
}

TEST_F(AmortizedHomomorphismProofTest, RejectsIncorrectCommitmentOpening) {
    auto wrong = witness;
    wrong.r += pp.ring_ctx->get_one();
    EXPECT_FALSE(amortized::verify(
        pp, statement, amortized::prove(pp, statement, wrong)));
    auto changed = statement;
    changed.p = changed.p + pp.u;
    EXPECT_FALSE(amortized::verify(
        pp, changed, amortized::prove(pp, changed, witness)));
}

TEST_F(AmortizedHomomorphismProofTest, RejectsCorrectOpeningWithWrongPolynomial) {
    auto wrong = witness;
    wrong.y[0] += pp.ring_ctx->get_one();
    auto changed = statement;
    changed.p = ec_point_msm(pp.vector_g, wrong.y) + pp.u * wrong.r;
    EXPECT_FALSE(amortized::verify(
        pp, changed, amortized::prove(pp, changed, wrong)));
}

TEST_F(AmortizedHomomorphismProofTest, RejectsCorrectOpeningWithWrongHomomorphismValue) {
    auto wrong = witness;
    wrong.y[pp.statement_count - pp.threshold] += pp.ring_ctx->get_one();
    auto changed = statement;
    changed.p = ec_point_msm(pp.vector_g, wrong.y) + pp.u * wrong.r;
    EXPECT_FALSE(amortized::verify(
        pp, changed, amortized::prove(pp, changed, wrong)));
}

TEST_F(AmortizedHomomorphismProofTest, RejectsChangedPublicStatementBeforeProving) {
    auto changed = statement;
    changed.c[0] = changed.c[0] + pp.u;
    EXPECT_FALSE(amortized::verify(
        pp, changed, amortized::prove(pp, changed, witness)));
}

TEST_F(AmortizedHomomorphismProofTest, BindsContextCommitmentAndStatementOrder) {
    const auto proof = amortized::prove(pp, statement, witness, "session-a");
    EXPECT_TRUE(amortized::verify(pp, statement, proof, "session-a"));
    EXPECT_FALSE(amortized::verify(pp, statement, proof, "session-b"));
    auto changed = statement;
    changed.p = changed.p + pp.u;
    EXPECT_FALSE(amortized::verify(pp, changed, proof, "session-a"));
    for (std::size_t j = 0; j < pp.statement_count; ++j) {
        changed = statement;
        changed.c[j] = changed.c[j] + pp.u;
        EXPECT_FALSE(amortized::verify(pp, changed, proof, "session-a"));
    }
    changed = statement;
    std::swap(changed.c[0], changed.c[1]);
    EXPECT_FALSE(amortized::verify(pp, changed, proof, "session-a"));
}

TEST_F(AmortizedHomomorphismProofTest, BindsThresholdAndCommitmentBases) {
    const auto proof = amortized::prove(pp, statement, witness);
    auto changed = pp;
    changed.threshold = 1;
    EXPECT_FALSE(amortized::verify(changed, statement, proof));
    changed = pp;
    changed.g = changed.g + pp.u;
    EXPECT_FALSE(amortized::verify(changed, statement, proof));
    changed = pp;
    changed.u = changed.u + pp.g;
    EXPECT_FALSE(amortized::verify(changed, statement, proof));
    changed = pp;
    std::swap(changed.vector_g[0], changed.vector_g[1]);
    EXPECT_FALSE(amortized::verify(changed, statement, proof));
}

TEST_F(AmortizedHomomorphismProofTest, RejectsTamperedOuterMessagesAndResponse) {
    const auto valid = amortized::prove(pp, statement, witness);
    auto proof = valid;
    proof.a_p = proof.a_p + pp.g;
    EXPECT_FALSE(amortized::verify(pp, statement, proof));
    proof = valid;
    proof.a_f = proof.a_f + pp.g;
    EXPECT_FALSE(amortized::verify(pp, statement, proof));
    proof = valid;
    proof.f += pp.ring_ctx->get_one();
    EXPECT_FALSE(amortized::verify(pp, statement, proof));
}

TEST_F(AmortizedHomomorphismProofTest, RejectsTamperedEmbeddedProof) {
    const auto valid = amortized::prove(pp, statement, witness);
    for (const auto member : {&multi_exp_eq::Proof::left_g,
                              &multi_exp_eq::Proof::right_g,
                              &multi_exp_eq::Proof::left_p,
                              &multi_exp_eq::Proof::right_p}) {
        auto proof = valid;
        (proof.equality_proof.*member)[0] =
            (proof.equality_proof.*member)[0] + pp.g;
        EXPECT_FALSE(amortized::verify(pp, statement, proof));
    }
    auto proof = valid;
    proof.equality_proof.a += pp.ring_ctx->get_one();
    EXPECT_FALSE(amortized::verify(pp, statement, proof));
}

TEST_F(AmortizedHomomorphismProofTest, RejectsMalformedDimensions) {
    const auto valid = amortized::prove(pp, statement, witness);
    auto changed_statement = statement;
    changed_statement.c.pop_back();
    EXPECT_FALSE(amortized::verify(pp, changed_statement, valid));
    for (const auto member : {&multi_exp_eq::Proof::left_g,
                              &multi_exp_eq::Proof::right_g,
                              &multi_exp_eq::Proof::left_p,
                              &multi_exp_eq::Proof::right_p}) {
        auto proof = valid;
        (proof.equality_proof.*member).pop_back();
        EXPECT_FALSE(amortized::verify(pp, statement, proof));
    }
    for (const auto member : {&amortized::PublicParameters::statement_count,
                              &amortized::PublicParameters::threshold,
                              &amortized::PublicParameters::vector_length,
                              &amortized::PublicParameters::rounds}) {
        auto changed = pp;
        changed.*member = 0;
        EXPECT_FALSE(amortized::verify(changed, statement, valid));
    }
    auto changed = pp;
    changed.threshold = pp.statement_count + 1;
    EXPECT_FALSE(amortized::verify(changed, statement, valid));
    changed = pp;
    changed.vector_g.pop_back();
    EXPECT_FALSE(amortized::verify(changed, statement, valid));
}

TEST_F(AmortizedHomomorphismProofTest, SerializationRoundTrip) {
    const auto proof = amortized::prove(pp, statement, witness, "round-trip");
    std::stringstream stream;
    stream << proof;
    auto decoded = empty_proof();
    stream >> decoded;
    ASSERT_TRUE(stream);
    EXPECT_EQ(decoded, proof);
    EXPECT_TRUE(amortized::verify(pp, statement, decoded, "round-trip"));
}

TEST_F(AmortizedHomomorphismProofTest, DeserializationRejectsTruncatedProof) {
    std::stringstream stream;
    stream << amortized::prove(pp, statement, witness);
    const auto encoded = stream.str();
    const std::size_t point_size = pp.group_ctx->get_point_byte_len();
    const std::size_t scalar_size = pp.ring_ctx->element_byte_len;
    for (const std::size_t size : {std::size_t{0}, point_size - 1,
                                  2 * point_size - 1,
                                  2 * point_size + scalar_size - 1,
                                  2 * point_size + scalar_size + 1,
                                  encoded.size() - 1}) {
        std::istringstream input(encoded.substr(0, size));
        auto decoded = empty_proof();
        input >> decoded;
        EXPECT_TRUE(input.fail()) << "Truncation size: " << size;
    }
}

TEST_F(AmortizedHomomorphismProofTest, DeserializationRejectsUnexpectedEmbeddedCount) {
    std::stringstream stream;
    stream << amortized::prove(pp, statement, witness);
    std::string encoded = stream.str();
    const auto count = std::numeric_limits<std::uint64_t>::max();
    const std::size_t offset = 2 * pp.group_ctx->get_point_byte_len() +
                               pp.ring_ctx->element_byte_len;
    encoded.replace(offset, sizeof(count), reinterpret_cast<const char*>(&count),
                    sizeof(count));
    std::istringstream input(encoded);
    auto decoded = empty_proof();
    input >> decoded;
    EXPECT_TRUE(input.fail());
    EXPECT_EQ(decoded.equality_proof.left_g.size(), pp.rounds);
}

TEST_F(AmortizedHomomorphismProofTest, DeserializationRejectsNonCanonicalScalars) {
    std::stringstream stream;
    stream << amortized::prove(pp, statement, witness);
    const auto encoded = stream.str();
    const auto modulus = pp.ring_ctx->modulus.to_bytes();
    ASSERT_EQ(modulus.size(), pp.ring_ctx->element_byte_len);
    for (const std::size_t offset : {2 * pp.group_ctx->get_point_byte_len(),
                                    encoded.size() - modulus.size()}) {
        std::string invalid = encoded;
        invalid.replace(offset, modulus.size(),
                        reinterpret_cast<const char*>(modulus.data()), modulus.size());
        std::istringstream input(invalid);
        auto decoded = empty_proof();
        input >> decoded;
        EXPECT_TRUE(input.fail());
    }
}

TEST(AmortizedHomomorphismProofStandaloneTest, HandlesSmallCountsAndThresholdBoundaries) {
    for (const auto& [count, threshold] :
         {std::pair{1U, 1U}, {2U, 1U}, {4U, 1U}, {4U, 4U}, {8U, 3U}, {8U, 8U}}) {
        const auto pp = amortized::setup(NID_X9_62_prime256v1, count, threshold);
        const auto witness = make_witness(pp);
        const auto statement = make_statement(pp, witness);
        const auto proof = amortized::prove(pp, statement, witness);
        EXPECT_TRUE(amortized::verify(pp, statement, proof))
            << "n=" << count << ", k=" << threshold;
    }
}

#ifndef NDEBUG
TEST_F(AmortizedHomomorphismProofTest, RejectsInvalidSetupAndProverContracts) {
    EXPECT_DEATH(amortized::setup(pp.curve_id, 0, 1), "positive power of two");
    EXPECT_DEATH(amortized::setup(pp.curve_id, 3, 1), "positive power of two");
    EXPECT_DEATH(amortized::setup(pp.curve_id, 4, 0), "threshold out of range");
    EXPECT_DEATH(amortized::setup(pp.curve_id, 4, 5), "threshold out of range");
    auto wrong = witness;
    wrong.y.pop_back();
    EXPECT_DEATH(amortized::prove(pp, statement, wrong), "witness length");
    auto changed = statement;
    changed.c.pop_back();
    EXPECT_DEATH(amortized::prove(pp, changed, witness), "statement length");
    auto shorter = pp.vector_g;
    shorter.pop_back();
    EXPECT_DEATH(amortized::setup(pp.group_ctx, pp.ring_ctx, 4, 2, pp.g, pp.u, shorter),
                 "parameter dimensions");
    EXPECT_DEATH(amortized::setup(nullptr, pp.ring_ctx, 4, 2, pp.g, pp.u, pp.vector_g),
                 "contexts cannot be null");
    const auto foreign_ring = std::make_shared<Zn>(BigInt(uint64_t{17}));
    EXPECT_DEATH(amortized::setup(pp.group_ctx, foreign_ring, 4, 2, pp.g, pp.u, pp.vector_g),
                 "modulus mismatch");
    EXPECT_DEATH(amortized::setup(pp.group_ctx, pp.ring_ctx, 4, 2,
                                 pp.group_ctx->get_infinity(), pp.u, pp.vector_g),
                 "bases cannot be identities");
    const auto foreign_group = std::make_shared<ECGroup>(pp.curve_id);
    const auto foreign_g = foreign_group->get_generator();
    EXPECT_DEATH(amortized::setup(pp.group_ctx, pp.ring_ctx, 4, 2,
                                 foreign_g, pp.u, pp.vector_g), "base context");
    auto foreign = pp.vector_g;
    foreign[0] = foreign_g;
    EXPECT_DEATH(amortized::setup(pp.group_ctx, pp.ring_ctx, 4, 2, pp.g, pp.u, foreign),
                 "generator context");
}
#endif

} // namespace
