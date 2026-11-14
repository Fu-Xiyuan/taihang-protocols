#include <gtest/gtest.h>

#include <sstream>
#include <openssl/obj_mac.h>

#include <taihang/zkp/sigma_protocols/homomorphism_evaluation_proof.hpp>

namespace {
using namespace taihang;
namespace evaluation = taihang::zkp::nizk::homomorphism_evaluation;
namespace equality = taihang::zkp::nizk::multi_exponentiation_equality;

class HomomorphismEvaluationProofTest : public ::testing::Test {
protected:
    HomomorphismEvaluationProofTest()
        : pp(evaluation::setup(NID_X9_62_prime256v1, 8)),
          witness{gen_random_znelement_vector(pp.ring_ctx, 8), pp.ring_ctx->gen_random()},
          statement{ec_point_msm(pp.vector_g, witness.a) + pp.u * witness.r,
                    pp.group_ctx->get_infinity(), pp.group_ctx->gen_random(8)} {
        statement.q = ec_point_msm(statement.bases, witness.a);
    }
    evaluation::Proof empty() const {
        return {ECPoint(pp.group_ctx), ECPoint(pp.group_ctx), ZnElement(pp.ring_ctx),
            {std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
             std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
             std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
             std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)), ZnElement(pp.ring_ctx)}};
    }
    evaluation::PublicParameters pp;
    evaluation::Witness witness;
    evaluation::Statement statement;
};

TEST_F(HomomorphismEvaluationProofTest, AcceptsAndReusesParentContexts) {
    auto composed = evaluation::setup(pp.group_ctx, pp.ring_ctx, pp.u, pp.vector_g);
    EXPECT_EQ(composed.group_ctx.get(), pp.group_ctx.get());
    EXPECT_EQ(composed.ring_ctx.get(), pp.ring_ctx.get());
    EXPECT_TRUE(evaluation::verify(pp, statement, evaluation::prove(composed, statement, witness)));
}

TEST_F(HomomorphismEvaluationProofTest, RejectsWrongOpeningOrImage) {
    auto wrong = witness;
    wrong.r += pp.ring_ctx->get_one();
    EXPECT_FALSE(evaluation::verify(pp, statement, evaluation::prove(pp, statement, wrong)));
    auto changed = statement;
    changed.q = changed.q + pp.u;
    EXPECT_FALSE(evaluation::verify(pp, changed, evaluation::prove(pp, changed, witness)));
}

TEST_F(HomomorphismEvaluationProofTest, BindsContextImageBasesAndCommitment) {
    const auto proof = evaluation::prove(pp, statement, witness, "a");
    EXPECT_TRUE(evaluation::verify(pp, statement, proof, "a"));
    EXPECT_FALSE(evaluation::verify(pp, statement, proof, "b"));
    auto changed = statement;
    std::swap(changed.bases[0], changed.bases[1]);
    EXPECT_FALSE(evaluation::verify(pp, changed, proof, "a"));
    changed = statement;
    changed.p = changed.p + pp.u;
    EXPECT_FALSE(evaluation::verify(pp, changed, proof, "a"));
}

TEST_F(HomomorphismEvaluationProofTest, AcceptsIdentityImageAndPadding) {
    auto bases = pp.vector_g;
    bases.back() = pp.group_ctx->get_infinity();
    const auto composed = evaluation::setup(pp.group_ctx, pp.ring_ctx, pp.u, bases);
    const evaluation::Statement relation{
        ec_point_msm(bases, witness.a) + pp.u * witness.r, pp.group_ctx->get_infinity(),
        std::vector<ECPoint>(8, pp.group_ctx->get_infinity())};
    EXPECT_TRUE(evaluation::verify(composed, relation, evaluation::prove(composed, relation, witness)));
}

TEST_F(HomomorphismEvaluationProofTest, RejectsTamperingAndMalformedDimensions) {
    const auto valid = evaluation::prove(pp, statement, witness);
    for (auto member : {&evaluation::Proof::a_p, &evaluation::Proof::a_q}) {
        auto proof = valid;
        proof.*member = proof.*member + pp.u;
        EXPECT_FALSE(evaluation::verify(pp, statement, proof));
    }
    auto proof = valid;
    proof.f += pp.ring_ctx->get_one();
    EXPECT_FALSE(evaluation::verify(pp, statement, proof));
    for (auto member : {&equality::Proof::left_g, &equality::Proof::right_g,
                         &equality::Proof::left_p, &equality::Proof::right_p}) {
        proof = valid;
        (proof.equality_proof.*member)[0] = (proof.equality_proof.*member)[0] + pp.u;
        EXPECT_FALSE(evaluation::verify(pp, statement, proof));
        (proof.equality_proof.*member).pop_back();
        EXPECT_FALSE(evaluation::verify(pp, statement, proof));
    }
    auto changed = statement;
    changed.bases.pop_back();
    EXPECT_FALSE(evaluation::verify(pp, changed, valid));
}

TEST_F(HomomorphismEvaluationProofTest, SerializationAndTruncation) {
    const auto proof = evaluation::prove(pp, statement, witness);
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

TEST(HomomorphismEvaluationProofStandaloneTest, HandlesLengthOne) {
    auto pp = evaluation::setup(NID_X9_62_prime256v1, 1);
    const evaluation::Witness witness{{pp.ring_ctx->get_one()}, pp.ring_ctx->get_zero()};
    const evaluation::Statement statement{pp.vector_g[0], pp.u, {pp.u}};
    EXPECT_TRUE(evaluation::verify(pp, statement, evaluation::prove(pp, statement, witness)));
}
} // namespace
