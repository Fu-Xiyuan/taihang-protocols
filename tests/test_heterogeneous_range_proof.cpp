#include <gtest/gtest.h>

#include <sstream>
#include <limits>
#include <openssl/obj_mac.h>

#include <taihang/zkp/k_out_of_n_protocols/heterogeneous_range_proof.hpp>

namespace {
using namespace taihang;
namespace knowledge = taihang::zkp::k_out_of_n::heterogeneous_range;
namespace heterogeneous = taihang::zkp::k_out_of_n::heterogeneous;
namespace evaluation = taihang::zkp::nizk::homomorphism_evaluation;

class HeterogeneousRangeProofTest : public ::testing::Test {
protected:
    HeterogeneousRangeProofTest() : pp(knowledge::setup(NID_X9_62_prime256v1, 4, 2, 2, 2, 8)) {
        const auto& cp = pp.core.commitment;
        witness.indices = {3, 0};
        for (std::size_t i = 0; i < 2; ++i) {
            witness.openings.push_back({ZnElement(cp.ring_ctx, BigInt(uint64_t{i + 3})),
                                        ZnElement(cp.ring_ctx, BigInt(uint64_t{i + 17}))});
        }
        statement.bases.assign(4, std::vector<ECPoint>(4, ECPoint(cp.group_ctx)));
        statement.outputs.assign(4, std::vector<ECPoint>(2, ECPoint(cp.group_ctx)));
        for (std::size_t j = 0; j < 4; ++j) {
            for (auto& base : statement.bases[j]) {
                base = cp.group_ctx->gen_random();
            }
            for (auto& output : statement.outputs[j]) {
                output = cp.group_ctx->gen_random();
            }
        }
        update_outputs();
    }
    void update_outputs() {
        for (std::size_t i = 0; i < 2; ++i) {
            const auto j = witness.indices[i];
            for (std::size_t q = 0; q < 2; ++q) {
                statement.outputs[j][q] = ec_point_msm(statement.bases[j][q * 2], witness.openings[i][0],
                    statement.bases[j][q * 2 + 1], witness.openings[i][1]);
            }
        }
    }
    evaluation::Proof empty_evaluation() const {
        const auto& cp = pp.core.commitment;
        return {ECPoint(cp.group_ctx), ECPoint(cp.group_ctx), ZnElement(cp.ring_ctx),
            {std::vector<ECPoint>(cp.rounds, ECPoint(cp.group_ctx)),
             std::vector<ECPoint>(cp.rounds, ECPoint(cp.group_ctx)),
             std::vector<ECPoint>(cp.rounds, ECPoint(cp.group_ctx)),
             std::vector<ECPoint>(cp.rounds, ECPoint(cp.group_ctx)), ZnElement(cp.ring_ctx)}};
    }
    knowledge::Proof empty() const {
        const auto& cp = pp.core.commitment;
        const auto& bp = pp.core.selection;
        knowledge::Proof proof;
        auto& core = proof.core;
        core.p = ECPoint(cp.group_ctx);
        core.s = ECPoint(cp.group_ctx);
        core.selection = {ECPoint(cp.group_ctx), ECPoint(cp.group_ctx), ECPoint(cp.group_ctx),
            ZnElement(cp.ring_ctx), ZnElement(cp.ring_ctx), ZnElement(cp.ring_ctx),
            {std::vector<ECPoint>(bp.rounds, ECPoint(cp.group_ctx)),
             std::vector<ECPoint>(bp.rounds, ECPoint(cp.group_ctx)), ZnElement(cp.ring_ctx), ZnElement(cp.ring_ctx)}};
        core.consistency = empty_evaluation();
        core.evaluations.assign(pp.core.output_length + 1, empty_evaluation());
        proof.range = {ECPoint(cp.group_ctx), ECPoint(cp.group_ctx), ECPoint(cp.group_ctx),
            ECPoint(cp.group_ctx), ECPoint(cp.group_ctx), ZnElement(cp.ring_ctx), ZnElement(cp.ring_ctx),
            ZnElement(cp.ring_ctx), {std::vector<ECPoint>(pp.range.rounds, ECPoint(cp.group_ctx)),
                std::vector<ECPoint>(pp.range.rounds, ECPoint(cp.group_ctx)), ZnElement(cp.ring_ctx), ZnElement(cp.ring_ctx)}};
        return proof;
    }
    knowledge::PublicParameters pp;
    knowledge::Witness witness;
    knowledge::Statement statement;
};

TEST_F(HeterogeneousRangeProofTest, AcceptsDistinctMultiInputMultiOutputMaps) {
    const auto proof = knowledge::prove(pp, statement, witness);
    EXPECT_TRUE(knowledge::verify(pp, statement, proof));
}

TEST_F(HeterogeneousRangeProofTest, FreshMasksProduceDifferentProofs) {
    const auto first = knowledge::prove(pp, statement, witness);
    const auto second = knowledge::prove(pp, statement, witness);
    EXPECT_NE(first, second);
    EXPECT_TRUE(knowledge::verify(pp, statement, second));
}

TEST_F(HeterogeneousRangeProofTest, RejectsWrongOpeningInEveryCoordinate) {
    const auto ring = pp.core.commitment.ring_ctx;
    for (std::size_t i = 0; i < 2; ++i) {
        for (std::size_t a = 0; a < 2; ++a) {
            auto wrong = witness;
            wrong.openings[i][a] += ring->get_one();
            EXPECT_FALSE(knowledge::verify(pp, statement, knowledge::prove(pp, statement, wrong)));
        }
    }
}

TEST_F(HeterogeneousRangeProofTest, RejectsWrongSelectedIndexAndChangedSelectedOutput) {
    auto wrong = witness;
    wrong.indices[0] = 1;
    EXPECT_FALSE(knowledge::verify(pp, statement, knowledge::prove(pp, statement, wrong)));
    auto changed = statement;
    changed.outputs[3][1] = changed.outputs[3][1] + pp.core.selection.u;
    EXPECT_FALSE(knowledge::verify(pp, changed, knowledge::prove(pp, changed, witness)));
}

TEST_F(HeterogeneousRangeProofTest, BindsContextEveryMapAndEveryPublicOutput) {
    const auto proof = knowledge::prove(pp, statement, witness, "a");
    EXPECT_TRUE(knowledge::verify(pp, statement, proof, "a"));
    EXPECT_FALSE(knowledge::verify(pp, statement, proof, "b"));
    for (std::size_t j = 0; j < 4; ++j) {
        auto changed = statement;
        changed.bases[j][0] = changed.bases[j][0] + pp.core.selection.u;
        EXPECT_FALSE(knowledge::verify(pp, changed, proof, "a"));
        changed = statement;
        changed.outputs[j][0] = changed.outputs[j][0] + pp.core.selection.u;
        EXPECT_FALSE(knowledge::verify(pp, changed, proof, "a"));
    }
}

TEST_F(HeterogeneousRangeProofTest, AcceptsArbitraryUnselectedOutputsAndMaps) {
    statement.outputs[1][0] = pp.core.commitment.group_ctx->get_infinity();
    statement.bases[2][0] = pp.core.selection.u;
    EXPECT_TRUE(knowledge::verify(pp, statement, knowledge::prove(pp, statement, witness)));
}

TEST_F(HeterogeneousRangeProofTest, RejectsSplicedConsistencySelectionOrEvaluation) {
    const auto first = knowledge::prove(pp, statement, witness);
    const auto second = knowledge::prove(pp, statement, witness);
    auto proof = first;
    auto& core = proof.core;
    const auto& other = second.core;
    core.consistency = other.consistency;
    EXPECT_FALSE(knowledge::verify(pp, statement, proof));
    proof = first;
    core.selection = other.selection;
    EXPECT_FALSE(knowledge::verify(pp, statement, proof));
    proof = first;
    core.evaluations[0] = other.evaluations[0];
    EXPECT_FALSE(knowledge::verify(pp, statement, proof));
}

TEST_F(HeterogeneousRangeProofTest, RejectsCommitmentAndNestedResponseTampering) {
    const auto valid = knowledge::prove(pp, statement, witness);
    auto proof = valid;
    auto& core = proof.core;
    core.p = core.p + pp.core.selection.u;
    EXPECT_FALSE(knowledge::verify(pp, statement, proof));
    proof = valid;
    core.s = core.s + pp.core.selection.u;
    EXPECT_FALSE(knowledge::verify(pp, statement, proof));
    proof = valid;
    core.evaluations[0].f += pp.core.commitment.ring_ctx->get_one();
    EXPECT_FALSE(knowledge::verify(pp, statement, proof));
    proof = valid;
    core.consistency.equality_proof.a += pp.core.commitment.ring_ctx->get_one();
    EXPECT_FALSE(knowledge::verify(pp, statement, proof));
}

TEST_F(HeterogeneousRangeProofTest, RejectsMalformedStatementAndProofDimensions) {
    const auto valid = knowledge::prove(pp, statement, witness);
    auto changed = statement;
    changed.bases[0].pop_back();
    EXPECT_FALSE(knowledge::verify(pp, changed, valid));
    changed = statement;
    changed.outputs[0].pop_back();
    EXPECT_FALSE(knowledge::verify(pp, changed, valid));
    auto proof = valid;
    auto& core = proof.core;
    core.evaluations.pop_back();
    EXPECT_FALSE(knowledge::verify(pp, statement, proof));
    proof = valid;
    core.selection.inner_product.left.pop_back();
    EXPECT_FALSE(knowledge::verify(pp, statement, proof));
    proof = valid;
    core.consistency.equality_proof.right_p.pop_back();
    EXPECT_FALSE(knowledge::verify(pp, statement, proof));
}

TEST_F(HeterogeneousRangeProofTest, SerializationAndTruncation) {
    const auto proof = knowledge::prove(pp, statement, witness);
    std::stringstream stream;
    stream << proof;
    auto decoded = empty();
    stream >> decoded;
    ASSERT_TRUE(stream);
    EXPECT_EQ(proof, decoded);
    EXPECT_TRUE(knowledge::verify(pp, statement, decoded));
    const auto bytes = stream.str();
    for (std::size_t n = 0; n < bytes.size(); n += 11) {
        std::istringstream input(bytes.substr(0, n));
        decoded = empty();
        input >> decoded;
        ASSERT_TRUE(input.fail());
    }
}

#ifndef NDEBUG
TEST_F(HeterogeneousRangeProofTest, RejectsDuplicateOutOfRangeAndWrongDimensionWitnesses) {
    auto wrong = witness;
    wrong.indices[0] = wrong.indices[1];
    EXPECT_DEATH(knowledge::prove(pp, statement, wrong), "indices must be distinct");
    wrong = witness;
    wrong.indices[0] = 4;
    EXPECT_DEATH(knowledge::prove(pp, statement, wrong), "index out of range");
    wrong = witness;
    wrong.openings[0].pop_back();
    EXPECT_DEATH(knowledge::prove(pp, statement, wrong), "opening length mismatch");
}
#endif

TEST_F(HeterogeneousRangeProofTest, RejectsOutOfRangeAndNegativeSelectedValue) {
    witness.openings[0][0] = ZnElement(pp.range.ring_ctx, BigInt(uint64_t{256}));
    update_outputs();
    EXPECT_FALSE(knowledge::verify(pp, statement, knowledge::prove(pp, statement, witness)));
    witness.openings[0][0] = ZnElement(pp.range.ring_ctx, pp.range.ring_ctx->modulus - kBigIntOne);
    update_outputs();
    EXPECT_FALSE(knowledge::verify(pp, statement, knowledge::prove(pp, statement, witness)));
}

TEST_F(HeterogeneousRangeProofTest, RangeAppliesOnlyToCoordinateZeroAndAcceptsUpperBoundary) {
    witness.openings[0][0] = ZnElement(pp.range.ring_ctx, BigInt(uint64_t{255}));
    witness.openings[0][1] = ZnElement(pp.range.ring_ctx, pp.range.ring_ctx->modulus - kBigIntOne);
    update_outputs();
    EXPECT_TRUE(knowledge::verify(pp, statement, knowledge::prove(pp, statement, witness)));
}

TEST_F(HeterogeneousRangeProofTest, RejectsAggregateTamperingAndAnotherExecutionRangeProof) {
    const auto first = knowledge::prove(pp, statement, witness);
    const auto second = knowledge::prove(pp, statement, witness);
    auto proof = first;
    proof.range = second.range;
    EXPECT_FALSE(knowledge::verify(pp, statement, proof));
    proof = first;
    proof.range.aggregate = proof.range.aggregate + pp.range.g;
    EXPECT_FALSE(knowledge::verify(pp, statement, proof));
    proof = first;
    proof.core.evaluations.back().equality_proof.a += pp.range.ring_ctx->get_one();
    EXPECT_FALSE(knowledge::verify(pp, statement, proof));
}

TEST_F(HeterogeneousRangeProofTest, RejectsChangedThresholdAndParameterDimensions) {
    const auto proof = knowledge::prove(pp, statement, witness);
    auto changed = pp;
    changed.core.threshold = 1;
    EXPECT_FALSE(knowledge::verify(changed, statement, proof));
    changed = pp;
    changed.core.opening_length = 0;
    EXPECT_FALSE(knowledge::verify(changed, statement, proof));
    changed = pp;
    changed.core.commitment.vector_g.pop_back();
    EXPECT_FALSE(knowledge::verify(changed, statement, proof));
    changed = pp;
    changed.core.selection.vector_h.pop_back();
    EXPECT_FALSE(knowledge::verify(changed, statement, proof));
    changed = pp;
    changed.range.vector_h.pop_back();
    EXPECT_FALSE(knowledge::verify(changed, statement, proof));
}

TEST_F(HeterogeneousRangeProofTest, RejectsUnexpectedEvaluationCountAndNonCanonicalFinalScalar) {
    const auto proof = knowledge::prove(pp, statement, witness);
    const auto& core = proof.core;
    std::ostringstream prefix;
    prefix << core.p << core.s << core.selection << core.consistency;
    std::ostringstream stream;
    stream << proof;
    std::string bytes = stream.str();
    const std::uint64_t count = std::numeric_limits<std::uint64_t>::max();
    bytes.replace(prefix.str().size(), sizeof(count), reinterpret_cast<const char*>(&count), sizeof(count));
    std::istringstream input(bytes);
    auto decoded = empty();
    input >> decoded;
    EXPECT_TRUE(input.fail());
    bytes = stream.str();
    const auto modulus = pp.core.commitment.ring_ctx->modulus.to_bytes();
    bytes.replace(bytes.size() - modulus.size(), modulus.size(),
                  reinterpret_cast<const char*>(modulus.data()), modulus.size());
    std::istringstream invalid_scalar(bytes);
    decoded = empty();
    invalid_scalar >> decoded;
    EXPECT_TRUE(invalid_scalar.fail());
}

TEST(HeterogeneousRangeProofStandaloneTest, HandlesSingleInstanceFullThresholdAndRectangularMaps) {
    for (const auto& dimensions : {std::vector<std::size_t>{1,1,1,1}, {2,2,1,1},
                                  {4,4,2,1}, {8,3,3,2}}) {
        const auto n = dimensions[0];
        const auto k = dimensions[1];
        const auto t = dimensions[2];
        const auto q = dimensions[3];
        const auto pp = knowledge::setup(NID_X9_62_prime256v1,n,k,t,q,8);
        const auto& cp = pp.core.commitment;
        knowledge::Statement statement;
        knowledge::Witness witness;
        for (std::size_t j = 0; j < n; ++j) {
            statement.bases.push_back(cp.group_ctx->gen_random(t*q));
            statement.outputs.push_back(cp.group_ctx->gen_random(q));
        }
        for (std::size_t i = 0; i < k; ++i) {
            witness.indices.push_back(n-1-i);
            witness.openings.push_back(gen_random_znelement_vector(cp.ring_ctx, t));
            witness.openings.back()[0] = ZnElement(cp.ring_ctx, BigInt(uint64_t{i % 256}));
            const auto j = witness.indices.back();
            for (std::size_t output = 0; output < q; ++output) {
                std::vector<ECPoint> bases(statement.bases[j].begin()+output*t,
                                            statement.bases[j].begin()+(output+1)*t);
                statement.outputs[j][output] = ec_point_msm(bases, witness.openings.back());
            }
        }
        EXPECT_TRUE(knowledge::verify(pp, statement, knowledge::prove(pp, statement, witness)));
        witness.openings[0][0] += cp.ring_ctx->get_one();
        EXPECT_FALSE(knowledge::verify(pp, statement, knowledge::prove(pp, statement, witness)));
    }
}

} // namespace
