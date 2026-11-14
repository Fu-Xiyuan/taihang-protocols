#include <gtest/gtest.h>

#include <sstream>
#include <openssl/obj_mac.h>

#include <taihang/zkp/apgc/ciphertext_homomorphism_proof.hpp>

namespace {
using namespace taihang;
namespace protocol = taihang::zkp::apgc::ciphertext_homomorphism;
namespace encryption = taihang::pke::twisted_elgamal;

class APGCCiphertextHomomorphismTest : public ::testing::Test {
protected:
    APGCCiphertextHomomorphismTest() : enc(encryption::setup(NID_X9_62_prime256v1, 8)), pp(protocol::setup(enc, 4)) {
        for (std::size_t j = 0; j < 4; ++j) {
            const auto key = encryption::keygen(enc);
            keys.push_back(key.first.y);
            secrets.push_back(key.second.x);
            randomness.push_back(enc.ring_ctx->gen_random());
            const auto amount = j == 0 ? -ZnElement(enc.ring_ctx, BigInt(uint64_t{9})) :
                ZnElement(enc.ring_ctx, BigInt(uint64_t{j == 1 ? 0 : j + 2}));
            values.push_back(amount);
            transfers.push_back(encryption::encrypt(enc, key.first, amount, randomness.back()));
            balances.push_back(encryption::encrypt(enc, key.first, ZnElement(enc.ring_ctx, BigInt(uint64_t{100}))));
        }
        statement.public_keys = keys;
        statement.transfers = transfers;
        witness.a = randomness;
        witness.a.insert(witness.a.end(), values.begin(), values.end());
        witness.r = enc.ring_ctx->gen_random();
        statement.p = ec_point_msm(pp.commitment.vector_g, witness.a) + pp.commitment.u * witness.r;
    }
    encryption::PublicParameters enc;
    protocol::PublicParameters pp;
    std::vector<ECPoint> keys;
    std::vector<ZnElement> secrets, randomness, values;
    std::vector<encryption::Ciphertext> transfers, balances;
    protocol::Statement statement;
    protocol::Witness witness;
};

TEST_F(APGCCiphertextHomomorphismTest, AcceptsOriginalRelationAndAssociatedContext) {
    const auto proof = protocol::prove(pp, statement, witness, "payment");
    EXPECT_TRUE(protocol::verify(pp, statement, proof, "payment"));
    EXPECT_FALSE(protocol::verify(pp, statement, proof, "other-payment"));
}

TEST_F(APGCCiphertextHomomorphismTest, RejectsChangedPublicInput) {
    const auto proof = protocol::prove(pp, statement, witness);
    statement.transfers[2].c2 = statement.transfers[2].c2 + enc.h;
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCCiphertextHomomorphismTest, RejectsWrongWitness) {
    witness.a[0] += enc.ring_ctx->get_one();
    const auto proof = protocol::prove(pp, statement, witness);
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCCiphertextHomomorphismTest, FreshMasksAndResponseTampering) {
    auto proof = protocol::prove(pp, statement, witness);
    const auto other = protocol::prove(pp, statement, witness);
    EXPECT_NE(proof, other);
    proof.f += enc.ring_ctx->get_one();
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}

TEST_F(APGCCiphertextHomomorphismTest, SerializationRoundTripAndTruncation) {
    const auto proof = protocol::prove(pp, statement, witness);
    std::ostringstream output;
    output << proof;
    auto decoded = protocol::initialize_proof(pp);
    std::istringstream input(output.str());
    input >> decoded;
    ASSERT_TRUE(input);
    EXPECT_EQ(proof, decoded);
    EXPECT_TRUE(protocol::verify(pp, statement, decoded));
    for (const auto length : {std::size_t{0}, output.str().size() / 2, output.str().size() - 1}) {
        std::istringstream truncated(output.str().substr(0, length));
        decoded = protocol::initialize_proof(pp);
        truncated >> decoded;
        EXPECT_TRUE(truncated.fail());
    }
}

TEST_F(APGCCiphertextHomomorphismTest, RejectsMalformedDimensions) {
    const auto proof = protocol::prove(pp, statement, witness);
    statement.transfers.pop_back();
    EXPECT_FALSE(protocol::verify(pp, statement, proof));
}


TEST_F(APGCCiphertextHomomorphismTest, MatchesOriginalAmorHomWellformChallengeAndEqualityRelation) {
    namespace equality = taihang::zkp::nizk::multi_exponentiation_equality;
    const auto proof = protocol::prove(pp, statement, witness);
    std::ostringstream transcript;
    transcript << statement.p;
    for (std::size_t j = 0; j < 4; ++j) {
        transcript << keys[j] << transfers[j].c1 << transfers[j].c2;
    }
    const auto rho = hash_to_zn(transcript.str(), *enc.ring_ctx);
    std::vector<ZnElement> powers(8, enc.ring_ctx->get_one());
    for (std::size_t i = 1; i < 8; ++i) powers[i] = powers[i - 1] * rho;
    std::vector<ECPoint> bases(8, ECPoint(enc.group_ctx));
    auto image = enc.group_ctx->get_infinity();
    for (std::size_t j = 0; j < 4; ++j) {
        bases[j] = keys[j] * powers[j] + enc.g * powers[4 + j];
        bases[4 + j] = enc.h * powers[4 + j];
        image = image + transfers[j].c1 * powers[j] + transfers[j].c2 * powers[4 + j];
    }
    transcript << proof.a_p << proof.a_q;
    const auto e = hash_to_zn(transcript.str(), *enc.ring_ctx);
    const auto eq = equality::setup(enc.group_ctx, enc.ring_ctx, bases, pp.commitment.vector_g);
    EXPECT_TRUE(equality::verify(eq, {image * e + proof.a_q,
        statement.p * e + proof.a_p - pp.commitment.u * proof.f}, proof.equality_proof));
}

} // namespace
