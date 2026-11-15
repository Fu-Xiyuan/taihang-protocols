#include <gtest/gtest.h>

#include <cstring>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <openssl/obj_mac.h>

#include <taihang/zkp/apgc/apgc.hpp>

namespace {
using namespace taihang;
namespace application = taihang::zkp::apgc;
namespace encryption = taihang::pke::twisted_elgamal;

class APGCTest : public ::testing::Test {
protected:
    APGCTest() : pp(application::setup(NID_X9_62_prime256v1, 4, 2, 8)),
        solver(*pp.encryption.group_ctx, pp.encryption.h, {8, 0, 1}) {
        for (std::size_t j = 0; j < 4; ++j) {
            accounts.push_back(application::create_account(pp, "account-" + std::to_string(j),
                BigInt(uint64_t{100})));
        }
        // Build the tiny decryption table in memory, without persisting test data.
        for (std::size_t i = 0; i < solver.babystep_num; ++i) {
            const ECPoint point = pp.encryption.h * BigInt(uint64_t{i});
            EXPECT_TRUE(solver.key_to_index.emplace(point.xxhash_to_uint64(solver.hash_salt),
                static_cast<uint32_t>(i)).second);
        }
    }
    std::vector<application::Participant> participants() const {
        std::vector<application::Participant> result;
        for (const application::Account& account : accounts) {
            result.push_back({account.identity, account.public_key.y, account.balance});
        }
        return result;
    }
    application::Transaction create() const {
        return application::create_transaction(pp, accounts[0], {BigInt(uint64_t{4}),
            BigInt(uint64_t{5})}, participants(), 0, {2, 3}, solver);
    }
    application::PublicParameters pp;
    dlog::BSGSSolver solver;
    std::vector<application::Account> accounts;
};

TEST_F(APGCTest, CreatesVerifiesUpdatesAndRevealsBalances) {
    const application::Transaction tx = create();
    EXPECT_TRUE(application::verify_transaction(pp, tx, participants()));
    ASSERT_TRUE(application::update_accounts(pp, tx, accounts, solver));
    const std::vector<uint64_t> expected{91, 100, 104, 105};
    for (std::size_t j = 0; j < 4; ++j) {
        EXPECT_EQ(accounts[j].amount, BigInt(expected[j]));
        EXPECT_EQ(application::reveal_balance(pp, accounts[j], solver), BigInt(expected[j]));
    }
    const application::Transaction next = create();
    EXPECT_TRUE(application::verify_transaction(pp, next, participants()));
}

TEST_F(APGCTest, CreatesFromEncryptedBalanceWhenPlaintextCacheIsStale) {
    accounts[0].amount = BigInt(uint64_t{0});
    const application::Transaction transaction = create();
    EXPECT_TRUE(application::verify_transaction(pp, transaction, participants()));
    ASSERT_TRUE(application::update_accounts(pp, transaction, accounts, solver));
    EXPECT_EQ(accounts[0].amount, BigInt(uint64_t{91}));
    EXPECT_EQ(application::reveal_balance(pp, accounts[0], solver),
              BigInt(uint64_t{91}));
}

TEST_F(APGCTest, CachedAmountCannotAuthorizeAnOverdrawnTransfer) {
    accounts[0].amount = BigInt(uint64_t{200});
    accounts[0].balance = encryption::encrypt(
        pp.encryption, accounts[0].public_key,
        ZnElement(pp.encryption.ring_ctx, BigInt(uint64_t{8})));
    EXPECT_THROW(create(), std::invalid_argument);
}

TEST_F(APGCTest, AccountSerializationRoundTrip) {
    const application::Account& account = accounts[0];
    std::ostringstream output;
    output << account;
    application::Account decoded = application::initialize_account(pp);
    std::istringstream input(output.str());
    input >> decoded;
    ASSERT_TRUE(input);
    EXPECT_EQ(account.identity, decoded.identity);
    EXPECT_EQ(account.public_key.y, decoded.public_key.y);
    EXPECT_EQ(account.secret_key.x, decoded.secret_key.x);
    EXPECT_EQ(account.balance, decoded.balance);
    EXPECT_EQ(account.amount, decoded.amount);
    std::istringstream truncated(output.str().substr(0, output.str().size() - 1));
    decoded = application::initialize_account(pp);
    truncated >> decoded;
    EXPECT_TRUE(truncated.fail());
}

TEST_F(APGCTest, KeepsSerialAsOriginalTransactionMetadata) {
    application::Transaction tx = create();
    tx.serial += pp.encryption.ring_ctx->get_one();
    EXPECT_TRUE(application::verify_transaction(pp, tx, participants()));
}

TEST_F(APGCTest, RejectsChangedExternalBalanceAndParticipantKey) {
    const application::Transaction tx = create();
    for (std::size_t j = 0; j < 4; ++j) {
        std::vector<application::Participant> changed = participants();
        changed[j].balance.c2 = changed[j].balance.c2 + pp.encryption.h;
        EXPECT_FALSE(application::verify_transaction(pp, tx, changed));
        changed = participants();
        changed[j].public_key = changed[j].public_key + pp.encryption.g;
        EXPECT_FALSE(application::verify_transaction(pp, tx, changed));
    }
}

TEST_F(APGCTest, RejectsEveryChangedTransferCiphertext) {
    const application::Transaction valid = create();
    for (std::size_t j = 0; j < 4; ++j) {
        application::Transaction tx = valid;
        tx.transfers[j].c1 = tx.transfers[j].c1 + pp.encryption.g;
        EXPECT_FALSE(application::verify_transaction(pp, tx, participants()));
        tx = valid;
        tx.transfers[j].c2 = tx.transfers[j].c2 + pp.encryption.h;
        EXPECT_FALSE(application::verify_transaction(pp, tx, participants()));
    }
}

TEST_F(APGCTest, RejectsMalformedDimensionsAndCounts) {
    const application::Transaction valid = create();
    application::Transaction tx = valid;
    tx.transfers.pop_back();
    EXPECT_FALSE(application::verify_transaction(pp, tx, participants()));
    tx = valid;
    tx.public_keys.pop_back();
    EXPECT_FALSE(application::verify_transaction(pp, tx, participants()));
    tx = valid;
    tx.receiver_count = 1;
    EXPECT_FALSE(application::verify_transaction(pp, tx, participants()));
    std::vector<application::Participant> changed = participants();
    changed.pop_back();
    EXPECT_FALSE(application::verify_transaction(pp, valid, changed));
}

TEST_F(APGCTest, RejectsSplicedSubproofs) {
    const application::Transaction valid = create();
    const application::Transaction other = create();
    application::Transaction tx = valid;
    tx.well_formedness = other.well_formedness;
    EXPECT_FALSE(application::verify_transaction(pp, tx, participants()));
    tx = valid;
    tx.zero_sum = other.zero_sum;
    EXPECT_FALSE(application::verify_transaction(pp, tx, participants()));
    tx = valid;
    tx.inactive_participant = other.inactive_participant;
    EXPECT_FALSE(application::verify_transaction(pp, tx, participants()));
    tx = valid;
    tx.solvency = other.solvency;
    EXPECT_FALSE(application::verify_transaction(pp, tx, participants()));
    tx = valid;
    tx.positive_transfer = other.positive_transfer;
    EXPECT_FALSE(application::verify_transaction(pp, tx, participants()));
}

TEST_F(APGCTest, InvalidProofLeavesAccountsUnchanged) {
    application::Transaction tx = create();
    const std::vector<application::Account> original = accounts;
    tx.solvency.z_s += pp.encryption.ring_ctx->get_one();
    EXPECT_FALSE(application::update_accounts(pp, tx, accounts, solver));
    for (std::size_t j = 0; j < 4; ++j) {
        EXPECT_EQ(accounts[j].balance, original[j].balance);
        EXPECT_EQ(accounts[j].amount, original[j].amount);
    }
}

TEST_F(APGCTest, PreservesOriginalStrictlyPositiveRemainingBalanceAtCreation) {
    accounts[0].amount = BigInt(uint64_t{9});
    accounts[0].balance = encryption::encrypt(pp.encryption, accounts[0].public_key,
        ZnElement(pp.encryption.ring_ctx, accounts[0].amount));
    EXPECT_THROW(create(), std::invalid_argument);
    accounts[0].amount = BigInt(uint64_t{10});
    accounts[0].balance = encryption::encrypt(pp.encryption, accounts[0].public_key,
        ZnElement(pp.encryption.ring_ctx, accounts[0].amount));
    EXPECT_TRUE(application::verify_transaction(pp, create(), participants()));
}

TEST_F(APGCTest, RejectsZeroNegativeInsufficientAndMalformedCreationInputs) {
    const std::vector<application::Participant> set = participants();
    const BigInt zero(uint64_t{0}), one(uint64_t{1}), hundred(uint64_t{100});
    EXPECT_THROW(application::create_transaction(pp, accounts[0], {zero, one}, set, 0, {2, 3},
        solver), std::invalid_argument);
    EXPECT_THROW(application::create_transaction(pp, accounts[0], {-one, one}, set, 0, {2, 3},
        solver), std::invalid_argument);
    EXPECT_THROW(application::create_transaction(pp, accounts[0], {hundred, hundred}, set, 0,
        {2, 3}, solver), std::invalid_argument);
    EXPECT_THROW(application::create_transaction(pp, accounts[0], {one, one}, set, 0, {2, 2},
        solver), std::invalid_argument);
    EXPECT_THROW(application::create_transaction(pp, accounts[0], {one, one}, set, 0, {0, 2},
        solver), std::invalid_argument);
    EXPECT_THROW(application::create_transaction(pp, accounts[0], {one, one}, set, 0, {2, 4},
        solver), std::invalid_argument);
    EXPECT_THROW(application::create_transaction(pp, accounts[0], {one}, set, 0, {2}, solver),
        std::invalid_argument);
}

TEST_F(APGCTest, SerializationContainsEachTransferOnceAndNoBalanceCiphertexts) {
    application::GenerationMetrics metrics;
    const application::Transaction tx = application::create_transaction(pp, accounts[0],
        {BigInt(uint64_t{4}), BigInt(uint64_t{5})},
        participants(), 0, {2, 3}, solver, &metrics);
    std::ostringstream bytes;
    std::ostringstream serial;
    std::ostringstream payload;
    std::ostringstream proofs;
    bytes << tx;
    serial << tx.serial;
    for (const ECPoint& key : tx.public_keys) {
        payload << key;
    }
    for (const encryption::Ciphertext& ct : tx.transfers) {
        payload << ct;
    }
    proofs << tx.well_formedness << tx.zero_sum << tx.inactive_participant << tx.solvency <<
        tx.positive_transfer;
    EXPECT_EQ(bytes.str().size(),
        serial.str().size() + sizeof(std::uint64_t) + payload.str().size() + proofs.str().size());
    EXPECT_EQ(metrics.transaction_bytes, bytes.str().size());
    EXPECT_EQ(metrics.proof_bytes, proofs.str().size());
    EXPECT_GT(metrics.proof_generation_ms, 0);
    EXPECT_GE(metrics.transaction_generation_ms, metrics.proof_generation_ms);
    EXPECT_GT(metrics.serialization_ms, 0);
    application::Transaction decoded = application::initialize_transaction(pp);
    std::istringstream input(bytes.str());
    input >> decoded;
    ASSERT_TRUE(input);
    EXPECT_TRUE(application::verify_transaction(pp, decoded, participants()));
    std::ostringstream encoded;
    encoded << decoded;
    EXPECT_EQ(encoded.str(), bytes.str());
}

TEST_F(APGCTest, RejectsTruncatedTransactionsInvalidReceiverCountAndNonCanonicalSerial) {
    const application::Transaction tx = create();
    std::ostringstream output;
    std::ostringstream serial;
    output << tx;
    serial << tx.serial;
    const std::string bytes = output.str();
    for (std::size_t length = 0; length < bytes.size(); length += 127) {
        std::istringstream input(bytes.substr(0, length));
        application::Transaction decoded = application::initialize_transaction(pp);
        input >> decoded;
        ASSERT_TRUE(input.fail());
    }
    std::string changed = bytes;
    const std::uint64_t count = std::numeric_limits<std::uint64_t>::max();
    std::memcpy(changed.data() + serial.str().size(), &count, sizeof(count));
    std::istringstream invalid_count(changed);
    application::Transaction decoded = application::initialize_transaction(pp);
    invalid_count >> decoded;
    EXPECT_TRUE(invalid_count.fail());
    const std::vector<uint8_t> modulus = pp.encryption.ring_ctx->modulus.to_bytes();
    changed = bytes;
    changed.replace(0, modulus.size(), reinterpret_cast<const char*>(modulus.data()),
        modulus.size());
    std::istringstream invalid_scalar(changed);
    decoded = application::initialize_transaction(pp);
    invalid_scalar >> decoded;
    EXPECT_TRUE(invalid_scalar.fail());
}

TEST(APGCStandaloneTest, SingleReceiverPreservesOriginalPositiveProofOmission) {
    const application::PublicParameters pp = application::setup(NID_X9_62_prime256v1, 2, 1, 8);
    std::vector<application::Account> accounts;
    std::vector<application::Participant> participants;
    for (std::size_t i = 0; i < 2; ++i) {
        accounts.push_back(application::create_account(pp, std::to_string(i),
            BigInt(uint64_t{100})));
        participants.push_back({accounts.back().identity, accounts.back().public_key.y,
            accounts.back().balance});
    }
    dlog::BSGSSolver solver(*pp.encryption.group_ctx, pp.encryption.h, {8, 0, 1});
    for (std::size_t i = 0; i < solver.babystep_num; ++i) {
        const ECPoint point = pp.encryption.h * BigInt(uint64_t{i});
        solver.key_to_index.emplace(point.xxhash_to_uint64(solver.hash_salt),
            static_cast<uint32_t>(i));
    }
    application::Transaction tx = application::create_transaction(pp, accounts[0],
        {BigInt(uint64_t{3})}, participants, 0, {1}, solver);
    EXPECT_TRUE(application::verify_transaction(pp, tx, participants));
    tx.positive_transfer.values.t += pp.encryption.ring_ctx->get_one();
    EXPECT_TRUE(application::verify_transaction(pp, tx, participants));
    std::ostringstream output;
    std::ostringstream payload;
    std::ostringstream proofs;
    output << tx;
    payload << tx.serial;
    for (const ECPoint& key : tx.public_keys) {
        payload << key;
    }
    for (const encryption::Ciphertext& ct : tx.transfers) {
        payload << ct;
    }
    proofs << tx.well_formedness << tx.zero_sum << tx.inactive_participant << tx.solvency;
    EXPECT_EQ(output.str().size(),
        sizeof(std::uint64_t) + payload.str().size() + proofs.str().size());
    application::Transaction decoded = application::initialize_transaction(pp);
    std::istringstream input(output.str());
    input >> decoded;
    ASSERT_TRUE(input);
    EXPECT_TRUE(application::verify_transaction(pp, decoded, participants));
}

TEST(APGCStandaloneTest, SupportsOriginalDefault32BitAmountsAndFourReceivers) {
    for (const std::pair<std::size_t, std::size_t>& dimensions : {std::pair<std::size_t,
        std::size_t>{4, 2}, {8, 4}}) {
        const application::PublicParameters pp = application::setup(NID_X9_62_prime256v1,
            dimensions.first, dimensions.second);
        std::vector<application::Account> accounts;
        std::vector<application::Participant> participants;
        for (std::size_t j = 0; j < dimensions.first; ++j) {
            accounts.push_back(application::create_account(pp, std::to_string(j),
                BigInt(uint64_t{1000000000})));
            participants.push_back({accounts.back().identity, accounts.back().public_key.y,
                accounts.back().balance});
        }
        std::vector<BigInt> amounts(dimensions.second, BigInt(uint64_t{100000000}));
        std::vector<std::size_t> indices;
        for (std::size_t i = 0; i < dimensions.second; ++i) {
            indices.push_back(i + 1);
        }
        dlog::BSGSSolver solver(*pp.encryption.group_ctx, pp.encryption.h, {32, 0, 1});
        for (std::size_t i = 0; i < solver.babystep_num; ++i) {
            const ECPoint point = pp.encryption.h * BigInt(uint64_t{i});
            solver.key_to_index.emplace(point.xxhash_to_uint64(solver.hash_salt),
                static_cast<uint32_t>(i));
        }
        const application::Transaction tx = application::create_transaction(pp, accounts[0],
            amounts, participants, 0, indices, solver);
        EXPECT_TRUE(application::verify_transaction(pp, tx, participants));
    }
}

} // namespace
