/****************************************************************************
 * @file      apgc.cpp
 * @brief     Original APGC workflow with supervisory ciphertexts and duplicate writes removed.
 *****************************************************************************/

#include <taihang/zkp/apgc/apgc.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <istream>
#include <ostream>
#include <sstream>
#include <stdexcept>

#include <taihang/common/check.hpp>
#include <taihang/utility/arithmetic.hpp>

namespace taihang::zkp::apgc {
namespace {

namespace encryption = taihang::pke::twisted_elgamal;
using Clock = std::chrono::steady_clock;

solvency::Statement sender_statement(const Transaction& tx, const std::vector<Participant>& participants) {
    solvency::Statement statement{tx.public_keys, tx.transfers, {}};
    for (const Participant& participant : participants) {
        statement.balances.push_back(participant.balance);
    }
    return statement;
}

std::vector<ECPoint> commitments(const Transaction& tx) {
    std::vector<ECPoint> result;
    for (const encryption::Ciphertext& ct : tx.transfers) {
        result.push_back(ct.c2);
    }
    return result;
}

ECPoint sum_commitments(const PublicParameters& pp, const Transaction& tx) {
    ECPoint sum = pp.encryption.group_ctx->get_infinity();
    for (const encryption::Ciphertext& ct : tx.transfers) {
        sum = sum + ct.c2;
    }
    return sum;
}

std::ostream& write_proofs(std::ostream& os, const Transaction& tx) {
    os << tx.well_formedness << tx.zero_sum << tx.inactive_participant << tx.solvency;
    if (tx.receiver_count > 1) {
        os << tx.positive_transfer;
    }
    return os;
}

double milliseconds(Clock::time_point from, Clock::time_point to) {
    return std::chrono::duration<double, std::milli>(to - from).count();
}

} // namespace

PublicParameters setup(int curve_id, std::size_t participant_count,
                       std::size_t receiver_count, std::size_t message_bits,
                       std::size_t serial_bits) {
    TAIHANG_ASSERT(taihang::arithmetic::is_pow2(participant_count) && participant_count >= 2 &&
        receiver_count > 0 && receiver_count < participant_count, "APGC invalid participant or receiver count");
    TAIHANG_ASSERT(message_bits > 0 && message_bits <= 32,
                   "APGC message bits must be in [1,32]");
    PublicParameters pp;
    pp.encryption = encryption::setup(curve_id, message_bits);
    pp.participant_count = participant_count;
    pp.receiver_count = receiver_count;
    pp.maximum_receiver_count = participant_count - 1;
    pp.serial_bits = serial_bits;
    pp.maximum_coins = kBigIntOne.lshift(static_cast<int>(message_bits));
    pp.well_formedness = ciphertext_well_formedness::setup(pp.encryption, participant_count);
    pp.zero_sum = zero_sum::setup(pp.encryption, participant_count);
    pp.inactive_participant = inactive_participant::setup(pp.encryption, participant_count);
    pp.positive_transfer = positive_transfer::setup(pp.encryption, participant_count, receiver_count);
    pp.solvency = solvency::setup(pp.encryption, participant_count);
    return pp;
}

Account initialize_account(const PublicParameters& pp) {
    const std::shared_ptr<ECGroup> group = pp.encryption.group_ctx;
    return {{}, {ECPoint(group)}, {ZnElement(pp.encryption.ring_ctx)}, {ECPoint(group), ECPoint(group)}, kBigIntZero};
}

Account create_account(const PublicParameters& pp, const std::string& identity,
                        const BigInt& initial_balance) {
    Account account = initialize_account(pp);
    account.identity = identity;
    const std::pair<encryption::PublicKey, encryption::SecretKey> key = encryption::keygen(pp.encryption);
    account.public_key = key.first;
    account.secret_key = key.second;
    account.amount = initial_balance;
    const ZnElement r = hash_to_zn(identity, *pp.encryption.ring_ctx);
    account.balance = encryption::encrypt(pp.encryption, account.public_key,
        ZnElement(pp.encryption.ring_ctx, initial_balance), r);
    return account;
}

BigInt reveal_balance(const PublicParameters& pp, const Account& account,
                       const dlog::BSGSSolver& solver) {
    return encryption::decrypt_exp(pp.encryption, account.secret_key, account.balance, solver).value;
}

Transaction initialize_transaction(const PublicParameters& pp) {
    const std::shared_ptr<ECGroup> group = pp.encryption.group_ctx;
    return {ZnElement(pp.encryption.ring_ctx), pp.receiver_count,
        std::vector<ECPoint>(pp.participant_count, ECPoint(group)),
        std::vector<encryption::Ciphertext>(pp.participant_count, {ECPoint(group), ECPoint(group)}),
        ciphertext_well_formedness::initialize_proof(pp.well_formedness), zero_sum::initialize_proof(pp.zero_sum),
        inactive_participant::initialize_proof(pp.inactive_participant), solvency::initialize_proof(pp.solvency),
        positive_transfer::initialize_proof(pp.positive_transfer)};
}

Transaction create_transaction(const PublicParameters& pp, const Account& sender,
    const std::vector<BigInt>& amounts, const std::vector<Participant>& participants,
    std::size_t sender_index, const std::vector<std::size_t>& receiver_indices, GenerationMetrics* metrics) {
    const Clock::time_point start = Clock::now();
    if (participants.size() != pp.participant_count || sender_index >= pp.participant_count ||
        amounts.size() != pp.receiver_count || receiver_indices.size() != pp.receiver_count) {
        throw std::invalid_argument("APGC participant or witness dimensions mismatch");
    }
    const std::shared_ptr<Zn> ring = pp.encryption.ring_ctx;
    if (participants[sender_index].public_key != sender.public_key.y ||
        participants[sender_index].balance != sender.balance || sender.secret_key.x.value.is_zero() ||
        pp.encryption.g * sender.secret_key.x != sender.public_key.y) {
        throw std::invalid_argument("APGC sender account does not match the anonymous set");
    }
    if (encryption::decrypt_raw(pp.encryption, sender.secret_key, sender.balance) !=
        pp.encryption.h * ZnElement(ring, sender.amount)) {
        throw std::invalid_argument("APGC cached balance does not match the encrypted balance");
    }
    const BigInt transfer_limit = kBigIntOne.lshift(32);
    BigInt debit = kBigIntZero;
    std::vector<bool> selected(pp.participant_count, false);
    selected[sender_index] = true;
    for (std::size_t i = 0; i < amounts.size(); ++i) {
        if (receiver_indices[i] >= pp.participant_count || selected[receiver_indices[i]]) {
            throw std::invalid_argument("APGC receivers must be distinct and exclude the sender");
        }
        if (amounts[i] <= kBigIntZero || amounts[i] > transfer_limit) {
            throw std::invalid_argument("APGC invalid transfer amount");
        }
        selected[receiver_indices[i]] = true;
        debit += amounts[i];
    }
    const BigInt post_balance = sender.amount - debit;
    if (debit <= kBigIntZero || debit > transfer_limit || post_balance <= kBigIntZero || post_balance > transfer_limit) {
        throw std::invalid_argument("APGC invalid transfer amount or remaining balance");
    }
    Transaction tx = initialize_transaction(pp);
    tx.serial = ring->gen_random();
    std::vector<ZnElement> values(pp.participant_count, ring->get_zero());
    values[sender_index] = -ZnElement(ring, debit);
    for (std::size_t i = 0; i < amounts.size(); ++i) {
        values[receiver_indices[i]] = ZnElement(ring, amounts[i]);
    }
    const std::vector<ZnElement> randomness = gen_random_znelement_vector(ring, pp.participant_count);
    for (std::size_t j = 0; j < pp.participant_count; ++j) {
        tx.public_keys[j] = participants[j].public_key;
        tx.transfers[j] = encryption::encrypt(pp.encryption, {tx.public_keys[j]}, values[j], randomness[j]);
    }
    const Clock::time_point proof_start = Clock::now();
    tx.well_formedness = ciphertext_well_formedness::prove(pp.well_formedness,
        {tx.public_keys, tx.transfers}, {values, randomness});
    tx.zero_sum = zero_sum::prove(pp.zero_sum, {sum_commitments(pp, tx)}, {randomness});
    inactive_participant::Witness inactive;
    inactive.bits.assign(pp.participant_count, ring->get_zero());
    for (std::size_t j = 0; j < pp.participant_count; ++j) {
        if (!selected[j]) {
            inactive.bits[j] = ring->get_one();
            inactive.randomness.push_back(randomness[j]);
        }
    }
    const std::vector<ECPoint> public_commitments = commitments(tx);
    tx.inactive_participant = inactive_participant::prove(pp.inactive_participant,
        {public_commitments, pp.participant_count - pp.receiver_count - 1}, inactive);
    tx.solvency = solvency::prove(pp.solvency, sender_statement(tx, participants),
        {sender.secret_key.x, sender_index, ZnElement(ring, post_balance), values[sender_index], randomness[sender_index]});
    if (pp.receiver_count > 1) {
        positive_transfer::Witness positive;
        for (const std::size_t index : receiver_indices) {
            positive.indices.push_back(index);
            positive.values.push_back(values[index]);
            positive.randomness.push_back(randomness[index]);
        }
        tx.positive_transfer = positive_transfer::prove(pp.positive_transfer, {public_commitments}, positive);
    }
    const Clock::time_point finish = Clock::now();
    if (metrics) {
        metrics->transaction_generation_ms = milliseconds(start, finish);
        metrics->proof_generation_ms = milliseconds(proof_start, finish);
        const Clock::time_point serialization_start = Clock::now();
        std::ostringstream bytes;
        bytes << tx;
        metrics->transaction_bytes = bytes.str().size();
        metrics->serialization_ms = milliseconds(serialization_start, Clock::now());
        std::ostringstream proofs;
        write_proofs(proofs, tx);
        metrics->proof_bytes = proofs.str().size();
    }
    return tx;
}

bool verify_transaction(const PublicParameters& pp, const Transaction& tx,
                         const std::vector<Participant>& participants) {
    if (participants.size() != pp.participant_count || tx.public_keys.size() != pp.participant_count ||
        tx.transfers.size() != pp.participant_count || tx.receiver_count != pp.receiver_count) {
        return false;
    }
    for (std::size_t j = 0; j < participants.size(); ++j) {
        if (participants[j].public_key != tx.public_keys[j]) {
            return false;
        }
    }
    const std::vector<ECPoint> public_commitments = commitments(tx);
    return ciphertext_well_formedness::verify(pp.well_formedness, {tx.public_keys, tx.transfers}, tx.well_formedness) &&
        zero_sum::verify(pp.zero_sum, {sum_commitments(pp, tx)}, tx.zero_sum) &&
        inactive_participant::verify(pp.inactive_participant,
            {public_commitments, pp.participant_count - pp.receiver_count - 1}, tx.inactive_participant) &&
        solvency::verify(pp.solvency, sender_statement(tx, participants), tx.solvency) &&
        (tx.receiver_count == 1 || positive_transfer::verify(pp.positive_transfer, {public_commitments}, tx.positive_transfer));
}

bool update_accounts(const PublicParameters& pp, const Transaction& tx,
                       std::vector<Account>& accounts, const dlog::BSGSSolver& solver) {
    std::vector<Participant> participants;
    for (const Account& account : accounts) {
        participants.push_back({account.identity, account.public_key.y, account.balance});
    }
    if (!verify_transaction(pp, tx, participants)) {
        return false;
    }
    std::vector<Account> updated = accounts;
    for (std::size_t j = 0; j < updated.size(); ++j) {
        updated[j].balance = updated[j].balance + tx.transfers[j];
        updated[j].amount = reveal_balance(pp, updated[j], solver);
    }
    accounts = std::move(updated);
    return true;
}

std::ostream& operator<<(std::ostream& os, const Transaction& tx) {
    if (tx.transfers.size() != tx.public_keys.size()) {
        os.setstate(std::ios::failbit);
        return os;
    }
    const std::uint64_t receivers = tx.receiver_count;
    os << tx.serial;
    os.write(reinterpret_cast<const char*>(&receivers), sizeof(receivers));
    for (const ECPoint& key : tx.public_keys) {
        os << key;
    }
    for (const encryption::Ciphertext& ct : tx.transfers) {
        os << ct;
    }
    return write_proofs(os, tx);
}

std::istream& operator>>(std::istream& is, Transaction& tx) {
    std::uint64_t receivers = 0;
    is >> tx.serial;
    is.read(reinterpret_cast<char*>(&receivers), sizeof(receivers));
    if (!is || receivers != tx.receiver_count || tx.transfers.size() != tx.public_keys.size()) {
        is.setstate(std::ios::failbit);
        return is;
    }
    for (ECPoint& key : tx.public_keys) {
        if (!(is >> key)) {
            return is;
        }
    }
    for (encryption::Ciphertext& ct : tx.transfers) {
        if (!(is >> ct)) {
            return is;
        }
    }
    if (is) {
        is >> tx.well_formedness;
    }
    if (is) {
        is >> tx.zero_sum;
    }
    if (is) {
        is >> tx.inactive_participant;
    }
    if (is) {
        is >> tx.solvency;
    }
    if (is && tx.receiver_count > 1) {
        is >> tx.positive_transfer;
    }
    return is;
}

std::ostream& operator<<(std::ostream& os, const Account& account) {
    const std::uint64_t length = account.identity.size();
    os.write(reinterpret_cast<const char*>(&length), sizeof(length));
    os.write(account.identity.data(), static_cast<std::streamsize>(length));
    return os << account.public_key.y << account.secret_key.x << account.balance << account.amount;
}

std::istream& operator>>(std::istream& is, Account& account) {
    std::uint64_t length = 0;
    if (!is.read(reinterpret_cast<char*>(&length), sizeof(length)) || length > account.identity.max_size()) {
        is.setstate(std::ios::failbit);
        return is;
    }
    account.identity.clear();
    char buffer[4096];
    while (length > 0) {
        const std::size_t count = static_cast<std::size_t>(std::min<std::uint64_t>(length, sizeof(buffer)));
        if (!is.read(buffer, static_cast<std::streamsize>(count))) {
            return is;
        }
        account.identity.append(buffer, count);
        length -= count;
    }
    return is >> account.public_key.y >> account.secret_key.x >> account.balance >> account.amount;
}

} // namespace taihang::zkp::apgc
