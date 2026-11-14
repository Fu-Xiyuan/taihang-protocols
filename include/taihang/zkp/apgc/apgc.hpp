/****************************************************************************
 * @file      apgc.hpp
 * @brief     APGC accounts and transactions using the original legal-proof composition.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_APGC_HPP
#define TAIHANG_PROTOCOLS_APGC_HPP

#include <taihang/zkp/apgc/ciphertext_well_formedness_proof.hpp>
#include <taihang/zkp/apgc/zero_sum_proof.hpp>
#include <taihang/zkp/apgc/inactive_participant_proof.hpp>
#include <taihang/zkp/apgc/positive_transfer_proof.hpp>
#include <taihang/zkp/apgc/solvency_proof.hpp>

namespace taihang::zkp::apgc {

struct PublicParameters {
    pke::twisted_elgamal::PublicParameters encryption;
    std::size_t participant_count;
    std::size_t receiver_count;
    std::size_t maximum_receiver_count;
    std::size_t serial_bits;
    BigInt maximum_coins;
    ciphertext_well_formedness::PublicParameters well_formedness;
    zero_sum::PublicParameters zero_sum;
    inactive_participant::PublicParameters inactive_participant;
    positive_transfer::PublicParameters positive_transfer;
    solvency::PublicParameters solvency;
};

struct Account {
    std::string identity;
    pke::twisted_elgamal::PublicKey public_key;
    pke::twisted_elgamal::SecretKey secret_key;
    pke::twisted_elgamal::Ciphertext balance;
    BigInt amount;

    friend std::ostream& operator<<(std::ostream& os, const Account& account);
    friend std::istream& operator>>(std::istream& is, Account& account);
};

/** @brief Public anonymous-set entry; balance ciphertexts are external verifier input. */
struct Participant {
    std::string identity;
    ECPoint public_key;
    pke::twisted_elgamal::Ciphertext balance;
};

struct Transaction {
    ZnElement serial;
    std::size_t receiver_count;
    std::vector<ECPoint> public_keys;
    std::vector<pke::twisted_elgamal::Ciphertext> transfers;
    ciphertext_well_formedness::Proof well_formedness;
    zero_sum::Proof zero_sum;
    inactive_participant::Proof inactive_participant;
    solvency::Proof solvency;
    positive_transfer::Proof positive_transfer;

    friend std::ostream& operator<<(std::ostream& os, const Transaction& transaction);
    friend std::istream& operator>>(std::istream& is, Transaction& transaction);
};

struct GenerationMetrics {
    double transaction_generation_ms{0};
    double proof_generation_ms{0};
    double serialization_ms{0};
    std::size_t transaction_bytes{0};
    std::size_t proof_bytes{0};
};

PublicParameters setup(int curve_id, std::size_t participant_count,
                       std::size_t receiver_count, std::size_t message_bits = 32,
                       std::size_t serial_bits = 256);
Account create_account(const PublicParameters& pp, const std::string& identity,
                        const BigInt& initial_balance);
Account initialize_account(const PublicParameters& pp);
BigInt reveal_balance(const PublicParameters& pp, const Account& account,
                       const dlog::BSGSSolver& solver);
Transaction create_transaction(const PublicParameters& pp, const Account& sender,
    const std::vector<BigInt>& amounts, const std::vector<Participant>& participants,
    std::size_t sender_index, const std::vector<std::size_t>& receiver_indices,
    GenerationMetrics* metrics = nullptr);
bool verify_transaction(const PublicParameters& pp, const Transaction& transaction,
                         const std::vector<Participant>& participants);
bool update_accounts(const PublicParameters& pp, const Transaction& transaction,
                       std::vector<Account>& accounts, const dlog::BSGSSolver& solver);
Transaction initialize_transaction(const PublicParameters& pp);

} // namespace taihang::zkp::apgc

#endif // TAIHANG_PROTOCOLS_APGC_HPP
