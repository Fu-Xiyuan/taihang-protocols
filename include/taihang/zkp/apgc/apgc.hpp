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

/** @brief Encryption parameters and subproof bases for APGC transactions. */
struct PublicParameters {
    /// Twisted ElGamal parameters shared by balances and transfers.
    pke::twisted_elgamal::PublicParameters encryption;

    /// Number of entries in the anonymous set.
    std::size_t participant_count;

    /// Number of receivers in each transaction.
    std::size_t receiver_count;

    /// Maximum receiver count, equal to participant_count - 1.
    std::size_t maximum_receiver_count;

    /// Serial-length metadata retained from the original APGC interface.
    std::size_t serial_bits;

    /// Nominal encryption message bound, equal to 2^message_bits.
    BigInt maximum_coins;

    /// Parameters for proving correct transfer encryption.
    ciphertext_well_formedness::PublicParameters well_formedness;

    /// Parameters for proving that transfer amounts sum to zero.
    zero_sum::PublicParameters zero_sum;

    /// Parameters for proving that nonparticipants transfer zero.
    inactive_participant::PublicParameters inactive_participant;

    /// Parameters for the receiver selector and positive amount ranges.
    positive_transfer::PublicParameters positive_transfer;

    /// Parameters for the sender balance and debit range proofs.
    solvency::PublicParameters solvency;
};

/** @brief Local account state, including the secret key and encrypted balance. */
struct Account {
    /// Local account identifier.
    std::string identity;

    /// Public key used for balance and transfer encryption.
    pke::twisted_elgamal::PublicKey public_key;

    /// Private decryption key; never included in a transaction.
    pke::twisted_elgamal::SecretKey secret_key;

    /// Encrypted current balance.
    pke::twisted_elgamal::Ciphertext balance;

    /// Plaintext balance cache; transaction creation decrypts balance instead.
    BigInt amount;

    friend std::ostream& operator<<(std::ostream& os, const Account& account);
    friend std::istream& operator>>(std::istream& is, Account& account);
};

/** @brief Public anonymous-set entry; balances are external verifier input. */
struct Participant {
    /// Public account identifier.
    std::string identity;

    /// Encryption public key at this anonymous-set index.
    ECPoint public_key;

    /// Ledger balance ciphertext, excluded from transaction serialization.
    pke::twisted_elgamal::Ciphertext balance;
};

/** @brief Transfer ciphertexts and the composed APGC legal proof. */
struct Transaction {
    /// Transaction metadata; the legal proof does not bind this scalar.
    ZnElement serial;

    /// Number of receivers, checked against PublicParameters.
    std::size_t receiver_count;

    /// Ordered public keys of the anonymous set.
    std::vector<ECPoint> public_keys;

    /// One transfer ciphertext per anonymous-set entry, serialized once.
    std::vector<pke::twisted_elgamal::Ciphertext> transfers;

    /// Proof that all transfer ciphertexts are correctly formed.
    ciphertext_well_formedness::Proof well_formedness;

    /// Proof that the signed transfer amounts sum to zero.
    zero_sum::Proof zero_sum;

    /// Proof for participant_count - receiver_count - 1 inactive entries.
    inactive_participant::Proof inactive_participant;

    /// Proof of a solvent sender and a strictly positive debit.
    solvency::Proof solvency;

    /// Receiver proof, verified and serialized only when receiver_count > 1.
    positive_transfer::Proof positive_transfer;

    friend std::ostream& operator<<(std::ostream& os,
                                    const Transaction& transaction);
    friend std::istream& operator>>(std::istream& is, Transaction& transaction);
};

/** @brief Optional generation timings and serialized sizes. */
struct GenerationMetrics {
    /// Generation time including balance decryption, encryption, and proofs.
    double transaction_generation_ms{0};

    /// Time spent generating the composed legal proof.
    double proof_generation_ms{0};

    /// Time spent serializing the complete transaction for size measurement.
    double serialization_ms{0};

    /// Complete serialized transaction size, excluding ledger balances.
    std::size_t transaction_bytes{0};

    /// Serialized legal-proof size, excluding transaction metadata and
    /// ciphertexts.
    std::size_t proof_bytes{0};
};

PublicParameters setup(int curve_id,
                       std::size_t participant_count,
                       std::size_t receiver_count,
                       std::size_t message_bits = 32,
                       std::size_t serial_bits = 256);

Account create_account(const PublicParameters& pp,
                       const std::string& identity,
                       const BigInt& initial_balance);

Account initialize_account(const PublicParameters& pp);

BigInt reveal_balance(const PublicParameters& pp,
                      const Account& account,
                      const dlog::BSGSSolver& solver);

Transaction create_transaction(const PublicParameters& pp,
                               const Account& sender,
                               const std::vector<BigInt>& amounts,
                               const std::vector<Participant>& participants,
                               std::size_t sender_index,
                               const std::vector<std::size_t>& receiver_indices,
                               const dlog::BSGSSolver& solver,
                               GenerationMetrics* metrics = nullptr);

bool verify_transaction(const PublicParameters& pp,
                        const Transaction& transaction,
                        const std::vector<Participant>& participants);

bool update_accounts(const PublicParameters& pp,
                     const Transaction& transaction,
                     std::vector<Account>& accounts,
                     const dlog::BSGSSolver& solver);

Transaction initialize_transaction(const PublicParameters& pp);

} // namespace taihang::zkp::apgc

#endif // TAIHANG_PROTOCOLS_APGC_HPP
