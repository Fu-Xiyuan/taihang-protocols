/****************************************************************************
 * @file      solvency_proof.hpp
 * @brief     Original APGC Solvent composition with a shared sender selector.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_APGC_SOLVENCY_PROOF_HPP
#define TAIHANG_PROTOCOLS_APGC_SOLVENCY_PROOF_HPP

#include <taihang/zkp/apgc/sender_balance_proof.hpp>

namespace taihang::zkp::apgc::solvency {

/** @brief Sender-balance parameters and bases for the debit range linkage. */
struct PublicParameters {
    /// Parameters for the post-transfer balance and sender selector.
    sender_balance::PublicParameters sender;

    /// Generator basis for the binary encoding of the sender index.
    std::vector<ECPoint> index_g;

    /// Parameters proving the debit lies in [0, 2^32).
    range_proofs::bulletproof::PublicParameters values_range;

    /// Parameters proving the debit minus one lies in [0, 2^32).
    range_proofs::bulletproof::PublicParameters shifted_range;
};

using Statement = sender_balance::Statement;

/** @brief Sender secret key, post-transfer balance, and signed transfer opening. */
struct Witness {
    /// Nonzero encryption secret key of the sender.
    ZnElement secret_key;

    /// Zero-based sender index in the anonymous set.
    std::size_t index;

    /// Plaintext balance after the transfer.
    ZnElement post_balance;

    /// Signed sender transfer amount; a debit is negative.
    ZnElement transfer_value;

    /// Encryption randomness for the sender's transfer ciphertext.
    ZnElement transfer_randomness;
};

/** @brief Binary index commitments, sender linkage, and two debit range proofs. */
struct Proof {
    /// Commitment to the index masks.
    ECPoint a;

    /// Commitment to the binary sender index.
    ECPoint b;

    /// Commitment to the linear bit-constraint coefficients.
    ECPoint c;

    /// Commitment to the constant bit-constraint coefficients.
    ECPoint d;

    /// Lower-degree polynomial commitments for the selected transfer.
    std::vector<ECPoint> c_c;

    /// Lower-degree polynomial commitments for the sender selector.
    std::vector<ECPoint> c_s;

    /// Masked sender-index bit responses.
    std::vector<ZnElement> f;

    /// Opening response for the binary index commitment.
    ZnElement z_a;

    /// Blinding response for the binary constraints.
    ZnElement z_c;

    /// Aggregate randomness response for the selected transfer.
    ZnElement z_g;

    /// Blinding response linking the selected index to sender.s.
    ZnElement z_s;

    /// Post-balance proof and its shared sender selector.
    sender_balance::Proof sender;

    /// Range proof for the debit.
    range_proofs::bulletproof::Proof values;

    /// Range proof for the debit minus one.
    range_proofs::bulletproof::Proof shifted;

    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }
    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

PublicParameters setup(const pke::twisted_elgamal::PublicParameters& encryption,
                       std::size_t participant_count);

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});

Proof initialize_proof(const PublicParameters& pp);

} // namespace taihang::zkp::apgc::solvency

#endif // TAIHANG_PROTOCOLS_APGC_SOLVENCY_PROOF_HPP
