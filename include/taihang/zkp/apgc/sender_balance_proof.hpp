/****************************************************************************
 * @file      sender_balance_proof.hpp
 * @brief     Original APGC sender-balance proof and its four subprotocols.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_APGC_SENDER_BALANCE_PROOF_HPP
#define TAIHANG_PROTOCOLS_APGC_SENDER_BALANCE_PROOF_HPP

#include <taihang/pke/twisted_elgamal.hpp>
#include <taihang/zkp/range_proofs/bullet_proof.hpp>
#include <taihang/zkp/sigma_protocols/homomorphism_evaluation_proof.hpp>
#include <taihang/zkp/sigma_protocols/fixed_weight_binary_vector_proof.hpp>
#include <taihang/zkp/sigma_protocols/multi_exponentiation_proof.hpp>

namespace taihang::zkp::apgc::sender_balance {

/** @brief Shared bases for the sender selector, balance range, and linkage. */
struct PublicParameters {
    /// Encryption bases used by balances and transfer ciphertexts.
    pke::twisted_elgamal::PublicParameters encryption;

    /// Power-of-two anonymous-set size.
    std::size_t participant_count;

    /// Blinding base shared by the vector and selector commitments.
    ECPoint u;

    /// Inner-product base for the fixed-weight selector argument.
    ECPoint inner_product_u;

    /// Generator basis for the sender selection vector.
    std::vector<ECPoint> vector_g;

    /// Generator basis for the selection complement.
    std::vector<ECPoint> vector_h;

    /// Bases for 2*n selected opening coordinates and n balance blindings.
    std::vector<ECPoint> vector_u;

    /// Parameters for the 32-bit post-transfer balance range proof.
    range_proofs::bulletproof::PublicParameters range;
};

/** @brief Public transfers and external ledger balances in anonymous-set order. */
struct Statement {
    /// Encryption public keys for the anonymous set.
    std::vector<ECPoint> public_keys;

    /// Signed transfer ciphertexts for the current transaction.
    std::vector<pke::twisted_elgamal::Ciphertext> transfers;

    /// Existing ledger balance ciphertexts, supplied separately by the
    /// verifier.
    std::vector<pke::twisted_elgamal::Ciphertext> balances;
};

/** @brief Selected sender opening for the post-transfer balance relation. */
struct Witness {
    /// Zero-based sender index in the anonymous set.
    std::size_t index;

    /// Inverse of the selected sender's nonzero secret key.
    ZnElement inverse_secret_key;

    /// Plaintext balance after applying the sender's transfer.
    ZnElement post_balance;
};

/** @brief Sender selector, balance commitment, and four composed subproofs. */
struct Proof {
    /// Commitment to the selected sender opening vector.
    ECPoint p;

    /// Commitment to the sender selection vector and its complement.
    ECPoint s;

    /// Post-balance commitment V = g*r_v + h*post_balance.
    ECPoint v;

    /// Unused legacy scalar, retained in the serialized proof format.
    ZnElement z_s;

    /// Unused legacy scalar, retained in the serialized proof format.
    ZnElement k;

    /// Masked blinding-difference response for the representation argument.
    ZnElement f;

    /// First message masking the opening of P - S.
    ECPoint a_x;

    /// Proof linking P to the balance and transfer ciphertexts.
    nizk::homomorphism_evaluation::Proof homomorphism;

    /// Fixed-weight binary-vector proof selecting exactly one sender.
    nizk::fixed_weight_binary_vector::Proof binary;

    /// Proof linking the vector and selector commitments.
    nizk::multi_exponentiation::Proof representation;

    /// Proof that the post-transfer balance lies in [0, 2^32).
    range_proofs::bulletproof::Proof range;

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

namespace detail {

/** @brief Prover-only randomness shared with Solvent; never serialize or publish it. */
struct ProverState {
    /// Blinding of S, shared privately with the solvency prover.
    ZnElement r_s;
};

Proof prove_with_state(const PublicParameters& pp,
                       const Statement& statement,
                       const Witness& witness,
                       ProverState& state,
                       std::string_view context = {});

bool valid_statement(const PublicParameters& pp, const Statement& statement);

/** @brief Original transcript passed from SdrBalance's final AmorHom to Solvent. */
std::string homomorphism_transcript(const PublicParameters& pp,
                                    const Statement& statement,
                                    const Proof& proof,
                                    std::string_view context = {});

} // namespace detail

} // namespace taihang::zkp::apgc::sender_balance

#endif // TAIHANG_PROTOCOLS_APGC_SENDER_BALANCE_PROOF_HPP
