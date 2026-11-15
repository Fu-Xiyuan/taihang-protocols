/****************************************************************************
 * @file      positive_transfer_proof.hpp
 * @brief     Original APGC Positive composition of Koon and two weighted ranges.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_APGC_POSITIVE_TRANSFER_PROOF_HPP
#define TAIHANG_PROTOCOLS_APGC_POSITIVE_TRANSFER_PROOF_HPP

#include <taihang/pke/twisted_elgamal.hpp>
#include <taihang/zkp/range_proofs/bullet_proof.hpp>
#include <taihang/zkp/sigma_protocols/logarithmic_binary_vector_proof.hpp>

namespace taihang::zkp::apgc::positive_transfer {

/** @brief Bases for the hidden receiver selector and weighted amount ranges. */
struct PublicParameters {
    /// Transfer commitment bases g and h.
    pke::twisted_elgamal::PublicParameters encryption;

    /// Power-of-two anonymous-set size.
    std::size_t participant_count;

    /// Number of distinct receivers selected by the proof.
    std::size_t receiver_count;

    /// Binary index length, equal to log2(participant_count).
    std::size_t index_bits;

    /// Blinding base for the selector commitments.
    ECPoint u;

    /// Inner-product base for the binary-vector argument.
    ECPoint inner_product_u;

    /// Generator basis for the receiver selection vector.
    std::vector<ECPoint> vector_g;

    /// Generator basis for the selection complement.
    std::vector<ECPoint> vector_h;

    /// Bases for receiver_count concatenated binary index encodings.
    std::vector<ECPoint> index_g;

    /// Parameters for the weighted 32-bit amount range proof.
    range_proofs::bulletproof::PublicParameters values_range;

    /// Parameters for the weighted range proof of amounts minus one.
    range_proofs::bulletproof::PublicParameters shifted_range;
};

/** @brief Public transfer commitments in anonymous-set order. */
struct Statement {
    /// Second ciphertext components c2_i = g*r_i + h*v_i.
    std::vector<ECPoint> commitments;
};

/** @brief Distinct receiver indices and their transfer openings. */
struct Witness {
    /// Zero-based receiver indices, in the same order as values and
    /// randomness.
    std::vector<std::size_t> indices;

    /// Strictly positive receiver amounts constrained by the two range proofs.
    std::vector<ZnElement> values;

    /// Encryption randomness for the selected transfer ciphertexts.
    std::vector<ZnElement> randomness;
};

/** @brief Koon selector with x before coefficient messages and e = H(A,B,C,D,P). */
struct SelectionProof {
    /// Commitment to the index masks.
    ECPoint a;

    /// Commitment to the concatenated binary receiver indices.
    ECPoint b;

    /// Commitment to the linear bit-constraint coefficients.
    ECPoint c;

    /// Commitment to the constant bit-constraint coefficients.
    ECPoint d;

    /// Commitment to the receiver selection vector and its complement.
    ECPoint p;

    /// Weighted lower-degree polynomial commitments for transfer aggregation.
    std::vector<ECPoint> c_c;

    /// Lower-degree polynomial commitments for selection consistency.
    std::vector<ECPoint> c_p;

    /// Masked receiver-index bit responses.
    std::vector<ZnElement> f;

    /// Opening response for the binary index commitment.
    ZnElement z_a;

    /// Blinding response for the binary constraints.
    ZnElement z_c;

    /// Aggregate randomness response for the selected transfers.
    ZnElement z_g;

    /// Blinding response linking the index polynomials to P.
    ZnElement z_p;

    /// Logarithmic binary-vector proof for the receiver selection vector.
    nizk::logarithmic_binary_vector::Proof binary;

    bool operator==(const SelectionProof& other) const;
    friend std::ostream& operator<<(std::ostream& os,
                                    const SelectionProof& proof);
    friend std::istream& operator>>(std::istream& is, SelectionProof& proof);
};

/** @brief Hidden receiver selector and two weighted amount range proofs. */
struct Proof {
    /// Koon selector defining the weighted aggregate commitment.
    SelectionProof subset;

    /// Range proof for the selected receiver amounts.
    range_proofs::bulletproof::Proof values;

    /// Range proof for the selected amounts minus one.
    range_proofs::bulletproof::Proof shifted;

    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }
    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

PublicParameters setup(const pke::twisted_elgamal::PublicParameters& encryption,
                       std::size_t participant_count,
                       std::size_t receiver_count);

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});

Proof initialize_proof(const PublicParameters& pp);

} // namespace taihang::zkp::apgc::positive_transfer

#endif // TAIHANG_PROTOCOLS_APGC_POSITIVE_TRANSFER_PROOF_HPP
