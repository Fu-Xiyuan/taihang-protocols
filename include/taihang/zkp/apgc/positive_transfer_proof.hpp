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

struct PublicParameters {
    pke::twisted_elgamal::PublicParameters encryption;
    std::size_t participant_count;
    std::size_t receiver_count;
    std::size_t index_bits;
    ECPoint u;
    ECPoint inner_product_u;
    std::vector<ECPoint> vector_g;
    std::vector<ECPoint> vector_h;
    std::vector<ECPoint> index_g;
    range_proofs::bulletproof::PublicParameters values_range;
    range_proofs::bulletproof::PublicParameters shifted_range;
};

struct Statement {
    std::vector<ECPoint> commitments;
};

struct Witness {
    std::vector<std::size_t> indices;
    std::vector<ZnElement> values;
    std::vector<ZnElement> randomness;
};

/** @brief Original Koon fields, with x before coefficient commitments and e=H(A,B,C,D,P). */
struct SelectionProof {
    ECPoint a;
    ECPoint b;
    ECPoint c;
    ECPoint d;
    ECPoint p;
    std::vector<ECPoint> c_c;
    std::vector<ECPoint> c_p;
    std::vector<ZnElement> f;
    ZnElement z_a;
    ZnElement z_c;
    ZnElement z_g;
    ZnElement z_p;
    nizk::logarithmic_binary_vector::Proof binary;

    bool operator==(const SelectionProof& other) const;
    friend std::ostream& operator<<(std::ostream& os, const SelectionProof& proof);
    friend std::istream& operator>>(std::istream& is, SelectionProof& proof);
};

struct Proof {
    SelectionProof subset;
    range_proofs::bulletproof::Proof values;
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
