/****************************************************************************
 * @file      solvency_proof.hpp
 * @brief     Original APGC Solvent composition with a shared sender selector.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_APGC_SOLVENCY_PROOF_HPP
#define TAIHANG_PROTOCOLS_APGC_SOLVENCY_PROOF_HPP

#include <taihang/zkp/apgc/sender_balance_proof.hpp>

namespace taihang::zkp::apgc::solvency {

struct PublicParameters {
    sender_balance::PublicParameters sender;
    std::vector<ECPoint> index_g;
    range_proofs::bulletproof::PublicParameters values_range;
    range_proofs::bulletproof::PublicParameters shifted_range;
};

using Statement = sender_balance::Statement;
struct Witness {
    ZnElement secret_key;
    std::size_t index;
    ZnElement post_balance;
    ZnElement transfer_value;
    ZnElement transfer_randomness;
};

struct Proof {
    ECPoint a;
    ECPoint b;
    ECPoint c;
    ECPoint d;
    std::vector<ECPoint> c_c;
    std::vector<ECPoint> c_s;
    std::vector<ZnElement> f;
    ZnElement z_a;
    ZnElement z_c;
    ZnElement z_g;
    ZnElement z_s;
    sender_balance::Proof sender;
    range_proofs::bulletproof::Proof values;
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
