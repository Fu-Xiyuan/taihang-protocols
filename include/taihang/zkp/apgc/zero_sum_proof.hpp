/****************************************************************************
 * @file      zero_sum_proof.hpp
 * @brief     Original APGC Sigma proof that transfer amounts sum to zero.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_APGC_ZERO_SUM_PROOF_HPP
#define TAIHANG_PROTOCOLS_APGC_ZERO_SUM_PROOF_HPP

#include <taihang/pke/twisted_elgamal.hpp>

namespace taihang::zkp::apgc::zero_sum {

struct PublicParameters {
    pke::twisted_elgamal::PublicParameters encryption;
    std::size_t participant_count;
};

struct Statement {
    ECPoint c;
};

struct Witness {
    std::vector<ZnElement> randomness;
};

struct Proof {
    ECPoint a;
    ZnElement z;
    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }
    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

PublicParameters setup(const pke::twisted_elgamal::PublicParameters& encryption, std::size_t count);
Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});
bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});
Proof initialize_proof(const PublicParameters& pp);

} // namespace taihang::zkp::apgc::zero_sum

#endif // TAIHANG_PROTOCOLS_APGC_ZERO_SUM_PROOF_HPP
