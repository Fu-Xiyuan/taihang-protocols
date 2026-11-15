/****************************************************************************
 * @file      inactive_participant_proof.hpp
 * @brief     Original ZGSX23 proof for inactive APGC participant entries.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_APGC_INACTIVE_PARTICIPANT_PROOF_HPP
#define TAIHANG_PROTOCOLS_APGC_INACTIVE_PARTICIPANT_PROOF_HPP

#include <taihang/pke/twisted_elgamal.hpp>
#include <taihang/zkp/range_proofs/inner_product_proof.hpp>

namespace taihang::zkp::apgc::inactive_participant {

struct PublicParameters {
    pke::twisted_elgamal::PublicParameters encryption;
    std::size_t participant_count;
    ECPoint u;
    std::vector<ECPoint> vector_g;
    std::vector<ECPoint> vector_h;
};

struct Statement {
    std::vector<ECPoint> commitments;
    std::size_t count;
};

/** @brief One bit per entry and randomness for its one entries, in ascending index order. */
struct Witness {
    std::vector<ZnElement> bits;
    std::vector<ZnElement> randomness;
};

struct Proof {
    ECPoint a;
    ECPoint s;
    ECPoint t1;
    ECPoint t2;
    ECPoint e;
    ZnElement taux;
    ZnElement mu;
    ZnElement t;
    ZnElement f_s;
    range_proofs::inner_product::Proof inner_product;

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

} // namespace taihang::zkp::apgc::inactive_participant

#endif // TAIHANG_PROTOCOLS_APGC_INACTIVE_PARTICIPANT_PROOF_HPP
