/****************************************************************************
 * @file      sender_balance_proof.hpp
 * @brief     Original APGC sender-balance proof and its four subprotocols.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_APGC_SENDER_BALANCE_PROOF_HPP
#define TAIHANG_PROTOCOLS_APGC_SENDER_BALANCE_PROOF_HPP

#include <taihang/zkp/apgc/ciphertext_homomorphism_proof.hpp>
#include <taihang/zkp/sigma_protocols/fixed_weight_binary_vector_proof.hpp>
#include <taihang/zkp/sigma_protocols/multi_exponentiation_proof.hpp>

namespace taihang::zkp::apgc::sender_balance {

struct PublicParameters {
    pke::twisted_elgamal::PublicParameters encryption;
    std::size_t participant_count;
    ECPoint u;
    ECPoint inner_product_u;
    std::vector<ECPoint> vector_g;
    std::vector<ECPoint> vector_h;
    std::vector<ECPoint> vector_u;
    range_proofs::bulletproof::PublicParameters range;
};

struct Statement {
    std::vector<ECPoint> public_keys;
    std::vector<pke::twisted_elgamal::Ciphertext> transfers;
    std::vector<pke::twisted_elgamal::Ciphertext> balances;
};

struct Witness {
    std::size_t index;
    ZnElement inverse_secret_key;
    ZnElement post_balance;
};

struct Proof {
    ECPoint p;
    ECPoint s;
    ECPoint v;
    ZnElement z_s;
    ZnElement k;
    ZnElement f;
    ECPoint a_x;
    ciphertext_homomorphism::Proof homomorphism;
    nizk::fixed_weight_binary_vector::Proof binary;
    nizk::multi_exponentiation::Proof representation;
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
    ZnElement r_s;
};

Proof prove_with_state(const PublicParameters& pp,
                       const Statement& statement,
                       const Witness& witness,
                       ProverState& state,
                       std::string_view context = {});

bool valid_statement(const PublicParameters& pp, const Statement& statement);
/** @brief Original transcript passed from SdrBalance's final AmorHom to Solvent. */
std::string homomorphism_transcript(const PublicParameters& pp, const Statement& statement,
                                   const Proof& proof, std::string_view context = {});

} // namespace detail

} // namespace taihang::zkp::apgc::sender_balance

#endif // TAIHANG_PROTOCOLS_APGC_SENDER_BALANCE_PROOF_HPP
