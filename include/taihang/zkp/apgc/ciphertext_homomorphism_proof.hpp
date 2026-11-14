/****************************************************************************
 * @file      ciphertext_homomorphism_proof.hpp
 * @brief     APGC ciphertext homomorphism proof from AmorHom_Wellform.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_APGC_CIPHERTEXT_HOMOMORPHISM_PROOF_HPP
#define TAIHANG_PROTOCOLS_APGC_CIPHERTEXT_HOMOMORPHISM_PROOF_HPP

#include <taihang/pke/twisted_elgamal.hpp>
#include <taihang/zkp/sigma_protocols/homomorphism_evaluation_proof.hpp>
#include <taihang/zkp/range_proofs/bullet_proof.hpp>

namespace taihang::zkp::apgc::ciphertext_homomorphism {

struct PublicParameters {
    pke::twisted_elgamal::PublicParameters encryption;
    std::size_t participant_count;
    nizk::homomorphism_evaluation::PublicParameters commitment;
};

struct Statement {
    ECPoint p;
    std::vector<ECPoint> public_keys;
    std::vector<pke::twisted_elgamal::Ciphertext> transfers;
};

using Witness = nizk::homomorphism_evaluation::Witness;
using Proof = nizk::homomorphism_evaluation::Proof;

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

std::size_t folding_rounds(std::size_t length);
std::vector<ZnElement> powers(std::size_t length, const ZnElement& base);
ZnElement dot(const std::vector<ZnElement>& a, const std::vector<ZnElement>& b);
std::vector<ECPoint> generators(const std::shared_ptr<ECGroup>& group,
                                std::size_t length, const std::string& label);
Proof initialize_evaluation(const nizk::homomorphism_evaluation::PublicParameters& pp);
/** @brief Original masked evaluation followed by the migrated Eqmdl subprotocol. */
Proof prove_evaluation(const nizk::homomorphism_evaluation::PublicParameters& pp,
                       const nizk::homomorphism_evaluation::Statement& statement,
                       const Witness& witness, std::string& transcript,
                       bool reset_equality_context = false);
bool verify_evaluation(const nizk::homomorphism_evaluation::PublicParameters& pp,
                       const nizk::homomorphism_evaluation::Statement& statement,
                       const Proof& proof, std::string& transcript,
                       bool reset_equality_context = false);
void append_equality(std::ostringstream& transcript,
                      const nizk::multi_exponentiation_equality::Proof& proof);
range_proofs::inner_product::PublicParameters inner_parameters(
    const pke::twisted_elgamal::PublicParameters& encryption,
    const std::vector<ECPoint>& g, const std::vector<ECPoint>& h, const ECPoint& u);
range_proofs::inner_product::Proof initialize_inner(
    const pke::twisted_elgamal::PublicParameters& encryption, std::size_t length);
range_proofs::bulletproof::PublicParameters range_parameters(
    const pke::twisted_elgamal::PublicParameters& encryption,
    std::size_t range_bits, std::size_t count, const ECPoint& u, const std::string& label);
range_proofs::bulletproof::Proof initialize_range(
    const range_proofs::bulletproof::PublicParameters& pp);

} // namespace detail

} // namespace taihang::zkp::apgc::ciphertext_homomorphism

#endif // TAIHANG_PROTOCOLS_APGC_CIPHERTEXT_HOMOMORPHISM_PROOF_HPP
