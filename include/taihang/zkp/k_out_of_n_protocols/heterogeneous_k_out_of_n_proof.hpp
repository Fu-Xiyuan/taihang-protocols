/****************************************************************************
 * @file      heterogeneous_k_out_of_n_proof.hpp
 * @brief     k-out-of-n knowledge proof for distinct linear group homomorphisms.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_ZKP_HETEROGENEOUS_K_OUT_OF_N_PROOF_HPP
#define TAIHANG_PROTOCOLS_ZKP_HETEROGENEOUS_K_OUT_OF_N_PROOF_HPP

#include <iosfwd>
#include <string>
#include <string_view>
#include <vector>

#include <taihang/zkp/sigma_protocols/fixed_weight_binary_vector_proof.hpp>
#include <taihang/zkp/sigma_protocols/homomorphism_evaluation_proof.hpp>
#include <taihang/zkp/sigma_protocols/multi_exponentiation_proof.hpp>

namespace taihang::zkp::k_out_of_n::heterogeneous {

struct PublicParameters {
    std::size_t statement_count;
    std::size_t threshold;
    std::size_t opening_length;
    std::size_t output_length;
    nizk::fixed_weight_binary_vector::PublicParameters selection;
    nizk::homomorphism_evaluation::PublicParameters commitment;
};

/** @brief bases[j][q*t+a] maps opening coordinate a to output q of instance j. */
struct Statement {
    std::vector<std::vector<ECPoint>> bases;
    std::vector<std::vector<ECPoint>> outputs;
};

/** @brief Openings at k distinct zero-based indices; other openings are not needed. */
struct Witness {
    std::vector<std::size_t> indices;
    std::vector<std::vector<ZnElement>> openings;
};

struct Proof {
    ECPoint p;
    ECPoint s;
    nizk::fixed_weight_binary_vector::Proof selection;
    ECPoint a_x;
    ZnElement f;
    nizk::multi_exponentiation::Proof consistency;
    std::vector<nizk::homomorphism_evaluation::Proof> evaluations;
    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }
    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    /** @note Preinitialize all contexts, nested folding vectors, and output_length evaluations. */
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

/** @brief Supports power-of-two n, arbitrary 1<=k<=n, and positive opening/output dimensions. */
PublicParameters setup(int curve_id,
                       std::size_t statement_count,
                       std::size_t threshold,
                       std::size_t opening_length = 1,
                       std::size_t output_length = 1);
Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});
/** @note Contexts must be compatible. Invalid dimensions or equations return false. */
bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});

namespace detail {

/** @brief Private state shared with the range extension; never serialize or publish it. */
struct ProverState {
    std::vector<ZnElement> y;
    std::vector<ZnElement> selection;
    std::vector<ZnElement> complement;
    ZnElement r_p;
    ZnElement r_s;
    ECPoint p;
    ECPoint s;
};

bool valid_parameters(const PublicParameters& pp);
bool valid_statement(const PublicParameters& pp, const Statement& statement);
ProverState prepare(const PublicParameters& pp, const Witness& witness);
std::string binding_context(const PublicParameters& pp,
                            const Statement& statement,
                            const ECPoint& p,
                            const ECPoint& s,
                            std::string_view context);
/** @brief The range parent may append one fully bound aggregate bridge equation. */
Proof prove_prepared(const PublicParameters& pp,
                     const Statement& statement,
                     const ProverState& state,
                     std::string_view context,
                     const std::vector<ECPoint>* bridge_bases = nullptr,
                     const ECPoint* bridge_target = nullptr,
                     std::string_view evaluation_context = {});
bool verify_extended(const PublicParameters& pp,
                     const Statement& statement,
                     const Proof& proof,
                     std::string_view context,
                     const std::vector<ECPoint>* bridge_bases = nullptr,
                     const ECPoint* bridge_target = nullptr,
                     std::string_view evaluation_context = {});

} // namespace detail
} // namespace taihang::zkp::k_out_of_n::heterogeneous
#endif // TAIHANG_PROTOCOLS_ZKP_HETEROGENEOUS_K_OUT_OF_N_PROOF_HPP
