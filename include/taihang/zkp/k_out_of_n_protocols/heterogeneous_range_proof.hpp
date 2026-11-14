/****************************************************************************
 * @file      heterogeneous_range_proof.hpp
 * @brief     Heterogeneous k-out-of-n range proof with one delayed bridge aggregate.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_ZKP_HETEROGENEOUS_RANGE_PROOF_HPP
#define TAIHANG_PROTOCOLS_ZKP_HETEROGENEOUS_RANGE_PROOF_HPP

#include <taihang/zkp/k_out_of_n_protocols/heterogeneous_k_out_of_n_proof.hpp>
#include <taihang/zkp/sigma_protocols/aggregate_range_proof.hpp>

namespace taihang::zkp::k_out_of_n::heterogeneous_range {

struct PublicParameters {
    /// Core opening length includes one extra coordinate for bridge randomness.
    heterogeneous::PublicParameters core;
    nizk::aggregate_range::PublicParameters range;
};

using Statement = heterogeneous::Statement;
/** @brief User map dimensions exclude the extra internal bridge coordinate. */
using Witness = heterogeneous::Witness;

struct Proof {
    heterogeneous::Proof core;
    nizk::aggregate_range::Proof range;
    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }
    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    /** @note Initialize core with output_length+1 evaluations for the extra bridge equation. */
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

/** @brief Range-constrain coordinate zero of each selected opening vector. */
PublicParameters setup(int curve_id, std::size_t statement_count, std::size_t threshold,
                       std::size_t opening_length, std::size_t output_length, std::size_t range_bits);
Proof prove(const PublicParameters& pp, const Statement& statement,
            const Witness& witness, std::string_view context = {});
bool verify(const PublicParameters& pp, const Statement& statement,
            const Proof& proof, std::string_view context = {});

} // namespace taihang::zkp::k_out_of_n::heterogeneous_range
#endif // TAIHANG_PROTOCOLS_ZKP_HETEROGENEOUS_RANGE_PROOF_HPP
