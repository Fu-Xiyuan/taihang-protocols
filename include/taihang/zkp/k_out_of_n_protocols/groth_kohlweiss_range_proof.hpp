/****************************************************************************
 * @file      groth_kohlweiss_range_proof.hpp
 * @brief     GK k-out-of-n proof of commitment openings in a prescribed range.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_ZKP_GROTH_KOHLWEISS_RANGE_PROOF_HPP
#define TAIHANG_PROTOCOLS_ZKP_GROTH_KOHLWEISS_RANGE_PROOF_HPP

#include <taihang/zkp/sigma_protocols/subset_aggregation_proof.hpp>
#include <taihang/zkp/sigma_protocols/aggregate_range_proof.hpp>

namespace taihang::zkp::k_out_of_n::groth_kohlweiss_range {

struct PublicParameters {
    nizk::subset_aggregation::PublicParameters subset;
    nizk::aggregate_range::PublicParameters range;
};

struct Statement {
    std::vector<ECPoint> commitments;
};

struct Witness {
    std::vector<std::size_t> indices;
    std::vector<ZnElement> values;
    std::vector<ZnElement> randomness;
};

struct Proof {
    nizk::subset_aggregation::Proof subset;
    nizk::aggregate_range::Proof range;
    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }
    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    /** @note Preinitialize both subproofs using their expected dimensions and contexts. */
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

/** @brief Supports power-of-two n>=2, arbitrary 1<=k<=n, and power-of-two range_bits. */
PublicParameters setup(int curve_id, std::size_t statement_count, std::size_t threshold,
                       std::size_t range_bits);
Proof prove(const PublicParameters& pp, const Statement& statement,
            const Witness& witness, std::string_view context = {});
bool verify(const PublicParameters& pp, const Statement& statement,
            const Proof& proof, std::string_view context = {});

} // namespace taihang::zkp::k_out_of_n::groth_kohlweiss_range
#endif // TAIHANG_PROTOCOLS_ZKP_GROTH_KOHLWEISS_RANGE_PROOF_HPP
