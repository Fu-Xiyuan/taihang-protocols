/****************************************************************************
 * @file      bench_attema_cramer_fehr_proof.cpp
 * @brief     Benchmark suite for ACF K-out-of-N proofs.
 *
 * Public-parameter setup, witness generation, and statement construction are
 * outside the timed region. Each operation is warmed up before measurement.
 *****************************************************************************/

#include <omp.h>
#include <openssl/obj_mac.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <taihang/common/config.hpp>
#include <taihang/system/cpu.hpp>
#include <taihang/zkp/k_out_of_n_protocols/attema_cramer_fehr_proof.hpp>

namespace {

using namespace taihang;
namespace protocol = taihang::zkp::k_out_of_n::attema_cramer_fehr;

using Clock = std::chrono::steady_clock;
using Milliseconds = std::chrono::duration<double, std::milli>;

constexpr int kCurveId = NID_X9_62_prime256v1;
constexpr std::size_t kDefaultIterations = 10;
constexpr std::size_t kDefaultWarmups = 1;
constexpr std::string_view kContext = "koon-benchmark";

constexpr std::array<std::size_t, 3> kStatementCounts = {32, 64, 128};
constexpr std::array<std::size_t, 3> kThresholds = {1, 4, 8};
constexpr std::array<int, 4> kThreadCounts = {1, 2, 4, 8};

struct Workload {
    std::size_t statement_count;
    std::size_t threshold;
    protocol::Witness witness;
    protocol::Statement statement;
};

struct BenchResult {
    std::size_t statement_count = 0;
    std::size_t threshold = 0;
    int thread_count = 0;
    double prove_ms = 0.0;
    double verify_ms = 0.0;
    std::size_t proof_bytes = 0;
    bool passed = false;
};

// Validation runs after each call, outside its measured interval.
template <typename Function, typename Validator>
double average_ms(std::size_t warmups,
                  std::size_t iterations,
                  Function&& function,
                  Validator&& validate) {
    for (std::size_t i = 0; i < warmups; ++i) {
        function();
        validate();
    }

    double elapsed_ms = 0.0;
    for (std::size_t i = 0; i < iterations; ++i) {
        const Clock::time_point begin = Clock::now();
        function();
        elapsed_ms += Milliseconds(Clock::now() - begin).count();
        validate();
    }
    return elapsed_ms / static_cast<double>(iterations);
}

void set_thread_count(int thread_count) {
    config::thread_num = thread_count;
    omp_set_dynamic(0);
    omp_set_num_threads(thread_count);
}

// Both discrete-log benchmarks use identical labels, selected indices,
// secrets and a common base; protocol setup remains outside measurement.
Workload make_workload(const protocol::PublicParameters& pp) {
    const std::size_t n = pp.statement_count;
    const std::size_t k = pp.threshold;
    protocol::Witness witness;
    protocol::Statement statement;
    for (std::size_t j = 0; j < n; ++j) {
        statement.points.push_back(hash_to_curve_standard(
            "taihang/koon-benchmark/point/" + std::to_string(j),
            "TAIHANG-PROTOCOLS-V01-P256_XMD:SHA-256_SSWU_RO_", *pp.group_ctx));
    }
    for (std::size_t i = 0; i < k; ++i) {
        const std::size_t index = n - 1 - i;
        witness.indices.push_back(index);
        witness.secrets.push_back(hash_to_zn(
            "taihang/koon-benchmark/secret/" + std::to_string(index), *pp.ring_ctx));
        statement.points[index] = pp.g * witness.secrets.back();
    }
    return {n, k, std::move(witness), std::move(statement)};
}

BenchResult run_once(const protocol::PublicParameters& pp,
                     const Workload& workload,
                     int thread_count,
                     std::size_t warmups,
                     std::size_t iterations) {
    set_thread_count(thread_count);

    protocol::Proof proof;
    bool passed = true;
    const double prove_ms = average_ms(warmups, iterations, [&] {
        proof = protocol::prove(
            pp, workload.statement, workload.witness, kContext);
    }, [&] {
        passed = protocol::verify(
                     pp, workload.statement, proof, kContext) && passed;
    });

    const double verify_ms = average_ms(warmups, iterations, [&] {
        passed = protocol::verify(
                     pp, workload.statement, proof, kContext) && passed;
    }, [] {});

    std::ostringstream encoded;
    encoded << proof;
    return {workload.statement_count, workload.threshold, thread_count,
            prove_ms, verify_ms, encoded.str().size(), passed && encoded.good()};
}

void print_benchmark_header(std::size_t physical_cores,
                            std::size_t warmups,
                            std::size_t iterations) {
    std::cout
        << "\n"
        << "===================================================="
           "====================================================\n"
        << "                              Taihang ACF K-out-of-N Benchmark\n"
        << "===================================================="
           "====================================================\n"
        << "Curve               : Secp256r1\n"
        << "Statement counts    : 32, 64, 128\n"
        << "Thresholds          : 1, 4, 8\n"
        << "Public relations    : common-base discrete logarithms\n"
        << "OpenMP thread counts: 1, 2, 4, 8\n"
        << "Physical CPU cores  : " << physical_cores << "\n"
        << "Warmup calls        : " << warmups << " per operation\n"
        << "Measured calls      : " << iterations << " per operation\n"
        << "Proof size          : serialized proof only, in bytes\n"
        << "Timing excludes     : setup, inputs, validation, serialization\n"
        << "===================================================="
           "====================================================\n";
}

void print_workload_header(std::size_t statement_count, std::size_t threshold) {
    std::cout << "\n"
              << "========================================"
                 "========================================\n"
              << "ACF K-out-of-N / n=" << statement_count << " / k=" << threshold << "\n"
              << "----------------------------------------"
                 "----------------------------------------\n"
              << std::left << std::setw(12) << "Threads"
              << std::right << std::setw(16) << "Prove(ms)"
              << std::setw(16) << "Verify(ms)"
              << std::setw(16) << "Proof(bytes)"
              << std::setw(12) << "Status" << "\n"
              << "----------------------------------------"
                 "----------------------------------------\n";
}

void print_workload_result(const BenchResult& result) {
    std::cout << std::left << std::setw(12) << result.thread_count
              << std::right << std::fixed << std::setprecision(3)
              << std::setw(16) << result.prove_ms
              << std::setw(16) << result.verify_ms
              << std::setw(16) << result.proof_bytes
              << std::setw(12) << (result.passed ? "PASS" : "FAIL")
              << "\n";
}

void print_summary(const std::vector<BenchResult>& results) {
    constexpr int kConfigurationWidth = 20;

    std::cout
        << "\n\n"
        << "===================================================="
           "====================================================\n"
        << "                              ACF K-out-of-N Benchmark Summary\n"
        << "===================================================="
           "====================================================\n"
        << std::left << std::setw(kConfigurationWidth) << "Configuration"
        << std::right << std::setw(10) << "Threads"
        << std::setw(14) << "Prove(ms)"
        << std::setw(13) << "Prove(x)"
        << std::setw(14) << "Verify(ms)"
        << std::setw(14) << "Verify(x)"
        << std::setw(16) << "Proof(bytes)"
        << std::setw(10) << "Status" << "\n"
        << "----------------------------------------------------"
           "----------------------------------------------------\n";

    for (std::size_t statement_count : kStatementCounts) {
        for (std::size_t threshold : kThresholds) {
            const BenchResult* baseline = nullptr;
            for (const BenchResult& result : results) {
                if (result.statement_count == statement_count &&
                    result.threshold == threshold && result.thread_count == 1) {
                    baseline = &result;
                    break;
                }
            }

            for (const BenchResult& result : results) {
                if (result.statement_count != statement_count ||
                    result.threshold != threshold) {
                    continue;
                }
                const std::string label = "n=" + std::to_string(statement_count) +
                                          ", k=" + std::to_string(threshold);
                std::cout << std::left << std::setw(kConfigurationWidth) << label
                          << std::right << std::setw(10) << result.thread_count
                          << std::fixed << std::setprecision(3)
                          << std::setw(14) << result.prove_ms
                          << std::setw(13) << baseline->prove_ms / result.prove_ms
                          << std::setw(14) << result.verify_ms
                          << std::setw(14) << baseline->verify_ms / result.verify_ms
                          << std::setw(16) << result.proof_bytes
                          << std::setw(10) << (result.passed ? "PASS" : "FAIL")
                          << "\n";
            }
        }
    }

    std::cout
        << "===================================================="
           "====================================================\n";
}

std::size_t parse_positive(const char* value, const char* name) {
    char* end = nullptr;
    errno = 0;
    const unsigned long long parsed = std::strtoull(value, &end, 10);
    if (*value < '0' || *value > '9' || *end != '\0' || parsed == 0 ||
        errno == ERANGE || parsed > std::numeric_limits<std::size_t>::max()) {
        std::cerr << name << " must be a positive integer\n";
        std::exit(EXIT_FAILURE);
    }
    return static_cast<std::size_t>(parsed);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc > 3) {
        std::cerr << "Usage: " << argv[0] << " [iterations] [warmups]\n";
        return EXIT_FAILURE;
    }

    const std::size_t iterations =
        argc > 1 ? parse_positive(argv[1], "iterations")
                 : kDefaultIterations;
    const std::size_t warmups =
        argc > 2 ? parse_positive(argv[2], "warmups") : kDefaultWarmups;

    const std::size_t physical_cores = system::get_physical_core_count();
    print_benchmark_header(physical_cores, warmups, iterations);

    std::vector<BenchResult> summary;
    summary.reserve(kStatementCounts.size() * kThresholds.size() *
                    kThreadCounts.size());
    bool passed = true;
    for (std::size_t statement_count : kStatementCounts) {
        for (std::size_t threshold : kThresholds) {
            set_thread_count(1);
            const protocol::PublicParameters pp = protocol::setup(
                kCurveId, statement_count, threshold);
            const Workload workload = make_workload(pp);
            print_workload_header(statement_count, threshold);
            for (int thread_count : kThreadCounts) {
                const BenchResult result = run_once(
                    pp, workload, thread_count, warmups, iterations);
                print_workload_result(result);
                summary.emplace_back(result);
                passed = result.passed && passed;
            }
        }
    }

    print_summary(summary);
    return passed ? EXIT_SUCCESS : EXIT_FAILURE;
}
