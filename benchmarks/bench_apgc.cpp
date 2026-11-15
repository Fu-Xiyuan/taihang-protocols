/****************************************************************************
 * @file      bench_apgc.cpp
 * @brief     Benchmark suite for APGC transaction generation and verification.
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
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <taihang/algorithm/bsgs_dlog.hpp>
#include <taihang/common/config.hpp>
#include <taihang/system/cpu.hpp>
#include <taihang/zkp/apgc/apgc.hpp>

namespace {

using namespace taihang;
namespace application = taihang::zkp::apgc;
namespace encryption = taihang::pke::twisted_elgamal;

using Clock = std::chrono::steady_clock;
using Milliseconds = std::chrono::duration<double, std::milli>;

constexpr int kCurveId = NID_X9_62_prime256v1;
constexpr std::size_t kRangeBits = 32;
constexpr std::size_t kDefaultIterations = 10;
constexpr std::size_t kDefaultWarmups = 1;
constexpr std::size_t kBsgsTradeoff = 7;
constexpr std::uint64_t kInitialBalance = 1024;
constexpr std::uint64_t kReceiverAmount = 2;

constexpr std::array<int, 4> kThreadCounts = {1, 2, 4, 8};
constexpr std::array<std::pair<std::size_t, std::size_t>, 17> kConfigurations = {{
    {16, 1}, {16, 4}, {16, 8},
    {32, 1}, {32, 4}, {32, 8},
    {64, 1}, {64, 4}, {64, 8},
    {256, 1}, {256, 2}, {256, 4}, {256, 8},
    {256, 16}, {256, 32}, {256, 64}, {256, 128}
}};

struct Workload {
    application::Account sender;
    std::vector<application::Participant> participants;
    std::vector<BigInt> amounts;
    std::vector<std::size_t> receiver_indices;
};

struct BenchResult {
    std::size_t participant_count = 0;
    std::size_t receiver_count = 0;
    int thread_count = 0;
    double generate_ms = 0.0;
    double verify_ms = 0.0;
    std::size_t transaction_bytes = 0;
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

// Build the 32-bit baby-step table once in memory. No table files are written.
// Every workload uses the same P-256 encryption base, checked before reuse.
void prepare_decryption_table(dlog::BSGSSolver& solver) {
    solver.key_to_index.reserve(solver.babystep_num);
    bool unique = false;
    while (!unique) {
        unique = true;
        solver.key_to_index.clear();
        ECPoint point = solver.group_ctx->get_infinity();
        for (std::size_t i = 0; i < solver.babystep_num; ++i) {
            if (!solver.key_to_index.emplace(
                    point.xxhash_to_uint64(solver.hash_salt),
                    static_cast<std::uint32_t>(i)).second) {
                unique = false;
                ++solver.hash_salt;
                break;
            }
            point.add_inplace(solver.g);
        }
    }
}

Workload make_workload(const application::PublicParameters& pp) {
    Workload workload{application::initialize_account(pp), {}, {}, {}};
    for (std::size_t j = 0; j < pp.participant_count; ++j) {
        const application::Account account = application::create_account(
            pp, "benchmark-account-" + std::to_string(j), BigInt(kInitialBalance));
        workload.participants.push_back(
            {account.identity, account.public_key.y, account.balance});
        if (j == 0) {
            workload.sender = account;
        }
    }
    for (std::size_t i = 0; i < pp.receiver_count; ++i) {
        workload.receiver_indices.push_back(i + 1);
        workload.amounts.emplace_back(kReceiverAmount);
    }
    return workload;
}

BenchResult run_once(const application::PublicParameters& pp,
                     const Workload& workload,
                     const dlog::BSGSSolver& table,
                     int thread_count,
                     std::size_t warmups,
                     std::size_t iterations) {
    set_thread_count(thread_count);
    dlog::BSGSSolver solver(*pp.encryption.group_ctx, pp.encryption.h,
                           {kRangeBits, kBsgsTradeoff, static_cast<std::size_t>(thread_count)});
    if (solver.g.to_bytes() != table.g.to_bytes()) {
        std::cerr << "BSGS table base does not match the workload\n";
        std::exit(EXIT_FAILURE);
    }
    solver.hash_salt = table.hash_salt;
    solver.key_to_index = table.key_to_index;

    application::Transaction transaction;
    bool passed = true;
    const double generate_ms = average_ms(warmups, iterations, [&] {
        // Includes balance decryption, transfer encryption and all proofs.
        // No metrics pointer: size calculation is outside the timed call.
        transaction = application::create_transaction(
            pp, workload.sender, workload.amounts, workload.participants,
            0, workload.receiver_indices, solver);
    }, [&] {
        passed = application::verify_transaction(
                     pp, transaction, workload.participants) && passed;
    });

    const double verify_ms = average_ms(warmups, iterations, [&] {
        passed = application::verify_transaction(
                     pp, transaction, workload.participants) && passed;
    }, [] {});

    std::ostringstream encoded;
    encoded << transaction;
    return {pp.participant_count, pp.receiver_count, thread_count,
            generate_ms, verify_ms, encoded.str().size(), passed && encoded.good()};
}

void print_benchmark_header(std::size_t physical_cores,
                            std::size_t warmups,
                            std::size_t iterations) {
    std::cout
        << "\n"
        << "===================================================="
           "====================================================\n"
        << "                              Taihang APGC Benchmark\n"
        << "===================================================="
           "====================================================\n"
        << "Curve               : Secp256r1\n"
        << "Anonymous sets      : n=16,32,64 with t=1,4,8\n"
        << "Large anonymous set : n=256 with t=1,2,4,8,16,32,64,128\n"
        << "Range bits          : " << kRangeBits << "\n"
        << "Initial balance     : " << kInitialBalance << "\n"
        << "Receiver amount     : " << kReceiverAmount << " per receiver\n"
        << "BSGS tradeoff       : " << kBsgsTradeoff
        << " (2^23 baby steps, 2^9 giant steps)\n"
        << "BSGS threads        : matches each row's thread count\n"
        << "OpenMP thread counts: 1, 2, 4, 8\n"
        << "Physical CPU cores  : " << physical_cores << "\n"
        << "Warmup calls        : " << warmups << " per operation\n"
        << "Measured calls      : " << iterations << " per operation\n"
        << "Transaction size    : complete serialized transaction, in bytes\n"
        << "Timing includes     : balance decryption, encryption, all proofs\n"
        << "Timing excludes     : setup, inputs, BSGS table, validation, serialization\n"
        << "===================================================="
           "====================================================\n";
}

void print_workload_header(std::size_t participant_count, std::size_t receiver_count) {
    std::cout << "\n"
              << "========================================"
                 "========================================\n"
              << "APGC / n=" << participant_count << " / t=" << receiver_count << "\n"
              << "----------------------------------------"
                 "----------------------------------------\n"
              << std::left << std::setw(12) << "Threads"
              << std::right << std::setw(16) << "Generate(ms)"
              << std::setw(16) << "Verify(ms)"
              << std::setw(16) << "Tx(bytes)"
              << std::setw(12) << "Status" << "\n"
              << "----------------------------------------"
                 "----------------------------------------\n";
}

void print_workload_result(const BenchResult& result) {
    std::cout << std::left << std::setw(12) << result.thread_count
              << std::right << std::fixed << std::setprecision(3)
              << std::setw(16) << result.generate_ms
              << std::setw(16) << result.verify_ms
              << std::setw(16) << result.transaction_bytes
              << std::setw(12) << (result.passed ? "PASS" : "FAIL")
              << "\n";
}

void print_summary(const std::vector<BenchResult>& results) {
    constexpr int kConfigurationWidth = 20;

    std::cout
        << "\n\n"
        << "===================================================="
           "====================================================\n"
        << "                              APGC Benchmark Summary\n"
        << "===================================================="
           "====================================================\n"
        << std::left << std::setw(kConfigurationWidth) << "Configuration"
        << std::right << std::setw(10) << "Threads"
        << std::setw(14) << "Generate(ms)"
        << std::setw(13) << "Generate(x)"
        << std::setw(14) << "Verify(ms)"
        << std::setw(14) << "Verify(x)"
        << std::setw(16) << "Tx(bytes)"
        << std::setw(10) << "Status" << "\n"
        << "----------------------------------------------------"
           "----------------------------------------------------\n";

    for (const std::pair<std::size_t, std::size_t>& configuration : kConfigurations) {
        const std::size_t participant_count = configuration.first;
        const std::size_t receiver_count = configuration.second;
        const BenchResult* baseline = nullptr;
        for (const BenchResult& result : results) {
            if (result.participant_count == participant_count &&
                result.receiver_count == receiver_count && result.thread_count == 1) {
                baseline = &result;
                break;
            }
        }

        for (const BenchResult& result : results) {
            if (result.participant_count != participant_count ||
                result.receiver_count != receiver_count) {
                continue;
            }
            const std::string label = "n=" + std::to_string(participant_count) +
                                      ", t=" + std::to_string(receiver_count);
            std::cout << std::left << std::setw(kConfigurationWidth) << label
                      << std::right << std::setw(10) << result.thread_count
                      << std::fixed << std::setprecision(3)
                      << std::setw(14) << result.generate_ms
                      << std::setw(13) << baseline->generate_ms / result.generate_ms
                      << std::setw(14) << result.verify_ms
                      << std::setw(14) << baseline->verify_ms / result.verify_ms
                      << std::setw(16) << result.transaction_bytes
                      << std::setw(10) << (result.passed ? "PASS" : "FAIL")
                      << "\n";
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

    set_thread_count(1);
    const encryption::PublicParameters encryption_pp = encryption::setup(kCurveId, kRangeBits);
    dlog::BSGSSolver table(*encryption_pp.group_ctx, encryption_pp.h, {kRangeBits, kBsgsTradeoff, 1});
    prepare_decryption_table(table);

    std::vector<BenchResult> summary;
    summary.reserve(kConfigurations.size() * kThreadCounts.size());
    bool passed = true;
    for (const std::pair<std::size_t, std::size_t>& configuration : kConfigurations) {
        const std::size_t participant_count = configuration.first;
        const std::size_t receiver_count = configuration.second;
        set_thread_count(1);
        const application::PublicParameters pp = application::setup(
            kCurveId, participant_count, receiver_count, kRangeBits);
        const Workload workload = make_workload(pp);
        print_workload_header(participant_count, receiver_count);
        for (int thread_count : kThreadCounts) {
            const BenchResult result = run_once(
                pp, workload, table, thread_count, warmups, iterations);
            print_workload_result(result);
            summary.emplace_back(result);
            passed = result.passed && passed;
        }
    }

    print_summary(summary);
    return passed ? EXIT_SUCCESS : EXIT_FAILURE;
}
