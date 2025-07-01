#pragma once

// NUTSHELL COMPATIBILITY: cashu/core/helpers.py
// Helper functions for Cashu operations - amount summary, fee calculation, async wrappers
// 100% compatible with nutshell NUT-08 Lightning fee reserve and blank outputs

#include "cashu/core/base.hpp"
#include <vector>
#include <string>
#include <functional>
#include <future>

namespace cashu::core::helpers {
    using namespace boost::multiprecision;
    using namespace cashu::core::base;

/**
 * @brief Create amount summary string showing amount distribution
 * NUTSHELL COMPATIBILITY: Matches amount_summary() in nutshell helpers.py exactly
 * 
 * @param proofs List of proofs to summarize
 * @param unit Unit for formatting amounts
 * @return Summary string in format "Amount (count), Amount (count), ..."
 * 
 * Example: "1 sat (5x), 2 sat (3x), 4 sat (1x)"
 */
std::string amount_summary(const std::vector<Proof>& proofs, Unit unit);

/**
 * @brief Calculate total amount from list of proofs
 * NUTSHELL COMPATIBILITY: Matches sum_proofs() in nutshell helpers.py exactly
 * 
 * @param proofs List of proofs to sum
 * @return Total amount in satoshis
 */
cpp_int sum_proofs(const std::vector<Proof>& proofs);

/**
 * @brief Calculate total amount from list of blinded signatures
 * NUTSHELL COMPATIBILITY: Matches sum_promises() in nutshell helpers.py exactly
 * 
 * @param promises List of blinded signatures to sum
 * @return Total amount in satoshis
 */
cpp_int sum_promises(const std::vector<BlindedSignature>& promises);

/**
 * @brief Calculate Lightning fee reserve according to NUT-08
 * NUTSHELL COMPATIBILITY: Matches fee_reserve() in nutshell helpers.py exactly
 * 
 * @param amount_msat Amount in millisatoshis
 * @return Fee reserve amount in millisatoshis
 * 
 * Formula: max(lightning_reserve_fee_min, amount_msat * lightning_fee_percent / 100.0)
 * Default values:
 * - lightning_reserve_fee_min: 2000 msat (2 sats minimum)
 * - lightning_fee_percent: 1.0% default fee
 * 
 * NUT-08: Lightning fee reserve calculation for overpayment protection
 */
cpp_int fee_reserve(const cpp_int& amount_msat);

/**
 * @brief Calculate number of blank outputs for fee overpayment (NUT-08 core function)
 * NUTSHELL COMPATIBILITY: Matches calculate_number_of_blank_outputs() in nutshell helpers.py exactly
 * 
 * @param fee_reserve_sat Fee reserve amount in satoshis
 * @return Number of blank outputs needed
 * 
 * Formula: max(ceil(log2(fee_reserve_sat)), 1) for fee_reserve_sat > 0
 * Returns 0 if fee_reserve_sat is 0
 * 
 * NUT-08: Used for returning overpaid fees in binary denomination system.
 * The formula ensures that any overpaid amount can be represented as a sum of powers of 2.
 * 
 * Example: 1000 sat reserve → ceil(log2(1000)) = ceil(9.96) = 10 blank outputs
 * This allows representation of any amount 0-1023 using powers of 2.
 */
int calculate_number_of_blank_outputs(int fee_reserve_sat);

/**
 * @brief Async wrapper function for C++ (simplified version)
 * NUTSHELL COMPATIBILITY: Simplified version of nutshell's async_wrap
 * 
 * @param func Function to wrap
 * @return Future result
 * 
 * Note: This is a simplified version of nutshell's async_wrap.
 * For full async support, would need boost::asio or similar async framework.
 * Nutshell uses asyncio event loops and thread pool executors.
 */
template<typename Func, typename... Args>
std::future<std::invoke_result_t<Func, Args...>> async_wrap(Func&& func, Args&&... args) {
    return std::async(std::launch::async, std::forward<Func>(func), std::forward<Args>(args)...);
}

/**
 * @brief Async unwrap function (simplified version)
 * NUTSHELL COMPATIBILITY: Simplified version of nutshell's async_unwrap
 * 
 * @param future Future to unwrap
 * @return Result value
 * 
 * Note: This is a simplified version of nutshell's async_unwrap.
 * Nutshell uses asyncio.run_until_complete for proper async execution.
 */
template<typename T>
T async_unwrap(std::future<T>& future) {
    return future.get();
}

} // namespace cashu::core::helpers