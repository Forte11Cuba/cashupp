// NUTSHELL COMPATIBILITY: cashu/core/helpers.py
// Helper functions implementation for Cashu operations
// 100% compatible with nutshell NUT-08 Lightning fee reserve and blank outputs

#include "cashu/core/helpers.hpp"
#include <map>
#include <set>
#include <algorithm>
#include <numeric>
#include <sstream>
#include <cmath>
#include <cassert>

using namespace std;
using namespace boost::multiprecision;

namespace cashu::core::helpers {

//=============================================================================
// Helper Function Implementations (100% nutshell compatible)
//=============================================================================

string amount_summary(const vector<Proof>& proofs, Unit unit) {
    // NUTSHELL COMPATIBILITY: Matches nutshell helpers.py exactly
    // Python: amounts_we_have = [(amount, len([p for p in proofs if p.amount == amount])) 
    //                           for amount in {p.amount for p in proofs}]
    
    // Count proofs by amount: {amount: count}
    map<cpp_int, int> amount_counts;
    for (const auto& proof : proofs) {
        amount_counts[proof.amount]++;
    }
    
    // Create sorted list of (amount, count) pairs
    vector<pair<cpp_int, int>> amounts_we_have;
    for (const auto& [amount, count] : amount_counts) {
        amounts_we_have.emplace_back(amount, count);
    }
    
    // Sort by amount (already sorted due to map, but explicit for clarity)
    sort(amounts_we_have.begin(), amounts_we_have.end(), 
         [](const auto& a, const auto& b) { return a.first < b.first; });
    
    // Build summary string: "Amount (count), Amount (count), ..."
    // Python: f"{', '.join([f'{Amount(unit, a).str()} ({c}x)' for a, c in amounts_we_have])}"
    vector<string> parts;
    for (const auto& [amount, count] : amounts_we_have) {
        Amount amt(unit, amount);
        ostringstream part;
        part << amt.str() << " (" << count << "x)";
        parts.push_back(part.str());
    }
    
    // Join with commas
    ostringstream result;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) result << ", ";
        result << parts[i];
    }
    
    return result.str();
}

cpp_int sum_proofs(const vector<Proof>& proofs) {
    // NUTSHELL COMPATIBILITY: Matches nutshell helpers.py exactly
    // Python: return sum([p.amount for p in proofs])
    return accumulate(proofs.begin(), proofs.end(), cpp_int(0),
                     [](const cpp_int& sum, const Proof& p) { return sum + p.amount; });
}

cpp_int sum_promises(const vector<BlindedSignature>& promises) {
    // NUTSHELL COMPATIBILITY: Matches nutshell helpers.py exactly
    // Python: return sum([p.amount for p in promises])
    return accumulate(promises.begin(), promises.end(), cpp_int(0),
                     [](const cpp_int& sum, const BlindedSignature& p) { return sum + p.amount; });
}

cpp_int fee_reserve(const cpp_int& amount_msat) {
    // NUTSHELL COMPATIBILITY: Matches nutshell helpers.py exactly
    // Python: return max(
    //     int(settings.lightning_reserve_fee_min),
    //     int(amount_msat * settings.lightning_fee_percent / 100.0),
    // )
    
    // Default values from nutshell settings
    // settings.lightning_reserve_fee_min: int = Field(default=2000)  # 2000 msat = 2 sats minimum
    // settings.lightning_fee_percent: float = Field(default=1.0)    # 1% default fee
    const cpp_int lightning_reserve_fee_min = 2000; // 2000 msat = 2 sats minimum
    const double lightning_fee_percent = 1.0;       // 1% default fee
    
    // Calculate percentage fee: amount_msat * lightning_fee_percent / 100.0
    cpp_int calculated_fee = amount_msat * cpp_int(static_cast<int>(lightning_fee_percent * 100)) / 10000;
    
    // Return maximum of minimum fee or calculated fee
    return max(lightning_reserve_fee_min, calculated_fee);
}

int calculate_number_of_blank_outputs(int fee_reserve_sat) {
    // NUTSHELL COMPATIBILITY: Matches nutshell helpers.py exactly
    // Python: def calculate_number_of_blank_outputs(fee_reserve_sat: int):
    //     """Calculates the number of blank outputs used for returning overpaid fees.
    //     
    //     The formula ensures that any overpaid fees can be represented by the blank outputs,
    //     see NUT-08 for details.
    //     """
    //     assert fee_reserve_sat >= 0, "Fee reserve can't be negative."
    //     if fee_reserve_sat == 0:
    //         return 0
    //     return max(math.ceil(math.log2(fee_reserve_sat)), 1)
    
    assert(fee_reserve_sat >= 0); // "Fee reserve can't be negative."
    
    if (fee_reserve_sat == 0) {
        return 0;
    }
    
    // NUT-08: Formula ensures any overpaid amount can be represented as sum of powers of 2
    // Example: For 1000 sat reserve → ceil(log2(1000)) = ceil(9.96) = 10 blank outputs
    // This allows representation of any amount 0-1023 using powers of 2
    return max(static_cast<int>(ceil(log2(fee_reserve_sat))), 1);
}

} // namespace cashu::core::helpers