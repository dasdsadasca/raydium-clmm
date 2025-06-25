## Security Analysis Report: AMM Mathematical Calculations

**Date:** 2023-10-27
**Auditor:** Jules (AI Security Analyst)
**Version:** 1.2 (Updated based on feedback and refined analysis of AMM-MATH-CRIT-001)

**Project:** Solana AMM Program (Concentrated Liquidity Model)

**Scope:** Deep analysis of mathematical calculations within the AMM's core libraries (`big_num.rs`, `fixed_point_64.rs`, `full_math.rs`, `liquidity_math.rs`, `sqrt_price_math.rs`, `swap_math.rs`, `tick_math.rs`, `unsafe_math.rs`) and their usage in instruction handlers (`swap.rs`, `increase_liquidity.rs`, `decrease_liquidity.rs`, `open_position.rs`, `initialize_reward.rs`, `update_reward_info.rs`, and their V2 counterparts where applicable). The analysis focused on identifying potential vulnerabilities, calculation manipulations, missing checks, and pitfalls related to mathematical operations, including cross-function interactions and state management, with reference to known CLMM vulnerabilities.

**Methodology:** Manual code review, logical inference, scenario analysis, and comparison with known vulnerability patterns in similar AMM/CLMM protocols.

---

### **Executive Summary**

This security analysis focused on the mathematical integrity of the Solana AMM program. The codebase implements sophisticated mechanics for concentrated liquidity, drawing from established patterns. While many aspects of the arithmetic are handled with care using custom large-number types and fixed-point representations, our review has identified **two critical vulnerabilities** that could lead to direct or indirect loss of user funds or theft from the protocol. Additionally, **three high-severity Denial of Service (DoS) vulnerabilities** were found, alongside several medium and lower-severity concerns.

The most pressing issues are:
1.  **Inflated Fee/Reward Claims (AMM-MATH-CRIT-001):** An incorrect fee/reward growth calculation using `wrapping_sub` when the current price is *outside* a position's range can be exploited. This allows generation of artificially inflated `fee_growth_inside` values, potentially leading to draining pool fee/reward vaults.
2.  **Silent Loss of User Fees/Rewards (AMM-MATH-CRIT-002):** The `to_underflow_u64()` function incorrectly handles overflows by silently zeroing out values, causing users to lose legitimately earned fees/rewards if their accrued amounts exceed `u64::MAX` during a calculation step.

Addressing these critical and high-severity issues is paramount. The validation of `TickArrayBitmapExtension` accounts appears correctly implemented in the reviewed functions.

---

### **Table of Contents**

1.  **Critical Severity Vulnerabilities**
    1.1. Inflated Fee/Reward Claims via `wrapping_sub` in Out-of-Range Growth Calculation (AMM-MATH-CRIT-001)
    1.2. Silent Loss of User Fees/Rewards via `to_underflow_u64()` (AMM-MATH-CRIT-002)
2.  **High Severity Vulnerabilities (Denial of Service)**
    2.1. DoS in `PoolState::update_reward_infos` via `as_u128()` Panic (Reward Growth Delta) (AMM-MATH-HIGH-001)
    2.2. DoS in `PoolState::update_reward_infos` via `mul_div_ceil().unwrap()` or `as_u64()` Panic (Total Emission) (AMM-MATH-HIGH-002)
    2.3. DoS in `initialize_reward` via `as_u64()` Panic (Total Reward Deposit) (AMM-MATH-HIGH-003)
3.  **Medium Severity Vulnerabilities and Concerns**
    3.1. Widespread Use of `.unwrap()` (AMM-MATH-MED-001)
    3.2. Inconsistent Error Handling in `swap_math::calculate_amount_in_range` (AMM-MATH-MED-002)
    3.3. Propagation of Erroneous Growth Snapshots in `open_position` (AMM-MATH-MED-003)
    3.4. DoS in `open_position` via `assert!(*liquidity > 0)` (AMM-MATH-MED-004)
4.  **Low Severity Vulnerabilities and Other Observations**
    4.1. Incorrect Condition in `to_underflow_u64()`
    4.2. Potential Division by Zero in `liquidity_math` (Zero-Width Ranges)
    4.3. Missing Admin Fee Rate Sanity Checks for `AmmConfig`
    4.4. Clarity of `sqrt_price_limit_x64 == 0` Handling in Swaps
    4.5. Potential Fee Collection DoS (`check_unclaimed_fees_and_vault`)
    4.6. `TickArrayBitmapExtension` Validation (Appears Correct)
    4.7. Precision of Tick Math & Fixed-Point Constants
    4.8. State Accumulator Precision (`u64` vs. `u128`)
    4.9. Complex Reward Initialization Permissions
5.  **Recommendations Summary**

---

### **1. Critical Severity Vulnerabilities**

#### **1.1. Inflated Fee/Reward Claims via `wrapping_sub` in Out-of-Range Growth Calculation (AMM-MATH-CRIT-001)**

*   **Vulnerability ID:** AMM-MATH-CRIT-001
*   **Location:**
    *   `programs/amm/src/states/tick_array.rs::get_fee_growth_inside`
    *   `programs/amm/src/states/tick_array.rs::get_reward_growths_inside`
*   **Description (Refined based on feedback):**
    The functions `get_fee_growth_inside` and `get_reward_growths_inside` calculate the total fees/rewards accrued *within* a specified tick range \[tick\_lower, tick\_upper] up to the current moment. A critical flaw exists in this calculation when the current pool price (`tick_current`) is *outside* this defined range.

    The calculation relies on `fee_growth_global_X_x64` (G) and `tick_Y.fee_growth_outside_X_x64` (O_Y for a tick Y). The invariant `G >= O_Y` (for any single tick Y, assuming G is current) likely holds, making intermediate subtractions like `G.checked_sub(O_Y)` safe from panic.

    However, when `tick_current` is outside the range `[tick_lower, tick_upper)`, the formula for `fee_growth_inside_X_calculated` (FIG_calc) effectively becomes:
    *   If `tick_current < tick_lower.tick`: `FIG_calc = tick_lower.fee_growth_outside_X (O_L) .wrapping_sub(tick_upper.fee_growth_outside_X (O_U))`
    *   If `tick_current >= tick_upper.tick`: `FIG_calc = tick_upper.fee_growth_outside_X (O_U) .wrapping_sub(tick_lower.fee_growth_outside_X (O_L))`

    The values `O_L` and `O_U` are historical snapshots of global fee/reward growth taken when `tick_lower` and `tick_upper` were respectively last initialized or crossed. These snapshots are independent. It is entirely plausible for `O_U` to be significantly larger than `O_L` (or vice-versa) due to the timing of their last updates relative to global fee accumulation.
    If, for instance, `O_U > O_L` and the current price is below `tick_lower`, the calculation `O_L.wrapping_sub(O_U)` will underflow and wrap around, resulting in an **erroneously massive positive value** for `FIG_calc` (e.g., `O_L - O_U + U128_MAX_PLUS_1`). This massive value is an arithmetic artifact and does not represent any real fees accrued *within* the range. Standard CLMM logic (e.g., Uniswap v3, which would revert on such an underflow) would imply that if the price is outside the range, the *additional* growth *inside* the range for the current moment is zero.

*   **Impact & Exploitation (Refined based on feedback):**
    1.  **Protocol State Corruption:** This erroneously massive `FIG_calc` updates `ProtocolPositionState.fee_growth_inside_X_last_x64` (let's call this `ProtoFIG_wrapped`).
    2.  **Exploitable Delta Calculation:** When a `PersonalPositionState` (with a normal, non-wrapped `fee_growth_inside_X_last_x64` snapshot, `PPos_FIG_normal`) subsequently calculates its claimable fees, the function `calculate_latest_token_fees` (or similar for rewards) computes the delta as:
        `delta_for_user = ProtoFIG_wrapped.wrapping_sub(PPos_FIG_normal)`.
        Since `ProtoFIG_wrapped` is enormous and `PPos_FIG_normal` is small, this `delta_for_user` becomes a huge positive number.
    3.  **Inflated Claim:** This huge delta, when scaled by the user's (even minimal) liquidity, can result in `tokens_owed` being calculated as a very large amount. If this amount fits within `u64` (i.e., is not completely zeroed out by the separate `to_underflow_u64` bug, AMM-MATH-CRIT-002), the attacker can withdraw far more fees/rewards than legitimately earned, draining funds from pool vaults.
    The company's argument that "even if underflow occurs, it will not affect the final calculated difference" does not hold for this initial transition where an artificially massive wrapped value (`ProtoFIG_wrapped`) is differenced against a normal, non-wrapped prior snapshot (`PPos_FIG_normal`).

*   **Conceptual Devnet POC Steps (CPI-based recommended):**
    1.  **Setup Target Tick States:**
        *   Initialize a pool. Let global fee growth be `G_initial`.
        *   Cross `tick_lower` (T_L). `T_L.fee_growth_outside_X` (O_L) will be based on `G_initial`.
        *   Generate significant additional global fee growth (e.g., many swaps) so `fee_growth_global_X` becomes `G_high` (`G_high >> G_initial`).
        *   Cross `tick_upper` (T_U). `T_U.fee_growth_outside_X` (O_U) will be based on `G_high`. Now, `O_U` is significantly larger than `O_L`.
    2.  **Attacker Opens Position:** Attacker opens a minimal liquidity position (P_attack) in range `[T_L, T_U]`. Its `PersonalPositionState.fee_growth_inside_X_last_x64` (P_FIG_snapshot) is recorded based on a normal calculation.
    3.  **Move Price Out of Range:** Swaps move `tick_current` such that `tick_current < T_L`.
    4.  **Trigger ProtocolPosition Update:** Any action (e.g., tiny liquidity change by any user, or attacker with a separate position) updates the `ProtocolPositionState` for range `[T_L, T_U]`.
        *   `get_fee_growth_inside` is called. It computes `FIG_calc = O_L.wrapping_sub(O_U)`, resulting in `W_FIG` (a huge wrapped number).
        *   `ProtocolPositionState_{[T_L,T_U]}.fee_growth_inside_X_last_x64` becomes `W_FIG`. (Verify this state).
    5.  **Attacker Claims:** Attacker updates their P_attack position.
        *   `calculate_latest_token_fees` computes delta: `W_FIG.wrapping_sub(P_FIG_snapshot)`. This is a massive positive delta.
        *   Attacker is credited with inflated fees. (Verify `tokens_owed` in `PersonalPositionState`).

*   **Affected Instructions:** `open_position` (and V2), `increase_liquidity` (and V2), `decrease_liquidity` (and V2).
*   **Recommendation:**
    *   For the out-of-range cases in `get_fee_growth_inside` and `get_reward_growths_inside`:
        *   If `tick_current < tick_lower.tick`: `fee_growth_inside_X = tick_lower.fee_growth_outside_X.saturating_sub(tick_upper.fee_growth_outside_X)`.
        *   If `tick_current >= tick_upper.tick`: `fee_growth_inside_X = tick_upper.fee_growth_outside_X.saturating_sub(tick_lower.fee_growth_outside_X)`.
        This correctly yields 0 if an underflow would occur, reflecting no *new* growth inside an out-of-range position and preventing the wrap.
    *   For the in-range case (`tick_lower.tick <= tick_current < tick_upper.tick`), the formula `fee_growth_global_X.saturating_sub(fee_growth_below_X).saturating_sub(fee_growth_above_X)` should be used to prevent wrapping if `global_X < (below_X + above_X)` due to any potential (though less likely if company's invariant on `G >= O_individual_tick` holds and G is perfectly current) inconsistencies.

#### **1.2. Silent Loss of User Fees/Rewards via `to_underflow_u64()` (AMM-MATH-CRIT-002)**
    *(Content remains the same as in version 1.1 of this report)*
*   **Location:**
    *   `programs/amm/src/libraries/full_math.rs::MulDiv::to_underflow_u64`
    *   `programs/amm/src/states/protocol_position.rs::ProtocolPositionState::update`
    *   `programs/amm/src/instructions/increase_liquidity.rs::calculate_latest_token_fees`
    *   `programs/amm/src/states/personal_position.rs::PersonalPositionState::update_rewards`
*   **Description:** The `to_underflow_u64()` method converts `U128` or `U256` to `u64`. If the value `>` `u64::MAX` (or `=` `u64::MAX` due to a minor bug in the condition `self < U128::from(u64::MAX)`), it returns `0` silently.
*   **Impact:**
    1.  **Direct User Fee Loss:** In `calculate_latest_token_fees`, if the true fee delta for a user's position (calculated as `U128`) exceeds `u64::MAX`, it becomes `0`. The user is credited with no fees for that period, and their snapshot updates, making the loss permanent.
    2.  **Direct User Reward Loss:** In `PersonalPositionState::update_rewards`, if the true reward delta (calculated as `U256`) exceeds `u64::MAX` when converted, it becomes `0`, leading to permanent reward loss.
    3.  **Inaccurate Protocol Position Accounting:** `ProtocolPositionState.token_fees_owed_x` can also become inaccurate.
*   **Recommendation:**
    *   **Immediately remove or replace all uses of `to_underflow_u64()` in critical fee/reward pathways.**
    *   For `calculate_latest_token_fees` and `PersonalPositionState::update_rewards`:
        *   The calculated delta (as `U128` or `U256`) should be added to a `u128` field for `token_fees_owed_x` and `reward_amount_owed` in `PersonalPositionState`.
        *   If even `u128` is insufficient (unlikely for per-update deltas but possible for total owed), the system must error robustly (e.g., `ErrorCode::ClaimExceedsMax`) or implement partial claims.
    *   Correct the condition in `to_underflow_u64` to `self <= UXXX::from(u64::MAX)` if used elsewhere non-critically.

---

### **2. High Severity Vulnerabilities (Denial of Service)**
    *(Content remains the same as version 1.1 of this report)*

#### **2.1. DoS in `PoolState::update_reward_infos` via `as_u128()` Panic (Reward Growth Delta) (AMM-MATH-HIGH-001)**
*   **Location:** `programs/amm/src/states/pool.rs::PoolState::update_reward_infos`
*   **Description:** `reward_growth_delta.as_u128()` panics if `reward_growth_delta` (U256) > `u128::MAX`.
*   **Impact:** DoS for swaps and liquidity operations.
*   **Recommendation:** Cap `reward_growth_delta` at `u128::MAX` before `as_u128()` or error.

#### **2.2. DoS in `PoolState::update_reward_infos` via `mul_div_ceil().unwrap()` or `as_u64()` Panic (Total Emission) (AMM-MATH-HIGH-002)**
*   **Location:** `programs/amm/src/states/pool.rs::PoolState::update_reward_infos`
*   **Description:** `mul_div_ceil().unwrap()` panics if intermediate result for total emission > `u128::MAX`. Subsequent `.as_u64()` panics if the `u128` result > `u64::MAX`. `RewardInfo.reward_total_emissioned` being `u64` is too small.
*   **Impact:** DoS for critical pool operations.
*   **Recommendation:** Handle `Option` from `mul_div_ceil`. Change `RewardInfo.reward_total_emissioned` to `u128`. Use safe conversion to `u64` if necessary, or cap.

#### **2.3. DoS in `initialize_reward` via `as_u64()` Panic (Total Reward Deposit) (AMM-MATH-HIGH-003)**
*   **Location:** `programs/amm/src/instructions/initialize_reward.rs`
*   **Description:** Total `reward_amount` to deposit is `U256` then `.as_u64()`, which can panic if total raw units > `u64::MAX`.
*   **Impact:** Prevents reward setup for common tokens/durations.
*   **Recommendation:** Calculate `reward_amount` as `u128`. Check against `u64::MAX` before `as_u64()` and return a specific error (e.g., `ErrorCode::RewardDepositAmountExceedsUint64`).

---

### **3. Medium Severity Vulnerabilities and Concerns**
    *(Content remains the same as version 1.1 of this report)*

#### **3.1. Widespread Use of `.unwrap()` (AMM-MATH-MED-001)**
*   **Recommendation:** Systematically review and replace with `?` or explicit capped/safe arithmetic.

#### **3.2. Inconsistent Error Handling in `swap_math::calculate_amount_in_range` (AMM-MATH-MED-002)**
*   **Recommendation:** Unify logic to match production behavior (`Ok(None)` on `MaxTokenOverflow`).

#### **3.3. Propagation of Erroneous Growth Snapshots in `open_position` (AMM-MATH-MED-003)**
*   **Description:** If `ProtocolPositionState` has flawed `fee_growth_inside` values (due to AMM-MATH-CRIT-001), these are snapshotted into new `PersonalPositionState`s.
*   **Impact:** Corrupts baseline for new positions, potentially compounding the `wrapping_sub` exploit.
*   **Recommendation:** Primarily fixed by addressing AMM-MATH-CRIT-001. Consider sanity checks in `open_position`.

#### **3.4. DoS in `open_position` via `assert!(*liquidity > 0)` (AMM-MATH-MED-004)**
*   **Recommendation:** Replace assert with `require!(*liquidity > 0, ErrorCode::CannotDetermineLiquidityFromSingleAssetOutOfRange)`.

---

### **4. Low Severity Vulnerabilities and Other Observations**
    *(Content remains largely the same as version 1.1 of this report)*

*   **4.1. Incorrect Condition in `to_underflow_u64()`**.
*   **4.2. Potential Division by Zero in `liquidity_math` (Zero-Width Ranges)**.
*   **4.3. Missing Admin Fee Rate Sanity Checks for `AmmConfig`**.
*   **4.4. Clarity of `sqrt_price_limit_x64 == 0` Handling in Swaps**.
*   **4.5. Potential Fee Collection DoS (`check_unclaimed_fees_and_vault`)**.
*   **4.6. `TickArrayBitmapExtension` Validation (Appears Correct)**.
*   **4.7. Precision of Tick Math & Fixed-Point Constants**.
*   **4.8. State Accumulator Precision (`u64` vs. `u128`)**.
*   **4.9. Complex Reward Initialization Permissions**.

---

### **5. Recommendations Summary**

1.  **CRITICAL (AMM-MATH-CRIT-001): Fix `wrapping_sub` in `get_fee_growth_inside` / `get_reward_growths_inside`:** For out-of-range calculations, ensure growth is 0 (e.g., using `saturating_sub` for `O_L - O_U` style terms). For in-range, use `saturating_sub` for `G - B - A`.
2.  **CRITICAL (AMM-MATH-CRIT-002): Eliminate `to_underflow_u64()` for Fee/Reward Deltas:** Use `u128` for `PersonalPositionState.token_fees_owed_x / reward_amount_owed`. Handle potential `u128` overflows with errors/caps.
3.  **HIGH: Address DoS Panics in Reward Calculations (AMM-MATH-HIGH-001, 002, 003):** Implement safe conversions, use larger types (e.g., `u128` for `RewardInfo.reward_total_emissioned`), and return specific errors on overflow.
4.  **MEDIUM: Reduce `.unwrap()` Usage (AMM-MATH-MED-001).**
5.  **MEDIUM: Unify `swap_math::calculate_amount_in_range` Logic (AMM-MATH-MED-002).**
6.  **MEDIUM: Review `open_position` DoS/Snapshotting (AMM-MATH-MED-003, AMM-MATH-MED-004).**
7.  **Address Low Severity Items:** Implement minor fixes and conduct further reviews as noted.

---
This concludes the updated mathematical security analysis.
