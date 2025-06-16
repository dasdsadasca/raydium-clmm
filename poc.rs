#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct U128(pub [u64; 2]); // (low, high)

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct U256(pub [u64; 4]); // (limb0, limb1, limb2, limb3)

// Helper functions
fn u128_to_u128_struct(val: u128) -> U128 {
    U128([val as u64, (val >> 64) as u64])
}

fn u64_to_u128_struct(val: u64) -> U128 {
    U128([val, 0])
}

fn u128_struct_to_u128(val: &U128) -> u128 {
    (val.0[0] as u128) | ((val.0[1] as u128) << 64)
}

fn compare_u128_structs(a: &U128, b: &U128) -> std::cmp::Ordering {
    u128_struct_to_u128(a).cmp(&u128_struct_to_u128(b))
}

// Core math functions
fn multiply_u128_values_to_u256(a_val: u128, b_val: u128) -> U256 {
    // Decompose u128 inputs into u64 limbs
    let a_lo = a_val as u64;
    let a_hi = (a_val >> 64) as u64;
    let b_lo = b_val as u64;
    let b_hi = (b_val >> 64) as u64;

    // Multiply u64 limbs, results are u128
    let p0 = (a_lo as u128) * (b_lo as u128); // a_lo * b_lo
    let p1 = (a_lo as u128) * (b_hi as u128); // a_lo * b_hi
    let p2 = (a_hi as u128) * (b_lo as u128); // a_hi * b_lo
    let p3 = (a_hi as u128) * (b_hi as u128); // a_hi * b_hi

    // Calculate U256 limbs with carries
    let r0 = p0 as u64; // Lower 64 bits of p0
    let carry1 = p0 >> 64; // Upper 64 bits of p0

    // Sum for r1: carry from p0 + lower_of_p1 + lower_of_p2
    let r1_temp = carry1 + (p1 & std::u64::MAX as u128) + (p2 & std::u64::MAX as u128);
    let r1 = r1_temp as u64; // Lower 64 bits of sum
    let carry2 = r1_temp >> 64; // Carry for r2

    // Sum for r2: carry from r1_temp + upper_of_p1 + upper_of_p2 + lower_of_p3
    let r2_temp = carry2 + (p1 >> 64) + (p2 >> 64) + (p3 & std::u64::MAX as u128);
    let r2 = r2_temp as u64; // Lower 64 bits of sum
    let carry3 = r2_temp >> 64; // Carry for r3

    // Sum for r3: carry from r2_temp + upper_of_p3
    let r3_val = (p3 >> 64) + carry3;
    U256([r0, r1, r2, r3_val as u64])
}

fn simplified_mul_div_floor(fee_growth: &U128, liquidity: &U128, q64_denom: &U128) -> U128 {
    if q64_denom.0[0] != 0 || q64_denom.0[1] != 1 { // Expects Q64 = 2^64 = U128([0, 1])
        panic!("simplified_mul_div_floor expects q64_denom to be 2^64");
    }
    let fee_growth_u128 = u128_struct_to_u128(fee_growth);
    let liquidity_u128 = u128_struct_to_u128(liquidity);

    let product_u256 = multiply_u128_values_to_u256(fee_growth_u128, liquidity_u128);

    // Division of U256 by 2^64 is a right shift of its limbs by 1 limb (64 bits).
    // U256([limb0, limb1, limb2, limb3]) / 2^64 results in a U128 formed by limbs [limb1, limb2] of product_u256.
    U128([product_u256.0[1], product_u256.0[2]])
}

fn to_underflow_u64_poc(val_u128_struct: &U128) -> u64 {
    let u64_max_val: u64 = std::u64::MAX;
    let u64_max_as_u128_struct = u64_to_u128_struct(u64_max_val); // This is U128([std::u64::MAX, 0])

    if compare_u128_structs(val_u128_struct, &u64_max_as_u128_struct) == std::cmp::Ordering::Less {
        // This implies val_u128_struct.0[1] must be 0.
        val_u128_struct.0[0]
    } else { // Greater than or equal to u64::MAX
        0
    }
}

fn main() {
    println!("Starting Proof of Concept for to_underflow_u64 vulnerability.");

    let q64_struct = u128_to_u128_struct(1u128 << 64);

    // Scenario 1: Intermediate result is exactly u64::MAX
    let liquidity1_u128 = 1u128 << 60;
    // fee_growth_latest1_u128 = (2^64-1) * 2^4 = 2^68 - 2^4
    let fee_growth_latest1_u128 = ((1u128 << 64) - 1) << 4;

    let liquidity1_struct = u128_to_u128_struct(liquidity1_u128);
    let fee_growth1_struct = u128_to_u128_struct(fee_growth_latest1_u128);

    println!("
Scenario 1: Intermediate result target: u64::MAX");
    println!("Fee Growth (u128): {}, Liquidity (u128): {}", fee_growth_latest1_u128, liquidity1_u128);

    let intermediate1 = simplified_mul_div_floor(&fee_growth1_struct, &liquidity1_struct, &q64_struct);
    let result1 = to_underflow_u64_poc(&intermediate1);

    println!("Intermediate U128 struct: {:?}", intermediate1);
    println!("Intermediate U128 as u128: {}", u128_struct_to_u128(&intermediate1));
    println!("Resulting u64 (after to_underflow_u64_poc): {}", result1);

    assert_eq!(u128_struct_to_u128(&intermediate1), std::u64::MAX as u128, "Scenario 1 intermediate value mismatch");
    assert_eq!(result1, 0, "Scenario 1 result mismatch");
    println!("Scenario 1 assertions passed.");

    // Scenario 2: Intermediate result is u64::MAX + 1 (i.e., 2^64)
    let liquidity2_u128 = 1u128 << 60;
    let fee_growth_latest2_u128 = 1u128 << 68; // 2^68

    let liquidity2_struct = u128_to_u128_struct(liquidity2_u128);
    let fee_growth2_struct = u128_to_u128_struct(fee_growth_latest2_u128);

    println!("
Scenario 2: Intermediate result target: 2^64 (u64::MAX + 1)");
    println!("Fee Growth (u128): {}, Liquidity (u128): {}", fee_growth_latest2_u128, liquidity2_u128);

    let intermediate2 = simplified_mul_div_floor(&fee_growth2_struct, &liquidity2_struct, &q64_struct);
    let result2 = to_underflow_u64_poc(&intermediate2);

    println!("Intermediate U128 struct: {:?}", intermediate2);
    println!("Intermediate U128 as u128: {}", u128_struct_to_u128(&intermediate2));
    println!("Resulting u64 (after to_underflow_u64_poc): {}", result2);

    assert_eq!(u128_struct_to_u128(&intermediate2), 1u128 << 64, "Scenario 2 intermediate value mismatch");
    assert_eq!(result2, 0, "Scenario 2 result mismatch");
    println!("Scenario 2 assertions passed.");

    println!("
Proof of Concept completed successfully.");
}
