use super::add_liquidity;
use crate::error::ErrorCode;
use crate::libraries::{big_num::U128, fixed_point_64, full_math::MulDiv};
use crate::states::*;
use crate::util::*;
use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount};
use anchor_spl::token_interface::{Mint, Token2022};

#[derive(Accounts)]
pub struct IncreaseLiquidity<'info> {
    /// Pays to mint the position
    pub nft_owner: Signer<'info>,

    /// The token account for nft
    #[account(
        constraint = nft_account.mint == personal_position.nft_mint,
        constraint = nft_account.amount == 1,
        token::authority = nft_owner
    )]
    pub nft_account: Box<Account<'info, TokenAccount>>,

    #[account(mut)]
    pub pool_state: AccountLoader<'info, PoolState>,

    #[account(
        mut,
        seeds = [
            POSITION_SEED.as_bytes(),
            pool_state.key().as_ref(),
            &personal_position.tick_lower_index.to_be_bytes(),
            &personal_position.tick_upper_index.to_be_bytes(),
        ],
        bump,
        constraint = protocol_position.pool_id == pool_state.key(),
    )]
    pub protocol_position: Box<Account<'info, ProtocolPositionState>>,

    /// Increase liquidity for this position
    #[account(mut, constraint = personal_position.pool_id == pool_state.key())]
    pub personal_position: Box<Account<'info, PersonalPositionState>>,

    /// Stores init state for the lower tick
    #[account(mut, constraint = tick_array_lower.load()?.pool_id == pool_state.key())]
    pub tick_array_lower: AccountLoader<'info, TickArrayState>,

    /// Stores init state for the upper tick
    #[account(mut, constraint = tick_array_upper.load()?.pool_id == pool_state.key())]
    pub tick_array_upper: AccountLoader<'info, TickArrayState>,

    /// The payer's token account for token_0
    #[account(
        mut,
        token::mint = token_vault_0.mint
    )]
    pub token_account_0: Box<Account<'info, TokenAccount>>,

    /// The token account spending token_1 to mint the position
    #[account(
        mut,
        token::mint = token_vault_1.mint
    )]
    pub token_account_1: Box<Account<'info, TokenAccount>>,

    /// The address that holds pool tokens for token_0
    #[account(
        mut,
        constraint = token_vault_0.key() == pool_state.load()?.token_vault_0
    )]
    pub token_vault_0: Box<Account<'info, TokenAccount>>,

    /// The address that holds pool tokens for token_1
    #[account(
        mut,
        constraint = token_vault_1.key() == pool_state.load()?.token_vault_1
    )]
    pub token_vault_1: Box<Account<'info, TokenAccount>>,

    /// Program to create mint account and mint tokens
    pub token_program: Program<'info, Token>,
    // remaining account
    // #[account(
    //     seeds = [
    //         POOL_TICK_ARRAY_BITMAP_SEED.as_bytes(),
    //         pool_state.key().as_ref(),
    //     ],
    //     bump
    // )]
    // pub tick_array_bitmap: AccountLoader<'info, TickArrayBitmapExtension>,
}

pub fn increase_liquidity_v1<'a, 'b, 'c: 'info, 'info>(
    ctx: Context<'a, 'b, 'c, 'info, IncreaseLiquidity<'info>>,
    liquidity: u128,
    amount_0_max: u64,
    amount_1_max: u64,
    base_flag: Option<bool>,
) -> Result<()> {
    increase_liquidity(
        &ctx.accounts.nft_owner,
        &ctx.accounts.pool_state,
        &mut ctx.accounts.protocol_position,
        &mut ctx.accounts.personal_position,
        &ctx.accounts.tick_array_lower,
        &ctx.accounts.tick_array_upper,
        &ctx.accounts.token_account_0.to_account_info(),
        &ctx.accounts.token_account_1.to_account_info(),
        &ctx.accounts.token_vault_0.to_account_info(),
        &ctx.accounts.token_vault_1.to_account_info(),
        &ctx.accounts.token_program,
        None,
        None,
        None,
        &ctx.remaining_accounts,
        liquidity,
        amount_0_max,
        amount_1_max,
        base_flag,
    )
}

pub fn increase_liquidity<'a, 'b, 'c: 'info, 'info>(
    nft_owner: &'b Signer<'info>,
    pool_state_loader: &'b AccountLoader<'info, PoolState>,
    protocol_position: &'b mut Box<Account<'info, ProtocolPositionState>>,
    personal_position: &'b mut Box<Account<'info, PersonalPositionState>>,
    tick_array_lower_loader: &'b AccountLoader<'info, TickArrayState>,
    tick_array_upper_loader: &'b AccountLoader<'info, TickArrayState>,
    token_account_0: &'b AccountInfo<'info>,
    token_account_1: &'b AccountInfo<'info>,
    token_vault_0: &'b AccountInfo<'info>,
    token_vault_1: &'b AccountInfo<'info>,
    token_program: &'b Program<'info, Token>,
    token_program_2022: Option<&Program<'info, Token2022>>,
    vault_0_mint: Option<Box<InterfaceAccount<'info, Mint>>>,
    vault_1_mint: Option<Box<InterfaceAccount<'info, Mint>>>,

    remaining_accounts: &'c [AccountInfo<'info>],
    liquidity: u128,
    amount_0_max: u64,
    amount_1_max: u64,
    base_flag: Option<bool>,
) -> Result<()> {
    let mut liquidity = liquidity;
    let pool_state = &mut pool_state_loader.load_mut()?;
    if !pool_state.get_status_by_bit(PoolStatusBitIndex::OpenPositionOrIncreaseLiquidity) {
        return err!(ErrorCode::NotApproved);
    }
    let tick_lower = personal_position.tick_lower_index;
    let tick_upper = personal_position.tick_upper_index;

    let use_tickarray_bitmap_extension =
        pool_state.is_overflow_default_tickarray_bitmap(vec![tick_lower, tick_upper]);

    let (amount_0, amount_1, amount_0_transfer_fee, amount_1_transfer_fee) = add_liquidity(
        &nft_owner,
        token_account_0,
        token_account_1,
        token_vault_0,
        token_vault_1,
        &AccountLoad::<TickArrayState>::try_from(&tick_array_lower_loader.to_account_info())?,
        &AccountLoad::<TickArrayState>::try_from(&tick_array_upper_loader.to_account_info())?,
        protocol_position,
        token_program_2022,
        token_program,
        vault_0_mint,
        vault_1_mint,
        if use_tickarray_bitmap_extension {
            require_keys_eq!(
                remaining_accounts[0].key(),
                TickArrayBitmapExtension::key(pool_state_loader.key())
            );
            Some(&remaining_accounts[0])
        } else {
            None
        },
        pool_state,
        &mut liquidity,
        amount_0_max,
        amount_1_max,
        tick_lower,
        tick_upper,
        base_flag,
    )?;

    personal_position.token_fees_owed_0 = calculate_latest_token_fees(
        personal_position.token_fees_owed_0,
        personal_position.fee_growth_inside_0_last_x64,
        protocol_position.fee_growth_inside_0_last_x64,
        personal_position.liquidity,
    );
    personal_position.token_fees_owed_1 = calculate_latest_token_fees(
        personal_position.token_fees_owed_1,
        personal_position.fee_growth_inside_1_last_x64,
        protocol_position.fee_growth_inside_1_last_x64,
        personal_position.liquidity,
    );

    personal_position.fee_growth_inside_0_last_x64 = protocol_position.fee_growth_inside_0_last_x64;
    personal_position.fee_growth_inside_1_last_x64 = protocol_position.fee_growth_inside_1_last_x64;

    // update rewards, must update before increase liquidity
    personal_position.update_rewards(protocol_position.reward_growth_inside, true)?;
    personal_position.liquidity = personal_position.liquidity.checked_add(liquidity).unwrap();

    emit!(IncreaseLiquidityEvent {
        position_nft_mint: personal_position.nft_mint,
        liquidity,
        amount_0,
        amount_1,
        amount_0_transfer_fee,
        amount_1_transfer_fee
    });

    Ok(())
}

pub fn calculate_latest_token_fees(
    last_total_fees: u64,
    fee_growth_inside_last_x64: u128,
    fee_growth_inside_latest_x64: u128,
    liquidity: u128,
) -> u64 {
    let fee_growth_delta =
        U128::from(fee_growth_inside_latest_x64.wrapping_sub(fee_growth_inside_last_x64))
            .mul_div_floor(U128::from(liquidity), U128::from(fixed_point_64::Q64))
            .unwrap()
            .to_underflow_u64();
    #[cfg(feature = "enable-log")]
    msg!("calculate_latest_token_fees fee_growth_delta:{}, fee_growth_inside_latest_x64:{}, fee_growth_inside_last_x64:{}, liquidity:{}", fee_growth_delta, fee_growth_inside_latest_x64, fee_growth_inside_last_x64, liquidity);
    last_total_fees.checked_add(fee_growth_delta).unwrap()
}

#[cfg(test)]
mod vulnerability_tests {
    use super::calculate_latest_token_fees;
    use crate::libraries::{big_num::U128, fixed_point_64, full_math::MulDiv};

    #[test]
    fn test_calculate_latest_token_fees_overflow_scenario() {
        // 1. Define input values
        let last_total_fees: u64 = 0;
        let fee_growth_inside_last_x64: u128 = 0;
        let liquidity: u128 = 1_u128 << 60; // 2^60
        let fee_growth_inside_latest_x64: u128 = ((1_u128 << 64) - 1) << 4; // (2^64 - 1) * 2^4 = 2^68 - 2^4
        let q64_val: u128 = 1_u128 << 64; // Represents fixed_point_64::Q64

        // 2. Replicate the calculation for `fee_growth_delta`
        let fee_growth_val = fee_growth_inside_latest_x64.wrapping_sub(fee_growth_inside_last_x64);
        let expected_intermediate_result_before_to_underflow = U128::from(fee_growth_val)
            .mul_div_floor(U128::from(liquidity), U128::from(q64_val))
            .unwrap();

        // This intermediate result should be U128::from(u64::MAX)
        // u64::MAX is (1_u128 << 64) - 1
        assert_eq!(
            expected_intermediate_result_before_to_underflow,
            U128::from((1_u128 << 64) - 1),
            "Intermediate result before to_underflow_u64 should be u64::MAX"
        );

        let fee_growth_delta = expected_intermediate_result_before_to_underflow.to_underflow_u64();
        assert_eq!(
            fee_growth_delta, 0,
            "fee_growth_delta should be 0 due to to_underflow_u64 behavior at u64::MAX"
        );

        // 3. Call `calculate_latest_token_fees` with the defined inputs.
        // Ensure fixed_point_64::Q64 is correctly referenced or its value passed.
        // The original function uses fixed_point_64::Q64 directly.
        let actual_result = calculate_latest_token_fees(
            last_total_fees,
            fee_growth_inside_last_x64,
            fee_growth_inside_latest_x64,
            liquidity,
        );

        // 4. Assert that the final result of `calculate_latest_token_fees` is `0`.
        assert_eq!(
            actual_result, 0,
            "Final result should be 0 when fee_growth_delta is 0 and last_total_fees is 0"
        );
    }
}
