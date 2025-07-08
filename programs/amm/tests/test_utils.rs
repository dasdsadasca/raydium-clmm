use {
    anchor_lang::{prelude::*, InstructionData},
    anchor_spl::metadata,
    raydium_amm_v3,
    solana_program_test::*,
    solana_sdk::{
        account::Account,
        program_pack::Pack,
        signature::{Keypair, Signer},
    },
    std::str::FromStr,
};

pub const PREFIX: &'static [u8] = "metadata".as_bytes();

pub struct SetUpInfo {
    pub amm_config: Pubkey,
    pub mint0: Pubkey,
    pub mint1: Pubkey,
    pub vault0: Pubkey,
    pub vault1: Pubkey,
    pub token0: Pubkey,
    pub token1: Pubkey,
    pub pool_id: Pubkey,
    pub observation: Pubkey,
    pub bitmap_extension: Pubkey,
    pub tick_spacing: u16,
}

pub fn get_pool_address(amm_config: Pubkey, mint0: Pubkey, mint1: Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[
            raydium_amm_v3::states::POOL_SEED.as_bytes(),
            amm_config.to_bytes().as_ref(),
            mint0.to_bytes().as_ref(),
            mint1.to_bytes().as_ref(),
        ],
        &raydium_amm_v3::id(),
    )
    .0
}

pub fn get_vault_address(pool_id: Pubkey, mint: Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[
            raydium_amm_v3::states::POOL_VAULT_SEED.as_bytes(),
            pool_id.to_bytes().as_ref(),
            mint.to_bytes().as_ref(),
        ],
        &raydium_amm_v3::id(),
    )
    .0
}

pub fn get_observation_address(pool_id: Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[
            raydium_amm_v3::states::OBSERVATION_SEED.as_bytes(),
            pool_id.to_bytes().as_ref(),
        ],
        &raydium_amm_v3::id(),
    )
    .0
}

pub fn get_bitmap_extension_address(pool_id: Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[
            raydium_amm_v3::states::POOL_TICK_ARRAY_BITMAP_SEED.as_bytes(),
            pool_id.to_bytes().as_ref(),
        ],
        &raydium_amm_v3::id(),
    )
    .0
}

pub fn tick_with_spacing(tick: i32, tick_spacing: i32) -> i32 {
    let mut compressed = tick / tick_spacing;
    if tick < 0 && tick % tick_spacing != 0 {
        compressed -= 1; // round towards negative infinity
    }
    compressed * tick_spacing
}

pub fn setup(
    program_test: &mut ProgramTest,
    wallet_address: &Pubkey,
    tick_spacing: u16,
    trade_fee_rate: u32,
) -> SetUpInfo {
    // Add metadata program
    program_test.prefer_bpf(true);
    program_test.add_program(
        "mpl_metadata",
        Pubkey::from_str("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s").unwrap(),
        None,
    );
    // Get SOL for wallet
    program_test.add_account(
        *wallet_address,
        Account {
            lamports: 1_000_000_000 * 100,
            data: vec![],
            owner: anchor_lang::system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    // Build config account for test
    let config_index = 0u16;
    let (amm_config_key, bump) = Pubkey::find_program_address(
        &[
            raydium_amm_v3::states::AMM_CONFIG_SEED.as_bytes(),
            &config_index.to_be_bytes(),
        ],
        &raydium_amm_v3::id(),
    );

    let amm_config = raydium_amm_v3::states::AmmConfig {
        bump,
        index: config_index,
        trade_fee_rate,
        tick_spacing,
        ..Default::default()
    };
    let mut amm_config_data = Vec::with_capacity(raydium_amm_v3::states::AmmConfig::LEN);
    amm_config.try_serialize(&mut amm_config_data).unwrap();
    program_test.add_account(
        amm_config_key,
        Account {
            lamports: 1705200,
            data: amm_config_data,
            owner: raydium_amm_v3::id(),
            executable: false,
            rent_epoch: 0,
        },
    );

    // Build mint0
    let mint0_keypair = Keypair::new();
    let mint0 = anchor_spl::token::spl_token::state::Mint {
        mint_authority: solana_sdk::program_option::COption::Some(*wallet_address),
        supply: u64::MAX,
        decimals: 6,
        is_initialized: true,
        freeze_authority: solana_sdk::program_option::COption::None,
    };
    let mut mint0_data = vec![0u8; anchor_spl::token::spl_token::state::Mint::LEN];
    anchor_spl::token::spl_token::state::Mint::pack_into_slice(&mint0, &mut mint0_data);
    program_test.add_account(
        mint0_keypair.pubkey(),
        Account {
            lamports: 399269547297,
            data: mint0_data,
            owner: anchor_spl::token::spl_token::id(),
            executable: false,
            rent_epoch: 0,
        },
    );
    // Build mint1
    let mint1_keypair = Keypair::new();
    let mint1 = anchor_spl::token::spl_token::state::Mint {
        mint_authority: solana_sdk::program_option::COption::Some(*wallet_address),
        supply: u64::MAX,
        decimals: 6,
        is_initialized: true,
        freeze_authority: solana_sdk::program_option::COption::None,
    };
    let mut mint1_data = vec![0u8; anchor_spl::token::spl_token::state::Mint::LEN];
    anchor_spl::token::spl_token::state::Mint::pack_into_slice(&mint1, &mut mint1_data);
    program_test.add_account(
        mint1_keypair.pubkey(),
        Account {
            lamports: 399269547297,
            data: mint1_data,
            owner: anchor_spl::token::spl_token::id(),
            executable: false,
            rent_epoch: 0,
        },
    );
    // Build token0
    let token0_ata = anchor_spl::associated_token::get_associated_token_address(
        wallet_address,
        &mint0_keypair.pubkey(),
    );
    let token0 = anchor_spl::token::spl_token::state::Account {
        mint: mint0_keypair.pubkey(),
        owner: *wallet_address,
        amount: u64::MAX,
        delegate: solana_sdk::program_option::COption::None,
        state: anchor_spl::token::spl_token::state::AccountState::Initialized,
        ..Default::default()
    };
    let mut token0_data = vec![0u8; anchor_spl::token::spl_token::state::Account::LEN];
    anchor_spl::token::spl_token::state::Account::pack_into_slice(&token0, &mut token0_data);
    program_test.add_account(
        token0_ata,
        Account {
            lamports: 399269547297,
            data: token0_data,
            owner: anchor_spl::token::spl_token::id(),
            executable: false,
            rent_epoch: 0,
        },
    );
    // Build token1
    let token1_ata = anchor_spl::associated_token::get_associated_token_address(
        wallet_address,
        &mint1_keypair.pubkey(),
    );
    let token1 = anchor_spl::token::spl_token::state::Account {
        mint: mint1_keypair.pubkey(),
        owner: *wallet_address,
        amount: u64::MAX,
        delegate: solana_sdk::program_option::COption::None,
        state: anchor_spl::token::spl_token::state::AccountState::Initialized,
        ..Default::default()
    };
    let mut token1_data = vec![0u8; anchor_spl::token::spl_token::state::Account::LEN];
    anchor_spl::token::spl_token::state::Account::pack_into_slice(&token1, &mut token1_data);
    program_test.add_account(
        token1_ata,
        Account {
            lamports: 399269547297,
            data: token1_data,
            owner: anchor_spl::token::spl_token::id(),
            executable: false,
            rent_epoch: 0,
        },
    );

    let (mint0, mint1, token0, token1) = if mint0_keypair.pubkey() > mint1_keypair.pubkey() {
        (
            mint1_keypair.pubkey(),
            mint0_keypair.pubkey(),
            token1_ata,
            token0_ata,
        )
    } else {
        (
            mint0_keypair.pubkey(),
            mint1_keypair.pubkey(),
            token0_ata,
            token1_ata,
        )
    };

    let pool_id = get_pool_address(amm_config_key, mint0, mint1);
    return SetUpInfo {
        amm_config: amm_config_key,
        mint0,
        mint1,
        vault0: get_vault_address(pool_id, mint0),
        vault1: get_vault_address(pool_id, mint1),
        pool_id,
        token0,
        token1,
        observation: get_observation_address(pool_id),
        bitmap_extension: get_bitmap_extension_address(pool_id),
        tick_spacing: 10,
    };
}

pub fn create_pool_ix(
    setup_account: &SetUpInfo,
    wallet: Pubkey,
    init_tick: i32,
) -> Result<anchor_lang::solana_program::instruction::Instruction> {
    let metadata_accounts = raydium_amm_v3::accounts::CreatePool {
        pool_creator: wallet,
        amm_config: setup_account.amm_config,
        token_mint_0: setup_account.mint0,
        token_mint_1: setup_account.mint1,
        pool_state: setup_account.pool_id,
        token_vault_0: setup_account.vault0,
        token_vault_1: setup_account.vault1,
        observation_state: setup_account.observation,
        tick_array_bitmap: setup_account.bitmap_extension,
        token_program_0: anchor_spl::token::spl_token::id(),
        token_program_1: anchor_spl::token::spl_token::id(),
        system_program: anchor_lang::system_program::ID,
        rent: anchor_lang::solana_program::sysvar::rent::id(),
    }
    .to_account_metas(None);
    let crete_pool_instruction = anchor_lang::solana_program::instruction::Instruction {
        program_id: raydium_amm_v3::id(),
        accounts: metadata_accounts,
        data: raydium_amm_v3::instruction::CreatePool {
            sqrt_price_x64: raydium_amm_v3::libraries::get_sqrt_price_at_tick(init_tick).unwrap(),
            open_time: 0,
        }
        .data(),
    };
    Ok(crete_pool_instruction)
}

pub fn open_position_ix(
    setup_account: &SetUpInfo,
    wallet: Pubkey,
    position_nft_mint: Pubkey,
    tick_lower: i32,
    tick_upper: i32,
    liquidity: u128,
) -> Result<anchor_lang::solana_program::instruction::Instruction> {
    let tick_array_lower_start_index =
        raydium_amm_v3::states::TickArrayState::get_array_start_index(
            tick_lower,
            setup_account.tick_spacing.into(),
        );
    let tick_array_upper_start_index =
        raydium_amm_v3::states::TickArrayState::get_array_start_index(
            tick_upper,
            setup_account.tick_spacing.into(),
        );
    let (tick_array_lower, __bump) = Pubkey::find_program_address(
        &[
            raydium_amm_v3::states::TICK_ARRAY_SEED.as_bytes(),
            setup_account.pool_id.to_bytes().as_ref(),
            &tick_array_lower_start_index.to_be_bytes(),
        ],
        &raydium_amm_v3::id(),
    );
    let (tick_array_upper, __bump) = Pubkey::find_program_address(
        &[
            raydium_amm_v3::states::TICK_ARRAY_SEED.as_bytes(),
            setup_account.pool_id.to_bytes().as_ref(),
            &tick_array_upper_start_index.to_be_bytes(),
        ],
        &raydium_amm_v3::id(),
    );

    let position_nft_account =
        anchor_spl::associated_token::get_associated_token_address(&wallet, &position_nft_mint);
    let (metadata_account, _bump) = Pubkey::find_program_address(
        &[
            PREFIX,
            metadata::ID.to_bytes().as_ref(),
            position_nft_mint.to_bytes().as_ref(),
        ],
        &metadata::ID,
    );
    let (protocol_position, __bump) = Pubkey::find_program_address(
        &[
            raydium_amm_v3::states::POSITION_SEED.as_bytes(),
            setup_account.pool_id.to_bytes().as_ref(),
            &tick_lower.to_be_bytes(),
            &tick_upper.to_be_bytes(),
        ],
        &raydium_amm_v3::id(),
    );
    let (personal_position, __bump) = Pubkey::find_program_address(
        &[
            raydium_amm_v3::states::POSITION_SEED.as_bytes(),
            position_nft_mint.to_bytes().as_ref(),
        ],
        &raydium_amm_v3::id(),
    );

    let mut metadata_accounts = raydium_amm_v3::accounts::OpenPositionV2 {
        payer: wallet,
        position_nft_mint,
        position_nft_owner: wallet,
        position_nft_account,
        pool_state: setup_account.pool_id,
        metadata_account,
        protocol_position,
        tick_array_lower,
        tick_array_upper,
        personal_position,
        token_account_0: setup_account.token0,
        token_account_1: setup_account.token1,
        token_vault_0: setup_account.vault0,
        token_vault_1: setup_account.vault1,
        rent: anchor_lang::solana_program::sysvar::rent::id(),
        system_program: anchor_lang::system_program::ID,
        token_program: anchor_spl::token::spl_token::id(),
        associated_token_program: anchor_spl::associated_token::ID,
        metadata_program: metadata::ID,
        token_program_2022: spl_token_2022::id(),
        vault_0_mint: setup_account.mint0,
        vault_1_mint: setup_account.mint1,
    }
    .to_account_metas(None);
    let mut remaining_accounts = Vec::new();
    remaining_accounts.push(AccountMeta::new(setup_account.bitmap_extension, false));
    metadata_accounts.extend(remaining_accounts);

    let open_position_instruction = anchor_lang::solana_program::instruction::Instruction {
        program_id: raydium_amm_v3::id(),
        accounts: metadata_accounts,
        data: raydium_amm_v3::instruction::OpenPositionV2 {
            liquidity,
            tick_lower_index: tick_lower,
            tick_upper_index: tick_upper,
            tick_array_lower_start_index,
            tick_array_upper_start_index,
            amount_0_max: 1_000_000_000000,
            amount_1_max: 1_000_000_000000,
            with_metadata: false,
            base_flag: None,
        }
        .data(),
    };
    Ok(open_position_instruction)
}

pub fn swap_ix(
    setup_account: &SetUpInfo,
    wallet: Pubkey,
    amount_in: u64,
    zero_for_one: bool,
    sqrt_price_limit_x64: u128,
    tick_array_indexs: Vec<i32>,
) -> Result<anchor_lang::solana_program::instruction::Instruction> {
    let (input_token, output_token, input_vault, output_vault, input_mint, output_mint) =
        if zero_for_one {
            (
                setup_account.token0,
                setup_account.token1,
                setup_account.vault0,
                setup_account.vault1,
                setup_account.mint0,
                setup_account.mint1,
            )
        } else {
            (
                setup_account.token1,
                setup_account.token0,
                setup_account.vault1,
                setup_account.vault0,
                setup_account.mint1,
                setup_account.mint0,
            )
        };
    let mut metadata_accounts = raydium_amm_v3::accounts::SwapSingleV2 {
        payer: wallet,
        amm_config: setup_account.amm_config,
        pool_state: setup_account.pool_id,
        input_token_account: input_token,
        output_token_account: output_token,
        input_vault,
        output_vault,
        observation_state: setup_account.observation,
        token_program: anchor_spl::token::spl_token::id(),
        token_program_2022: anchor_spl::token_2022::ID,
        memo_program: anchor_spl::memo::ID,
        input_vault_mint: input_mint,
        output_vault_mint: output_mint,
    }
    .to_account_metas(None);
    let mut remaining_accounts = Vec::new();
    remaining_accounts.push(AccountMeta::new(setup_account.bitmap_extension, false));
    let mut accounts = tick_array_indexs
        .into_iter()
        .map(|index| {
            AccountMeta::new(
                Pubkey::find_program_address(
                    &[
                        raydium_amm_v3::states::TICK_ARRAY_SEED.as_bytes(),
                        setup_account.pool_id.to_bytes().as_ref(),
                        &index.to_be_bytes(),
                    ],
                    &raydium_amm_v3::id(),
                )
                .0,
                false,
            )
        })
        .collect();
    remaining_accounts.append(&mut accounts);
    metadata_accounts.extend(remaining_accounts);

    let swap_instruction = anchor_lang::solana_program::instruction::Instruction {
        program_id: raydium_amm_v3::id(),
        accounts: metadata_accounts,
        data: raydium_amm_v3::instruction::SwapV2 {
            amount: amount_in,
            other_amount_threshold: 0,
            sqrt_price_limit_x64,
            is_base_input: true,
        }
        .data(),
    };
    Ok(swap_instruction)
}

pub fn decrease_liquidity_ix(
    setup_account: &SetUpInfo,
    wallet: Pubkey,
    position_nft_mint: Pubkey,
    tick_lower: i32,
    tick_upper: i32,
    liquidity: u128,
) -> Result<anchor_lang::solana_program::instruction::Instruction> {
    let (personal_position, __bump) = Pubkey::find_program_address(
        &[
            raydium_amm_v3::states::POSITION_SEED.as_bytes(),
            position_nft_mint.to_bytes().as_ref(),
        ],
        &raydium_amm_v3::id(),
    );
    let (protocol_position, __bump) = Pubkey::find_program_address(
        &[
            raydium_amm_v3::states::POSITION_SEED.as_bytes(),
            setup_account.pool_id.to_bytes().as_ref(),
            &tick_lower.to_be_bytes(),
            &tick_upper.to_be_bytes(),
        ],
        &raydium_amm_v3::id(),
    );

    let tick_array_lower_start_index =
        raydium_amm_v3::states::TickArrayState::get_array_start_index(
            tick_lower,
            setup_account.tick_spacing.into(),
        );
    let tick_array_upper_start_index =
        raydium_amm_v3::states::TickArrayState::get_array_start_index(
            tick_upper,
            setup_account.tick_spacing.into(),
        );
    let (tick_array_lower, __bump) = Pubkey::find_program_address(
        &[
            raydium_amm_v3::states::TICK_ARRAY_SEED.as_bytes(),
            setup_account.pool_id.to_bytes().as_ref(),
            &tick_array_lower_start_index.to_be_bytes(),
        ],
        &raydium_amm_v3::id(),
    );
    let (tick_array_upper, __bump) = Pubkey::find_program_address(
        &[
            raydium_amm_v3::states::TICK_ARRAY_SEED.as_bytes(),
            setup_account.pool_id.to_bytes().as_ref(),
            &tick_array_upper_start_index.to_be_bytes(),
        ],
        &raydium_amm_v3::id(),
    );

    let position_nft_account =
        anchor_spl::associated_token::get_associated_token_address(&wallet, &position_nft_mint);

    let mut metadata_accounts = raydium_amm_v3::accounts::DecreaseLiquidityV2 {
        nft_owner: wallet,
        nft_account: position_nft_account,
        personal_position,
        pool_state: setup_account.pool_id,
        protocol_position,
        token_vault_0: setup_account.vault0,
        token_vault_1: setup_account.vault1,
        tick_array_lower,
        tick_array_upper,
        recipient_token_account_0: setup_account.token0,
        recipient_token_account_1: setup_account.token1,
        token_program: anchor_spl::token::spl_token::id(),
        token_program_2022: anchor_spl::token_2022::ID,
        memo_program: anchor_spl::memo::ID,
        vault_0_mint: setup_account.mint0,
        vault_1_mint: setup_account.mint1,
    }
    .to_account_metas(None);
    let mut remaining_accounts = Vec::new();
    remaining_accounts.push(AccountMeta::new(setup_account.bitmap_extension, false));
    metadata_accounts.extend(remaining_accounts);

    let decrease_liquidity_instruction = anchor_lang::solana_program::instruction::Instruction {
        program_id: raydium_amm_v3::id(),
        accounts: metadata_accounts,
        data: raydium_amm_v3::instruction::DecreaseLiquidityV2 {
            liquidity,
            amount_0_min: 0,
            amount_1_min: 0,
        }
        .data(),
    };
    Ok(decrease_liquidity_instruction)
}
