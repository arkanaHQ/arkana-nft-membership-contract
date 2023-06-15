use near_sdk::ext_contract;
use near_sdk::json_types::U64;

pub const TGAS: u64 = 1_000_000_000_000;
pub const NO_DEPOSIT: u128 = 0;
pub const XCC_SUCCESS: u64 = 1;

// Validator interface, for cross-contract calls
#[ext_contract(arkana_core_contract)]
trait ArkanaCoreContract {
    fn generate_points(&mut self, account_id: AccountId, points: U64) -> U64;
}
