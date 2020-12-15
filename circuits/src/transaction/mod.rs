pub mod constraints;

pub mod core_transaction;

pub trait Transaction: Default {}

pub trait TransactionProverData<T: Transaction>: Default {}