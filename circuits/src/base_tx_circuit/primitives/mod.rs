pub mod transaction;

#[derive(Debug)]
pub enum BaseTxError {
    InvalidCoinBox(String),
    InvalidTx(String),
}

impl std::fmt::Display for BaseTxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            BaseTxError::InvalidCoinBox(msg) => format!("Invalid coin box: {}", msg),
            BaseTxError::InvalidTx(msg) => format!("Invalid tx: {}", msg),
        };
        write!(f, "{}", msg)
    }
}

impl std::error::Error for BaseTxError {
    #[inline]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}