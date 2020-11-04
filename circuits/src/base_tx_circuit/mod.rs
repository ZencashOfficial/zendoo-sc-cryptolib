pub mod gadgets;
pub mod primitives;
pub mod constants;

#[derive(Debug)]
pub enum BaseTxError {
    InvalidSigPk,
    InvalidSig,
    InvalidBox,
    InvalidTx,
    MissingBoxId,
    MissingBoxNonce,
}

impl std::fmt::Display for BaseTxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            BaseTxError::InvalidSigPk => {
                "Semantically invalid Schnorr Signature Public Key"
            },
            BaseTxError::InvalidSig => {
                "Semantically invalid Schnorr Signature"
            },
            BaseTxError::InvalidBox => {
                "Semantically invalid Box"
            },
            BaseTxError::InvalidTx => {
                "Semantically invalid Tx"
            },
            BaseTxError::MissingBoxId => {
                "ID missing for Box"
            },
            BaseTxError::MissingBoxNonce => {
                "Nonce missing for Box"
            },
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