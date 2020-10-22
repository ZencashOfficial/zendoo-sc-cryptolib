//ASCII hex string
pub const GH_FIRST_BLOCK: &'static [u8; 64]
= b"53756e4d65726375727956656e757345617274684d6172734a75706974657253";

// BLAKE2s invocation personalizations

/// BLAKE2s Personalization for NULL_PK in NaiveThresholdSigCircuit
pub const NULL_PK_PERSONALIZATION: &'static [u8; 8]
= b"ZenullPK";

// Group hash personalizations
/// BLAKE2s Personalization for Group hash generators used for VRF.
pub const VRF_GROUP_HASH_GENERATORS_PERSONALIZATION: &'static [u8; 8]
= b"ZenVrfPH";