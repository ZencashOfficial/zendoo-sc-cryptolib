#![deny(
    unused_import_braces,
    unused_qualifications,
    trivial_casts,
    trivial_numeric_casts
)]
#![deny(
    unused_qualifications,
    variant_size_differences,
    stable_features,
    unreachable_pub
)]
// #![deny(
//     non_shorthand_field_patterns,
//     unused_attributes,
//     unused_imports,
//     unused_extern_crates
// )]
#![deny(
non_shorthand_field_patterns,
unused_attributes,
unused_extern_crates
)]
#![deny(
    renamed_and_removed_lints,
    stable_features,
    unused_allocation,
    unused_comparisons,
    bare_trait_objects
)]
#![deny(
    const_err,
    unused_must_use,
    unused_mut,
    unused_unsafe,
    private_in_public,
    unsafe_code
)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate algebra;

pub mod demo_circuit;

// Fixing modules sequentially to not get lost among errors, so some of them are detached by commenting

pub mod base_gadgets;
pub use self::base_gadgets::*;

pub mod transaction_box;
// pub use self::transaction_box::*;
// pub mod transaction;
// pub use self::transaction::*;
//
//
// pub mod rules;
// pub use self::rules::*;
//
//

//
// pub mod extendable_tx_circuit;

#[macro_use]
extern crate derivative;
