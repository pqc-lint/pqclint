//! ML-KEM 768

use super::{constants::*, ind_cca::*, types::*, *};

// Kyber 768 parameters
const RANK_768: usize = 3;
const RANKED_BYTES_PER_RING_ELEMENT_768: usize = RANK_768 * BITS_PER_RING_ELEMENT / 8;
const T_AS_NTT_ENCODED_SIZE_768: usize =
    (RANK_768 * COEFFICIENTS_IN_RING_ELEMENT * BITS_PER_COEFFICIENT) / 8;
const VECTOR_U_COMPRESSION_FACTOR_768: usize = 10;
// [hax]: hacspec/hacspec-v2#27 stealing error
// block_len::<VECTOR_U_COMPRESSION_FACTOR_768>()
const C1_BLOCK_SIZE_768: usize =
    (COEFFICIENTS_IN_RING_ELEMENT * VECTOR_U_COMPRESSION_FACTOR_768) / 8;
// [hax]: hacspec/hacspec-v2#27 stealing error
//  serialized_len::<RANK_768, C1_BLOCK_SIZE_768>();
const C1_SIZE_768: usize = C1_BLOCK_SIZE_768 * RANK_768;
const VECTOR_V_COMPRESSION_FACTOR_768: usize = 4;
// [hax]: hacspec/hacspec-v2#27 stealing error
//  block_len::<VECTOR_V_COMPRESSION_FACTOR_768>()
const C2_SIZE_768: usize = (COEFFICIENTS_IN_RING_ELEMENT * VECTOR_V_COMPRESSION_FACTOR_768) / 8;
const CPA_PKE_SECRET_KEY_SIZE_768: usize =
    (RANK_768 * COEFFICIENTS_IN_RING_ELEMENT * BITS_PER_COEFFICIENT) / 8;
pub(crate) const CPA_PKE_PUBLIC_KEY_SIZE_768: usize = T_AS_NTT_ENCODED_SIZE_768 + 32;
// These two are used in the hybrid kem. This could probably be improved.
const CPA_PKE_CIPHERTEXT_SIZE_768: usize = C1_SIZE_768 + C2_SIZE_768;
const SECRET_KEY_SIZE_768: usize =
    CPA_PKE_SECRET_KEY_SIZE_768 + CPA_PKE_PUBLIC_KEY_SIZE_768 + H_DIGEST_SIZE + SHARED_SECRET_SIZE;

const ETA1: usize = 2;
const ETA1_RANDOMNESS_SIZE: usize = ETA1 * 64;
const ETA2: usize = 2;
const ETA2_RANDOMNESS_SIZE: usize = ETA2 * 64;

const IMPLICIT_REJECTION_HASH_INPUT_SIZE: usize = SHARED_SECRET_SIZE + CPA_PKE_CIPHERTEXT_SIZE_768;

// Kyber 768 types
/// An ML-KEM 768 Ciphertext
pub type MlKem768Ciphertext = MlKemCiphertext<CPA_PKE_CIPHERTEXT_SIZE_768>;
/// An ML-KEM 768 Private key
pub type MlKem768PrivateKey = MlKemPrivateKey<SECRET_KEY_SIZE_768>;
/// An ML-KEM 768 Public key
pub type MlKem768PublicKey = MlKemPublicKey<CPA_PKE_PUBLIC_KEY_SIZE_768>;
/// An ML-KEM 768 Key pair
pub type MlKem768KeyPair = MlKemKeyPair<SECRET_KEY_SIZE_768, CPA_PKE_PUBLIC_KEY_SIZE_768>;

// Instantiate the different functions.
macro_rules! instantiate {
    ($modp:ident, $p:path, $vec:path, $doc:expr) => {
        #[doc = $doc]
        pub mod $modp {
            use super::*;
            use $p as p;

            /// Validate a public key.
            ///
            /// Returns `true` if valid, and `false` otherwise.
            pub fn validate_public_key(public_key: &MlKem768PublicKey) -> bool {
                p::validate_public_key::<
                    RANK_768,
                    T_AS_NTT_ENCODED_SIZE_768,
                    RANKED_BYTES_PER_RING_ELEMENT_768,
                    CPA_PKE_PUBLIC_KEY_SIZE_768,
                >(&public_key.value)
            }

            /// Validate a private key.
            ///
            /// Returns `true` if valid, and `false` otherwise.
            pub fn validate_private_key(
                private_key: &MlKem768PrivateKey,
                ciphertext: &MlKem768Ciphertext,
            ) -> bool {
                p::validate_private_key::<
                    RANK_768,
                    SECRET_KEY_SIZE_768,
                    CPA_PKE_CIPHERTEXT_SIZE_768,
                >(private_key, ciphertext)
            }

            /// Generate ML-KEM 768 Key Pair
            pub fn generate_key_pair(
                randomness: [u8; KEY_GENERATION_SEED_SIZE],
            ) -> MlKem768KeyPair {
                p::generate_keypair::<
                    RANK_768,
                    CPA_PKE_SECRET_KEY_SIZE_768,
                    SECRET_KEY_SIZE_768,
                    CPA_PKE_PUBLIC_KEY_SIZE_768,
                    RANKED_BYTES_PER_RING_ELEMENT_768,
                    ETA1,
                    ETA1_RANDOMNESS_SIZE,
                >(randomness)
            }

            /// Generate Kyber 768 Key Pair
            #[cfg(feature = "kyber")]
            #[cfg_attr(docsrs, doc(cfg(feature = "kyber")))]
            pub fn kyber_generate_key_pair(
                randomness: [u8; KEY_GENERATION_SEED_SIZE],
            ) -> MlKem768KeyPair {
                p::kyber_generate_keypair::<
                    RANK_768,
                    CPA_PKE_SECRET_KEY_SIZE_768,
                    SECRET_KEY_SIZE_768,
                    CPA_PKE_PUBLIC_KEY_SIZE_768,
                    RANKED_BYTES_PER_RING_ELEMENT_768,
                    ETA1,
                    ETA1_RANDOMNESS_SIZE,
                >(randomness)
            }

            /// Encapsulate ML-KEM 768
            ///
            /// Generates an ([`MlKem768Ciphertext`], [`MlKemSharedSecret`]) tuple.
            /// The input is a reference to an [`MlKem768PublicKey`] and [`SHARED_SECRET_SIZE`]
            /// bytes of `randomness`.
            pub fn encapsulate(
                public_key: &MlKem768PublicKey,
                randomness: [u8; SHARED_SECRET_SIZE],
            ) -> (MlKem768Ciphertext, MlKemSharedSecret) {
                p::encapsulate::<
                    RANK_768,
                    CPA_PKE_CIPHERTEXT_SIZE_768,
                    CPA_PKE_PUBLIC_KEY_SIZE_768,
                    T_AS_NTT_ENCODED_SIZE_768,
                    C1_SIZE_768,
                    C2_SIZE_768,
                    VECTOR_U_COMPRESSION_FACTOR_768,
                    VECTOR_V_COMPRESSION_FACTOR_768,
                    C1_BLOCK_SIZE_768,
                    ETA1,
                    ETA1_RANDOMNESS_SIZE,
                    ETA2,
                    ETA2_RANDOMNESS_SIZE,
                >(public_key, randomness)
            }

            /// Encapsulate Kyber 768
            ///
            /// Generates an ([`MlKem768Ciphertext`], [`MlKemSharedSecret`]) tuple.
            /// The input is a reference to an [`MlKem768PublicKey`] and [`SHARED_SECRET_SIZE`]
            /// bytes of `randomness`.
            #[cfg(feature = "kyber")]
            #[cfg_attr(docsrs, doc(cfg(feature = "kyber")))]
            pub fn kyber_encapsulate(
                public_key: &MlKem768PublicKey,
                randomness: [u8; SHARED_SECRET_SIZE],
            ) -> (MlKem768Ciphertext, MlKemSharedSecret) {
                p::kyber_encapsulate::<
                    RANK_768,
                    CPA_PKE_CIPHERTEXT_SIZE_768,
                    CPA_PKE_PUBLIC_KEY_SIZE_768,
                    T_AS_NTT_ENCODED_SIZE_768,
                    C1_SIZE_768,
                    C2_SIZE_768,
                    VECTOR_U_COMPRESSION_FACTOR_768,
                    VECTOR_V_COMPRESSION_FACTOR_768,
                    C1_BLOCK_SIZE_768,
                    ETA1,
                    ETA1_RANDOMNESS_SIZE,
                    ETA2,
                    ETA2_RANDOMNESS_SIZE,
                >(public_key, randomness)
            }

            /// Decapsulate ML-KEM 768
            ///
            /// Generates an [`MlKemSharedSecret`].
            /// The input is a reference to an [`MlKem768PrivateKey`] and an [`MlKem768Ciphertext`].
            pub fn decapsulate(
                private_key: &MlKem768PrivateKey,
                ciphertext: &MlKem768Ciphertext,
            ) -> MlKemSharedSecret {
                p::decapsulate::<
                    RANK_768,
                    SECRET_KEY_SIZE_768,
                    CPA_PKE_SECRET_KEY_SIZE_768,
                    CPA_PKE_PUBLIC_KEY_SIZE_768,
                    CPA_PKE_CIPHERTEXT_SIZE_768,
                    T_AS_NTT_ENCODED_SIZE_768,
                    C1_SIZE_768,
                    C2_SIZE_768,
                    VECTOR_U_COMPRESSION_FACTOR_768,
                    VECTOR_V_COMPRESSION_FACTOR_768,
                    C1_BLOCK_SIZE_768,
                    ETA1,
                    ETA1_RANDOMNESS_SIZE,
                    ETA2,
                    ETA2_RANDOMNESS_SIZE,
                    IMPLICIT_REJECTION_HASH_INPUT_SIZE,
                >(private_key, ciphertext)
            }

            /// Decapsulate Kyber 768
            ///
            /// Generates an [`MlKemSharedSecret`].
            /// The input is a reference to an [`MlKem768PrivateKey`] and an [`MlKem768Ciphertext`].
            #[cfg(feature = "kyber")]
            #[cfg_attr(docsrs, doc(cfg(feature = "kyber")))]
            pub fn kyber_decapsulate(
                private_key: &MlKem768PrivateKey,
                ciphertext: &MlKem768Ciphertext,
            ) -> MlKemSharedSecret {
                p::kyber_decapsulate::<
                    RANK_768,
                    SECRET_KEY_SIZE_768,
                    CPA_PKE_SECRET_KEY_SIZE_768,
                    CPA_PKE_PUBLIC_KEY_SIZE_768,
                    CPA_PKE_CIPHERTEXT_SIZE_768,
                    T_AS_NTT_ENCODED_SIZE_768,
                    C1_SIZE_768,
                    C2_SIZE_768,
                    VECTOR_U_COMPRESSION_FACTOR_768,
                    VECTOR_V_COMPRESSION_FACTOR_768,
                    C1_BLOCK_SIZE_768,
                    ETA1,
                    ETA1_RANDOMNESS_SIZE,
                    ETA2,
                    ETA2_RANDOMNESS_SIZE,
                    IMPLICIT_REJECTION_HASH_INPUT_SIZE,
                >(private_key, ciphertext)
            }

            /// Unpacked APIs that don't use serialized keys.
            pub mod unpacked {
                use super::*;

                /// An Unpacked ML-KEM 768 Public key
                pub type MlKem768PublicKeyUnpacked = p::unpacked::MlKemPublicKeyUnpacked<RANK_768>;

                /// Am Unpacked ML-KEM 768 Key pair
                pub type MlKem768KeyPairUnpacked = p::unpacked::MlKemKeyPairUnpacked<RANK_768>;

                /// Create a new, empty unpacked key.
                pub fn init_key_pair() -> MlKem768KeyPairUnpacked {
                    MlKem768KeyPairUnpacked::default()
                }

                /// Create a new, empty unpacked public key.
                pub fn init_public_key() -> MlKem768PublicKeyUnpacked {
                    MlKem768PublicKeyUnpacked::default()
                }

                /// Get the serialized public key.
                pub fn serialized_public_key(public_key: &MlKem768PublicKeyUnpacked, serialized : &mut MlKem768PublicKey) {
                    public_key.serialized_public_key_mut::<RANKED_BYTES_PER_RING_ELEMENT_768, CPA_PKE_PUBLIC_KEY_SIZE_768>(serialized);
                }

                /// Get the serialized public key.
                pub fn key_pair_serialized_public_key(key_pair: &MlKem768KeyPairUnpacked, serialized : &mut MlKem768PublicKey) {
                    key_pair.serialized_public_key_mut::<RANKED_BYTES_PER_RING_ELEMENT_768, CPA_PKE_PUBLIC_KEY_SIZE_768>(serialized);
                }

                /// Get the unpacked public key.
                pub fn public_key(key_pair: &MlKem768KeyPairUnpacked, pk: &mut MlKem768PublicKeyUnpacked) {
                    *pk = (*key_pair.public_key()).clone();
                }

                /// Get the unpacked public key.
                pub fn unpacked_public_key(
                    public_key: &MlKem768PublicKey,
                    unpacked_public_key: &mut MlKem768PublicKeyUnpacked
                ) {
                    p::unpacked::unpack_public_key::<
                        RANK_768,
                        T_AS_NTT_ENCODED_SIZE_768,
                        RANKED_BYTES_PER_RING_ELEMENT_768,
                        CPA_PKE_PUBLIC_KEY_SIZE_768,
                    >(public_key, unpacked_public_key)
                }

                /// Generate ML-KEM 768 Key Pair in "unpacked" form.
                pub fn generate_key_pair(
                    randomness: [u8; KEY_GENERATION_SEED_SIZE],
                    key_pair: &mut MlKem768KeyPairUnpacked,
                ) {
                    p::unpacked::generate_keypair::<
                        RANK_768,
                        CPA_PKE_SECRET_KEY_SIZE_768,
                        SECRET_KEY_SIZE_768,
                        CPA_PKE_PUBLIC_KEY_SIZE_768,
                        RANKED_BYTES_PER_RING_ELEMENT_768,
                        ETA1,
                        ETA1_RANDOMNESS_SIZE,
                    >(randomness, key_pair);
                }

                /// Encapsulate ML-KEM 768 (unpacked)
                ///
                /// Generates an ([`MlKem768Ciphertext`], [`MlKemSharedSecret`]) tuple.
                /// The input is a reference to an unpacked public key of type [`MlKem768PublicKeyUnpacked`],
                /// the SHA3-256 hash of this public key, and [`SHARED_SECRET_SIZE`] bytes of `randomness`.
                #[cfg_attr(
                    hax,
                    hax_lib::fstar::before(
                        interface,
                        "
                let _ =
                (* This module has implicit dependencies, here we make them explicit. *)
                (* The implicit dependencies arise from typeclasses instances. *)
                let open Libcrux_ml_kem.Vector.Portable in
                let open Libcrux_ml_kem.Vector.Neon in
                ()"
                    )
                )]
                pub fn encapsulate(
                    public_key: &MlKem768PublicKeyUnpacked,
                    randomness: [u8; SHARED_SECRET_SIZE],
                ) -> (MlKem768Ciphertext, MlKemSharedSecret) {
                    p::unpacked::encapsulate::<
                        RANK_768,
                        CPA_PKE_CIPHERTEXT_SIZE_768,
                        CPA_PKE_PUBLIC_KEY_SIZE_768,
                        T_AS_NTT_ENCODED_SIZE_768,
                        C1_SIZE_768,
                        C2_SIZE_768,
                        VECTOR_U_COMPRESSION_FACTOR_768,
                        VECTOR_V_COMPRESSION_FACTOR_768,
                        C1_BLOCK_SIZE_768,
                        ETA1,
                        ETA1_RANDOMNESS_SIZE,
                        ETA2,
                        ETA2_RANDOMNESS_SIZE,
                    >(public_key, randomness)
                }

                /// Decapsulate ML-KEM 768 (unpacked)
                ///
                /// Generates an [`MlKemSharedSecret`].
                /// The input is a reference to an unpacked key pair of type [`MlKem768KeyPairUnpacked`]
                /// and an [`MlKem768Ciphertext`].
                pub fn decapsulate(
                    private_key: &MlKem768KeyPairUnpacked,
                    ciphertext: &MlKem768Ciphertext,
                ) -> MlKemSharedSecret {
                    p::unpacked::decapsulate::<
                        RANK_768,
                        SECRET_KEY_SIZE_768,
                        CPA_PKE_SECRET_KEY_SIZE_768,
                        CPA_PKE_PUBLIC_KEY_SIZE_768,
                        CPA_PKE_CIPHERTEXT_SIZE_768,
                        T_AS_NTT_ENCODED_SIZE_768,
                        C1_SIZE_768,
                        C2_SIZE_768,
                        VECTOR_U_COMPRESSION_FACTOR_768,
                        VECTOR_V_COMPRESSION_FACTOR_768,
                        C1_BLOCK_SIZE_768,
                        ETA1,
                        ETA1_RANDOMNESS_SIZE,
                        ETA2,
                        ETA2_RANDOMNESS_SIZE,
                        IMPLICIT_REJECTION_HASH_INPUT_SIZE,
                    >(private_key, ciphertext)
                }
            }
        }
    };
}

// Instantiations

instantiate! {portable, ind_cca::instantiations::portable, vector::portable::PortableVector, "Portable ML-KEM 768"}
#[cfg(feature = "simd256")]
instantiate! {avx2, ind_cca::instantiations::avx2, vector::SIMD256Vector, "AVX2 Optimised ML-KEM 768"}
#[cfg(feature = "simd128")]
instantiate! {neon, ind_cca::instantiations::neon, vector::SIMD128Vector, "Neon Optimised ML-KEM 768"}

/// Validate a public key.
///
/// Returns `true` if valid, and `false` otherwise.
#[cfg(not(eurydice))]
pub fn validate_public_key(public_key: &MlKem768PublicKey) -> bool {
    multiplexing::validate_public_key::<
        RANK_768,
        T_AS_NTT_ENCODED_SIZE_768,
        RANKED_BYTES_PER_RING_ELEMENT_768,
        CPA_PKE_PUBLIC_KEY_SIZE_768,
    >(&public_key.value)
}

/// Validate a private key.
///
/// Returns `true` if valid, and `false` otherwise.
#[cfg(not(eurydice))]
pub fn validate_private_key(
    private_key: &MlKem768PrivateKey,
    ciphertext: &MlKem768Ciphertext,
) -> bool {
    multiplexing::validate_private_key::<RANK_768, SECRET_KEY_SIZE_768, CPA_PKE_CIPHERTEXT_SIZE_768>(
        private_key,
        ciphertext,
    )
}

/// Generate ML-KEM 768 Key Pair
///
/// Generate an ML-KEM key pair. The input is a byte array of size
/// [`KEY_GENERATION_SEED_SIZE`].
///
/// This function returns an [`MlKem768KeyPair`].
#[cfg(not(eurydice))]
pub fn generate_key_pair(randomness: [u8; KEY_GENERATION_SEED_SIZE]) -> MlKem768KeyPair {
    multiplexing::generate_keypair::<
        RANK_768,
        CPA_PKE_SECRET_KEY_SIZE_768,
        SECRET_KEY_SIZE_768,
        CPA_PKE_PUBLIC_KEY_SIZE_768,
        RANKED_BYTES_PER_RING_ELEMENT_768,
        ETA1,
        ETA1_RANDOMNESS_SIZE,
    >(randomness)
}

// /// Fake a public key.
// pub fn fake_key_pair(
//     private_key: [&[i16]; RANK_768],
//     public_key: [&[i16]; RANK_768],
//     seed: &[u8],
// ) -> MlKem768KeyPair {
//     generate_fake_key_pair::<
//         RANK_768,
//         CPA_PKE_SECRET_KEY_SIZE_768,
//         SECRET_KEY_SIZE_768,
//         CPA_PKE_PUBLIC_KEY_SIZE_768,
//         RANKED_BYTES_PER_RING_ELEMENT_768,
//         ETA1,
//         ETA1_RANDOMNESS_SIZE,
//         vector::portable::PortableVector,
//         hash_functions::portable::PortableHash<RANK_768>,
//     >(private_key, public_key, seed)
// }

/// Encapsulate ML-KEM 768
///
/// Generates an ([`MlKem768Ciphertext`], [`MlKemSharedSecret`]) tuple.
/// The input is a reference to an [`MlKem768PublicKey`] and [`SHARED_SECRET_SIZE`]
/// bytes of `randomness`.
#[cfg(not(eurydice))]
pub fn encapsulate(
    public_key: &MlKem768PublicKey,
    randomness: [u8; SHARED_SECRET_SIZE],
) -> (MlKem768Ciphertext, MlKemSharedSecret) {
    multiplexing::encapsulate::<
        RANK_768,
        CPA_PKE_CIPHERTEXT_SIZE_768,
        CPA_PKE_PUBLIC_KEY_SIZE_768,
        T_AS_NTT_ENCODED_SIZE_768,
        C1_SIZE_768,
        C2_SIZE_768,
        VECTOR_U_COMPRESSION_FACTOR_768,
        VECTOR_V_COMPRESSION_FACTOR_768,
        C1_BLOCK_SIZE_768,
        ETA1,
        ETA1_RANDOMNESS_SIZE,
        ETA2,
        ETA2_RANDOMNESS_SIZE,
    >(public_key, randomness)
}

/// Decapsulate ML-KEM 768
///
/// Generates an [`MlKemSharedSecret`].
/// The input is a reference to an [`MlKem768PrivateKey`] and an [`MlKem768Ciphertext`].
#[cfg(not(eurydice))]
pub fn decapsulate(
    private_key: &MlKem768PrivateKey,
    ciphertext: &MlKem768Ciphertext,
) -> MlKemSharedSecret {
    multiplexing::decapsulate::<
        RANK_768,
        SECRET_KEY_SIZE_768,
        CPA_PKE_SECRET_KEY_SIZE_768,
        CPA_PKE_PUBLIC_KEY_SIZE_768,
        CPA_PKE_CIPHERTEXT_SIZE_768,
        T_AS_NTT_ENCODED_SIZE_768,
        C1_SIZE_768,
        C2_SIZE_768,
        VECTOR_U_COMPRESSION_FACTOR_768,
        VECTOR_V_COMPRESSION_FACTOR_768,
        C1_BLOCK_SIZE_768,
        ETA1,
        ETA1_RANDOMNESS_SIZE,
        ETA2,
        ETA2_RANDOMNESS_SIZE,
        IMPLICIT_REJECTION_HASH_INPUT_SIZE,
    >(private_key, ciphertext)
}

/// Randomized APIs
///
/// The functions in this module are equivalent to the one in the main module,
/// but sample their own randomness, provided a random number generator that
/// implements `RngCore` and `CryptoRng`.
///
/// Decapsulation is not provided in this module as it does not require randomness.
#[cfg(all(not(eurydice), feature = "rand"))]
pub mod rand {
    use super::{
        MlKem768Ciphertext, MlKem768KeyPair, MlKem768PublicKey, MlKemSharedSecret,
        KEY_GENERATION_SEED_SIZE, SHARED_SECRET_SIZE,
    };
    use ::rand::{CryptoRng, RngCore};

    /// Generate ML-KEM 768 Key Pair
    ///
    /// The random number generator `rng` needs to implement `RngCore` and
    /// `CryptoRng` to sample the required randomness internally.
    ///
    /// This function returns an [`MlKem768KeyPair`].
    pub fn generate_key_pair(rng: &mut (impl RngCore + CryptoRng)) -> MlKem768KeyPair {
        let mut randomness = [0u8; KEY_GENERATION_SEED_SIZE];
        rng.fill_bytes(&mut randomness);

        super::generate_key_pair(randomness)
    }

    /// Encapsulate ML-KEM 768
    ///
    /// Generates an ([`MlKem768Ciphertext`], [`MlKemSharedSecret`]) tuple.
    /// The input is a reference to an [`MlKem768PublicKey`].
    /// The random number generator `rng` needs to implement `RngCore` and
    /// `CryptoRng` to sample the required randomness internally.
    pub fn encapsulate(
        public_key: &MlKem768PublicKey,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> (MlKem768Ciphertext, MlKemSharedSecret) {
        let mut randomness = [0u8; SHARED_SECRET_SIZE];
        rng.fill_bytes(&mut randomness);

        super::encapsulate(public_key, randomness)
    }
}

#[cfg(all(not(eurydice), feature = "kyber"))]
pub(crate) mod kyber {
    use super::*;

    /// Generate Kyber 768 Key Pair
    ///
    /// Generate a Kyber key pair. The input is a byte array of size
    /// [`KEY_GENERATION_SEED_SIZE`].
    ///
    /// This function returns an [`MlKem768KeyPair`].
    pub fn generate_key_pair(randomness: [u8; KEY_GENERATION_SEED_SIZE]) -> MlKem768KeyPair {
        multiplexing::kyber_generate_keypair::<
            RANK_768,
            CPA_PKE_SECRET_KEY_SIZE_768,
            SECRET_KEY_SIZE_768,
            CPA_PKE_PUBLIC_KEY_SIZE_768,
            RANKED_BYTES_PER_RING_ELEMENT_768,
            ETA1,
            ETA1_RANDOMNESS_SIZE,
        >(randomness)
    }

    /// Encapsulate Kyber 768
    ///
    /// Generates an ([`MlKem768Ciphertext`], [`MlKemSharedSecret`]) tuple.
    /// The input is a reference to an [`MlKem768PublicKey`] and [`SHARED_SECRET_SIZE`]
    /// bytes of `randomness`.
    pub fn encapsulate(
        public_key: &MlKem768PublicKey,
        randomness: [u8; SHARED_SECRET_SIZE],
    ) -> (MlKem768Ciphertext, MlKemSharedSecret) {
        multiplexing::kyber_encapsulate::<
            RANK_768,
            CPA_PKE_CIPHERTEXT_SIZE_768,
            CPA_PKE_PUBLIC_KEY_SIZE_768,
            T_AS_NTT_ENCODED_SIZE_768,
            C1_SIZE_768,
            C2_SIZE_768,
            VECTOR_U_COMPRESSION_FACTOR_768,
            VECTOR_V_COMPRESSION_FACTOR_768,
            C1_BLOCK_SIZE_768,
            ETA1,
            ETA1_RANDOMNESS_SIZE,
            ETA2,
            ETA2_RANDOMNESS_SIZE,
        >(public_key, randomness)
    }

    /// Decapsulate ML-KEM 768
    ///
    /// Generates an [`MlKemSharedSecret`].
    /// The input is a reference to an [`MlKem768PrivateKey`] and an [`MlKem768Ciphertext`].
    pub fn decapsulate(
        private_key: &MlKem768PrivateKey,
        ciphertext: &MlKem768Ciphertext,
    ) -> MlKemSharedSecret {
        multiplexing::kyber_decapsulate::<
            RANK_768,
            SECRET_KEY_SIZE_768,
            CPA_PKE_SECRET_KEY_SIZE_768,
            CPA_PKE_PUBLIC_KEY_SIZE_768,
            CPA_PKE_CIPHERTEXT_SIZE_768,
            T_AS_NTT_ENCODED_SIZE_768,
            C1_SIZE_768,
            C2_SIZE_768,
            VECTOR_U_COMPRESSION_FACTOR_768,
            VECTOR_V_COMPRESSION_FACTOR_768,
            C1_BLOCK_SIZE_768,
            ETA1,
            ETA1_RANDOMNESS_SIZE,
            ETA2,
            ETA2_RANDOMNESS_SIZE,
            IMPLICIT_REJECTION_HASH_INPUT_SIZE,
        >(private_key, ciphertext)
    }
}
#[cfg(test)]
mod tests {
    use rand::{rngs::OsRng, RngCore};

    use crate::mlkem768::MlKem768PublicKey;

    use super::{
        mlkem768::{generate_key_pair, validate_public_key},
        KEY_GENERATION_SEED_SIZE,
    };

    #[test]
    fn pk_validation() {
        let mut randomness = [0u8; KEY_GENERATION_SEED_SIZE];
        OsRng.fill_bytes(&mut randomness);

        let key_pair = generate_key_pair(randomness);
        assert!(validate_public_key(&key_pair.pk));
    }

    #[test]
    fn zero_rand() {
        let pk = [
            0x4e, 0xc8, 0x97, 0xb2, 0xc8, 0x9a, 0x51, 0x80, 0x94, 0x88, 0xcc, 0x5b, 0xda, 0x01,
            0xb4, 0x4b, 0x31, 0x2f, 0xc9, 0xc6, 0x14, 0xdb, 0xb3, 0x92, 0x28, 0x79, 0x35, 0x8d,
            0x81, 0x10, 0xbb, 0x2a, 0x70, 0xf8, 0xd5, 0x52, 0xd9, 0xcb, 0x24, 0x21, 0x56, 0xa2,
            0x61, 0xc9, 0x93, 0xbd, 0x20, 0x8b, 0xf9, 0x97, 0x5d, 0x33, 0x61, 0x47, 0xa7, 0x25,
            0x08, 0x05, 0x57, 0x62, 0xd1, 0x02, 0x5a, 0xb6, 0x65, 0xc8, 0x69, 0xc4, 0xaa, 0xb3,
            0xd7, 0x04, 0x1a, 0x61, 0x7a, 0x54, 0x60, 0xca, 0xb7, 0xa2, 0x34, 0xd6, 0x38, 0x3f,
            0x9a, 0x17, 0x68, 0xf7, 0x77, 0xcc, 0x12, 0x18, 0x28, 0xac, 0xa9, 0x5d, 0x78, 0xa8,
            0x5d, 0x1f, 0x61, 0x98, 0xe6, 0x2a, 0x91, 0xac, 0xec, 0xa1, 0xe3, 0xa0, 0x1a, 0x3f,
            0xbb, 0x86, 0xa6, 0x85, 0xb8, 0xdf, 0x85, 0x29, 0xd2, 0x98, 0xc9, 0x9c, 0xe6, 0x76,
            0x67, 0x39, 0x27, 0x4d, 0xa9, 0x1f, 0x2e, 0xb7, 0xb5, 0x00, 0xe6, 0x1b, 0x16, 0x3b,
            0x7b, 0x35, 0xd6, 0x32, 0xee, 0x69, 0xcb, 0x9d, 0x33, 0x8e, 0x67, 0x2c, 0x75, 0x0d,
            0x96, 0xc8, 0x21, 0xe3, 0x9e, 0xda, 0xb5, 0xb1, 0x03, 0xf5, 0xcb, 0xa0, 0x61, 0x58,
            0xf4, 0x08, 0x16, 0xba, 0x51, 0x5a, 0x4d, 0x6a, 0x2e, 0xb2, 0x03, 0x83, 0xcd, 0xb5,
            0x59, 0x33, 0x00, 0xc8, 0x1c, 0x96, 0x79, 0x4a, 0x76, 0x3b, 0x20, 0x44, 0x26, 0x5a,
            0x2a, 0x4f, 0x49, 0x77, 0x2c, 0xaa, 0x2c, 0x55, 0x35, 0x14, 0x9b, 0xf5, 0x68, 0x18,
            0x2d, 0x50, 0x85, 0xc5, 0x87, 0x30, 0x4f, 0xf1, 0x43, 0x96, 0xa3, 0x1e, 0xc0, 0xa1,
            0xaa, 0x1a, 0x14, 0x29, 0x02, 0x3b, 0x2f, 0xd7, 0x65, 0x16, 0xa6, 0xba, 0x85, 0x1c,
            0x42, 0x60, 0x43, 0xe1, 0x79, 0x47, 0xd1, 0xc7, 0xe9, 0x8a, 0x34, 0x9f, 0x15, 0x2a,
            0x5e, 0xf5, 0x5d, 0xf4, 0x97, 0x62, 0x05, 0x66, 0x28, 0xa1, 0x07, 0x20, 0x53, 0x46,
            0xb4, 0xc0, 0x21, 0x9c, 0xf0, 0x72, 0xc7, 0xec, 0xf3, 0x9a, 0x8b, 0x79, 0xa8, 0xa9,
            0x77, 0xa7, 0x1f, 0x02, 0x58, 0x98, 0x78, 0x03, 0xb3, 0x42, 0x37, 0x0c, 0xa3, 0x69,
            0x09, 0xa2, 0x36, 0x1e, 0xa6, 0x26, 0xc2, 0x90, 0x4c, 0xba, 0x6b, 0x2c, 0x5b, 0xc5,
            0x63, 0xc8, 0xd7, 0x0f, 0x8a, 0x44, 0x69, 0xa3, 0xd4, 0xac, 0xc0, 0x16, 0x84, 0x94,
            0xe0, 0x00, 0xa8, 0xa3, 0xbc, 0xb5, 0xfb, 0xc4, 0x2a, 0x12, 0xb6, 0xf3, 0x7a, 0x6c,
            0xc4, 0xf4, 0xbc, 0xe7, 0xda, 0x2a, 0xdb, 0x7c, 0x45, 0x6d, 0x07, 0x77, 0xbc, 0x56,
            0x93, 0x22, 0x70, 0x84, 0x58, 0x25, 0xa8, 0x39, 0x2b, 0x4c, 0x88, 0xb9, 0x6d, 0xd2,
            0x12, 0x5e, 0x34, 0x09, 0x3c, 0xe4, 0x00, 0x94, 0x9e, 0xa4, 0x34, 0xf6, 0x34, 0x20,
            0x9a, 0x48, 0x83, 0x3b, 0x48, 0x3f, 0x37, 0x81, 0xa4, 0xb3, 0x0b, 0x8c, 0xb1, 0x15,
            0xaa, 0xe2, 0x04, 0x50, 0x0a, 0x33, 0x5d, 0xc6, 0x33, 0x89, 0x60, 0xd3, 0x41, 0x4f,
            0x72, 0x93, 0x7d, 0xd3, 0x56, 0xc5, 0x44, 0x82, 0x51, 0xd8, 0x89, 0x76, 0xe7, 0xb8,
            0x58, 0x78, 0x24, 0x38, 0x5b, 0x08, 0x5e, 0xa9, 0x78, 0x16, 0x36, 0x73, 0x7a, 0x82,
            0x2f, 0x1b, 0xb6, 0xb5, 0x6b, 0x8b, 0x63, 0xfc, 0x92, 0x2f, 0x3b, 0x60, 0x5b, 0x64,
            0x66, 0x0e, 0x56, 0xac, 0x3e, 0x2b, 0x93, 0x80, 0xbd, 0xe5, 0xa3, 0x9b, 0x13, 0x60,
            0x00, 0x37, 0x8b, 0x8f, 0xe1, 0x24, 0x2a, 0xb5, 0x8f, 0x2c, 0x97, 0x66, 0xfd, 0x8a,
            0x78, 0x27, 0x56, 0x89, 0xa5, 0x04, 0x85, 0x51, 0x4c, 0x2b, 0x04, 0x40, 0x38, 0x6a,
            0xe2, 0xbc, 0x8c, 0x5b, 0x08, 0xad, 0x99, 0x55, 0x80, 0xb4, 0xa3, 0x63, 0x1a, 0x5b,
            0x27, 0xd6, 0xb1, 0x94, 0xe3, 0x50, 0x95, 0x81, 0x1e, 0xf2, 0x92, 0x90, 0x3d, 0x0a,
            0x1a, 0x04, 0x76, 0xc5, 0xc8, 0xc6, 0x95, 0x3f, 0xe0, 0x5b, 0x71, 0x92, 0x72, 0xfe,
            0x36, 0x98, 0x3c, 0x80, 0x03, 0xe3, 0x11, 0x58, 0x35, 0xb5, 0xa0, 0x4e, 0xa9, 0x16,
            0x82, 0x47, 0x74, 0x10, 0x20, 0x20, 0xb4, 0x26, 0xa2, 0x91, 0x98, 0x4c, 0xe6, 0x28,
            0xc9, 0xc1, 0x77, 0x29, 0xb3, 0x16, 0x56, 0xed, 0xb7, 0xa7, 0x30, 0x94, 0xad, 0x84,
            0x80, 0x91, 0x92, 0xb7, 0x3b, 0xa6, 0xb9, 0x84, 0xaf, 0x04, 0x56, 0x6c, 0xfa, 0x70,
            0x14, 0xd9, 0xc9, 0xd6, 0xbc, 0x88, 0x50, 0x67, 0x9e, 0x29, 0x70, 0xb6, 0x20, 0xb1,
            0x44, 0xaf, 0x13, 0x33, 0x79, 0x2c, 0x78, 0x00, 0x07, 0x01, 0x12, 0x64, 0x38, 0x5a,
            0x34, 0x18, 0x4b, 0xd4, 0x4d, 0x24, 0x22, 0x32, 0x8c, 0x52, 0x81, 0x60, 0xf7, 0x0f,
            0x72, 0xb2, 0x9f, 0x26, 0x80, 0xa1, 0xdb, 0xd5, 0xac, 0x11, 0x38, 0x55, 0x7d, 0xc1,
            0x26, 0xd2, 0x95, 0xab, 0xa1, 0x1c, 0xa4, 0xe1, 0xeb, 0xb9, 0xb9, 0x76, 0x25, 0x36,
            0xb7, 0x39, 0xd7, 0x90, 0xba, 0xee, 0x30, 0xb4, 0xd9, 0x83, 0xa6, 0xb3, 0x70, 0x77,
            0x05, 0x80, 0x09, 0x04, 0xe6, 0x01, 0x13, 0x93, 0x5a, 0xf6, 0x04, 0xbe, 0x4e, 0x4b,
            0xcf, 0xe3, 0xe2, 0x38, 0x7d, 0x8a, 0x55, 0xf3, 0x74, 0x20, 0xf9, 0x83, 0x34, 0xd4,
            0xb4, 0x5d, 0xe8, 0xb6, 0x13, 0x37, 0x38, 0x9d, 0x65, 0x06, 0xaa, 0xe8, 0x1c, 0x8d,
            0xaf, 0xfc, 0x76, 0x12, 0xfb, 0xa4, 0x3c, 0xf9, 0x48, 0x1e, 0x48, 0x96, 0x6f, 0xc8,
            0xaa, 0x1e, 0x30, 0x80, 0x81, 0xf6, 0x4e, 0x53, 0xec, 0x35, 0x43, 0xd4, 0x93, 0xdf,
            0x56, 0x5e, 0xf2, 0x29, 0xbc, 0x59, 0x8c, 0x71, 0xfc, 0x85, 0xca, 0xd2, 0x62, 0x62,
            0x0c, 0xeb, 0xbc, 0xbf, 0xab, 0x7e, 0xdb, 0x44, 0x93, 0xd7, 0x57, 0x56, 0x4c, 0xdc,
            0x27, 0x63, 0xe8, 0xa4, 0xdd, 0x40, 0x89, 0x7f, 0x9c, 0x67, 0xdc, 0xb0, 0x7b, 0x8a,
            0xcc, 0x9f, 0xf9, 0x68, 0x35, 0xea, 0x58, 0x7d, 0x26, 0x86, 0xbd, 0x07, 0xfa, 0x89,
            0x25, 0x1b, 0x48, 0x41, 0x98, 0xab, 0x71, 0x4b, 0xa4, 0x7c, 0x43, 0x4a, 0x40, 0xbb,
            0x33, 0x3f, 0xf6, 0xb5, 0x10, 0x41, 0x59, 0xae, 0xf0, 0x25, 0x3e, 0x85, 0x04, 0xf4,
            0x4c, 0x2a, 0xf2, 0x6b, 0x0c, 0x2e, 0x41, 0x0d, 0xb5, 0xbb, 0xac, 0x52, 0x9a, 0x91,
            0x58, 0x31, 0x93, 0xdc, 0x23, 0x4a, 0x9f, 0xb1, 0x70, 0x96, 0xec, 0x47, 0xe2, 0xfa,
            0xb0, 0x5d, 0x62, 0x48, 0xd9, 0x54, 0x2d, 0x16, 0x58, 0x6e, 0xd7, 0xe3, 0x2e, 0xb5,
            0x3c, 0x9d, 0x0f, 0x34, 0x84, 0x0d, 0xd3, 0x5e, 0x09, 0x12, 0x9f, 0x8e, 0x67, 0x94,
            0xae, 0x24, 0x04, 0x76, 0x18, 0x4b, 0x4b, 0x28, 0x6e, 0x45, 0xeb, 0x96, 0x59, 0xf6,
            0x85, 0x0c, 0x07, 0xc4, 0x5a, 0xb7, 0x89, 0xe6, 0x61, 0x67, 0x57, 0x28, 0x62, 0xa8,
            0x30, 0x85, 0x27, 0x87, 0xbe, 0x87, 0x04, 0x8a, 0x22, 0x75, 0x5d, 0xad, 0x57, 0x30,
            0xa1, 0xe0, 0x06, 0x6f, 0x01, 0xb2, 0x7a, 0x18, 0xa0, 0xe4, 0x38, 0x95, 0xd8, 0x46,
            0x02, 0xad, 0x41, 0x9f, 0xb3, 0x2a, 0xcc, 0x86, 0x62, 0x51, 0x87, 0x98, 0xa0, 0x34,
            0xe2, 0x01, 0x91, 0xa4, 0xa3, 0x32, 0xbb, 0x80, 0x05, 0xd4, 0x6f, 0x36, 0x80, 0x27,
            0xe0, 0x31, 0x56, 0x54, 0xe0, 0x0f, 0xe7, 0x2b, 0x3c, 0xe6, 0x12, 0xa0, 0xe3, 0xc8,
            0x90, 0xa5, 0x64, 0xb5, 0x9c, 0x29, 0x4a, 0x56, 0x95, 0x33, 0xe6, 0xb8, 0x17, 0xe0,
            0xd6, 0x20, 0x85, 0xbc, 0x8b, 0xfe, 0x54, 0x0b, 0xe6, 0x96, 0xb1, 0x59, 0x67, 0x3f,
            0x58, 0x38, 0x7d, 0x4b, 0xec, 0x48, 0xc6, 0xca, 0x93, 0x97, 0xb6, 0x0a, 0x47, 0xd8,
            0x00, 0x94, 0x23, 0x0b, 0x0e, 0xb3, 0xc0, 0xa4, 0x60, 0x20, 0x32, 0x67, 0x23, 0x8a,
            0xe0, 0x9e, 0x49, 0xab, 0xb3, 0xd1, 0x41, 0xa6, 0xc6, 0x31, 0xbd, 0xaa, 0x13, 0xac,
            0xfe, 0xb7, 0x35, 0xc6, 0x93, 0x5d, 0x9c, 0x85, 0x02, 0x63, 0x22, 0x1a, 0x0a, 0xd6,
            0x95, 0x35, 0x4c, 0x59, 0xca, 0xb9, 0x32, 0xb6, 0x72, 0x9c, 0x70, 0xa3, 0xab, 0xae,
            0xa2, 0xa1, 0x5a, 0x8b, 0x51, 0x5e, 0xf9, 0x7f, 0x1c, 0x20, 0xbe, 0x05, 0x37, 0xcf,
            0x39, 0x54, 0xb5, 0x1e, 0xa5, 0x84, 0x17, 0xb1, 0x5e, 0x83, 0xb9, 0xca, 0x0b, 0xc9,
            0x21, 0xe5, 0xdb, 0xbb, 0x28, 0x70, 0x00, 0xdc, 0x17, 0xba, 0xde, 0xe3, 0xc5, 0x0d,
            0x0b, 0x76, 0x2c, 0x85, 0x38, 0xc2, 0x78, 0x08, 0x29, 0x54, 0x65, 0x04, 0x73, 0x86,
            0x82, 0x94, 0xa6, 0xff, 0x29, 0x78, 0x21, 0xca, 0x90, 0x20, 0xe7, 0x63, 0x90, 0x99,
            0x90, 0xe3, 0x30, 0xcd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let pk = MlKem768PublicKey::try_from(&pk).unwrap();
        let valid = validate_public_key(&pk);

        assert!(!valid);
    }
}
