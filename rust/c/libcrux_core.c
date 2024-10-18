/*
 * SPDX-FileCopyrightText: 2024 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: 45f5a34f336e35c6cc2253bc90cbdb8d812cefa9
 * Eurydice: 1fff1c51ae6e6c87eafd28ec9d5594f54bc91c0c
 * Karamel: 8c3612018c25889288da6857771be3ad03b75bcd
 * F*: 5643e656b989aca7629723653a2570c7df6252b9-dirty
 * Libcrux: 2e8f138dbcbfbfabf4bbd994c8587ec00d197102
 */

#include "internal/libcrux_core.h"

/**
 Return 1 if `value` is not zero and 0 otherwise.
*/
static uint8_t inz(uint8_t value) {
  uint16_t value0 = (uint16_t)value;
  uint16_t result = (((uint32_t)value0 |
                      (uint32_t)core_num__u16_7__wrapping_add(~value0, 1U)) &
                     0xFFFFU) >>
                        8U &
                    1U;
  return (uint8_t)result;
}

static KRML_NOINLINE uint8_t is_non_zero(uint8_t value) { return inz(value); }

/**
 Return 1 if the bytes of `lhs` and `rhs` do not exactly
 match and 0 otherwise.
*/
static uint8_t compare(Eurydice_slice lhs, Eurydice_slice rhs) {
  uint8_t r = 0U;
  for (size_t i = (size_t)0U; i < Eurydice_slice_len(lhs, uint8_t); i++) {
    size_t i0 = i;
    r = (uint32_t)r |
        ((uint32_t)Eurydice_slice_index(lhs, i0, uint8_t, uint8_t *) ^
         (uint32_t)Eurydice_slice_index(rhs, i0, uint8_t, uint8_t *));
  }
  return is_non_zero(r);
}

static KRML_NOINLINE uint8_t
compare_ciphertexts_in_constant_time(Eurydice_slice lhs, Eurydice_slice rhs) {
  return compare(lhs, rhs);
}

/**
 If `selector` is not zero, return the bytes in `rhs`; return the bytes in
 `lhs` otherwise.
*/
static void select_ct(Eurydice_slice lhs, Eurydice_slice rhs, uint8_t selector,
                      uint8_t ret[32U]) {
  uint8_t mask = core_num__u8_6__wrapping_sub(is_non_zero(selector), 1U);
  uint8_t out[32U] = {0U};
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE;
       i++) {
    size_t i0 = i;
    out[i0] = ((uint32_t)Eurydice_slice_index(lhs, i0, uint8_t, uint8_t *) &
               (uint32_t)mask) |
              ((uint32_t)Eurydice_slice_index(rhs, i0, uint8_t, uint8_t *) &
               (uint32_t)~mask);
  }
  memcpy(ret, out, (size_t)32U * sizeof(uint8_t));
}

static KRML_NOINLINE void select_shared_secret_in_constant_time(
    Eurydice_slice lhs, Eurydice_slice rhs, uint8_t selector,
    uint8_t ret[32U]) {
  select_ct(lhs, rhs, selector, ret);
}

void libcrux_ml_kem_constant_time_ops_compare_ciphertexts_select_shared_secret_in_constant_time(
    Eurydice_slice lhs_c, Eurydice_slice rhs_c, Eurydice_slice lhs_s,
    Eurydice_slice rhs_s, uint8_t ret[32U]) {
  uint8_t selector = compare_ciphertexts_in_constant_time(lhs_c, rhs_c);
  uint8_t ret0[32U];
  select_shared_secret_in_constant_time(lhs_s, rhs_s, selector, ret0);
  memcpy(ret, ret0, (size_t)32U * sizeof(uint8_t));
}

/**
This function found in impl {(core::convert::From<@Array<u8, SIZE>> for
libcrux_ml_kem::types::MlKemPublicKey<SIZE>)#17}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_40
with const generics
- SIZE= 1568
*/
libcrux_ml_kem_types_MlKemPublicKey_64 libcrux_ml_kem_types_from_40_af(
    uint8_t value[1568U]) {
  /* Passing arrays by value in Rust generates a copy in C */
  uint8_t copy_of_value[1568U];
  memcpy(copy_of_value, value, (size_t)1568U * sizeof(uint8_t));
  libcrux_ml_kem_types_MlKemPublicKey_64 lit;
  memcpy(lit.value, copy_of_value, (size_t)1568U * sizeof(uint8_t));
  return lit;
}

/**
 Create a new [`MlKemKeyPair`] from the secret and public key.
*/
/**
This function found in impl
{libcrux_ml_kem::types::MlKemKeyPair<PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_17
with const generics
- PRIVATE_KEY_SIZE= 3168
- PUBLIC_KEY_SIZE= 1568
*/
libcrux_ml_kem_mlkem1024_MlKem1024KeyPair libcrux_ml_kem_types_from_17_94(
    libcrux_ml_kem_types_MlKemPrivateKey_83 sk,
    libcrux_ml_kem_types_MlKemPublicKey_64 pk) {
  return (
      CLITERAL(libcrux_ml_kem_mlkem1024_MlKem1024KeyPair){.sk = sk, .pk = pk});
}

/**
This function found in impl {(core::convert::From<@Array<u8, SIZE>> for
libcrux_ml_kem::types::MlKemPrivateKey<SIZE>)#10}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_88
with const generics
- SIZE= 3168
*/
libcrux_ml_kem_types_MlKemPrivateKey_83 libcrux_ml_kem_types_from_88_39(
    uint8_t value[3168U]) {
  /* Passing arrays by value in Rust generates a copy in C */
  uint8_t copy_of_value[3168U];
  memcpy(copy_of_value, value, (size_t)3168U * sizeof(uint8_t));
  libcrux_ml_kem_types_MlKemPrivateKey_83 lit;
  memcpy(lit.value, copy_of_value, (size_t)3168U * sizeof(uint8_t));
  return lit;
}

/**
This function found in impl {(core::convert::From<@Array<u8, SIZE>> for
libcrux_ml_kem::types::MlKemPublicKey<SIZE>)#17}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_40
with const generics
- SIZE= 1184
*/
libcrux_ml_kem_types_MlKemPublicKey_30 libcrux_ml_kem_types_from_40_d0(
    uint8_t value[1184U]) {
  /* Passing arrays by value in Rust generates a copy in C */
  uint8_t copy_of_value[1184U];
  memcpy(copy_of_value, value, (size_t)1184U * sizeof(uint8_t));
  libcrux_ml_kem_types_MlKemPublicKey_30 lit;
  memcpy(lit.value, copy_of_value, (size_t)1184U * sizeof(uint8_t));
  return lit;
}

/**
 Create a new [`MlKemKeyPair`] from the secret and public key.
*/
/**
This function found in impl
{libcrux_ml_kem::types::MlKemKeyPair<PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_17
with const generics
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
*/
libcrux_ml_kem_mlkem768_MlKem768KeyPair libcrux_ml_kem_types_from_17_74(
    libcrux_ml_kem_types_MlKemPrivateKey_d9 sk,
    libcrux_ml_kem_types_MlKemPublicKey_30 pk) {
  return (
      CLITERAL(libcrux_ml_kem_mlkem768_MlKem768KeyPair){.sk = sk, .pk = pk});
}

/**
This function found in impl {(core::convert::From<@Array<u8, SIZE>> for
libcrux_ml_kem::types::MlKemPrivateKey<SIZE>)#10}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_88
with const generics
- SIZE= 2400
*/
libcrux_ml_kem_types_MlKemPrivateKey_d9 libcrux_ml_kem_types_from_88_28(
    uint8_t value[2400U]) {
  /* Passing arrays by value in Rust generates a copy in C */
  uint8_t copy_of_value[2400U];
  memcpy(copy_of_value, value, (size_t)2400U * sizeof(uint8_t));
  libcrux_ml_kem_types_MlKemPrivateKey_d9 lit;
  memcpy(lit.value, copy_of_value, (size_t)2400U * sizeof(uint8_t));
  return lit;
}

/**
This function found in impl {(core::convert::From<@Array<u8, SIZE>> for
libcrux_ml_kem::types::MlKemPublicKey<SIZE>)#17}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_40
with const generics
- SIZE= 800
*/
libcrux_ml_kem_types_MlKemPublicKey_52 libcrux_ml_kem_types_from_40_4d(
    uint8_t value[800U]) {
  /* Passing arrays by value in Rust generates a copy in C */
  uint8_t copy_of_value[800U];
  memcpy(copy_of_value, value, (size_t)800U * sizeof(uint8_t));
  libcrux_ml_kem_types_MlKemPublicKey_52 lit;
  memcpy(lit.value, copy_of_value, (size_t)800U * sizeof(uint8_t));
  return lit;
}

/**
 Create a new [`MlKemKeyPair`] from the secret and public key.
*/
/**
This function found in impl
{libcrux_ml_kem::types::MlKemKeyPair<PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_17
with const generics
- PRIVATE_KEY_SIZE= 1632
- PUBLIC_KEY_SIZE= 800
*/
libcrux_ml_kem_types_MlKemKeyPair_3e libcrux_ml_kem_types_from_17_fa(
    libcrux_ml_kem_types_MlKemPrivateKey_fa sk,
    libcrux_ml_kem_types_MlKemPublicKey_52 pk) {
  return (CLITERAL(libcrux_ml_kem_types_MlKemKeyPair_3e){.sk = sk, .pk = pk});
}

/**
This function found in impl {(core::convert::From<@Array<u8, SIZE>> for
libcrux_ml_kem::types::MlKemPrivateKey<SIZE>)#10}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_88
with const generics
- SIZE= 1632
*/
libcrux_ml_kem_types_MlKemPrivateKey_fa libcrux_ml_kem_types_from_88_2a(
    uint8_t value[1632U]) {
  /* Passing arrays by value in Rust generates a copy in C */
  uint8_t copy_of_value[1632U];
  memcpy(copy_of_value, value, (size_t)1632U * sizeof(uint8_t));
  libcrux_ml_kem_types_MlKemPrivateKey_fa lit;
  memcpy(lit.value, copy_of_value, (size_t)1632U * sizeof(uint8_t));
  return lit;
}

/**
 A reference to the raw byte slice.
*/
/**
This function found in impl {libcrux_ml_kem::types::MlKemPublicKey<SIZE>#21}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.as_slice_ba
with const generics
- SIZE= 1184
*/
uint8_t *libcrux_ml_kem_types_as_slice_ba_d0(
    libcrux_ml_kem_types_MlKemPublicKey_30 *self) {
  return self->value;
}

/**
This function found in impl {(core::convert::From<@Array<u8, SIZE>> for
libcrux_ml_kem::types::MlKemCiphertext<SIZE>)#3}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_fc
with const generics
- SIZE= 1088
*/
libcrux_ml_kem_mlkem768_MlKem768Ciphertext libcrux_ml_kem_types_from_fc_80(
    uint8_t value[1088U]) {
  /* Passing arrays by value in Rust generates a copy in C */
  uint8_t copy_of_value[1088U];
  memcpy(copy_of_value, value, (size_t)1088U * sizeof(uint8_t));
  libcrux_ml_kem_mlkem768_MlKem768Ciphertext lit;
  memcpy(lit.value, copy_of_value, (size_t)1088U * sizeof(uint8_t));
  return lit;
}

/**
This function found in impl {(core::convert::AsRef<@Slice<u8>> for
libcrux_ml_kem::types::MlKemCiphertext<SIZE>)#2}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.as_ref_fd
with const generics
- SIZE= 1088
*/
Eurydice_slice libcrux_ml_kem_types_as_ref_fd_80(
    libcrux_ml_kem_mlkem768_MlKem768Ciphertext *self) {
  return Eurydice_array_to_slice((size_t)1088U, self->value, uint8_t);
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 1120
*/
void libcrux_ml_kem_utils_into_padded_array_15(Eurydice_slice slice,
                                               uint8_t ret[1120U]) {
  uint8_t out[1120U] = {0U};
  uint8_t *uu____0 = out;
  Eurydice_slice_copy(
      Eurydice_array_to_subslice2(uu____0, (size_t)0U,
                                  Eurydice_slice_len(slice, uint8_t), uint8_t),
      slice, uint8_t);
  memcpy(ret, out, (size_t)1120U * sizeof(uint8_t));
}

/**
 A reference to the raw byte slice.
*/
/**
This function found in impl {libcrux_ml_kem::types::MlKemPublicKey<SIZE>#21}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.as_slice_ba
with const generics
- SIZE= 800
*/
uint8_t *libcrux_ml_kem_types_as_slice_ba_4d(
    libcrux_ml_kem_types_MlKemPublicKey_52 *self) {
  return self->value;
}

/**
This function found in impl {(core::convert::From<@Array<u8, SIZE>> for
libcrux_ml_kem::types::MlKemCiphertext<SIZE>)#3}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_fc
with const generics
- SIZE= 768
*/
libcrux_ml_kem_types_MlKemCiphertext_1a libcrux_ml_kem_types_from_fc_d0(
    uint8_t value[768U]) {
  /* Passing arrays by value in Rust generates a copy in C */
  uint8_t copy_of_value[768U];
  memcpy(copy_of_value, value, (size_t)768U * sizeof(uint8_t));
  libcrux_ml_kem_types_MlKemCiphertext_1a lit;
  memcpy(lit.value, copy_of_value, (size_t)768U * sizeof(uint8_t));
  return lit;
}

/**
This function found in impl {(core::convert::AsRef<@Slice<u8>> for
libcrux_ml_kem::types::MlKemCiphertext<SIZE>)#2}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.as_ref_fd
with const generics
- SIZE= 768
*/
Eurydice_slice libcrux_ml_kem_types_as_ref_fd_d0(
    libcrux_ml_kem_types_MlKemCiphertext_1a *self) {
  return Eurydice_array_to_slice((size_t)768U, self->value, uint8_t);
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 800
*/
void libcrux_ml_kem_utils_into_padded_array_4d(Eurydice_slice slice,
                                               uint8_t ret[800U]) {
  uint8_t out[800U] = {0U};
  uint8_t *uu____0 = out;
  Eurydice_slice_copy(
      Eurydice_array_to_subslice2(uu____0, (size_t)0U,
                                  Eurydice_slice_len(slice, uint8_t), uint8_t),
      slice, uint8_t);
  memcpy(ret, out, (size_t)800U * sizeof(uint8_t));
}

/**
 A reference to the raw byte slice.
*/
/**
This function found in impl {libcrux_ml_kem::types::MlKemPublicKey<SIZE>#21}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.as_slice_ba
with const generics
- SIZE= 1568
*/
uint8_t *libcrux_ml_kem_types_as_slice_ba_af(
    libcrux_ml_kem_types_MlKemPublicKey_64 *self) {
  return self->value;
}

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0,
TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types uint8_t[32size_t], core_array_TryFromSliceError

*/
void core_result_unwrap_26_b3(core_result_Result_fb self, uint8_t ret[32U]) {
  if (self.tag == core_result_Ok) {
    uint8_t f0[32U];
    memcpy(f0, self.val.case_Ok, (size_t)32U * sizeof(uint8_t));
    memcpy(ret, f0, (size_t)32U * sizeof(uint8_t));
  } else {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__,
                      "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 34
*/
void libcrux_ml_kem_utils_into_padded_array_b6(Eurydice_slice slice,
                                               uint8_t ret[34U]) {
  uint8_t out[34U] = {0U};
  uint8_t *uu____0 = out;
  Eurydice_slice_copy(
      Eurydice_array_to_subslice2(uu____0, (size_t)0U,
                                  Eurydice_slice_len(slice, uint8_t), uint8_t),
      slice, uint8_t);
  memcpy(ret, out, (size_t)34U * sizeof(uint8_t));
}

/**
This function found in impl {(core::convert::From<@Array<u8, SIZE>> for
libcrux_ml_kem::types::MlKemCiphertext<SIZE>)#3}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_fc
with const generics
- SIZE= 1568
*/
libcrux_ml_kem_types_MlKemCiphertext_64 libcrux_ml_kem_types_from_fc_af(
    uint8_t value[1568U]) {
  /* Passing arrays by value in Rust generates a copy in C */
  uint8_t copy_of_value[1568U];
  memcpy(copy_of_value, value, (size_t)1568U * sizeof(uint8_t));
  libcrux_ml_kem_types_MlKemCiphertext_64 lit;
  memcpy(lit.value, copy_of_value, (size_t)1568U * sizeof(uint8_t));
  return lit;
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 33
*/
void libcrux_ml_kem_utils_into_padded_array_c8(Eurydice_slice slice,
                                               uint8_t ret[33U]) {
  uint8_t out[33U] = {0U};
  uint8_t *uu____0 = out;
  Eurydice_slice_copy(
      Eurydice_array_to_subslice2(uu____0, (size_t)0U,
                                  Eurydice_slice_len(slice, uint8_t), uint8_t),
      slice, uint8_t);
  memcpy(ret, out, (size_t)33U * sizeof(uint8_t));
}

/**
This function found in impl {(core::convert::AsRef<@Slice<u8>> for
libcrux_ml_kem::types::MlKemCiphertext<SIZE>)#2}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.as_ref_fd
with const generics
- SIZE= 1568
*/
Eurydice_slice libcrux_ml_kem_types_as_ref_fd_af(
    libcrux_ml_kem_types_MlKemCiphertext_64 *self) {
  return Eurydice_array_to_slice((size_t)1568U, self->value, uint8_t);
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 1600
*/
void libcrux_ml_kem_utils_into_padded_array_7f(Eurydice_slice slice,
                                               uint8_t ret[1600U]) {
  uint8_t out[1600U] = {0U};
  uint8_t *uu____0 = out;
  Eurydice_slice_copy(
      Eurydice_array_to_subslice2(uu____0, (size_t)0U,
                                  Eurydice_slice_len(slice, uint8_t), uint8_t),
      slice, uint8_t);
  memcpy(ret, out, (size_t)1600U * sizeof(uint8_t));
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 64
*/
void libcrux_ml_kem_utils_into_padded_array_24(Eurydice_slice slice,
                                               uint8_t ret[64U]) {
  uint8_t out[64U] = {0U};
  uint8_t *uu____0 = out;
  Eurydice_slice_copy(
      Eurydice_array_to_subslice2(uu____0, (size_t)0U,
                                  Eurydice_slice_len(slice, uint8_t), uint8_t),
      slice, uint8_t);
  memcpy(ret, out, (size_t)64U * sizeof(uint8_t));
}

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0,
TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types uint8_t[24size_t], core_array_TryFromSliceError

*/
void core_result_unwrap_26_70(core_result_Result_b2 self, uint8_t ret[24U]) {
  if (self.tag == core_result_Ok) {
    uint8_t f0[24U];
    memcpy(f0, self.val.case_Ok, (size_t)24U * sizeof(uint8_t));
    memcpy(ret, f0, (size_t)24U * sizeof(uint8_t));
  } else {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__,
                      "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0,
TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types uint8_t[20size_t], core_array_TryFromSliceError

*/
void core_result_unwrap_26_20(core_result_Result_e1 self, uint8_t ret[20U]) {
  if (self.tag == core_result_Ok) {
    uint8_t f0[20U];
    memcpy(f0, self.val.case_Ok, (size_t)20U * sizeof(uint8_t));
    memcpy(ret, f0, (size_t)20U * sizeof(uint8_t));
  } else {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__,
                      "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0,
TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types uint8_t[10size_t], core_array_TryFromSliceError

*/
void core_result_unwrap_26_ce(core_result_Result_9d self, uint8_t ret[10U]) {
  if (self.tag == core_result_Ok) {
    uint8_t f0[10U];
    memcpy(f0, self.val.case_Ok, (size_t)10U * sizeof(uint8_t));
    memcpy(ret, f0, (size_t)10U * sizeof(uint8_t));
  } else {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__,
                      "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0,
TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types int16_t[16size_t], core_array_TryFromSliceError

*/
void core_result_unwrap_26_00(core_result_Result_0a self, int16_t ret[16U]) {
  if (self.tag == core_result_Ok) {
    int16_t f0[16U];
    memcpy(f0, self.val.case_Ok, (size_t)16U * sizeof(int16_t));
    memcpy(ret, f0, (size_t)16U * sizeof(int16_t));
  } else {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__,
                      "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0,
TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types uint8_t[8size_t], core_array_TryFromSliceError

*/
void core_result_unwrap_26_68(core_result_Result_15 self, uint8_t ret[8U]) {
  if (self.tag == core_result_Ok) {
    uint8_t f0[8U];
    memcpy(f0, self.val.case_Ok, (size_t)8U * sizeof(uint8_t));
    memcpy(ret, f0, (size_t)8U * sizeof(uint8_t));
  } else {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__,
                      "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}
