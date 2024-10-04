use core::dict::{Felt252Dict, Felt252DictEntryTrait};
use core::num::traits::{Zero, One, BitSize};
use core::sha256::compute_sha256_byte_array;
use core::starknet::SyscallResultTrait;
use core::starknet::secp256_trait::{Secp256Trait, Signature, is_valid_signature};
use core::starknet::secp256k1::{Secp256k1Point};

// File: ./packages/cmds/src/main.cairo

#[derive(Clone, Drop)]
struct InputData {
    ScriptSig: ByteArray,
    ScriptPubKey: ByteArray
}

#[derive(Clone, Drop)]
struct InputDataWithFlags {
    ScriptSig: ByteArray,
    ScriptPubKey: ByteArray,
    Flags: ByteArray
}

#[derive(Clone, Drop)]
struct InputDataWithWitness {
    ScriptSig: ByteArray,
    ScriptPubKey: ByteArray,
    Flags: ByteArray,
    Witness: ByteArray
}

fn run_with_flags(input: InputDataWithFlags) -> Result<(), felt252> {
    println!(
        "Running Bitcoin Script with ScriptSig: '{}', ScriptPubKey: '{}' and Flags: '{}'",
        input.ScriptSig,
        input.ScriptPubKey,
        input.Flags
    );
    let mut compiler = CompilerImpl::new();
    let script_pubkey = compiler.compile(input.ScriptPubKey)?;
    let compiler = CompilerImpl::new();
    let script_sig = compiler.compile(input.ScriptSig)?;
    let tx = TransactionImpl::new_signed(script_sig);
    let flags = parse_flags(input.Flags);
    let mut engine = EngineInternalImpl::new(@script_pubkey, tx, 0, flags, 0)?;
    let _ = engine.execute()?;
    Result::Ok(())
}

fn run_with_witness(input: InputDataWithWitness) -> Result<(), felt252> {
    println!(
        "Running Bitcoin Script with ScriptSig: '{}', ScriptPubKey: '{}', Flags: '{}' and Witness: '{}'",
        input.ScriptSig,
        input.ScriptPubKey,
        input.Flags,
        input.Witness
    );
    let mut compiler = CompilerImpl::new();
    let script_pubkey = compiler.compile(input.ScriptPubKey)?;
    let compiler = CompilerImpl::new();
    let script_sig = compiler.compile(input.ScriptSig)?;
    let witness = parse_witness_input(input.Witness);
    let tx = TransactionImpl::new_signed_witness(script_sig, witness);
    let flags = parse_flags(input.Flags);
    let mut engine = EngineInternalImpl::new(@script_pubkey, tx, 0, flags, 0)?;
    let _ = engine.execute()?;
    Result::Ok(())
}

fn run(input: InputData) -> Result<(), felt252> {
    println!(
        "Running Bitcoin Script with ScriptSig: '{}' and ScriptPubKey: '{}'",
        input.ScriptSig,
        input.ScriptPubKey
    );
    let mut compiler = CompilerImpl::new();
    let script_pubkey = compiler.compile(input.ScriptPubKey)?;
    let compiler = CompilerImpl::new();
    let script_sig = compiler.compile(input.ScriptSig)?;
    let tx = TransactionImpl::new_signed(script_sig);
    let mut engine = EngineInternalImpl::new(@script_pubkey, tx, 0, 0, 0)?;
    let _ = engine.execute()?;
    Result::Ok(())
}

fn run_with_json(input: InputData) -> Result<(), felt252> {
    println!(
        "Running Bitcoin Script with ScriptSig: '{}' and ScriptPubKey: '{}'",
        input.ScriptSig,
        input.ScriptPubKey
    );
    let mut compiler = CompilerImpl::new();
    let script_pubkey = compiler.compile(input.ScriptPubKey)?;
    let compiler = CompilerImpl::new();
    let script_sig = compiler.compile(input.ScriptSig)?;
    let tx = TransactionImpl::new_signed(script_sig);
    let mut engine = EngineInternalImpl::new(@script_pubkey, tx, 0, 0, 0)?;
    let _ = engine.execute()?;
    engine.json();
    Result::Ok(())
}

fn debug(input: InputData) -> Result<bool, felt252> {
    println!(
        "Running Bitcoin Script with ScriptSig: '{}' and ScriptPubKey: '{}'",
        input.ScriptSig,
        input.ScriptPubKey
    );
    let mut compiler = CompilerImpl::new();
    let script_pubkey = compiler.compile(input.ScriptPubKey)?;
    let compiler = CompilerImpl::new();
    let script_sig = compiler.compile(input.ScriptSig)?;
    let tx = TransactionImpl::new_signed(script_sig);
    let mut engine = EngineInternalImpl::new(@script_pubkey, tx, 0, 0, 0)?;
    let mut res = Result::Ok(true);
    while true {
        res = engine.step();
        if res.is_err() {
            break;
        }
        if res.unwrap() == false {
            break;
        }
        engine.json();
    };
    res
}

fn main(input: InputDataWithFlags) -> u8 {
    let res = run_with_flags(input);
    match res {
        Result::Ok(_) => {
            println!("Execution successful");
            1
        },
        Result::Err(e) => {
            println!("Execution failed: {}", felt252_to_byte_array(e));
            0
        }
    }
}

fn main_with_witness(input: InputDataWithWitness) -> u8 {
    let res = run_with_witness(input);
    match res {
        Result::Ok(_) => {
            println!("Execution successful");
            1
        },
        Result::Err(e) => {
            println!("Execution failed: {}", felt252_to_byte_array(e));
            0
        }
    }
}

fn backend_run(input: InputData) -> u8 {
    let res = run_with_json(input);
    match res {
        Result::Ok(_) => {
            println!("Execution successful");
            1
        },
        Result::Err(e) => {
            println!("Execution failed: {}", felt252_to_byte_array(e));
            0
        }
    }
}

fn backend_debug(input: InputData) -> u8 {
    let res = debug(input);
    match res {
        Result::Ok(_) => {
            println!("Execution successful");
            1
        },
        Result::Err(e) => {
            println!("Execution failed: {}", felt252_to_byte_array(e));
            0
        }
    }
}

#[derive(Drop)]
struct ValidateRawInput {
    raw_transaction: ByteArray,
    utxo_hints: Array<UTXO>
}

fn run_raw_transaction(input: ValidateRawInput) -> u8 {
    println!("Running Bitcoin Script with raw transaction: '{}'", input.raw_transaction);
    let raw_transaction = hex_to_bytecode(@input.raw_transaction);
    let transaction = TransactionTrait::deserialize(raw_transaction);
    let res = validate_transaction(transaction, 0, input.utxo_hints);
    match res {
        Result::Ok(_) => {
            println!("Execution successful");
            1
        },
        Result::Err(e) => {
            println!("Execution failed: {}", felt252_to_byte_array(e));
            0
        }
    }
}

// File: ./packages/cmds/src/lib.cairo

pub mod main;

// File: ./packages/utils/src/bytecode.cairo

// TODO: little-endian?
// TODO: if odd number of bytes, prepend 0?
pub fn hex_to_bytecode(script_item: @ByteArray) -> ByteArray {
    let half_byte_shift = 16;
    let zero_string = '0';
    let a_string_lower = 'a';
    let a_string_capital = 'A';
    let mut i = 2;
    let mut bytecode = "";
    let script_item_len = script_item.len();
    while i != script_item_len {
        let mut upper_half_byte = 0;
        let mut lower_half_byte = 0;
        if script_item[i] >= a_string_lower {
            upper_half_byte = (script_item[i].into() - a_string_lower + 10) * half_byte_shift;
        } else if script_item[i] >= a_string_capital {
            upper_half_byte = (script_item[i].into() - a_string_capital + 10) * half_byte_shift;
        } else {
            upper_half_byte = (script_item[i].into() - zero_string) * half_byte_shift;
        }
        if script_item[i + 1] >= a_string_lower {
            lower_half_byte = script_item[i + 1].into() - a_string_lower + 10;
        } else if script_item[i + 1] >= a_string_capital {
            lower_half_byte = script_item[i + 1].into() - a_string_capital + 10;
        } else {
            lower_half_byte = script_item[i + 1].into() - zero_string;
        }
        let byte = upper_half_byte + lower_half_byte;
        bytecode.append_byte(byte);
        i += 2;
    };
    bytecode
}

pub fn bytecode_to_hex(bytecode: @ByteArray) -> ByteArray {
    let half_byte_shift = 16;
    let zero = '0';
    let a = 'a';
    let mut hex = "0x";
    let mut i = 0;
    let bytecode_len = bytecode.len();
    if bytecode_len == 0 {
        return "0x00";
    }
    while i != bytecode_len {
        let (upper_half_byte, lower_half_byte) = DivRem::div_rem(bytecode[i], half_byte_shift);
        let upper_half: u8 = if upper_half_byte < 10 {
            upper_half_byte + zero
        } else {
            upper_half_byte - 10 + a
        };
        let lower_half: u8 = if lower_half_byte < 10 {
            lower_half_byte + zero
        } else {
            lower_half_byte - 10 + a
        };
        hex.append_byte(upper_half);
        hex.append_byte(lower_half);
        i += 1;
    };
    hex
}

pub fn int_size_in_bytes(u_32: u32) -> u32 {
    let mut value: u32 = u_32;
    let mut size = 0;

    while value != 0 {
        size += 1;
        value /= 256;
    };
    if size == 0 {
        size = 1;
    }
    size
}

// File: ./packages/utils/src/bit_shifts.cairo

/// Performs a bitwise right shift on the given value by a specified number of bits.
pub fn shr<
    T,
    U,
    +Zero<T>,
    +Zero<U>,
    +One<T>,
    +One<U>,
    +Add<T>,
    +Add<U>,
    +Sub<U>,
    +Div<T>,
    +Mul<T>,
    +Div<U>,
    +Rem<U>,
    +Copy<T>,
    +Copy<U>,
    +Drop<T>,
    +Drop<U>,
    +PartialOrd<U>,
    +PartialEq<U>,
    +BitSize<T>,
    +Into<usize, U>
>(
    self: T, shift: U
) -> T {
    if shift > BitSize::<T>::bits().try_into().unwrap() - One::one() {
        return Zero::zero();
    }

    let two = One::one() + One::one();
    self / fast_power(two, shift)
}

/// Performs a bitwise left shift on the given value by a specified number of bits.
pub fn shl<
    T,
    U,
    +Zero<T>,
    +Zero<U>,
    +One<T>,
    +One<U>,
    +Add<T>,
    +Add<U>,
    +Sub<U>,
    +Mul<T>,
    +Div<U>,
    +Rem<U>,
    +Copy<T>,
    +Copy<U>,
    +Drop<T>,
    +Drop<U>,
    +PartialOrd<U>,
    +PartialEq<U>,
    +BitSize<T>,
    +Into<usize, U>
>(
    self: T, shift: U,
) -> T {
    if shift > BitSize::<T>::bits().into() - One::one() {
        return Zero::zero();
    }
    let two = One::one() + One::one();
    self * fast_power(two, shift)
}

// File: ./packages/utils/src/hex.cairo

pub fn int_to_hex(value: u8) -> felt252 {
    let half_byte_shift = 16;
    let byte_shift = 256;

    let (upper_half_value, lower_half_value) = DivRem::div_rem(value, half_byte_shift);
    let upper_half: u8 = if upper_half_value < 10 {
        upper_half_value + '0'
    } else {
        upper_half_value - 10 + 'a'
    };
    let lower_half: u8 = if lower_half_value < 10 {
        lower_half_value + '0'
    } else {
        lower_half_value - 10 + 'a'
    };

    upper_half.into() * byte_shift.into() + lower_half.into()
}

// File: ./packages/utils/src/maths.cairo

// Fast exponentiation using the square-and-multiply algorithm
pub fn fast_power<
    T,
    U,
    +Zero<T>,
    +Zero<U>,
    +One<T>,
    +One<U>,
    +Add<U>,
    +Mul<T>,
    +Rem<U>,
    +Div<U>,
    +Copy<T>,
    +Copy<U>,
    +Drop<T>,
    +Drop<U>,
    +PartialEq<U>,
>(
    base: T, exp: U
) -> T {
    if exp == Zero::zero() {
        return One::one();
    }

    let mut res: T = One::one();
    let mut base: T = base;
    let mut exp: U = exp;

    let two: U = One::one() + One::one();

    loop {
        if exp % two == One::one() {
            res = res * base;
        }
        exp = exp / two;
        if exp == Zero::zero() {
            break res;
        }
        base = base * base;
    }
}

// File: ./packages/utils/src/byte_array.cairo

// Big-endian
pub fn byte_array_to_felt252_be(byte_array: @ByteArray) -> felt252 {
    let byte_shift = 256;
    let mut value = 0;
    let mut i = 0;
    let byte_array_len = byte_array.len();
    while i != byte_array_len {
        value = value * byte_shift + byte_array[i].into();
        i += 1;
    };
    value
}

// Little-endian
pub fn byte_array_to_felt252_le(byte_array: @ByteArray) -> felt252 {
    let byte_shift = 256;
    let mut value = 0;
    let byte_array_len = byte_array.len();
    let mut i = byte_array_len - 1;
    while true {
        value = value * byte_shift + byte_array[i].into();
        if i == 0 {
            break;
        }
        i -= 1;
    };
    value
}

pub fn byte_array_value_at_be(byte_array: @ByteArray, ref offset: usize, len: usize) -> felt252 {
    let byte_shift = 256;
    let mut value = 0;
    let mut i = offset;
    while i != offset + len {
        value = value * byte_shift + byte_array[i].into();
        i += 1;
    };
    offset += len;
    value
}

pub fn byte_array_value_at_le(
    byte_array: @ByteArray, ref offset: usize, len: usize
) -> felt252 { // TODO: Bounds check
    let byte_shift = 256;
    let mut value = 0;
    let mut i = offset + len - 1;
    while true {
        value = value * byte_shift + byte_array[i].into();
        if i == offset {
            break;
        }
        i -= 1;
    };
    offset += len;
    value
}

pub fn sub_byte_array(byte_array: @ByteArray, ref offset: usize, len: usize) -> ByteArray {
    let mut sub_byte_array = "";
    let mut i = offset;
    while i != offset + len {
        sub_byte_array.append_byte(byte_array[i]);
        i += 1;
    };
    offset += len;
    sub_byte_array
}

// TODO: More efficient way to do this
pub fn felt252_to_byte_array(value: felt252) -> ByteArray {
    let byte_shift = 256;
    let mut byte_array = "";
    let mut valueU256: u256 = value.into();
    while valueU256 != 0 {
        let (value_upper, value_lower) = DivRem::div_rem(valueU256, byte_shift);
        byte_array.append_byte(value_lower.try_into().unwrap());
        valueU256 = value_upper;
    };
    byte_array.rev()
}

pub fn u256_from_byte_array_with_offset(arr: @ByteArray, offset: usize, len: usize) -> u256 {
    let total_bytes = arr.len();
    // Return 0 if offset out of bound or len greater than 32 bytes
    if offset >= total_bytes || len > 32 {
        return u256 { high: 0, low: 0 };
    }

    let mut high: u128 = 0;
    let mut low: u128 = 0;
    let mut i: usize = 0;
    let mut high_bytes: usize = 0;

    let available_bytes = total_bytes - offset;
    let read_bytes = if available_bytes < len {
        available_bytes
    } else {
        len
    };

    if read_bytes > 16 {
        high_bytes = read_bytes - 16;
    }
    while i != high_bytes {
        high = high * 256 + arr[i + offset].into();
        i += 1;
    };
    while i != read_bytes {
        low = low * 256 + arr[i + offset].into();
        i += 1;
    };
    u256 { high, low }
}

pub fn byte_array_to_bool(bytes: @ByteArray) -> bool {
    let mut i = 0;
    let mut ret_bool = false;
    while i < bytes.len() {
        if bytes.at(i).unwrap() != 0 {
            // Can be negative zero
            if i == bytes.len() - 1 && bytes.at(i).unwrap() == 0x80 {
                ret_bool = false;
                break;
            }
            ret_bool = true;
            break;
        }
        i += 1;
    };
    ret_bool
}

// File: ./packages/utils/src/hash.cairo

pub fn sha256_byte_array(byte: @ByteArray) -> ByteArray {
    let msg_hash = compute_sha256_byte_array(byte);
    let mut hash_value: ByteArray = "";
    for word in msg_hash.span() {
        hash_value.append_word((*word).into(), 4);
    };

    hash_value
}

pub fn double_sha256(byte: @ByteArray) -> u256 {
    let msg_hash = compute_sha256_byte_array(byte);
    let mut res_bytes = "";
    for word in msg_hash.span() {
        res_bytes.append_word((*word).into(), 4);
    };
    let msg_hash = compute_sha256_byte_array(@res_bytes);
    let mut hash_value: u256 = 0;
    for word in msg_hash
        .span() {
            hash_value *= 0x100000000;
            hash_value = hash_value + (*word).into();
        };

    hash_value
}

// File: ./packages/utils/src/lib.cairo
mod tests {}
// pub mod bit_shifts;
// pub mod byte_array;
// pub mod bytecode;
// pub mod hash;
// pub mod hex;
// pub mod maths;

#[cfg(test)]

// File: ./packages/engine/src/errors.cairo

pub mod Error {
    pub const SCRIPT_FAILED: felt252 = 'Script failed after execute';
    pub const SCRIPT_EMPTY_STACK: felt252 = 'Stack empty after execute';
    pub const SCRIPT_UNBALANCED_CONDITIONAL_STACK: felt252 = 'Unbalanced conditional';
    pub const SCRIPT_TOO_MANY_OPERATIONS: felt252 = 'Too many operations';
    pub const SCRIPT_PUSH_SIZE: felt252 = 'Push value size limit exceeded';
    pub const SCRIPT_NON_CLEAN_STACK: felt252 = 'Non-clean stack after execute';
    pub const SCRIPTNUM_OUT_OF_RANGE: felt252 = 'Scriptnum out of range';
    pub const STACK_OVERFLOW: felt252 = 'Stack overflow';
    pub const STACK_UNDERFLOW: felt252 = 'Stack underflow';
    pub const STACK_OUT_OF_RANGE: felt252 = 'Stack out of range';
    pub const VERIFY_FAILED: felt252 = 'Verify failed';
    pub const OPCODE_RESERVED: felt252 = 'Opcode reserved';
    pub const OPCODE_NOT_IMPLEMENTED: felt252 = 'Opcode not implemented';
    pub const OPCODE_DISABLED: felt252 = 'Opcode is disabled';
    pub const SCRIPT_DISCOURAGE_UPGRADABLE_NOPS: felt252 = 'Upgradable NOPs are discouraged';
    pub const UNSATISFIED_LOCKTIME: felt252 = 'Unsatisfied locktime';
    pub const SCRIPT_STRICT_MULTISIG: felt252 = 'OP_CHECKMULTISIG invalid dummy';
    pub const FINALIZED_TX_CLTV: felt252 = 'Finalized tx in OP_CLTV';
    pub const INVALID_TX_VERSION: felt252 = 'Invalid transaction version';
    pub const SCRIPT_INVALID: felt252 = 'Invalid script data';
    pub const INVALID_COINBASE: felt252 = 'Invalid coinbase transaction';
    pub const SIG_NULLFAIL: felt252 = 'Sig non-zero on failed checksig';
    pub const MINIMAL_DATA: felt252 = 'Opcode represents non-minimal';
    pub const MINIMAL_IF: felt252 = 'If conditional must be 0 or 1';
    pub const DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: felt252 = 'Upgradable witness program';
    pub const WITNESS_PROGRAM_INVALID: felt252 = 'Invalid witness program';
    pub const SCRIPT_TOO_LARGE: felt252 = 'Script is too large';
}

pub fn byte_array_err(err: felt252) -> ByteArray {
    let mut bytes = "";
    let mut word_len = 0;
    let mut byte_shift: u256 = 256;
    while (err.into() / byte_shift) != 0 {
        word_len += 1;
        byte_shift *= 256;
    };
    bytes.append_word(err, word_len);
    bytes
}

// File: ./packages/engine/src/signature/utils.cairo
    // Transaction, OutPoint, TransactionInput, TransactionOutput, EngineTransactionTrait,
    // EngineTransactionInputTrait, EngineTransactionOutputTrait
// };

// Removes `OP_CODESEPARATOR` opcodes from the `script`.
// By removing this opcode, the script becomes suitable for hashing and signature verification.
pub fn remove_opcodeseparator(script: @ByteArray) -> @ByteArray {
    let mut parsed_script: ByteArray = "";
    let mut i: usize = 0;

    // TODO: tokenizer/standardize script parsing
    while i < script.len() {
        let opcode = script[i];
        // TODO: Error handling
        if opcode == Opcode::OP_CODESEPARATOR {
            i += 1;
            continue;
        }
        let data_len = Opcode::data_len(i, script).unwrap();
        let end = i + data_len + 1;
        while i != end {
            parsed_script.append_byte(script[i]);
            i += 1;
        }
    };

    @parsed_script
}

// Prepares a modified copy of the transaction, ready for signature hashing.
//
// This function processes a transaction by modifying its inputs and outputs according to the hash
// type, which determines which parts of the transaction are included in the signature hash.
//
// @param transaction The original transaction to be processed.
// @param index The index of the current input being processed.
// @param signature_script The script that is added to the transaction input during processing.
// @param hash_type The hash type that dictates how the transaction should be modified.
// @return A modified copy of the transaction based on the provided hash type.
pub fn transaction_procedure<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    ref transaction: T, index: u32, signature_script: ByteArray, hash_type: u32
) -> Transaction {
    let hash_type_masked = hash_type & SIG_HASH_MASK;
    let mut transaction_inputs_clone = array![];
    for input in transaction
        .get_transaction_inputs() {
            let new_transaction_input = TransactionInput {
                previous_outpoint: OutPoint {
                    txid: input.get_prevout_txid(), vout: input.get_prevout_vout()
                },
                signature_script: input.get_signature_script().clone(),
                witness: input.get_witness().into(),
                sequence: input.get_sequence()
            };
            transaction_inputs_clone.append(new_transaction_input);
        };
    let mut transaction_outputs_clone = array![];
    for output in transaction
        .get_transaction_outputs() {
            let new_transaction_output = TransactionOutput {
                value: output.get_value(), publickey_script: output.get_publickey_script().clone()
            };
            transaction_outputs_clone.append(new_transaction_output);
        };
    let mut transaction_copy = Transaction {
        version: transaction.get_version(),
        transaction_inputs: transaction_inputs_clone,
        transaction_outputs: transaction_outputs_clone,
        locktime: transaction.get_locktime()
    };
    let mut i: usize = 0;
    let mut transaction_input: Array<TransactionInput> = transaction_copy.transaction_inputs;
    let mut processed_transaction_input: Array<TransactionInput> = ArrayTrait::<
        TransactionInput
    >::new();
    let mut processed_transaction_output: Array<TransactionOutput> = ArrayTrait::<
        TransactionOutput
    >::new();

    while i != transaction_input.len() {
        // TODO: Optimize this
        let mut temp_transaction_input: TransactionInput = transaction_input[i].clone();

        if hash_type_masked == SIG_HASH_SINGLE && i < index {
            processed_transaction_output
                .append(TransactionOutput { value: -1, publickey_script: "", });
        }

        if i == index {
            processed_transaction_input
                .append(
                    TransactionInput {
                        previous_outpoint: temp_transaction_input.previous_outpoint,
                        signature_script: signature_script.clone(),
                        witness: temp_transaction_input.witness.clone(),
                        sequence: temp_transaction_input.sequence
                    }
                );
        } else {
            if hash_type & SIG_HASH_ANYONECANPAY != 0 {
                continue;
            }
            let mut temp_sequence = temp_transaction_input.sequence;
            if hash_type_masked == SIG_HASH_NONE
                || hash_type_masked == SIG_HASH_SINGLE {
                temp_sequence = 0;
            }
            processed_transaction_input
                .append(
                    TransactionInput {
                        previous_outpoint: temp_transaction_input.previous_outpoint,
                        signature_script: "",
                        witness: temp_transaction_input.witness.clone(),
                        sequence: temp_sequence
                    }
                );
        }

        i += 1;
    };

    transaction_copy.transaction_inputs = processed_transaction_input;

    if hash_type_masked == SIG_HASH_NONE {
        transaction_copy.transaction_outputs = ArrayTrait::<TransactionOutput>::new();
    }

    if hash_type_masked == SIG_HASH_SINGLE {
        transaction_copy.transaction_outputs = processed_transaction_output;
    }

    transaction_copy
}

// Checks if the given script is a Pay-to-Witness-Public-Key-Hash (P2WPKH) script.
// A P2WPKH script has a length of 22 bytes and starts with a version byte (`0x00`)
// followed by a 20-byte public key hash.
//
// Thus, a Pay-to-Witness-Public-Key-Hash script is of the form:
// `OP_0 OP_DATA_20 <20-byte public key hash>`
pub fn is_witness_pub_key_hash(script: @ByteArray) -> bool {
    if script.len() == WITNESS_V0_PUB_KEY_HASH_LEN
        && script[0] == Opcode::OP_0
        && script[1] == Opcode::OP_DATA_20 {
        return true;
    }
    false
}

// File: ./packages/engine/src/signature/sighash.cairo
//     Transaction, TransactionTrait, TransactionInput, TransactionOutput, EngineTransactionTrait,
//     EngineTransactionInputTrait, EngineTransactionOutputTrait
// };
//     remove_opcodeseparator, transaction_procedure, is_witness_pub_key_hash
// };

// Calculates the signature hash for specified transaction data and hash type.
pub fn calc_signature_hash<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    sub_script: @ByteArray, hash_type: u32, ref transaction: T, tx_idx: u32
) -> u256 {
    let transaction_outputs_len: usize = transaction.get_transaction_outputs().len();
    // `SIG_HASH_SINGLE` only signs corresponding input/output pair.
    // The original Satoshi client gave a signature hash of 0x01 in cases where the input index
    // was out of bounds. This buggy/dangerous behavior is part of the consensus rules,
    // and would require a hard fork to fix.
    if hash_type & SIG_HASH_MASK == SIG_HASH_SINGLE
        && tx_idx >= transaction_outputs_len {
        return 0x01;
    }

    // Remove any OP_CODESEPARATOR opcodes from the subscript.
    let mut signature_script: @ByteArray = remove_opcodeseparator(sub_script);
    // Create a modified copy of the transaction according to the hash type.
    let transaction_copy: Transaction = transaction_procedure(
        ref transaction, tx_idx, signature_script.clone(), hash_type
    );

    let mut sig_hash_bytes: ByteArray = transaction_copy.serialize_no_witness();
    sig_hash_bytes.append_word_rev(hash_type.into(), 4);

    // Hash and return the serialized transaction data twice using SHA-256.
    double_sha256(@sig_hash_bytes)
}

// Calculates the signature hash for a Segregated Witness (SegWit) transaction and hash type.
pub fn calc_witness_transaction_hash(
    sub_script: @ByteArray, hash_type: u32, ref transaction: Transaction, index: u32, amount: i64
) -> u256 {
    let transaction_outputs_len: usize = transaction.transaction_outputs.len();
    if hash_type & SIG_HASH_MASK == SIG_HASH_SINGLE
        && index > transaction_outputs_len {
        return 0x01;
    }
    let mut sig_hash_bytes: ByteArray = "";
    let mut input_byte: ByteArray = "";
    let mut output_byte: ByteArray = "";
    let mut sequence_byte: ByteArray = "";
    // Serialize the transaction's version number.
    sig_hash_bytes.append_word_rev(transaction.version.into(), 4);
    // Serialize each input in the transaction.
    let input_len: usize = transaction.transaction_inputs.len();
    let mut i: usize = 0;
    while i != input_len {
        let input: @TransactionInput = transaction.transaction_inputs.at(i);

        let input_txid: u256 = *input.previous_outpoint.txid;
        let vout: u32 = *input.previous_outpoint.vout;
        let sequence: u32 = *input.sequence;

        input_byte.append_word(input_txid.high.into(), 16);
        input_byte.append_word(input_txid.low.into(), 16);
        input_byte.append_word_rev(vout.into(), 4);
        sequence_byte.append_word_rev(sequence.into(), 4);

        i += 1;
    };
    // Serialize each output if not using SIG_HASH_SINGLE or SIG_HASH_NONE else serialize only the
    // relevant output.
    if hash_type & SIG_HASH_SINGLE != SIG_HASH_SINGLE
        && hash_type & SIG_HASH_NONE != SIG_HASH_NONE {
        let output_len: usize = transaction.transaction_outputs.len();

        i = 0;
        while i != output_len {
            let output: @TransactionOutput = transaction.transaction_outputs.at(i);
            let value: i64 = *output.value;
            let script: @ByteArray = output.publickey_script;
            let script_len: usize = script.len();

            output_byte.append_word_rev(value.into(), 8);
            output_byte.append_word_rev(script_len.into(), int_size_in_bytes(script_len));
            output_byte.append(script);

            i += 1;
        };
    } else if hash_type & SIG_HASH_SINGLE == SIG_HASH_SINGLE {
        if index < transaction.transaction_outputs.len() {
            let output: @TransactionOutput = transaction.transaction_outputs.at(index);
            let value: i64 = *output.value;
            let script: @ByteArray = output.publickey_script;
            let script_len: usize = script.len();

            output_byte.append_word_rev(value.into(), 8);
            output_byte.append_word_rev(script_len.into(), int_size_in_bytes(script_len));
            output_byte.append(script);
        }
    }
    let mut hash_prevouts: u256 = 0;
    if hash_type & SIG_HASH_ANYONECANPAY != SIG_HASH_ANYONECANPAY {
        hash_prevouts = double_sha256(@input_byte);
    }

    let mut hash_sequence: u256 = 0;
    if hash_type & SIG_HASH_ANYONECANPAY != SIG_HASH_ANYONECANPAY
        && hash_type & SIG_HASH_SINGLE != SIG_HASH_SINGLE
        && hash_type & SIG_HASH_NONE != SIG_HASH_NONE {
        hash_sequence = double_sha256(@sequence_byte);
    }

    let mut hash_outputs: u256 = 0;
    if hash_type & SIG_HASH_ANYONECANPAY == SIG_HASH_ANYONECANPAY
        || hash_type & SIG_HASH_SINGLE == SIG_HASH_SINGLE
        || hash_type & SIG_HASH_ALL == SIG_HASH_ALL {
        hash_sequence = double_sha256(@output_byte);
    }

    // Append the hashed previous outputs and sequences.
    sig_hash_bytes.append_word_rev(hash_prevouts.high.into(), 16);
    sig_hash_bytes.append_word_rev(hash_prevouts.low.into(), 16);
    sig_hash_bytes.append_word_rev(hash_sequence.high.into(), 16);
    sig_hash_bytes.append_word_rev(hash_sequence.low.into(), 16);
    // Add the input being signed.

    let mut input: @TransactionInput = transaction.transaction_inputs.at(i);
    let input_txid: u256 = *input.previous_outpoint.txid;
    let vout: u32 = *input.previous_outpoint.vout;
    let sequence: u32 = *input.sequence;
    sig_hash_bytes.append_word_rev(input_txid.high.into(), 16);
    sig_hash_bytes.append_word_rev(input_txid.low.into(), 16);
    sig_hash_bytes.append_word_rev(vout.into(), 4);
    // Check if the script is a witness pubkey hash and serialize accordingly.
    if is_witness_pub_key_hash(sub_script) {
        sig_hash_bytes.append_byte(0x19);
        sig_hash_bytes.append_byte(0x76);
        sig_hash_bytes.append_byte(0xa9);
        sig_hash_bytes.append_byte(0x14);
        i = 2;
        while i != sub_script.len() {
            sig_hash_bytes.append_byte(sub_script[i]);
            i += 1;
        };
        sig_hash_bytes.append_byte(0x88);
        sig_hash_bytes.append_byte(0xac);
    } else {
        sig_hash_bytes.append(sub_script);
    }
    // Serialize the amount and sequence number.
    sig_hash_bytes.append_word_rev(amount.into(), 8);
    sig_hash_bytes.append_word_rev(sequence.into(), 4);
    // Serialize the hashed outputs.
    sig_hash_bytes.append_word_rev(hash_outputs.high.into(), 16);
    sig_hash_bytes.append_word_rev(hash_outputs.low.into(), 16);
    // Serialize the transaction's locktime and hash type.
    sig_hash_bytes.append_word_rev(transaction.locktime.into(), 4);
    sig_hash_bytes.append_word_rev(hash_type.into(), 4);
    // Hash and return the serialized transaction data twice using SHA-256.
    double_sha256(@sig_hash_bytes)
}

// File: ./packages/engine/src/signature/signature.cairo
//     EngineTransactionTrait, EngineTransactionInputTrait, EngineTransactionOutputTrait
// };

//`BaseSigVerifier` is used to verify ECDSA signatures encoded in DER or BER format (pre-SegWit sig)
#[derive(Drop)]
pub struct BaseSigVerifier {
    // public key as a point on the secp256k1 curve, used to verify the signature
    pub_key: Secp256k1Point,
    // ECDSA signature
    sig: Signature,
    // raw byte array of the signature
    sig_bytes: @ByteArray,
    // raw byte array of the public key
    pk_bytes: @ByteArray,
    // part of the script being verified
    sub_script: ByteArray,
    // specifies how the transaction was hashed for signing
    hash_type: u32,
}

pub trait BaseSigVerifierTrait<T> {
    fn new(
        ref vm: Engine<T>, sig_bytes: @ByteArray, pk_bytes: @ByteArray
    ) -> Result<BaseSigVerifier, felt252>;
    fn verify(ref self: BaseSigVerifier, ref vm: Engine<T>) -> bool;
}

impl BaseSigVerifierImpl<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
> of BaseSigVerifierTrait<T> {
    fn new(
        ref vm: Engine<T>, sig_bytes: @ByteArray, pk_bytes: @ByteArray
    ) -> Result<BaseSigVerifier, felt252> {
        let mut sub_script = vm.sub_script();
        sub_script = remove_signature(sub_script, sig_bytes);
        let (pub_key, sig, hash_type) = parse_base_sig_and_pk(ref vm, pk_bytes, sig_bytes)?;
        Result::Ok(BaseSigVerifier { pub_key, sig, sig_bytes, pk_bytes, sub_script, hash_type })
    }

    // TODO: add signature cache mechanism for optimization
    fn verify(ref self: BaseSigVerifier, ref vm: Engine<T>) -> bool {
        let sig_hash: u256 = calc_signature_hash(
            @self.sub_script, self.hash_type, ref vm.transaction, vm.tx_idx
        );

        is_valid_signature(sig_hash, self.sig.r, self.sig.s, self.pub_key)
    }
}

// Compares a slice of a byte array with the provided signature bytes to check for a match.
//
// @param script The byte array representing the script to be checked.
// @param sig_bytes The byte array containing the signature to compare against.
// @param i The starting index in the script where the comparison begins.
// @param push_data A byte that represents the length of the data segment to compare.
// @return `true` if the slice of the script matches the signature, `false` otherwise.
pub fn compare_data(script: @ByteArray, sig_bytes: @ByteArray, i: u32, push_data: u8) -> bool {
    let mut j: usize = 0;
    let mut len: usize = push_data.into();
    let mut found = true;

    while j != len {
        if script[i + j + 1] != sig_bytes[j] {
            found = false;
            break;
        }
        j += 1;
    };
    found
}

// Check if hash_type obeys scrict encoding requirements.
pub fn check_hash_type_encoding<T, +Drop<T>>(
    ref vm: Engine<T>, mut hash_type: u32
) -> Result<(), felt252> {
    if !vm.has_flag(ScriptFlags::ScriptVerifyStrictEncoding) {
        return Result::Ok(());
    }

    if hash_type > SIG_HASH_ANYONECANPAY {
        hash_type -= SIG_HASH_ANYONECANPAY;
    }

    if hash_type < SIG_HASH_ALL || hash_type > SIG_HASH_SINGLE {
        return Result::Err('invalid hash type');
    }

    return Result::Ok(());
}

// Check if signature obeys strict encoding requirements.
//
// This function checks the provided signature byte array (`sig_bytes`) against several
// encoding rules, including ASN.1 structure, length constraints, and other strict encoding
// requirements. It ensures the signature is properly formatted according to DER (Distinguished
// Encoding Rules) if required, and also checks the "low S" requirement if applicable.
//
// @param vm A reference to the `Engine` that manages the execution context and provides
//           the necessary script verification flags.
// @param sig_bytes The byte array containing the ECDSA signature that needs to be validated.
pub fn check_signature_encoding<T, +Drop<T>>(
    ref vm: Engine<T>, sig_bytes: @ByteArray
) -> Result<(), felt252> {
    let strict_encoding = vm.has_flag(ScriptFlags::ScriptVerifyStrictEncoding)
        || vm.has_flag(ScriptFlags::ScriptVerifyDERSignatures);
    let low_s = vm.has_flag(ScriptFlags::ScriptVerifyLowS);

    // ASN.1 identifiers for sequence and integer types.*
    let asn1_sequence_id: u8 = 0x30;
    let asn1_integer_id: u8 = 0x02;
    // Offsets used to parse the signature byte array.
    let sequence_offset: usize = 0;
    let data_len_offset: usize = 1;
    let data_offset: usize = 2;
    let r_type_offset: usize = 2;
    let r_len_offset: usize = 3;
    let r_offset: usize = 4;
    // Length of the signature byte array.
    let sig_bytes_len: usize = sig_bytes.len();
    // Check if the signature is empty.
    if sig_bytes_len == 0 {
        return Result::Err('invalid sig fmt: empty sig');
    }
    // Calculate the actual length of the signature, excluding the hash type.
    let sig_len = sig_bytes_len - HASH_TYPE_LEN;
    // Check if the signature is too short.
    if sig_len < MIN_SIG_LEN {
        return Result::Err('invalid sig fmt: too short');
    }
    // Check if the signature is too long.
    if sig_len > MAX_SIG_LEN {
        return Result::Err('invalid sig fmt: too long');
    }
    // Ensure the signature starts with the correct ASN.1 sequence identifier.
    if sig_bytes[sequence_offset] != asn1_sequence_id {
        return Result::Err('invalid sig fmt: wrong type');
    }
    // Verify that the length field matches the expected length.
    if sig_bytes[data_len_offset] != (sig_len - data_offset).try_into().unwrap() {
        return Result::Err('invalid sig fmt: bad length');
    }
    // Determine the length of the `R` value in the signature.
    let r_len: usize = sig_bytes[r_len_offset].into();
    let s_type_offset = r_offset + r_len;
    let s_len_offset = s_type_offset + 1;
    // Check if the `S` type offset exceeds the length of the signature.
    if s_type_offset > sig_len {
        return Result::Err('invalid sig fmt: S type missing');
    }
    // Check if the `S` length offset exceeds the length of the signature.
    if s_len_offset > sig_len {
        return Result::Err('invalid sig fmt: miss S length');
    }
    // Calculate the offset and length of the `S` value.
    let s_offset = s_len_offset + 1;
    let s_len: usize = sig_bytes[s_len_offset].into();
    // Ensure the `R` value is correctly identified as an ASN.1 integer.
    if sig_bytes[r_type_offset] != asn1_integer_id {
        return Result::Err('invalid sig fmt:R ASN.1');
    }
    // Validate the length of the `R` value.
    if r_len <= 0 || r_len > sig_len - r_offset - 3 {
        return Result::Err('invalid sig fmt:R length');
    }
    // If strict encoding is enforced, check for negative or excessively padded `R` values.
    if strict_encoding {
        if sig_bytes[r_offset] & 0x80 != 0 {
            return Result::Err('invalid sig fmt: negative R');
        }

        if r_len > 1 && sig_bytes[r_offset] == 0 && sig_bytes[r_offset + 1] & 0x80 == 0 {
            return Result::Err('invalid sig fmt: R padding');
        }
    }
    // Ensure the `S` value is correctly identified as an ASN.1 integer.
    if sig_bytes[s_type_offset] != asn1_integer_id {
        return Result::Err('invalid sig fmt:S ASN.1');
    }
    // Validate the length of the `S` value.
    if s_len <= 0 || s_len > sig_len - s_offset {
        return Result::Err('invalid sig fmt:S length');
    }
    // If strict encoding is enforced, check for negative or excessively padded `S` values.
    if strict_encoding {
        if sig_bytes[s_offset] & 0x80 != 0 {
            return Result::Err('invalid sig fmt: negative S');
        }

        if s_len > 1 && sig_bytes[s_offset] == 0 && sig_bytes[s_offset + 1] & 0x80 == 0 {
            return Result::Err('invalid sig fmt: S padding');
        }
    }
    // If the "low S" rule is enforced, check that the `S` value is below the threshold.
    if low_s {
        let s_value = u256_from_byte_array_with_offset(sig_bytes, s_offset, 32);
        let mut half_order = Secp256Trait::<Secp256k1Point>::get_curve_size();

        let (half_order_high_upper, half_order_high_lower) = DivRem::div_rem(half_order.high, 2);
        let carry = half_order_high_lower;
        half_order.low = (half_order.low / 2) + (carry * (MAX_U128 / 2 + 1));
        half_order.high = half_order_high_upper;

        if s_value > half_order {
            return Result::Err('sig not canonical high S value');
        }
    }

    return Result::Ok(());
}

// Checks if a public key is compressed based on its byte array representation.
// ie: 33 bytes, starts with 0x02 or 0x03, indicating ECP parity of the Y coord.
pub fn is_compressed_pub_key(pk_bytes: @ByteArray) -> bool {
    if pk_bytes.len() == 33 && (pk_bytes[0] == 0x02 || pk_bytes[0] == 0x03) {
        return true;
    }
    return false;
}

fn is_supported_pub_key_type(pk_bytes: @ByteArray) -> bool {
    if is_compressed_pub_key(pk_bytes) {
        return true;
    }

    // Uncompressed pub key
    if pk_bytes.len() == 65 && pk_bytes[0] == 0x04 {
        return true;
    }

    return false;
}

// Checks if a public key adheres to specific encoding rules based on the engine flags.
pub fn check_pub_key_encoding<T, +Drop<T>>(
    ref vm: Engine<T>, pk_bytes: @ByteArray
) -> Result<(), felt252> {
    // TODO check compressed pubkey post segwit
    // if vm.has_flag(ScriptFlags::ScriptVerifyWitnessPubKeyType) &&
    // vm.is_witness_version_active(BASE_SEGWIT_WITNESS_VERSION) && !is_compressed_pub_key(pk_bytes)
    // {
    // return Result::Err('only compressed keys are accepted post-segwit');
    // }

    if !vm.has_flag(ScriptFlags::ScriptVerifyStrictEncoding) {
        return Result::Ok(());
    }

    if !is_supported_pub_key_type(pk_bytes) {
        return Result::Err('unsupported public key type');
    }

    return Result::Ok(());
}

// Parses a public key byte array into a `Secp256k1Point` on the secp256k1 elliptic curve.
//
// This function processes the provided public key byte array (`pk_bytes`) and converts it into a
// `Secp256k1Point` object, which represents the public key as a point on the secp256k1 elliptic
// curve. Supports both compressed and uncompressed public keys.
//
// @param pk_bytes The byte array representing the public key to be parsed.
// @return A `Secp256k1Point` representing the public key on the secp256k1 elliptic curve.
pub fn parse_pub_key(pk_bytes: @ByteArray) -> Secp256k1Point {
    let mut pk_bytes_uncompressed = pk_bytes.clone();

    if is_compressed_pub_key(pk_bytes) {
        // Extract X coordinate and determine parity from prefix byte.
        let mut parity: bool = false;
        let pub_key: u256 = u256_from_byte_array_with_offset(pk_bytes, 1, 32);

        if pk_bytes[0] == 0x03 {
            parity = true;
        }
        return Secp256Trait::<Secp256k1Point>::secp256_ec_get_point_from_x_syscall(pub_key, parity)
            .unwrap_syscall()
            .expect('Secp256k1Point: Invalid point.');
    } else {
        // Extract X coordinate and determine parity from last byte.
        let pub_key: u256 = u256_from_byte_array_with_offset(@pk_bytes_uncompressed, 1, 32);
        let parity = !(pk_bytes_uncompressed[64] & 1 == 0);

        return Secp256Trait::<Secp256k1Point>::secp256_ec_get_point_from_x_syscall(pub_key, parity)
            .unwrap_syscall()
            .expect('Secp256k1Point: Invalid point.');
    }
}

// Parses a DER-encoded ECDSA signature byte array into a `Signature` struct.
//
// This function extracts the `r` and `s` values from a DER-encoded ECDSA signature (`sig_bytes`).
// The function performs various checks to ensure the integrity and validity of the signature.
pub fn parse_signature(sig_bytes: @ByteArray) -> Result<Signature, felt252> {
    let mut sig_len: usize = sig_bytes.len() - HASH_TYPE_LEN;
    let mut r_len: usize = sig_bytes[3].into();
    let mut s_len: usize = sig_bytes[r_len + 5].into();
    let mut r_offset = 4;
    let mut s_offset = 6 + r_len;
    let order: u256 = Secp256Trait::<Secp256k1Point>::get_curve_size();

    let mut i = 0;

    //Strip leading zero
    while s_len != 0 && sig_bytes[i + r_len + 6] == 0x00 {
        sig_len -= 1;
        s_len -= 1;
        s_offset += 1;
        i += 1;
    };

    let s_sig: u256 = u256_from_byte_array_with_offset(sig_bytes, s_offset, s_len);

    i = 0;

    while r_len != 0 && sig_bytes[i + 4] == 0x00 {
        sig_len -= 1;
        r_len -= 1;
        r_offset += 1;
        i += 1;
    };

    let r_sig: u256 = u256_from_byte_array_with_offset(sig_bytes, r_offset, r_len);

    if r_len > 32 {
        return Result::Err('invalid sig: R > 256 bits');
    }
    if r_sig >= order {
        return Result::Err('invalid sig: R >= group order');
    }
    if r_sig == 0 {
        return Result::Err('invalid sig: R is zero');
    }
    if s_len > 32 {
        return Result::Err('invalid sig: S > 256 bits');
    }
    if s_sig >= order {
        return Result::Err('invalid sig: S >= group order');
    }
    if s_sig == 0 {
        return Result::Err('invalid sig: S is zero');
    }
    if sig_len != r_len + s_len + 6 {
        return Result::Err('invalid sig: bad final length');
    }
    return Result::Ok(Signature { r: r_sig, s: s_sig, y_parity: false, });
}

// Parses the public key and signature byte arrays based on consensus rules.
// Returning a tuple containing the parsed public key, signature, and hash type.
pub fn parse_base_sig_and_pk<T, +Drop<T>>(
    ref vm: Engine<T>, pk_bytes: @ByteArray, sig_bytes: @ByteArray
) -> Result<(Secp256k1Point, Signature, u32), felt252> {
    if sig_bytes.len() == 0 {
        return Result::Err('empty signature');
    }
    // TODO: strct encoding
    let hash_type_offset: usize = sig_bytes.len() - 1;
    let hash_type: u32 = sig_bytes[hash_type_offset].into();

    check_hash_type_encoding(ref vm, hash_type)?;
    check_signature_encoding(ref vm, sig_bytes)?;
    check_pub_key_encoding(ref vm, pk_bytes)?;

    let pub_key = parse_pub_key(pk_bytes);
    let sig = parse_signature(sig_bytes)?;

    Result::Ok((pub_key, sig, hash_type))
}

// Removes the ECDSA signature from a given script.
pub fn remove_signature(script: ByteArray, sig_bytes: @ByteArray) -> ByteArray {
    if script.len() == 0 || sig_bytes.len() == 0 {
        return script;
    }

    let mut processed_script: ByteArray = "";
    let mut i: usize = 0;

    while i < script.len() {
        let push_data: u8 = script[i];
        if push_data >= 8 && push_data <= 72 {
            let mut len: usize = push_data.into();
            let mut found: bool = false;

            if len == sig_bytes.len() {
                found = compare_data(@script, sig_bytes, i, push_data);
            }

            if i + len <= script.len() {
                i += len;
            } else {
                i += 1;
            }
            if found {
                i += 1;
                continue;
            }
            processed_script.append_byte(push_data);
            while len != 0 && i - len < script.len() {
                processed_script.append_byte(script[i - len + 1]);
                len -= 1;
            };
        } else {
            processed_script.append_byte(push_data);
        }
        i += 1;
    };

    processed_script
}

// File: ./packages/engine/src/signature/constants.cairo

// Represents the default signature hash type, often treated as `SIG_HASH_ALL`, ensuring that all
// inputs and outputs of the transaction are signed to provide complete protection against
// unauthorized modifications.
pub const SIG_HASH_DEFAULT: u32 = 0x0;
//Sign all inputs and outputs of the transaction, making it the most secure and commonly used hash
//type that ensures the entire transaction is covered by the signature, preventing any changes after
//signing.
pub const SIG_HASH_ALL: u32 = 0x1;
//Sign all inputs but none of the outputs, allowing outputs to be modified after signing, which is
//useful in scenarios requiring flexible transaction outputs without invalidating the signature.
pub const SIG_HASH_NONE: u32 = 0x2;
//Sign only the input being signed and its corresponding output, enabling partial transaction
//signatures where each input is responsible for its associated output, useful for independent input
//signing.
pub const SIG_HASH_SINGLE: u32 = 0x3;
//Allows signing of only one input, leaving others unsigned, often used with other hash types for
//creating transactions that can be extended with additional inputs by different parties without
//invalidating the signature.
pub const SIG_HASH_ANYONECANPAY: u32 = 0x80;
//Mask to isolate the base signature hash type from a combined hash type that might include
//additional flags like `SIG_HASH_ANYONECANPAY`, ensuring accurate identification and processing of
//the core hash type.
pub const SIG_HASH_MASK: u32 = 0x1f;
//Base version number for Segregated Witness (SegWit) transactions, representing the initial version
//of SegWit that enables more efficient transaction validation by separating signature data from the
//main transaction body.
pub const BASE_SEGWIT_WITNESS_VERSION: u32 = 0x0;
//Minimum valid length for a DER-encoded ECDSA signature, ensuring that signatures meet the minimum
//required length for validity, as shorter signatures could indicate an incomplete or malformed
//signature.
pub const MIN_SIG_LEN: usize = 8;
//Maximum valid length for a DER-encoded ECDSA signature, ensuring that signatures do not exceed the
//expected length, which could indicate corruption or the inclusion of invalid data within the
//signature.
pub const MAX_SIG_LEN: usize = 72;
//Length of the byte that specifies the signature hash type in a signature, determining how the
//transaction was hashed before signing and influencing which parts of the transaction are covered
//by the signature.
pub const HASH_TYPE_LEN: usize = 1;
//Length of the witness program for P2WPKH (Pay-to-Witness-Public-Key-Hash) scripts in SegWit,
//including the version byte and the public key hash, ensuring correct data formatting and inclusion
//in SegWit transactions.
pub const WITNESS_V0_PUB_KEY_HASH_LEN: usize = 22;

pub const MAX_U128: u128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
pub const MAX_U32: u32 = 0xFFFFFFFF;

// File: ./packages/engine/src/tests/test_p2pk.cairo

// https://learnmeabitcoin.com/explorer/tx/3db8816c460f674e47f0e5799656721a249acdd53cd43a530c83384577485947
#[test]
fn test_compressed_pubkey() {
    let prevout_pk_script = "0x76a9147fbff43f08b409a03febae114cf0885c37ffd7c488ac";
    let prev_out = UTXO {
        amount: 3000, pubkey_script: hex_to_bytecode(@prevout_pk_script), block_height: 606376
    };
    let raw_transaction_hex =
        "0x010000000135655162f2df3af5e5f12b5b4b545e9069ed61897974622888b9c47e0f55e105000000006b483045022100bdd3796f6a6bb7f8ca42a70438a3150501f9ec760195b4d3314b1b4b21aac29402202f8479c9384a737bb323cd8600d9e3c5a379334a55acf7c3f4a4ca1eaaabe97e012103e49d61c45a729c427038b967df38459a2579a2c37057cf6a2efb2c3048f676aaffffffff018c0a000000000000232103203b768951584fe9af6d9d9e6ff26a5f76e453212f19ba163774182ab8057f3eac00000000";
    let raw_transaction = hex_to_bytecode(@raw_transaction_hex);
    let transaction = TransactionTrait::deserialize(raw_transaction);
    let utxo_hints = array![prev_out];

    let res = validate_transaction(transaction, 0, utxo_hints);
    assert!(res.is_ok(), "Transaction validation failed");
}

// https://learnmeabitcoin.com/explorer/tx/a16f3ce4dd5deb92d98ef5cf8afeaf0775ebca408f708b2146c4fb42b41e14be
#[test]
fn test_block_181_tx_mainnet() {
    let prevout_pk_script =
        "0x410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac";
    let prev_out = UTXO {
        amount: 3000000000, pubkey_script: hex_to_bytecode(@prevout_pk_script), block_height: 170
    };
    let raw_transaction_hex =
        "0x0100000001169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f40100000048473044022027542a94d6646c51240f23a76d33088d3dd8815b25e9ea18cac67d1171a3212e02203baf203c6e7b80ebd3e588628466ea28be572fe1aaa3f30947da4763dd3b3d2b01ffffffff0200ca9a3b00000000434104b5abd412d4341b45056d3e376cd446eca43fa871b51961330deebd84423e740daa520690e1d9e074654c59ff87b408db903649623e86f1ca5412786f61ade2bfac005ed0b20000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";
    let raw_transaction = hex_to_bytecode(@raw_transaction_hex);
    let transaction = TransactionTrait::deserialize(raw_transaction);
    let utxo_hints = array![prev_out];

    let res = validate_transaction(transaction, 0, utxo_hints);
    assert!(res.is_ok(), "Transaction validation failed");
}

// https://learnmeabitcoin.com/explorer/tx/591e91f809d716912ca1d4a9295e70c3e78bab077683f79350f101da64588073
#[test]
fn test_block_182_tx_mainnet() {
    let prevout_pk_script =
        "0x410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac";
    let prev_out = UTXO {
        amount: 3000000000, pubkey_script: hex_to_bytecode(@prevout_pk_script), block_height: 170
    };
    let raw_transaction_hex =
        "0x0100000001be141eb442fbc446218b708f40caeb7507affe8acff58ed992eb5ddde43c6fa1010000004847304402201f27e51caeb9a0988a1e50799ff0af94a3902403c3ad4068b063e7b4d1b0a76702206713f69bd344058b0dee55a9798759092d0916dbbc3e592fee43060005ddc17401ffffffff0200e1f5050000000043410401518fa1d1e1e3e162852d68d9be1c0abad5e3d6297ec95f1f91b909dc1afe616d6876f92918451ca387c4387609ae1a895007096195a824baf9c38ea98c09c3ac007ddaac0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";
    let raw_transaction = hex_to_bytecode(@raw_transaction_hex);
    let transaction = TransactionTrait::deserialize(raw_transaction);
    let utxo_hints = array![prev_out];

    let res = validate_transaction(transaction, 0, utxo_hints);
    assert!(res.is_ok(), "Transaction validation failed");
}

// https://learnmeabitcoin.com/explorer/tx/a3b0e9e7cddbbe78270fa4182a7675ff00b92872d8df7d14265a2b1e379a9d33
#[test]
fn test_block_496_tx_mainnet() {
    let prevout_pk_script =
        "0x41044ca7baf6d8b658abd04223909d82f1764740bdc9317255f54e4910f888bd82950e33236798517591e4c2181f69b5eaa2fa1f21866780a0cc5d8396a04fd36310ac";
    let prevout_pk_script_2 =
        "0x4104fe1b9ccf732e1f6b760c5ed3152388eeeadd4a073e621f741eb157e6a62e3547c8e939abbd6a513bf3a1fbe28f9ea85a4e64c526702435d726f7ff14da40bae4ac";
    let prevout_pk_script_3 =
        "0x4104bed827d37474beffb37efe533701ac1f7c600957a4487be8b371346f016826ee6f57ba30d88a472a0e4ecd2f07599a795f1f01de78d791b382e65ee1c58b4508ac";
    let prev_out = UTXO {
        amount: 5000000000, pubkey_script: hex_to_bytecode(@prevout_pk_script), block_height: 360
    };
    let prev_out2 = UTXO {
        amount: 1000000000, pubkey_script: hex_to_bytecode(@prevout_pk_script_2), block_height: 187
    };
    let prev_out3 = UTXO {
        amount: 100000000, pubkey_script: hex_to_bytecode(@prevout_pk_script_3), block_height: 248
    };

    let raw_transaction_hex =
        "0x010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000";
    let raw_transaction = hex_to_bytecode(@raw_transaction_hex);
    let transaction = TransactionTrait::deserialize(raw_transaction);
    let utxo_hints = array![prev_out, prev_out2, prev_out3];

    let res = validate_transaction(transaction, 0, utxo_hints);
    assert!(res.is_ok(), "Transaction validation failed");
}

// File: ./packages/engine/src/tests/test_scriptnum.cairo

#[test]
fn test_scriptnum_wrap_unwrap() {
    let mut int = 0;
    let mut returned_int = ScriptNum::unwrap(ScriptNum::wrap(int));
    assert!(int == returned_int, "Wrap/unwrap 0 not equal");

    int = 1;
    returned_int = ScriptNum::unwrap(ScriptNum::wrap(int));
    assert!(int == returned_int, "Wrap/unwrap 1 not equal");

    int = -1;
    returned_int = ScriptNum::unwrap(ScriptNum::wrap(int));
    assert!(int == returned_int, "Wrap/unwrap -1 not equal");

    int = 32767;
    returned_int = ScriptNum::unwrap(ScriptNum::wrap(int));
    assert!(int == returned_int, "Wrap/unwrap 32767 not equal");

    int = -452354;
    returned_int = ScriptNum::unwrap(ScriptNum::wrap(int));
    assert!(int == returned_int, "Wrap/unwrap 32767 not equal");

    int = 2147483647; // 0x7FFFFFFF
    returned_int = ScriptNum::unwrap(ScriptNum::wrap(int));
    assert!(int == returned_int, "Wrap/unwrap 2147483647 not equal");

    int = -2147483647; // 0x80000001
    returned_int = ScriptNum::unwrap(ScriptNum::wrap(int));
    assert!(int == returned_int, "Wrap/unwrap -2147483648 not equal");
}

#[test]
fn test_scriptnum_bytes_wrap() {
    let mut bytes: ByteArray = Default::default();
    bytes.append_byte(42); // 0x2A
    let mut returned_int = ScriptNum::unwrap(bytes);
    assert!(returned_int == 42, "Unwrap 0x2A not equal to 42");

    let mut bytes: ByteArray = "";
    returned_int = ScriptNum::unwrap(bytes);
    assert!(returned_int == 0, "Unwrap empty bytes not equal to 0");

    let mut bytes: ByteArray = Default::default();
    bytes.append_byte(129); // 0x81
    bytes.append_byte(128); // 0x80
    returned_int = ScriptNum::unwrap(bytes);
    assert!(returned_int == -129, "Unwrap 0x8180 not equal to -129");

    let mut bytes: ByteArray = Default::default();
    bytes.append_byte(255); // 0xFF
    bytes.append_byte(127); // 0x7F
    returned_int = ScriptNum::unwrap(bytes);
    assert!(returned_int == 32767, "0xFF7F not equal to 32767");

    let mut bytes: ByteArray = Default::default();
    bytes.append_byte(0); // 0x00
    bytes.append_byte(128); // 0x80
    bytes.append_byte(128); // 0x80
    returned_int = ScriptNum::unwrap(bytes);
    assert!(returned_int == -32768, "0x008080 not equal to -32768");
}

#[test]
#[should_panic]
fn test_scriptnum_too_big_unwrap_panic() {
    let mut bytes: ByteArray = Default::default();
    bytes.append_word_rev(2147483647 + 1, 5);
    ScriptNum::unwrap(bytes);
}

#[test]
#[should_panic]
fn test_scriptnum_too_small_unwrap_panic() {
    let mut bytes: ByteArray = Default::default();
    bytes.append_word_rev(-2147483647 - 1, 5);
    ScriptNum::unwrap(bytes);
}

// File: ./packages/engine/src/tests/test_transactions.cairo

// TODO: txid byte order reverse

#[test]
fn test_deserialize_transaction() {
    // Block 150007 transaction 7
    // tx: d823f0d96563ec214a2342c8637a5775038ca05e56ca069631c96f400ca2f9f7
    let raw_transaction_hex =
        "0x010000000291056d7ab3e99f9506f248783e0801c9039082d7d876dd45a8ab1f0a166226e2000000008c493046022100a3deff7d28eca94e018cfafcf4e705cc6bb56ce1dab83a6377e6e97d28d305d90221008cfc8d40bb8e336f5210a4197760f6b9650ae6ec4682cc1626841d9c87d1b0f20141049305a94c5b8e71d8be2a2d7188d74cb38affc9dc83ab77cc2fedf7c03a82a56175b9c335ce4546a943a2215a9c04757f08c2cc97f731a208ea767119050e0b97ffffffff465345e66a84047bf58a3787456d8023c38e04734c72d7f7039b9220ac503b6e000000008a47304402202ff5fe06ff3ee680e069cd28ff3ed9a60050ba52ed811a739a29b81e3667074602203c0d1b63d0c495ee1b63886e42c2db0c4cb041ce0c957ad7febe0fbcd23498ee014104cc2cb6eb11b7b504e1aa2826cf8ce7568bc757d7f58ab1eaa0b5e6945ccdcc5b111c0c1163a28037b89501e0b83e3fdceb22a2fd80533e5211acac060b17b2a4ffffffff0243190600000000001976a914a2baed4cdeda71053537312ee32cf0ab9f22cf1888acc0451b11000000001976a914f3e0b1ca6d94a95e1f3683ea6f3d2b563ad475e688ac00000000";
    let raw_transaction = hex_to_bytecode(@raw_transaction_hex);
    let transaction = TransactionTrait::deserialize(raw_transaction);

    assert_eq!(transaction.version, 1, "Version is not correct");
    assert_eq!(transaction.transaction_inputs.len(), 2, "Transaction inputs length is not correct");
    let input0 = transaction.transaction_inputs[0];
    let expected_txid_hex = "0x91056d7ab3e99f9506f248783e0801c9039082d7d876dd45a8ab1f0a166226e2";
    let expected_txid = hex_to_bytecode(@expected_txid_hex);
    let expected_sig_script_hex =
        "0x493046022100a3deff7d28eca94e018cfafcf4e705cc6bb56ce1dab83a6377e6e97d28d305d90221008cfc8d40bb8e336f5210a4197760f6b9650ae6ec4682cc1626841d9c87d1b0f20141049305a94c5b8e71d8be2a2d7188d74cb38affc9dc83ab77cc2fedf7c03a82a56175b9c335ce4546a943a2215a9c04757f08c2cc97f731a208ea767119050e0b97";
    let expected_sig_script = hex_to_bytecode(@expected_sig_script_hex);
    assert_eq!(
        input0.previous_outpoint.txid,
        @u256_from_byte_array_with_offset(@expected_txid, 0, 32),
        "Outpoint txid on input 1 is not correct"
    );
    assert_eq!(input0.previous_outpoint.vout, @0, "Outpoint vout on input 1 is not correct");
    assert_eq!(
        input0.signature_script, @expected_sig_script, "Script sig on input 1 is not correct"
    );
    assert_eq!(input0.sequence, @0xFFFFFFFF, "Sequence on input 1 is not correct");

    let input1 = transaction.transaction_inputs[1];
    let expected_txid_hex = "0x465345e66a84047bf58a3787456d8023c38e04734c72d7f7039b9220ac503b6e";
    let expected_txid = hex_to_bytecode(@expected_txid_hex);
    let expected_sig_script_hex =
        "0x47304402202ff5fe06ff3ee680e069cd28ff3ed9a60050ba52ed811a739a29b81e3667074602203c0d1b63d0c495ee1b63886e42c2db0c4cb041ce0c957ad7febe0fbcd23498ee014104cc2cb6eb11b7b504e1aa2826cf8ce7568bc757d7f58ab1eaa0b5e6945ccdcc5b111c0c1163a28037b89501e0b83e3fdceb22a2fd80533e5211acac060b17b2a4";
    let expected_sig_script = hex_to_bytecode(@expected_sig_script_hex);
    assert_eq!(
        input1.previous_outpoint.txid,
        @u256_from_byte_array_with_offset(@expected_txid, 0, 32),
        "Outpoint txid on input 2 is not correct"
    );
    assert_eq!(input1.previous_outpoint.vout, @0, "Outpoint vout on input 2 is not correct");
    assert_eq!(
        input1.signature_script, @expected_sig_script, "Script sig on input 2 is not correct"
    );
    assert_eq!(input1.sequence, @0xFFFFFFFF, "Sequence on input 2 is not correct");

    let output0 = transaction.transaction_outputs[0];
    assert_eq!(output0.value, @399683, "Output 1 value is not correct");
    let expected_pk_script_hex = "0x76a914a2baed4cdeda71053537312ee32cf0ab9f22cf1888ac";
    let expected_pk_script = hex_to_bytecode(@expected_pk_script_hex);
    assert_eq!(output0.publickey_script, @expected_pk_script, "Output 1 pk_script is not correct");

    let output1 = transaction.transaction_outputs[1];
    assert_eq!(output1.value, @287000000, "Output 2 value is not correct");
    let expected_pk_script_hex = "0x76a914f3e0b1ca6d94a95e1f3683ea6f3d2b563ad475e688ac";
    let expected_pk_script = hex_to_bytecode(@expected_pk_script_hex);
    assert_eq!(output1.publickey_script, @expected_pk_script, "Output 2 pk_script is not correct");

    assert_eq!(transaction.locktime, 0, "Lock time is not correct");
}


#[test]
fn test_deserialize_first_p2pkh_transaction() {
    // First ever P2PKH transaction
    // tx: 6f7cf9580f1c2dfb3c4d5d043cdbb128c640e3f20161245aa7372e9666168516
    let raw_transaction_hex =
        "0x0100000002f60b5e96f09422354ab150b0e506c4bffedaf20216d30059cc5a3061b4c83dff000000004a493046022100e26d9ff76a07d68369e5782be3f8532d25ecc8add58ee256da6c550b52e8006b022100b4431f5a9a4dcb51cbdcaae935218c0ae4cfc8aa903fe4e5bac4c208290b7d5d01fffffffff7272ef43189f5553c2baea50f59cde99b3220fd518884d932016d055895b62d000000004a493046022100a2ab7cdc5b67aca032899ea1b262f6e8181060f5a34ee667a82dac9c7b7db4c3022100911bc945c4b435df8227466433e56899fbb65833e4853683ecaa12ee840d16bf01ffffffff0100e40b54020000001976a91412ab8dc588ca9d5787dde7eb29569da63c3a238c88ac00000000";
    let raw_transaction = hex_to_bytecode(@raw_transaction_hex);
    let transaction = TransactionTrait::deserialize(raw_transaction);

    assert_eq!(transaction.version, 1, "Version is not correct");
    assert_eq!(transaction.transaction_inputs.len(), 2, "Transaction inputs length is not correct");
    let input0 = transaction.transaction_inputs[0];
    let expected_txid_hex = "0xf60b5e96f09422354ab150b0e506c4bffedaf20216d30059cc5a3061b4c83dff";
    let expected_txid = hex_to_bytecode(@expected_txid_hex);
    let expected_sig_script_hex =
        "0x493046022100e26d9ff76a07d68369e5782be3f8532d25ecc8add58ee256da6c550b52e8006b022100b4431f5a9a4dcb51cbdcaae935218c0ae4cfc8aa903fe4e5bac4c208290b7d5d01";
    let expected_sig_script = hex_to_bytecode(@expected_sig_script_hex);
    assert_eq!(
        input0.previous_outpoint.txid,
        @u256_from_byte_array_with_offset(@expected_txid, 0, 32),
        "Outpoint txid on input 1 is not correct"
    );
    assert_eq!(input0.previous_outpoint.vout, @0, "Outpoint vout on input 1 is not correct");
    assert_eq!(
        input0.signature_script, @expected_sig_script, "Script sig on input 1 is not correct"
    );
    assert_eq!(input0.sequence, @0xFFFFFFFF, "Sequence on input 1 is not correct");

    let input1 = transaction.transaction_inputs[1];
    let expected_txid_hex = "0xf7272ef43189f5553c2baea50f59cde99b3220fd518884d932016d055895b62d";
    let expected_txid = hex_to_bytecode(@expected_txid_hex);
    let expected_sig_script_hex =
        "0x493046022100a2ab7cdc5b67aca032899ea1b262f6e8181060f5a34ee667a82dac9c7b7db4c3022100911bc945c4b435df8227466433e56899fbb65833e4853683ecaa12ee840d16bf01";
    let expected_sig_script = hex_to_bytecode(@expected_sig_script_hex);
    assert_eq!(
        input1.previous_outpoint.txid,
        @u256_from_byte_array_with_offset(@expected_txid, 0, 32),
        "Outpoint txid on input 2 is not correct"
    );
    assert_eq!(input1.previous_outpoint.vout, @0, "Outpoint vout on input 2 is not correct");
    assert_eq!(
        input1.signature_script, @expected_sig_script, "Script sig on input 2 is not correct"
    );
    assert_eq!(input1.sequence, @0xFFFFFFFF, "Sequence on input 2 is not correct");

    let output0 = transaction.transaction_outputs[0];
    assert_eq!(output0.value, @10000000000, "Output 1 value is not correct");
    let expected_pk_script_hex = "0x76a91412ab8dc588ca9d5787dde7eb29569da63c3a238c88ac";
    let expected_pk_script = hex_to_bytecode(@expected_pk_script_hex);
    assert_eq!(output0.publickey_script, @expected_pk_script, "Output 1 pk_script is not correct");

    assert_eq!(transaction.locktime, 0, "Lock time is not correct");
}

#[test]
fn test_deserialize_coinbase_transaction() { // TODO
}

#[test]
fn test_validate_transaction() {
    // First ever transaction from Satoshi -> Hal Finney
    // tx: f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
    let raw_transaction_hex =
        "0x0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";
    let raw_transaction = hex_to_bytecode(@raw_transaction_hex);
    let transaction = TransactionTrait::deserialize(raw_transaction);

    // Setup UTXO hints ( previous valid outputs used to execute this transaction )
    let prevout_pk_script =
        "0x410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac";
    let prev_out = UTXO {
        amount: 5000000000, pubkey_script: hex_to_bytecode(@prevout_pk_script), block_height: 9
    };
    let utxo_hints = array![prev_out];

    // Run Shinigami and validate the transaction execution
    let res = validate_transaction(transaction, 0, utxo_hints);
    assert!(res.is_ok(), "Transaction validation failed");
}

// File: ./packages/engine/src/tests/test_coinbase.cairo

#[test]
fn test_block_subsidy_calculation() {
    assert(TransactionTrait::calculate_block_subsidy(0) == 5000000000, 'Incorrect genesis subsidy');
    assert(
        TransactionTrait::calculate_block_subsidy(210000) == 2500000000, 'Incorrect halving subsidy'
    );
    assert(
        TransactionTrait::calculate_block_subsidy(420000) == 1250000000,
        'Incorrect 2nd halving subsidy'
    );
    assert(
        TransactionTrait::calculate_block_subsidy(13440000) == 0, 'Should be 0 after 64 halvings'
    );
}

#[test]
fn test_validate_coinbase_block_0() {
    // Test the genesis block coinbase transaction
    let raw_transaction_hex =
        "0x01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
    let raw_transaction = hex_to_bytecode(@raw_transaction_hex);
    let transaction = TransactionTrait::deserialize(raw_transaction);
    assert!(
        transaction.validate_coinbase(0, 5000000000).is_ok(),
        "Genesis block coinbase transaction invalid"
    );
}

#[test]
fn test_validate_coinbase_block_1() {
    // Test the second block coinbase transaction
    let raw_transaction_hex =
        "0x01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000";
    let raw_transaction = hex_to_bytecode(@raw_transaction_hex);
    let transaction = TransactionTrait::deserialize(raw_transaction);
    assert!(
        transaction.validate_coinbase(1, 5000000000).is_ok(), "Block 1 coinbase transaction invalid"
    );
}

#[test]
fn test_validate_coinbase_block_150007() {
    // Test a random block from learnmebitcoin
    let raw_transaction_hex =
        "0x01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804233fa04e028b12ffffffff0130490b2a010000004341047eda6bd04fb27cab6e7c28c99b94977f073e912f25d1ff7165d9c95cd9bbe6da7e7ad7f2acb09e0ced91705f7616af53bee51a238b7dc527f2be0aa60469d140ac00000000";
    let raw_transaction = hex_to_bytecode(@raw_transaction_hex);
    let transaction = TransactionTrait::deserialize(raw_transaction);
    assert!(
        transaction.validate_coinbase(150007, 350000).is_ok(),
        "Block 150007 coinbase transaction invalid"
    );
}

#[test]
fn test_validate_coinbase_block_227835() {
    // Test the last block before BIP34 was activated
    let raw_transaction_hex =
        "0x01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0f0479204f51024f09062f503253482fffffffff01da495f9500000000232103ddcdae35e28aca364daa1397612d2dafd891ee136d2ca5ab83faff6bc12ed67eac00000000";
    let raw_transaction = hex_to_bytecode(@raw_transaction_hex);
    let transaction = TransactionTrait::deserialize(raw_transaction);
    assert!(
        transaction.validate_coinbase(227835, 6050010).is_ok(),
        "Block 227835 coinbase transaction invalid"
    );
}

#[test]
fn test_validate_coinbase_block_227836() {
    // Test the first block after BIP34 was activated
    let raw_transaction_hex =
        "0x01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2703fc7903062f503253482f04ac204f510858029a11000003550d3363646164312f736c7573682f0000000001207e6295000000001976a914e285a29e0704004d4e95dbb7c57a98563d9fb2eb88ac00000000";
    let raw_transaction = hex_to_bytecode(@raw_transaction_hex);
    let transaction = TransactionTrait::deserialize(raw_transaction);
    assert!(
        transaction.validate_coinbase(227836, 6260000).is_ok(),
        "Block 227836 coinbase transaction invalid"
    );
}

#[test]
fn test_validate_coinbase_block_400021() {
    // Test a random block from learnmebitcoin
    let raw_transaction_hex =
        "0x01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1b03951a0604f15ccf5609013803062b9b5a0100072f425443432f200000000001ebc31495000000001976a9142c30a6aaac6d96687291475d7d52f4b469f665a688ac00000000";
    let raw_transaction = hex_to_bytecode(@raw_transaction_hex);
    let transaction = TransactionTrait::deserialize(raw_transaction);
    assert!(
        transaction.validate_coinbase(400021, 1166059).is_ok(),
        "Block 400021 coinbase transaction invalid"
    );
}

#[test]
fn test_validate_coinbase_block_481823() {
    // Test the last block before BIP141 segwit
    let raw_transaction_hex =
        "0x01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4e031f5a070473319e592f4254432e434f4d2f4e59412ffabe6d6dcceb2a9d0444c51cabc4ee97a1a000036ca0cb48d25b94b78c8367d8b868454b0100000000000000c0309b21000008c5f8f80000ffffffff0291920b5d0000000017a914e083685a1097ce1ea9e91987ab9e94eae33d8a13870000000000000000266a24aa21a9ede6c99265a6b9e1d36c962fda0516b35709c49dc3b8176fa7e5d5f1f6197884b400000000";
    let raw_transaction = hex_to_bytecode(@raw_transaction_hex);
    let transaction = TransactionTrait::deserialize(raw_transaction);
    assert!(
        transaction.validate_coinbase(481823, 311039505).is_ok(),
        "Block 481823 coinbase transaction invalid"
    );
}

#[test]
#[ignore]
fn test_validate_coinbase_block_481824() {
    // Test the first block after BIP141 segwit
    let raw_transaction_hex =
        "0x010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff6403205a07f4d3f9da09acf878c2c9c96c410d69758f0eae0e479184e0564589052e832c42899c867100010000000000000000db9901006052ce25d80acfde2f425443432f20537570706f7274202f4e59412f00000000000000000000000000000000000000000000025d322c57000000001976a9142c30a6aaac6d96687291475d7d52f4b469f665a688ac0000000000000000266a24aa21a9ed6c3c4dff76b5760d58694147264d208689ee07823e5694c4872f856eacf5a5d80120000000000000000000000000000000000000000000000000000000000000000000000000";
    let raw_transaction = hex_to_bytecode(@raw_transaction_hex);
    let transaction = TransactionTrait::deserialize(raw_transaction);
    assert!(
        transaction.validate_coinbase(481824, 212514269).is_ok(),
        "Block 481824 coinbase transaction invalid"
    );
}

#[test]
#[ignore]
fn test_validate_coinbase_block_538403() {
    // Test random block from learnmebitcoin
    let raw_transaction_hex =
        "0x010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2503233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100ffffffff02f595814a000000001976a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac0000000000000000266a24aa21a9edfaa194df59043645ba0f58aad74bfd5693fa497093174d12a4bb3b0574a878db0120000000000000000000000000000000000000000000000000000000000000000000000000";
    let raw_transaction = hex_to_bytecode(@raw_transaction_hex);
    let transaction = TransactionTrait::deserialize(raw_transaction);
    assert!(
        transaction.validate_coinbase(538403, 6517).is_ok(),
        "Block 538403 coinbase transaction invalid"
    );
}
// TODO: Test invalid coinbase

// File: ./packages/engine/src/tests/test_p2pkh.cairo

#[test]
fn test_p2pkh_transaction() {
    // First ever P2PKH transaction
    // tx: 6f7cf9580f1c2dfb3c4d5d043cdbb128c640e3f20161245aa7372e9666168516
    let raw_transaction_hex =
        "0x0100000002f60b5e96f09422354ab150b0e506c4bffedaf20216d30059cc5a3061b4c83dff000000004a493046022100e26d9ff76a07d68369e5782be3f8532d25ecc8add58ee256da6c550b52e8006b022100b4431f5a9a4dcb51cbdcaae935218c0ae4cfc8aa903fe4e5bac4c208290b7d5d01fffffffff7272ef43189f5553c2baea50f59cde99b3220fd518884d932016d055895b62d000000004a493046022100a2ab7cdc5b67aca032899ea1b262f6e8181060f5a34ee667a82dac9c7b7db4c3022100911bc945c4b435df8227466433e56899fbb65833e4853683ecaa12ee840d16bf01ffffffff0100e40b54020000001976a91412ab8dc588ca9d5787dde7eb29569da63c3a238c88ac00000000";
    let raw_transaction = hex_to_bytecode(@raw_transaction_hex);
    let transaction = TransactionTrait::deserialize(raw_transaction);

    let prevout_pk_script_1 =
        "0x4104c9560dc538db21476083a5c65a34c7cc219960b1e6f27a87571cd91edfd00dac16dca4b4a7c4ab536f85bc263b3035b762c5576dc6772492b8fb54af23abff6dac";
    let prevout_1 = UTXO {
        amount: 5000000000, pubkey_script: hex_to_bytecode(@prevout_pk_script_1), block_height: 509
    };
    let prevout_pk_script_2 =
        "0x41043987a76015929873f06823f4e8d93abaaf7bcf55c6a564bed5b7f6e728e6c4cb4e2c420fe14d976f7e641d8b791c652dfeee9da584305ae544eafa4f7be6f777ac";
    let prevout_2 = UTXO {
        amount: 50000000000, pubkey_script: hex_to_bytecode(@prevout_pk_script_2), block_height: 357
    };
    let utxo_hints = array![prevout_1, prevout_2];

    let res = validate_transaction(transaction, 0, utxo_hints);
    assert!(res.is_ok(), "Transaction validation failed");
}

#[test]
fn test_p2pkh_transaction_spend() {
    // Spend the first ever P2PKH transaction output
    // tx: 12e753ef5cc30925a6eee2c457aa7f53022443ca013ea81882a6b59b69e342a6
    let raw_transaction_hex =
        "0x01000000030dd7891efbf67da47c651531db8aab3144ed7a524e4ae1e30b773525e27ddd7b000000004948304502206f6a68710a51f77e5a1fa4d1037a23a76723724a51fd54710949e0189ee02dfa022100dad3454ade12fe84f3818e14c41ec2e02bbb154dd3136a094cdf86f67ebbe0b601ffffffff16851666962e37a75a246101f2e340c628b1db3c045d4d3cfb2d1c0f58f97c6f000000008b48304502203f004eeed0cef2715643e2f25a27a28f3c578e94c7f0f6a4df104e7d163f7f8f022100b8b248c1cfd8f77a0365107a9511d759b7544d979dd152a955c867afac0ef7860141044d05240cfbd8a2786eda9dadd520c1609b8593ff8641018d57703d02ba687cf2f187f0cee2221c3afb1b5ff7888caced2423916b61444666ca1216f26181398cffffffffffda5d38e91fd9a0d92872d51f83cb746fc7bf5d3ff13402f8d0d5ed60ddc79c0000000049483045022100b6fd43f2fa16e092678283f64d2e08fb2070b4af2b3ddfb9ca3c5e238288acaa02200c5a28e0a4fc1a540f6eeb30ccc4788050eae46964fe33ccb4500c3de1320c2501ffffffff02c0c62d00000000001976a91417194e1bd175fb5b1b2a1f9d221f6f5c29e1928388ac00c817a8040000001976a91465bda9b05f7e9a8f96a7f4ba0996a877708ef90888ac00000000";
    let raw_transaction = hex_to_bytecode(@raw_transaction_hex);
    let transaction = TransactionTrait::deserialize(raw_transaction);

    let prevout_pk_script_0 =
        "0x4104889fcdfd7c5430d13f1eb5f508e2e87f38d2406fad8425a824e032ccb371ef62465331e1a6334d7c3770a2ad2a958e740130343399d01dbd87426db850f9faf9ac";
    let prevout_pkh_script_1 = "0x76a91412ab8dc588ca9d5787dde7eb29569da63c3a238c88ac";
    let prevout_pk_script_2 =
        "0x4104f51707ee3fd26b490bb83582f22c73b97c364b9c51a80c49e6a9bc491538f5206fc0ca8fc4c97dfd0a8b2ae9b82d1ef94599ce51eaf9ba82ce4a69d9ac9dc225ac";

    let prev_out0 = UTXO {
        amount: 5003000000,
        pubkey_script: hex_to_bytecode(@prevout_pk_script_0),
        block_height: 12983
    };

    let prev_out1 = UTXO {
        amount: 10000000000,
        pubkey_script: hex_to_bytecode(@prevout_pkh_script_1),
        block_height: 728
    };

    let prev_out2 = UTXO {
        amount: 5000000000,
        pubkey_script: hex_to_bytecode(@prevout_pk_script_2),
        block_height: 17233
    };

    let utxo_hints = array![prev_out0, prev_out1, prev_out2];

    // Run Shinigami and validate the transaction execution
    let res = validate_transaction(transaction, 0, utxo_hints);
    assert!(res.is_ok(), "Transaction validation failed");
}

#[ignore]
#[test]
fn test_10000_btc_pizza_transaction() { // The famous 10000 BTC pizza transaction
// tx: a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d
// TODO
}

#[test]
fn test_block_770000_p2pkh_transaction() {
    // tx: a2bf21f6d8b7aa77c740d0374e4759791d97c0134bc918c93bae8e14879c8ecc
    let raw_transaction_hex =
        "0x0200000001c3cbbd0f9ac1f59225df1381c10c4b104ed7d78beef73e89cbd163c8d98b729e000000006a47304402202acb8afaa5745d1fd99dab6e74d89ee679daca1973796f61916e6e27905cd01b022067120362c1145cdd2a2de182435618b3c356a72849718997e5546d62ea9925fb012102e34755efb7b73a51f0a2facc10c9aab73b99a3f676c60fe5a7e865c75d61cce3feffffff02acf15608020000001976a9149ee1cd0c085b88bd7b22e44abe52734e0a61c94288ac404b4c00000000001976a914a7e9478b4f77c490c32472cfe8ad672d24fc77a888accfbf0b00";
    let raw_transaction = hex_to_bytecode(@raw_transaction_hex);
    let transaction = TransactionTrait::deserialize(raw_transaction);

    let prevout_pk_script = "0x76a9140900bb14c7cb6a52fd8a22fd68a5986eb193c9f588ac";
    let prevout = UTXO {
        amount: 8734850959, pubkey_script: hex_to_bytecode(@prevout_pk_script), block_height: 769998
    };
    let utxo_hints = array![prevout];

    let res = validate_transaction(transaction, 0, utxo_hints);
    assert!(res.is_ok(), "Transaction validation failed");
}

// File: ./packages/engine/src/tests/test.cairo

#[test]
fn execution_test() {
    let program = "OP_0 OP_1 OP_ADD";
    let mut compiler = CompilerTraitImpl::new();
    let bytecode = compiler.compile(program);
    let mut engine = EngineTraitImpl::new(bytecode);
    let res = engine.execute();
    assert!(res.is_ok(), "Execution failed");
}

// File: ./packages/engine/src/scriptflags.cairo

#[derive(Copy, Drop)]
pub enum ScriptFlags {
    // ScriptBip16, allows P2SH transactions.
    ScriptBip16,
    // ScriptStrictMultiSig, CHECKMULTISIG stack item must be zero length.
    ScriptStrictMultiSig,
    // ScriptDiscourageUpgradableNops, reserves NOP1-NOP10.
    ScriptDiscourageUpgradableNops,
    // ScriptVerifyCheckLockTimeVerify, enforces locktime (BIP0065).
    ScriptVerifyCheckLockTimeVerify,
    // ScriptVerifyCheckSequenceVerify, restricts by output age (BIP0112).
    ScriptVerifyCheckSequenceVerify,
    // ScriptVerifyCleanStack, ensures one true element on stack.
    ScriptVerifyCleanStack,
    // ScriptVerifyDERSignatures, requires DER-formatted signatures.
    ScriptVerifyDERSignatures,
    // ScriptVerifyLowS, requires S <= order / 2.
    ScriptVerifyLowS,
    // ScriptVerifyMinimalData, uses minimal data pushes.
    ScriptVerifyMinimalData,
    // ScriptVerifyNullFail, requires empty signatures on failure.
    ScriptVerifyNullFail,
    // ScriptVerifySigPushOnly, allows only pushed data.
    ScriptVerifySigPushOnly,
    // ScriptVerifyStrictEncoding, enforces strict encoding.
    ScriptVerifyStrictEncoding,
    // ScriptVerifyWitness, verifies with witness programs.
    ScriptVerifyWitness,
    // ScriptVerifyDiscourageUpgradeableWitnessProgram, non-standard witness versions 2-16.
    ScriptVerifyDiscourageUpgradeableWitnessProgram,
    // ScriptVerifyMinimalIf, requires empty vector or [0x01] for OP_IF/OP_NOTIF.
    ScriptVerifyMinimalIf,
    // ScriptVerifyWitnessPubKeyType, requires compressed public keys.
    ScriptVerifyWitnessPubKeyType,
    // ScriptVerifyTaproot, verifies using taproot rules.
    ScriptVerifyTaproot,
    // ScriptVerifyDiscourageUpgradeableTaprootVersion, non-standard unknown taproot versions.
    ScriptVerifyDiscourageUpgradeableTaprootVersion,
    // ScriptVerifyDiscourageOpSuccess, non-standard OP_SUCCESS codes.
    ScriptVerifyDiscourageOpSuccess,
    // ScriptVerifyDiscourageUpgradeablePubkeyType, non-standard unknown pubkey versions.
    ScriptVerifyDiscourageUpgradeablePubkeyType,
    // ScriptVerifyConstScriptCode, fails if signature match in script code.
    ScriptVerifyConstScriptCode,
}

impl ScriptFlagsIntoU32 of Into<ScriptFlags, u32> {
    fn into(self: ScriptFlags) -> u32 {
        match self {
            ScriptFlags::ScriptBip16 => 0x1,
            ScriptFlags::ScriptStrictMultiSig => 0x2,
            ScriptFlags::ScriptDiscourageUpgradableNops => 0x4,
            ScriptFlags::ScriptVerifyCheckLockTimeVerify => 0x8,
            ScriptFlags::ScriptVerifyCheckSequenceVerify => 0x10,
            ScriptFlags::ScriptVerifyCleanStack => 0x20,
            ScriptFlags::ScriptVerifyDERSignatures => 0x40,
            ScriptFlags::ScriptVerifyLowS => 0x80,
            ScriptFlags::ScriptVerifyMinimalData => 0x100,
            ScriptFlags::ScriptVerifyNullFail => 0x200,
            ScriptFlags::ScriptVerifySigPushOnly => 0x400,
            ScriptFlags::ScriptVerifyStrictEncoding => 0x800,
            ScriptFlags::ScriptVerifyWitness => 0x1000,
            ScriptFlags::ScriptVerifyDiscourageUpgradeableWitnessProgram => 0x2000,
            ScriptFlags::ScriptVerifyMinimalIf => 0x4000,
            ScriptFlags::ScriptVerifyWitnessPubKeyType => 0x8000,
            ScriptFlags::ScriptVerifyTaproot => 0x10000,
            ScriptFlags::ScriptVerifyDiscourageUpgradeableTaprootVersion => 0x20000,
            ScriptFlags::ScriptVerifyDiscourageOpSuccess => 0x40000,
            ScriptFlags::ScriptVerifyDiscourageUpgradeablePubkeyType => 0x80000,
            ScriptFlags::ScriptVerifyConstScriptCode => 0x100000,
        }
    }
}

fn flag_from_string(flag: felt252) -> u32 {
    // TODO: To map and remaining flags
    if flag == 'P2SH' {
        return ScriptFlags::ScriptBip16.into();
    } else if flag == 'STRICTENC' {
        return ScriptFlags::ScriptVerifyStrictEncoding.into();
    } else if flag == 'MINIMALDATA' {
        return ScriptFlags::ScriptVerifyMinimalData.into();
    } else if flag == 'DISCOURAGE_UPGRADABLE_NOPS' {
        return ScriptFlags::ScriptDiscourageUpgradableNops.into();
    } else if flag == 'DERSIG' {
        return ScriptFlags::ScriptVerifyDERSignatures.into();
    } else if flag == 'WITNESS' {
        return ScriptFlags::ScriptVerifyWitness.into();
    } else if flag == 'LOW_S' {
        return ScriptFlags::ScriptVerifyLowS.into();
    } else if flag == 'NULLDUMMY' {
        // TODO: Double check this
        return ScriptFlags::ScriptStrictMultiSig.into();
    } else if flag == 'NULLFAIL' {
        return ScriptFlags::ScriptVerifyNullFail.into();
    } else if flag == 'SIGPUSHONLY' {
        return ScriptFlags::ScriptVerifySigPushOnly.into();
    } else if flag == 'CLEANSTACK' {
        return ScriptFlags::ScriptVerifyCleanStack.into();
    } else if flag == 'DISCOURAGE_UPGRADABLE_WITNESS' {
        return ScriptFlags::ScriptVerifyDiscourageUpgradeableWitnessProgram.into();
    } else if flag == 'WITNESS_PUBKEYTYPE' {
        return ScriptFlags::ScriptVerifyWitnessPubKeyType.into();
    } else if flag == 'MINIMALIF' {
        return ScriptFlags::ScriptVerifyMinimalIf.into();
    } else if flag == 'CHECKSEQUENCEVERIFY' {
        return ScriptFlags::ScriptVerifyCheckSequenceVerify.into();
    } else {
        return 0;
    }
}

pub fn parse_flags(flags: ByteArray) -> u32 {
    let mut script_flags: u32 = 0;

    // Split the flags string by commas.
    let seperator = ',';
    let mut split_flags: Array<ByteArray> = array![];
    let mut current = "";
    let mut i = 0;
    let flags_len = flags.len();
    while i != flags_len {
        let char = flags[i].into();
        if char == seperator {
            if current == "" {
                i += 1;
                continue;
            }
            split_flags.append(current);
            current = "";
        } else {
            current.append_byte(char);
        }
        i += 1;
    };
    // Handle the last flag.
    if current != "" {
        split_flags.append(current);
    }

    // Compile the flags into a single integer.
    let mut i = 0;
    let flags_len = split_flags.len();
    while i != flags_len {
        let flag = split_flags.at(i);
        let flag_value = flag_from_string(byte_array_to_felt252_be(flag));
        script_flags += flag_value;
        i += 1;
    };

    script_flags
}

// File: ./packages/engine/src/transaction.cairo

// Tracks previous transaction outputs
#[derive(Drop, Copy)]
pub struct OutPoint {
    pub txid: u256,
    pub vout: u32,
}

#[derive(Drop, Clone)]
pub struct TransactionInput {
    pub previous_outpoint: OutPoint,
    pub signature_script: ByteArray,
    pub witness: Array<ByteArray>,
    pub sequence: u32,
}

#[derive(Drop, Clone)]
pub struct TransactionOutput {
    pub value: i64,
    pub publickey_script: ByteArray,
}

#[derive(Drop, Clone)]
pub struct Transaction {
    pub version: i32,
    pub transaction_inputs: Array<TransactionInput>,
    pub transaction_outputs: Array<TransactionOutput>,
    pub locktime: u32,
}

pub trait TransactionTrait {
    fn new(
        version: i32,
        transaction_inputs: Array<TransactionInput>,
        transaction_outputs: Array<TransactionOutput>,
        locktime: u32
    ) -> Transaction;
    fn new_signed(script_sig: ByteArray) -> Transaction;
    fn new_signed_witness(script_sig: ByteArray, witness: Array<ByteArray>) -> Transaction;
    fn btc_decode(raw: ByteArray, encoding: u32) -> Transaction;
    fn deserialize(raw: ByteArray) -> Transaction;
    fn deserialize_no_witness(raw: ByteArray) -> Transaction;
    fn btc_encode(self: Transaction, encoding: u32) -> ByteArray;
    fn serialize(self: Transaction) -> ByteArray;
    fn serialize_no_witness(self: Transaction) -> ByteArray;
    fn calculate_block_subsidy(block_height: u32) -> i64;
    fn is_coinbase(self: @Transaction) -> bool;
    fn validate_coinbase(
        self: Transaction, block_height: u32, total_fees: i64
    ) -> Result<(), felt252>;
}

pub const BASE_ENCODING: u32 = 0x01;
pub const WITNESS_ENCODING: u32 = 0x02;

pub impl TransactionImpl of TransactionTrait {
    fn new(
        version: i32,
        transaction_inputs: Array<TransactionInput>,
        transaction_outputs: Array<TransactionOutput>,
        locktime: u32
    ) -> Transaction {
        Transaction {
            version: version,
            transaction_inputs: transaction_inputs,
            transaction_outputs: transaction_outputs,
            locktime: locktime,
        }
    }

    fn new_signed(script_sig: ByteArray) -> Transaction {
        // TODO
        let transaction = Transaction {
            version: 1,
            transaction_inputs: array![
                TransactionInput {
                    previous_outpoint: OutPoint { txid: 0x0, vout: 0, },
                    signature_script: script_sig,
                    witness: array![],
                    sequence: 0xffffffff,
                }
            ],
            transaction_outputs: array![],
            locktime: 0,
        };
        transaction
    }

    fn new_signed_witness(script_sig: ByteArray, witness: Array<ByteArray>) -> Transaction {
        // TODO
        let transaction = Transaction {
            version: 1,
            transaction_inputs: array![
                TransactionInput {
                    previous_outpoint: OutPoint { txid: 0x0, vout: 0, },
                    signature_script: script_sig,
                    witness: witness,
                    sequence: 0xffffffff,
                }
            ],
            transaction_outputs: array![],
            locktime: 0,
        };
        transaction
    }

    // Deserialize a transaction from a byte array.
    fn btc_decode(raw: ByteArray, encoding: u32) -> Transaction {
        let mut offset: usize = 0;
        let version: i32 = byte_array_value_at_le(@raw, ref offset, 4).try_into().unwrap();
        // TODO: ReadVerIntBuf
        let input_len: u8 = byte_array_value_at_le(@raw, ref offset, 1).try_into().unwrap();
        // TODO: input_len = 0 -> segwit
        // TODO: Error handling and bounds checks
        // TODO: Byte orderings
        let mut i = 0;
        let mut inputs: Array<TransactionInput> = array![];
        while i != input_len {
            let tx_id = u256 {
                high: byte_array_value_at_be(@raw, ref offset, 16).try_into().unwrap(),
                low: byte_array_value_at_be(@raw, ref offset, 16).try_into().unwrap(),
            };
            let vout: u32 = byte_array_value_at_le(@raw, ref offset, 4).try_into().unwrap();
            let script_len = byte_array_value_at_le(@raw, ref offset, 1).try_into().unwrap();
            let script = sub_byte_array(@raw, ref offset, script_len);
            let sequence: u32 = byte_array_value_at_le(@raw, ref offset, 4).try_into().unwrap();
            let input = TransactionInput {
                previous_outpoint: OutPoint { txid: tx_id, vout: vout },
                signature_script: script,
                witness: array![],
                sequence: sequence,
            };
            inputs.append(input);
            i += 1;
        };

        let output_len: u8 = byte_array_value_at_le(@raw, ref offset, 1).try_into().unwrap();
        let mut i = 0;
        let mut outputs: Array<TransactionOutput> = array![];
        while i != output_len {
            // TODO: negative values
            let value: i64 = byte_array_value_at_le(@raw, ref offset, 8).try_into().unwrap();
            let script_len = byte_array_value_at_le(@raw, ref offset, 1).try_into().unwrap();
            let script = sub_byte_array(@raw, ref offset, script_len);
            let output = TransactionOutput { value: value, publickey_script: script, };
            outputs.append(output);
            i += 1;
        };
        // TODO: Witness
        let locktime: u32 = byte_array_value_at_le(@raw, ref offset, 4).try_into().unwrap();
        Transaction {
            version: version,
            transaction_inputs: inputs,
            transaction_outputs: outputs,
            locktime: locktime,
        }
    }

    fn deserialize(raw: ByteArray) -> Transaction {
        Self::btc_decode(raw, WITNESS_ENCODING)
    }

    fn deserialize_no_witness(raw: ByteArray) -> Transaction {
        Self::btc_decode(raw, BASE_ENCODING)
    }

    // Serialize the transaction data for hashing based on encoding used.
    fn btc_encode(self: Transaction, encoding: u32) -> ByteArray {
        let mut bytes = "";
        bytes.append_word_rev(self.version.into(), 4);
        // TODO: Witness encoding

        // Serialize each input in the transaction.
        let input_len: usize = self.transaction_inputs.len();
        bytes.append_word_rev(input_len.into(), int_size_in_bytes(input_len));
        let mut i: usize = 0;
        while i != input_len {
            let input: @TransactionInput = self.transaction_inputs.at(i);
            let input_txid: u256 = *input.previous_outpoint.txid;
            let vout: u32 = *input.previous_outpoint.vout;
            let script: @ByteArray = input.signature_script;
            let script_len: usize = script.len();
            let sequence: u32 = *input.sequence;

            bytes.append_word(input_txid.high.into(), 16);
            bytes.append_word(input_txid.low.into(), 16);
            bytes.append_word_rev(vout.into(), 4);
            bytes.append_word_rev(script_len.into(), int_size_in_bytes(script_len));
            bytes.append(script);
            bytes.append_word_rev(sequence.into(), 4);

            i += 1;
        };

        // Serialize each output in the transaction.
        let output_len: usize = self.transaction_outputs.len();
        bytes.append_word_rev(output_len.into(), int_size_in_bytes(output_len));
        i = 0;
        while i != output_len {
            let output: @TransactionOutput = self.transaction_outputs.at(i);
            let value: i64 = *output.value;
            let script: @ByteArray = output.publickey_script;
            let script_len: usize = script.len();

            bytes.append_word_rev(value.into(), 8);
            bytes.append_word_rev(script_len.into(), int_size_in_bytes(script_len));
            bytes.append(script);

            i += 1;
        };

        bytes.append_word_rev(self.locktime.into(), 4);
        bytes
    }

    fn serialize(self: Transaction) -> ByteArray {
        self.btc_encode(WITNESS_ENCODING)
    }

    fn serialize_no_witness(self: Transaction) -> ByteArray {
        self.btc_encode(BASE_ENCODING)
    }

    fn calculate_block_subsidy(block_height: u32) -> i64 {
        let halvings = block_height / 210000;
        shr::<i64, u32>(5000000000, halvings)
    }

    fn is_coinbase(self: @Transaction) -> bool {
        if self.transaction_inputs.len() != 1 {
            return false;
        }

        let input = self.transaction_inputs.at(0);
        if input.previous_outpoint.txid != @0 || input.previous_outpoint.vout != @0xFFFFFFFF {
            return false;
        }

        true
    }

    fn validate_coinbase(
        self: Transaction, block_height: u32, total_fees: i64
    ) -> Result<(), felt252> {
        if !self.is_coinbase() {
            return Result::Err(Error::INVALID_COINBASE);
        }

        let input = self.transaction_inputs.at(0);
        let script_len = input.signature_script.len();
        if script_len < 2 || script_len > 100 {
            return Result::Err(Error::INVALID_COINBASE);
        }

        let subsidy = Self::calculate_block_subsidy(block_height);
        let mut total_out: i64 = 0;
        let output_len = self.transaction_outputs.len();
        let mut i = 0;
        while i != output_len {
            let output = self.transaction_outputs.at(i);
            total_out += *output.value;
            i += 1;
        };
        if total_out > total_fees + subsidy {
            return Result::Err(Error::INVALID_COINBASE);
        }

        // TODO: BIP34 checks for block height?

        Result::Ok(())
    }
}

impl TransactionDefault of Default<Transaction> {
    fn default() -> Transaction {
        let default_txin = TransactionInput {
            previous_outpoint: OutPoint { txid: 0, vout: 0, },
            signature_script: "",
            witness: array![],
            sequence: 0xffffffff,
        };
        let transaction = Transaction {
            version: 0,
            transaction_inputs: array![default_txin],
            transaction_outputs: array![],
            locktime: 0,
        };
        transaction
    }
}

pub trait EngineTransactionInputTrait<I> {
    fn get_prevout_txid(self: @I) -> u256;
    fn get_prevout_vout(self: @I) -> u32;
    fn get_signature_script(self: @I) -> @ByteArray;
    fn get_witness(self: @I) -> Span<ByteArray>;
    fn get_sequence(self: @I) -> u32;
}

pub impl EngineTransactionInputTraitInternalImpl of EngineTransactionInputTrait<TransactionInput> {
    fn get_prevout_txid(self: @TransactionInput) -> u256 {
        *self.previous_outpoint.txid
    }

    fn get_prevout_vout(self: @TransactionInput) -> u32 {
        *self.previous_outpoint.vout
    }

    fn get_signature_script(self: @TransactionInput) -> @ByteArray {
        self.signature_script
    }

    fn get_witness(self: @TransactionInput) -> Span<ByteArray> {
        self.witness.span()
    }

    fn get_sequence(self: @TransactionInput) -> u32 {
        *self.sequence
    }
}

pub trait EngineTransactionOutputTrait<O> {
    fn get_publickey_script(self: @O) -> @ByteArray;
    fn get_value(self: @O) -> i64;
}

pub impl EngineTransactionOutputTraitInternalImpl of EngineTransactionOutputTrait<
    TransactionOutput
> {
    fn get_publickey_script(self: @TransactionOutput) -> @ByteArray {
        self.publickey_script
    }

    fn get_value(self: @TransactionOutput) -> i64 {
        *self.value
    }
}

pub trait EngineTransactionTrait<
    T, I, O, +EngineTransactionInputTrait<I>, +EngineTransactionOutputTrait<O>
> {
    fn get_version(self: @T) -> i32;
    fn get_transaction_inputs(self: @T) -> Span<I>;
    fn get_transaction_outputs(self: @T) -> Span<O>;
    fn get_locktime(self: @T) -> u32;
}

pub impl EngineTransactionTraitInternalImpl of EngineTransactionTrait<
    Transaction,
    TransactionInput,
    TransactionOutput,
    EngineTransactionInputTraitInternalImpl,
    EngineTransactionOutputTraitInternalImpl
> {
    fn get_version(self: @Transaction) -> i32 {
        *self.version
    }

    fn get_transaction_inputs(self: @Transaction) -> Span<TransactionInput> {
        self.transaction_inputs.span()
    }

    fn get_transaction_outputs(self: @Transaction) -> Span<TransactionOutput> {
        self.transaction_outputs.span()
    }

    fn get_locktime(self: @Transaction) -> u32 {
        *self.locktime
    }
}

// File: ./packages/engine/src/witness.cairo

fn byte_to_smallint(byte: u8) -> Result<i64, felt252> {
    if byte == Opcode::OP_0 {
        return Result::Ok(0);
    }
    if byte >= Opcode::OP_1 && byte <= Opcode::OP_16 {
        return Result::Ok((byte - Opcode::OP_1 + 1).into());
    }
    Result::Err('Invalid small int')
}

pub fn parse_witness_program(witness: @ByteArray) -> Result<(i64, ByteArray), felt252> {
    if witness.len() < 4 || witness.len() > 42 {
        return Result::Err('Invalid witness program length');
    }

    let version: i64 = byte_to_smallint(witness[0])?;
    let data_len = Opcode::data_len(1, witness)?;
    let program: ByteArray = Opcode::data_at(2, data_len, witness)?;
    if !Opcode::is_canonical_push(witness[1], @program) {
        return Result::Err('Non-canonical witness program');
    }

    return Result::Ok((version, program));
}

pub fn is_witness_program(program: @ByteArray) -> bool {
    return parse_witness_program(program).is_ok();
}

pub fn parse_witness_input(input: ByteArray) -> Array<ByteArray> {
    // Comma seperated list of witness data as hex strings
    let mut witness_data: Array<ByteArray> = array![];
    let mut i = 0;
    let mut temp_witness: ByteArray = "";
    while i != input.len() {
        if input[i] == ',' {
            let witness_bytes = hex_to_bytecode(@temp_witness);
            witness_data.append(witness_bytes);
            temp_witness = "";
        } else {
            temp_witness.append_byte(input[i]);
        }
        i += 1;
    };

    witness_data
}

// File: ./packages/engine/src/validate.cairo

// TODO: Move validate coinbase here

// TODO: Remove hints?
// utxo_hints: Set of existing utxos that are being spent by this transaction
pub fn validate_transaction(
    tx: Transaction, flags: u32, utxo_hints: Array<UTXO>
) -> Result<(), felt252> {
    let input_count = tx.transaction_inputs.len();
    if input_count != utxo_hints.len() {
        return Result::Err('Invalid number of utxo hints');
    }

    let mut i = 0;
    let mut err = '';
    while i != input_count {
        let utxo = utxo_hints[i];
        // TODO: Error handling
        let mut engine = EngineInternalImpl::new(
            utxo.pubkey_script, tx.clone(), i, flags, *utxo.amount
        )
            .unwrap();
        let res = engine.execute();
        if res.is_err() {
            err = res.unwrap_err();
            break;
        }

        i += 1;
    };
    if err != '' {
        return Result::Err(err);
    }

    Result::Ok(())
}

// File: ./packages/engine/src/cond_stack.cairo

#[derive(Destruct)]
pub struct ConditionalStack {
    stack: Felt252Dict<u8>,
    len: usize,
}

#[generate_trait()]
pub impl ConditionalStackImpl of ConditionalStackTrait {
    fn new() -> ConditionalStack {
        ConditionalStack { stack: Default::default(), len: 0, }
    }

    fn push(ref self: ConditionalStack, value: u8) {
        self.stack.insert(self.len.into(), value);
        self.len += 1;
    }

    fn pop(ref self: ConditionalStack) -> Result<(), felt252> {
        if self.len == 0 {
            return Result::Err('pop: conditional stack is empty');
        }
        self.len -= 1;
        return Result::Ok(());
    }

    fn branch_executing(ref self: ConditionalStack) -> bool {
        if self.len == 0 {
            return true;
        } else {
            return self.stack[self.len.into() - 1] == 1;
        }
    }

    fn len(ref self: ConditionalStack) -> usize {
        self.len
    }

    fn swap_condition(ref self: ConditionalStack) {
        let cond_idx = self.len() - 1;
        match self.stack.get(cond_idx.into()) {
            0 => self.stack.insert(cond_idx.into(), 1),
            1 => self.stack.insert(cond_idx.into(), 0),
            2 => self.stack.insert(cond_idx.into(), 2),
            _ => panic!("Invalid condition")
        }
    }
}

// File: ./packages/engine/src/lib.cairo
mod tests {
pub mod engine;
pub mod stack;
pub mod cond_stack;
pub mod validate;
pub mod utxo;
pub mod witness;
pub mod errors;
pub mod opcodes {
    pub mod opcodes;
    pub mod constants;
    pub mod flow;
    pub mod locktime;
    pub mod stack;
    pub mod splice;
    pub mod bitwise;
    pub mod arithmetic;
    pub mod crypto;
    pub mod utils;
    #[cfg(test)]
    mod tests {
        mod test_constants;
        mod test_flow;
        mod test_locktime;
        mod test_stack;
        mod test_splice;
        mod test_bitwise;
        mod test_arithmetic;
        mod test_crypto;
        mod test_reserved;
        mod test_disabled;
        mod utils;
    }
    pub use opcodes::Opcode;
}
pub mod scriptnum;
pub use scriptnum::ScriptNum;
pub mod scriptflags;
pub mod signature {
    pub mod signature;
    pub mod sighash;
    pub mod constants;
    pub mod utils;
    pub use signature::{BaseSigVerifier, BaseSigVerifierTrait};
}
pub mod transaction;
#[cfg(test)]
    mod test_coinbase;
    mod test_transactions;
    mod test_scriptnum;
    mod test_p2pk;
    mod test_p2pkh;
}

// File: ./packages/engine/src/engine.cairo
//     Transaction, EngineTransactionInputTrait, EngineTransactionOutputTrait, EngineTransactionTrait
// };

// SigCache implements an Schnorr+ECDSA signature verification cache. Only valid signatures will be
// added to the cache.
pub trait SigCacheTrait<S> {
    // Returns true if sig cache contains sig_hash corresponding to signature and public key
    fn exists(sig_hash: u256, signature: ByteArray, pub_key: ByteArray) -> bool;
    // Adds a signature to the cache
    fn add(sig_hash: u256, signature: ByteArray, pub_key: ByteArray);
}

// HashCache caches the midstate of segwit v0 and v1 sighashes
pub trait HashCacheTrait<
    H,
    I,
    O,
    T,
    +EngineTransactionInputTrait<I>,
    +EngineTransactionOutputTrait<O>,
    +EngineTransactionTrait<T, I, O>
> {
    fn new(transaction: @T) -> H;

    // v0 represents sighash midstate used in the base segwit signatures BIP-143
    fn get_hash_prevouts_v0(self: @H) -> u256;
    fn get_hash_sequence_v0(self: @H) -> u256;
    fn get_hash_outputs_v0(self: @H) -> u256;

    // v1 represents sighash midstate used to compute taproot signatures BIP-341
    fn get_hash_prevouts_v1(self: @H) -> u256;
    fn get_hash_sequence_v1(self: @H) -> u256;
    fn get_hash_outputs_v1(self: @H) -> u256;
    fn get_hash_input_scripts_v1(self: @H) -> u256;
}

// Represents the VM that executes Bitcoin scripts
#[derive(Destruct)]
pub struct Engine<T> {
    // Execution behaviour flags
    flags: u32,
    // Is Bip16 p2sh
    bip16: bool,
    // Transaction context being executed
    pub transaction: T,
    // Input index within the tx containing signature script being executed
    pub tx_idx: u32,
    // Amount of the input being spent
    pub amount: i64,
    // The script to execute
    scripts: Array<@ByteArray>,
    // Index of the current script being executed
    script_idx: usize,
    // Program counter within the current script
    pub opcode_idx: usize,
    // The witness program
    pub witness_program: ByteArray,
    // The witness version
    pub witness_version: i64,
    // Primary data stack
    pub dstack: ScriptStack,
    // Alternate data stack
    pub astack: ScriptStack,
    // Tracks conditonal execution state supporting nested conditionals
    pub cond_stack: ConditionalStack,
    // Position within script of last OP_CODESEPARATOR
    pub last_code_sep: u32,
    // Count number of non-push opcodes
    pub num_ops: u32,
}

// TODO: SigCache
pub trait EngineTrait<
    E,
    I,
    O,
    T,
    H,
    +EngineTransactionInputTrait<I>,
    +EngineTransactionOutputTrait<O>,
    +EngineTransactionTrait<T, I, O>,
    +HashCacheTrait<H, I, O, T>
> {
    // Create a new Engine with the given script
    fn new(
        script_pubkey: @ByteArray,
        transaction: @T,
        tx_idx: u32,
        flags: u32,
        amount: i64,
        hash_cache: @H
    ) -> Result<E, felt252>;
    // Executes the entire script and returns top of stack or error if script fails
    fn execute(ref self: E) -> Result<ByteArray, felt252>;
}

pub impl EngineImpl<
    I,
    O,
    T,
    H,
    impl IEngineTransactionInput: EngineTransactionInputTrait<I>,
    impl IEngineTransactionOutput: EngineTransactionOutputTrait<O>,
    impl IEngineTransaction: EngineTransactionTrait<
        T, I, O, IEngineTransactionInput, IEngineTransactionOutput
    >,
    impl IHashCache: HashCacheTrait<H, I, O, T>,
> of EngineTrait<Engine<T>, I, O, T, H> {
    // Create a new Engine with the given script
    fn new(
        script_pubkey: @ByteArray,
        transaction: @T,
        tx_idx: u32,
        flags: u32,
        amount: i64,
        hash_cache: @H
    ) -> Result<Engine<T>, felt252> {
        let _ = transaction.get_transaction_inputs();
        return Result::Err('todo');
    }

    // Executes the entire script and returns top of stack or error if script fails
    fn execute(ref self: Engine<T>) -> Result<ByteArray, felt252> {
        // TODO
        Result::Ok("0")
    }
}

pub trait EngineExtrasTrait<T> {
    // Pulls the next len bytes from the script and advances the program counter
    fn pull_data(ref self: Engine<T>, len: usize) -> Result<ByteArray, felt252>;
    // Return true if the script engine instance has the specified flag set.
    fn has_flag(ref self: Engine<T>, flag: ScriptFlags) -> bool;
    // Pop bool enforcing minimal if
    fn pop_if_bool(ref self: Engine<T>) -> Result<bool, felt252>;
    // Return true if the witness program was active
    fn is_witness_active(ref self: Engine<T>, version: i64) -> bool;
    // Return the script since last OP_CODESEPARATOR
    fn sub_script(ref self: Engine<T>) -> ByteArray;
}

pub impl EngineExtrasImpl<T, +Drop<T>> of EngineExtrasTrait<T> {
    fn pull_data(ref self: Engine<T>, len: usize) -> Result<ByteArray, felt252> {
        let mut data = "";
        let mut i = self.opcode_idx + 1;
        let mut end = i + len;
        let script = *(self.scripts[self.script_idx]);
        if end > script.len() {
            return Result::Err(Error::SCRIPT_INVALID);
        }
        while i != end {
            data.append_byte(script[i]);
            i += 1;
        };
        self.opcode_idx = end - 1;
        return Result::Ok(data);
    }

    fn has_flag(ref self: Engine<T>, flag: ScriptFlags) -> bool {
        self.flags & flag.into() == flag.into()
    }

    fn pop_if_bool(ref self: Engine<T>) -> Result<bool, felt252> {
        if !self.is_witness_active(0) || !self.has_flag(ScriptFlags::ScriptVerifyMinimalIf) {
            return self.dstack.pop_bool();
        }
        let top = self.dstack.pop_byte_array()?;
        if top.len() > 1 {
            return Result::Err(Error::MINIMAL_IF);
        }

        if top.len() == 1 && top[0] != 0x01 {
            return Result::Err(Error::MINIMAL_IF);
        }
        return Result::Ok(byte_array_to_bool(@top));
    }

    fn is_witness_active(ref self: Engine<T>, version: i64) -> bool {
        return self.witness_version == version && self.witness_program.len() != 0;
    }

    fn sub_script(ref self: Engine<T>) -> ByteArray {
        let script = *(self.scripts[self.script_idx]);
        if self.last_code_sep == 0 {
            return script.clone();
        }

        let mut sub_script = "";
        let mut i = self.last_code_sep;
        while i != script.len() {
            sub_script.append_byte(script[i]);
            i += 1;
        };
        return sub_script;
    }
}

pub trait EngineInternalTrait {
    // Create a new Engine with the given script
    fn new(
        script_pubkey: @ByteArray, transaction: Transaction, tx_idx: u32, flags: u32, amount: i64
    ) -> Result<Engine<Transaction>, felt252>;
    // Returns true if the script is a script hash
    fn is_script_hash(ref self: Engine<Transaction>) -> bool;
    // Returns true if the script sig is push only
    fn is_push_only(ref self: Engine<Transaction>) -> bool;
    // Pulls the next len bytes from the script at the given index
    fn pull_data_at(
        ref self: Engine<Transaction>, idx: usize, len: usize
    ) -> Result<ByteArray, felt252>;
    fn get_dstack(ref self: Engine<Transaction>) -> Span<ByteArray>;
    fn get_astack(ref self: Engine<Transaction>) -> Span<ByteArray>;
    // Returns the length of the next push data opcode
    fn push_data_len(ref self: Engine<Transaction>, opcode: u8, idx: u32) -> Result<usize, felt252>;
    // Skip the next opcode if it is a push opcode in unexecuted conditional branch
    fn skip_push_data(ref self: Engine<Transaction>, opcode: u8) -> Result<(), felt252>;
    // Executes the next instruction in the script
    fn step(ref self: Engine<Transaction>) -> Result<bool, felt252>;
    // Executes the entire script and returns top of stack or error if script fails
    fn execute(ref self: Engine<Transaction>) -> Result<ByteArray, felt252>;
    // Validate witness program using witness input
    fn verify_witness(
        ref self: Engine<Transaction>, witness: Span<ByteArray>
    ) -> Result<(), felt252>;
    // Ensure the stack size is within limits
    fn check_stack_size(ref self: Engine<Transaction>) -> Result<(), felt252>;
    // Check if the next opcode is a minimal push
    fn check_minimal_data_push(ref self: Engine<Transaction>, opcode: u8) -> Result<(), felt252>;
    // Print engine data as a JSON object
    fn json(ref self: Engine<Transaction>);
}

pub const MAX_STACK_SIZE: u32 = 1000;
pub const MAX_SCRIPT_SIZE: u32 = 10000;
pub const MAX_OPS_PER_SCRIPT: u32 = 201;
pub const MAX_SCRIPT_ELEMENT_SIZE: u32 = 520;

pub impl EngineInternalImpl of EngineInternalTrait {
    fn new(
        script_pubkey: @ByteArray, transaction: Transaction, tx_idx: u32, flags: u32, amount: i64
    ) -> Result<Engine<Transaction>, felt252> {
        if tx_idx >= transaction.transaction_inputs.len() {
            return Result::Err('Engine::new: tx_idx invalid');
        }
        let script_sig = transaction.transaction_inputs[tx_idx].signature_script;

        if script_sig.len() == 0 && script_pubkey.len() == 0 {
            return Result::Err(Error::SCRIPT_EMPTY_STACK);
        }

        let witness_len = transaction.transaction_inputs[tx_idx].witness.len();
        let mut engine = Engine {
            flags: flags,
            bip16: false,
            transaction: transaction,
            tx_idx: tx_idx,
            amount: amount,
            scripts: array![script_sig, script_pubkey],
            script_idx: 0,
            opcode_idx: 0,
            witness_program: "",
            witness_version: 0,
            dstack: ScriptStackImpl::new(),
            astack: ScriptStackImpl::new(),
            cond_stack: ConditionalStackImpl::new(),
            last_code_sep: 0,
            num_ops: 0,
        };

        if engine.has_flag(ScriptFlags::ScriptVerifyCleanStack)
            && (!engine.has_flag(ScriptFlags::ScriptBip16)
                && !engine.has_flag(ScriptFlags::ScriptVerifyWitness)) {
            return Result::Err('Engine::new: invalid flag combo');
        }

        if engine.has_flag(ScriptFlags::ScriptVerifySigPushOnly) && !engine.is_push_only() {
            return Result::Err('Engine::new: not pushonly');
        }

        let mut bip16 = false;
        if engine.has_flag(ScriptFlags::ScriptBip16) && engine.is_script_hash() {
            if !engine.has_flag(ScriptFlags::ScriptVerifySigPushOnly) && !engine.is_push_only() {
                return Result::Err('Engine::new: p2sh not pushonly');
            }
            engine.bip16 = true;
            bip16 = true;
        }

        let mut i = 0;
        let mut valid_sizes = true;
        while i != engine.scripts.len() {
            let script = *(engine.scripts[i]);
            if script.len() > MAX_SCRIPT_SIZE {
                valid_sizes = false;
                break;
            }
            // TODO: Check parses?
            i += 1;
        };
        if !valid_sizes {
            return Result::Err('Engine::new: script too large');
        }

        if script_sig.len() == 0 {
            engine.script_idx = 1;
        }

        if engine.has_flag(ScriptFlags::ScriptVerifyMinimalData) {
            engine.dstack.verify_minimal_data = true;
            engine.astack.verify_minimal_data = true;
        }

        if engine.has_flag(ScriptFlags::ScriptVerifyWitness) {
            if !engine.has_flag(ScriptFlags::ScriptBip16) {
                return Result::Err('Engine::new: witness in nonp2sh');
            }

            let mut witness_program: ByteArray = "";
            if is_witness_program(script_pubkey) {
                if script_sig.len() != 0 {
                    return Result::Err('Engine::new: witness w/ sig');
                }
                witness_program = script_pubkey.clone();
            } else if witness_len != 0 && bip16 {
                let sig_clone = engine.scripts[0].clone();
                if sig_clone.len() > 2 {
                    let first_elem = sig_clone[0];
                    let mut remaining = "";
                    let mut i = 1;
                    // TODO: Optimize
                    while i != sig_clone.len() {
                        remaining.append_byte(sig_clone[i]);
                        i += 1;
                    };
                    if Opcode::is_canonical_push(first_elem, @remaining)
                        && is_witness_program(@remaining) {
                        witness_program = remaining;
                    } else {
                        return Result::Err('Engine::new: sig malleability');
                    }
                } else {
                    return Result::Err('Engine::new: sig malleability');
                }
            }

            if witness_program.len() != 0 {
                let (witness_version, witness_program) = parse_witness_program(
                    @witness_program
                )?;
                engine.witness_version = witness_version;
                engine.witness_program = witness_program;
            } else if engine.witness_program.len() == 0 && witness_len != 0 {
                return Result::Err('Engine::new: witness + no prog');
            }
        }

        return Result::Ok(engine);
    }

    fn is_script_hash(ref self: Engine<Transaction>) -> bool {
        let script_pubkey = *(self.scripts[1]);
        if script_pubkey.len() == 23
            && script_pubkey[0] == Opcode::OP_HASH160
            && script_pubkey[1] == Opcode::OP_DATA_20
            && script_pubkey[22] == Opcode::OP_EQUAL {
            return true;
        }
        return false;
    }

    fn is_push_only(ref self: Engine<Transaction>) -> bool {
        let script: @ByteArray = *(self.scripts[0]);
        let mut i = 0;
        let mut is_push_only = true;
        while i != script.len() {
            // TODO: Error handling if i outside bounds
            let opcode = script[i];
            if opcode > Opcode::OP_16 {
                is_push_only = false;
                break;
            }

            // TODO: Error handling
            let data_len = Opcode::data_len(i, script).unwrap();
            i += data_len + 1;
        };
        return is_push_only;
    }

    fn pull_data_at(
        ref self: Engine<Transaction>, idx: usize, len: usize
    ) -> Result<ByteArray, felt252> {
        let mut data = "";
        let mut i = idx;
        let mut end = i + len;
        let script = *(self.scripts[self.script_idx]);
        if end > script.len() {
            return Result::Err(Error::SCRIPT_INVALID);
        }
        while i != end {
            data.append_byte(script[i]);
            i += 1;
        };
        return Result::Ok(data);
    }

    fn get_dstack(ref self: Engine<Transaction>) -> Span<ByteArray> {
        return self.dstack.stack_to_span();
    }

    fn get_astack(ref self: Engine<Transaction>) -> Span<ByteArray> {
        return self.astack.stack_to_span();
    }

    fn push_data_len(
        ref self: Engine<Transaction>, opcode: u8, idx: u32
    ) -> Result<usize, felt252> {
        if opcode == Opcode::OP_PUSHDATA1 {
            return Result::Ok(
                byte_array_to_felt252_le(@self.pull_data_at(idx + 1, 1)?).try_into().unwrap()
            );
        } else if opcode == Opcode::OP_PUSHDATA2 {
            return Result::Ok(
                byte_array_to_felt252_le(@self.pull_data_at(idx + 1, 2)?).try_into().unwrap()
            );
        } else if opcode == Opcode::OP_PUSHDATA4 {
            return Result::Ok(
                byte_array_to_felt252_le(@self.pull_data_at(idx + 1, 4)?).try_into().unwrap()
            );
        }
        return Result::Err('Engine::push_data_len: invalid');
    }

    fn skip_push_data(ref self: Engine<Transaction>, opcode: u8) -> Result<(), felt252> {
        if opcode == Opcode::OP_PUSHDATA1 {
            self.opcode_idx += self.push_data_len(opcode, self.opcode_idx)? + 2;
        } else if opcode == Opcode::OP_PUSHDATA2 {
            self.opcode_idx += self.push_data_len(opcode, self.opcode_idx)? + 3;
        } else if opcode == Opcode::OP_PUSHDATA4 {
            self.opcode_idx += self.push_data_len(opcode, self.opcode_idx)? + 5;
        } else {
            return Result::Err(Error::SCRIPT_INVALID);
        }
        Result::Ok(())
    }

    fn step(ref self: Engine<Transaction>) -> Result<bool, felt252> {
        if self.script_idx >= self.scripts.len() {
            return Result::Ok(false);
        }
        let script = *(self.scripts[self.script_idx]);
        if self.opcode_idx >= script.len() {
            // Empty script skip
            if self.cond_stack.len() > 0 {
                return Result::Err(Error::SCRIPT_UNBALANCED_CONDITIONAL_STACK);
            }
            self.astack = ScriptStackImpl::new();
            if self.dstack.verify_minimal_data {
                self.astack.verify_minimal_data = true;
            }
            self.opcode_idx = 0;
            self.last_code_sep = 0;
            self.script_idx += 1;
            return self.step();
        }
        let opcode = script[self.opcode_idx];

        let illegal_opcode = Opcode::is_opcode_always_illegal(opcode, ref self);
        if illegal_opcode.is_err() {
            return Result::Err(illegal_opcode.unwrap_err());
        }

        if !self.cond_stack.branch_executing() && !is_branching_opcode(opcode) {
            if Opcode::is_data_opcode(opcode) {
                let opcode_32: u32 = opcode.into();
                self.opcode_idx += opcode_32 + 1;
                return Result::Ok(true);
            } else if Opcode::is_push_opcode(opcode) {
                let res = self.skip_push_data(opcode);
                if res.is_err() {
                    return Result::Err(res.unwrap_err());
                }
                return Result::Ok(true);
            } else {
                let res = Opcode::is_opcode_disabled(opcode, ref self);
                if res.is_err() {
                    return Result::Err(res.unwrap_err());
                }
                self.opcode_idx += 1;
                return Result::Ok(true);
            }
        }

        if self.dstack.verify_minimal_data
            && self.cond_stack.branch_executing()
            && opcode >= 0
            && opcode <= Opcode::OP_PUSHDATA4 {
            self.check_minimal_data_push(opcode)?;
        }

        let res = Opcode::execute(opcode, ref self);
        if res.is_err() {
            return Result::Err(res.unwrap_err());
        }
        self.check_stack_size()?;
        self.opcode_idx += 1;
        if self.opcode_idx >= script.len() {
            if self.cond_stack.len() > 0 {
                return Result::Err(Error::SCRIPT_UNBALANCED_CONDITIONAL_STACK);
            }
            self.astack = ScriptStackImpl::new();
            if self.dstack.verify_minimal_data {
                self.astack.verify_minimal_data = true;
            }
            self.opcode_idx = 0;
            self.last_code_sep = 0;
            self.script_idx += 1;
        }
        return Result::Ok(true);
    }

    fn execute(ref self: Engine<Transaction>) -> Result<ByteArray, felt252> {
        let mut err = '';
        // TODO: Optimize with != instead of < and check for bounds errors within the loop
        while self.script_idx < self.scripts.len() {
            let script: @ByteArray = *self.scripts[self.script_idx];
            while self.opcode_idx < script.len() {
                let opcode = script[self.opcode_idx];

                // Check if the opcode is always illegal (reserved).
                let illegal_opcode = Opcode::is_opcode_always_illegal(opcode, ref self);
                if illegal_opcode.is_err() {
                    err = illegal_opcode.unwrap_err();
                    break;
                }

                if opcode > Opcode::OP_16 {
                    self.num_ops += 1;
                    if self.num_ops > MAX_OPS_PER_SCRIPT {
                        err = Error::SCRIPT_TOO_MANY_OPERATIONS;
                        break;
                    }
                } else if Opcode::is_push_opcode(opcode) {
                    let res = self.push_data_len(opcode, self.opcode_idx);
                    if res.is_err() {
                        err = res.unwrap_err();
                        break;
                    }
                    if res.unwrap() > MAX_SCRIPT_ELEMENT_SIZE {
                        err = Error::SCRIPT_PUSH_SIZE;
                        break;
                    }
                }

                if !self.cond_stack.branch_executing() && !is_branching_opcode(opcode) {
                    if Opcode::is_data_opcode(opcode) {
                        let opcode_32: u32 = opcode.into();
                        self.opcode_idx += opcode_32 + 1;
                        continue;
                    } else if Opcode::is_push_opcode(opcode) {
                        let res = self.skip_push_data(opcode);
                        if res.is_err() {
                            err = res.unwrap_err();
                            break;
                        }
                        continue;
                    } else {
                        let res = Opcode::is_opcode_disabled(opcode, ref self);
                        if res.is_err() {
                            err = res.unwrap_err();
                            break;
                        }
                        self.opcode_idx += 1;
                        continue;
                    }
                }

                if self.dstack.verify_minimal_data
                    && self.cond_stack.branch_executing()
                    && opcode >= 0
                    && opcode <= Opcode::OP_PUSHDATA4 {
                    let res = self.check_minimal_data_push(opcode);
                    if res.is_err() {
                        err = res.unwrap_err();
                        break;
                    }
                }

                let res = Opcode::execute(opcode, ref self);
                if res.is_err() {
                    err = res.unwrap_err();
                    break;
                }
                let res = self.check_stack_size();
                if res.is_err() {
                    err = res.unwrap_err();
                    break;
                }
                self.opcode_idx += 1;
            };
            if err != '' {
                break;
            }
            if self.cond_stack.len() > 0 {
                err = Error::SCRIPT_UNBALANCED_CONDITIONAL_STACK;
                break;
            }
            self.astack = ScriptStackImpl::new();
            if self.dstack.verify_minimal_data {
                self.astack.verify_minimal_data = true;
            }
            self.num_ops = 0;
            self.opcode_idx = 0;
            if (self.script_idx == 1 && self.witness_program.len() != 0)
                || (self.script_idx == 2 && self.witness_program.len() != 0 && self.bip16) {
                self.script_idx += 1;
                let witness = self.transaction.transaction_inputs[self.tx_idx].witness;
                let res = self.verify_witness(witness.span());
                if res.is_err() {
                    err = res.unwrap_err();
                    break;
                }
            } else {
                self.script_idx += 1;
            }
            self.last_code_sep = 0;
            // TODO: other things
        };
        if err != '' {
            return Result::Err(err);
        }

        // TODO: CheckErrorCondition
        if self.is_witness_active(0) && self.dstack.len() != 1 { // TODO: Hardcoded 0
            return Result::Err(Error::SCRIPT_NON_CLEAN_STACK);
        }
        if self.has_flag(ScriptFlags::ScriptVerifyCleanStack) && self.dstack.len() != 1 {
            return Result::Err(Error::SCRIPT_NON_CLEAN_STACK);
        }

        if self.dstack.len() < 1 {
            return Result::Err(Error::SCRIPT_EMPTY_STACK);
        } else {
            // TODO: pop bool?
            let top_stack = self.dstack.peek_byte_array(0)?;
            let ret_val = top_stack.clone();
            let mut is_ok = false;
            let mut i = 0;
            while i != top_stack.len() {
                if top_stack[i] != 0 {
                    is_ok = true;
                    break;
                }
                i += 1;
            };
            if is_ok {
                return Result::Ok(ret_val);
            } else {
                return Result::Err(Error::SCRIPT_FAILED);
            }
        }
    }

    fn verify_witness(
        ref self: Engine<Transaction>, witness: Span<ByteArray>
    ) -> Result<(), felt252> {
        if self.is_witness_active(0) {
            // Verify a base witness (segwit) program, ie P2WSH || P2WPKH
            if self.witness_program.len() == 20 {
                // P2WPKH
                if witness.len() != 2 {
                    return Result::Err(Error::WITNESS_PROGRAM_INVALID);
                }
                // OP_DUP OP_HASH160 OP_DATA_20 <pkhash> OP_EQUALVERIFY OP_CHECKSIG
                let mut pk_script = hex_to_bytecode(@"0x76a914");
                pk_script.append(@self.witness_program);
                pk_script.append(@hex_to_bytecode(@"0x88ac"));

                self.scripts.append(@pk_script);
                self.dstack.set_stack(witness, 0, witness.len());
            } else if self.witness_program.len() == 32 {
                // P2WSH
                if witness.len() == 0 {
                    return Result::Err(Error::WITNESS_PROGRAM_INVALID);
                }
                let witness_script = witness[witness.len() - 1];
                if witness_script.len() > MAX_SCRIPT_SIZE {
                    return Result::Err(Error::SCRIPT_TOO_LARGE);
                }
                let witness_hash = sha256_byte_array(witness_script);
                if witness_hash != self.witness_program {
                    return Result::Err(Error::WITNESS_PROGRAM_INVALID);
                }

                self.scripts.append(witness_script);
                self.dstack.set_stack(witness, 0, witness.len() - 1);
            } else {
                return Result::Err(Error::WITNESS_PROGRAM_INVALID);
            }
            // Sanity checks
            let mut err = '';
            for w in self
                .dstack
                .stack_to_span() {
                    if w.len() > MAX_SCRIPT_ELEMENT_SIZE {
                        err = Error::SCRIPT_PUSH_SIZE;
                        break;
                    }
                };
            if err != '' {
                return Result::Err(err);
            }
        } else if self.is_witness_active(1) {
            // Verify a taproot witness program
            // TODO: Implement
            return Result::Err('Taproot not implemented');
        } else if self.has_flag(ScriptFlags::ScriptVerifyDiscourageUpgradeableWitnessProgram) {
            return Result::Err(Error::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
        } else {
            self.witness_program = "";
        }

        return Result::Ok(());
    }

    fn check_stack_size(ref self: Engine<Transaction>) -> Result<(), felt252> {
        if self.dstack.len() + self.astack.len() > MAX_STACK_SIZE {
            return Result::Err(Error::STACK_OVERFLOW);
        }
        return Result::Ok(());
    }

    fn check_minimal_data_push(ref self: Engine<Transaction>, opcode: u8) -> Result<(), felt252> {
        if opcode == Opcode::OP_0 {
            return Result::Ok(());
        }
        let script = *(self.scripts[self.script_idx]);
        if opcode == Opcode::OP_DATA_1 {
            let value: u8 = script.at(self.opcode_idx + 1).unwrap();
            if value <= 16 {
                // Should be OP_1 to OP_16
                return Result::Err(Error::MINIMAL_DATA);
            }
            if value == 0x81 {
                // Should be OP_1NEGATE
                return Result::Err(Error::MINIMAL_DATA);
            }
        }
        // TODO: More checks?
        if !Opcode::is_push_opcode(opcode) {
            return Result::Ok(());
        }

        let len = self.push_data_len(opcode, self.opcode_idx)?;
        if len <= 75 {
            // Should have used OP_DATA_X
            return Result::Err(Error::MINIMAL_DATA);
        } else if len <= 255 && opcode != Opcode::OP_PUSHDATA1 {
            // Should have used OP_PUSHDATA1
            return Result::Err(Error::MINIMAL_DATA);
        } else if len <= 65535 && opcode != Opcode::OP_PUSHDATA2 {
            // Should have used OP_PUSHDATA2
            return Result::Err(Error::MINIMAL_DATA);
        }
        return Result::Ok(());
    }

    fn json(ref self: Engine<Transaction>) {
        self.dstack.json();
    }
}

// File: ./packages/engine/src/scriptnum.cairo

// Wrapper around Bitcoin Script 'sign-magnitude' 4 byte integer.
pub mod ScriptNum {
    use crate::errors::Error;

    const BYTESHIFT: i64 = 256;
    const MAX_INT32: i32 = 2147483647;
    const MIN_INT32: i32 = -2147483647;

    fn check_minimal_data(input: @ByteArray) -> Result<(), felt252> {
        if input.len() == 0 {
            return Result::Ok(());
        }

        let last_element = input.at(input.len() - 1).unwrap();
        if last_element & 0x7F == 0 {
            if input.len() == 1 || input.at(input.len() - 2).unwrap() & 0x80 == 0 {
                return Result::Err(Error::MINIMAL_DATA);
            }
        }

        return Result::Ok(());
    }

    // Wrap i64 with a maximum size of 4 bytes. Can result in 5 byte array.
    pub fn wrap(mut input: i64) -> ByteArray {
        if input == 0 {
            return "";
        }

        // TODO
        // if input > MAX_INT32.into() || input < MIN_INT32.into() {
        //     return Result::Err(Error::SCRIPTNUM_OUT_OF_RANGE);
        // }

        let mut result: ByteArray = Default::default();
        let is_negative = {
            if input < 0 {
                input *= -1;
                true
            } else {
                false
            }
        };
        let unsigned: u64 = input.try_into().unwrap();
        let bytes_len: usize = integer_bytes_len(input.into());
        result.append_word_rev(unsigned.into(), bytes_len - 1);
        // Compute 'sign-magnitude' byte.
        let sign_byte: u8 = get_last_byte_of_uint(unsigned);
        if is_negative {
            if (sign_byte > 127) {
                result.append_byte(sign_byte);
                result.append_byte(128);
            } else {
                result.append_byte(sign_byte + 128);
            }
        } else {
            if (sign_byte > 127) {
                result.append_byte(sign_byte);
                result.append_byte(0);
            } else {
                result.append_byte(sign_byte);
            }
        }
        result
    }

    // Unwrap sign-magnitude encoded ByteArray into a 4 byte int maximum.
    pub fn try_into_num(input: ByteArray, minimal_required: bool) -> Result<i64, felt252> {
        let mut result: i64 = 0;
        let mut i: u32 = 0;
        let mut multiplier: i64 = 1;
        if minimal_required {
            check_minimal_data(@input)?;
        }

        if input.len() == 0 {
            return Result::Ok(0);
        }
        let snap_input = @input;
        while i != snap_input.len() - 1 {
            result += snap_input.at(i).unwrap().into() * multiplier;
            multiplier *= BYTESHIFT;
            i += 1;
        };
        // Recover value and sign from 'sign-magnitude' byte.
        let sign_byte: i64 = input.at(i).unwrap().into();
        if sign_byte >= 128 {
            result = (multiplier * (sign_byte - 128) * -1) - result;
        } else {
            result += sign_byte * multiplier;
        }
        if result > MAX_INT32.into() || result < MIN_INT32.into() {
            return Result::Err(Error::SCRIPTNUM_OUT_OF_RANGE);
        }
        Result::Ok(result)
    }

    pub fn into_num(input: ByteArray) -> i64 {
        try_into_num(input, false).unwrap()
    }

    pub fn unwrap(input: ByteArray) -> i64 {
        try_into_num(input, false).unwrap()
    }

    // Unwrap 'n' byte of sign-magnitude encoded ByteArray.
    pub fn try_into_num_n_bytes(
        input: ByteArray, n: usize, minimal_required: bool
    ) -> Result<i64, felt252> {
        let mut result: i64 = 0;
        let mut i: u32 = 0;
        let mut multiplier: i64 = 1;
        if minimal_required {
            check_minimal_data(@input)?;
        }
        if input.len() == 0 {
            return Result::Ok(0);
        }
        let snap_input = @input;
        while i != snap_input.len() - 1 {
            result += snap_input.at(i).unwrap().into() * multiplier;
            multiplier *= BYTESHIFT;
            i += 1;
        };
        // Recover value and sign from 'sign-magnitude' byte.
        let sign_byte: i64 = input.at(i).unwrap().into();
        if sign_byte >= 128 {
            result = (multiplier * (sign_byte - 128) * -1) - result;
        } else {
            result += sign_byte * multiplier;
        }
        if integer_bytes_len(result.into()) > n {
            return Result::Err(Error::SCRIPTNUM_OUT_OF_RANGE);
        }
        return Result::Ok(result);
    }

    pub fn into_num_n_bytes(input: ByteArray, n: usize) -> i64 {
        try_into_num_n_bytes(input, n, false).unwrap()
    }

    pub fn unwrap_n(input: ByteArray, n: usize) -> i64 {
        try_into_num_n_bytes(input, n, false).unwrap()
    }

    // Return the minimal number of byte to represent 'value'.
    fn integer_bytes_len(mut value: i128) -> usize {
        if value < 0 {
            value *= -1;
        }
        let mut power_byte = BYTESHIFT.try_into().unwrap();
        let mut bytes_len: usize = 1;
        while value >= power_byte {
            bytes_len += 1;
            power_byte *= 256;
        };
        bytes_len
    }

    // Return the value of the last byte of 'value'.
    fn get_last_byte_of_uint(mut value: u64) -> u8 {
        let byteshift = BYTESHIFT.try_into().unwrap();
        while value > byteshift {
            value = value / byteshift;
        };
        value.try_into().unwrap()
    }

    // Return i64 as an i32 within range [-2^31, 2^31 - 1].
    pub fn to_int32(mut n: i64) -> i32 {
        if n > MAX_INT32.into() {
            return MAX_INT32;
        }

        if n < MIN_INT32.into() {
            return MIN_INT32;
        }

        return n.try_into().unwrap();
    }
}

// File: ./packages/engine/src/opcodes/utils.cairo

pub fn abstract_verify<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let verified = engine.dstack.pop_bool()?;
    if !verified {
        return Result::Err(Error::VERIFY_FAILED);
    }
    Result::Ok(())
}

pub fn not_implemented<T>(ref engine: Engine<T>) -> Result<(), felt252> {
    return Result::Err(Error::OPCODE_NOT_IMPLEMENTED);
}

pub fn opcode_reserved<T>(msg: ByteArray, ref engine: Engine<T>) -> Result<(), felt252> {
    return Result::Err(Error::OPCODE_RESERVED);
}

pub fn opcode_disabled<T>(ref engine: Engine<T>) -> Result<(), felt252> {
    return Result::Err(Error::OPCODE_DISABLED);
}

// File: ./packages/engine/src/opcodes/locktime.cairo
//     EngineTransactionTrait, EngineTransactionInputTrait, EngineTransactionOutputTrait
// };

const LOCKTIME_THRESHOLD: u32 = 500000000; // Nov 5 00:53:20 1985 UTC
const SEQUENCE_LOCKTIME_DISABLED: u32 = 0x80000000;
const SEQUENCE_LOCKTIME_IS_SECOND: u32 = 0x00400000;
const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000FFFF;
const SEQUENCE_MAX: u32 = 0xFFFFFFFF;

fn verify_locktime(tx_locktime: i64, threshold: i64, stack_locktime: i64) -> Result<(), felt252> {
    // Check if 'tx_locktime' and 'locktime' are same type (locktime or height)
    if !((tx_locktime < threshold && stack_locktime < threshold)
        || (tx_locktime >= threshold && stack_locktime >= threshold)) {
        return Result::Err(Error::UNSATISFIED_LOCKTIME);
    }

    // Check validity
    if stack_locktime > tx_locktime {
        return Result::Err(Error::UNSATISFIED_LOCKTIME);
    }

    Result::Ok(())
}

pub fn opcode_checklocktimeverify<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    ref engine: Engine<T>
) -> Result<(), felt252> {
    if !engine.has_flag(ScriptFlags::ScriptVerifyCheckLockTimeVerify) {
        if engine.has_flag(ScriptFlags::ScriptDiscourageUpgradableNops) {
            return Result::Err(Error::SCRIPT_DISCOURAGE_UPGRADABLE_NOPS);
        }
        // Behave as OP_NOP
        return Result::Ok(());
    }

    let tx_locktime: i64 = EngineTransactionTrait::<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >::get_locktime(@engine.transaction)
        .into();
    // Get locktime as 5 byte integer because 'tx_locktime' is u32
    let stack_locktime: i64 = ScriptNum::try_into_num_n_bytes(
        engine.dstack.peek_byte_array(0)?, 5, engine.dstack.verify_minimal_data
    )?;

    if stack_locktime < 0 {
        return Result::Err(Error::UNSATISFIED_LOCKTIME);
    }

    // Check if tx sequence is not 'SEQUENCE_MAX' else if tx may be considered as finalized and the
    // behavior of OP_CHECKLOCKTIMEVERIFY can be bypassed
    let transaction_input = EngineTransactionTrait::<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >::get_transaction_inputs(@engine.transaction)
        .at(engine.tx_idx);
    let sequence = EngineTransactionInputTrait::<I>::get_sequence(transaction_input);
    if sequence == SEQUENCE_MAX {
        return Result::Err(Error::FINALIZED_TX_CLTV);
    }

    verify_locktime(tx_locktime, LOCKTIME_THRESHOLD.into(), stack_locktime)
}

pub fn opcode_checksequenceverify<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    ref engine: Engine<T>
) -> Result<(), felt252> {
    if !engine.has_flag(ScriptFlags::ScriptVerifyCheckSequenceVerify) {
        if engine.has_flag(ScriptFlags::ScriptDiscourageUpgradableNops) {
            return Result::Err(Error::SCRIPT_DISCOURAGE_UPGRADABLE_NOPS);
        }
        // Behave as OP_NOP
        return Result::Ok(());
    }

    // Get sequence as 5 byte integer because 'sequence' is u32
    let stack_sequence: i64 = ScriptNum::try_into_num_n_bytes(
        engine.dstack.peek_byte_array(0)?, 5, engine.dstack.verify_minimal_data
    )?;

    if stack_sequence < 0 {
        return Result::Err(Error::UNSATISFIED_LOCKTIME);
    }

    // Redefine 'stack_sequence' to perform bitwise operation easily
    let stack_sequence_u32: u32 = stack_sequence.try_into().unwrap();

    // Disabled bit set in 'stack_sequence' result as OP_NOP behavior
    if stack_sequence_u32 & SEQUENCE_LOCKTIME_DISABLED != 0 {
        return Result::Ok(());
    }

    // Prevent trigger OP_CHECKSEQUENCEVERIFY before tx version 2
    let version = EngineTransactionTrait::<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >::get_version(@engine.transaction);
    if version < 2 {
        return Result::Err(Error::INVALID_TX_VERSION);
    }

    let transaction_input = EngineTransactionTrait::<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >::get_transaction_inputs(@engine.transaction)
        .at(engine.tx_idx);
    let tx_sequence: u32 = EngineTransactionInputTrait::<I>::get_sequence(transaction_input);

    // Disabled bit set in 'tx_sequence' result is an error
    if tx_sequence & SEQUENCE_LOCKTIME_DISABLED != 0 {
        return Result::Err(Error::UNSATISFIED_LOCKTIME);
    }

    // Mask off non-consensus bits before comparisons
    let locktime_mask = SEQUENCE_LOCKTIME_IS_SECOND | SEQUENCE_LOCKTIME_MASK;
    verify_locktime(
        (tx_sequence & locktime_mask).into(),
        SEQUENCE_LOCKTIME_IS_SECOND.into(),
        (stack_sequence_u32 & locktime_mask).into()
    )
}

// File: ./packages/engine/src/opcodes/tests/test_constants.cairo
//     test_compile_and_run, test_compile_and_run_err, check_expected_dstack, check_dstack_size
// };

fn test_op_n(value: u8) {
    let program = format!("OP_{}", value);
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(value.into())];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_0() {
    let program = "OP_0";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_true() {
    let program = "OP_TRUE";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_n_all() {
    test_op_n(1);
    test_op_n(2);
    test_op_n(3);
    test_op_n(4);
    test_op_n(5);
    test_op_n(6);
    test_op_n(7);
    test_op_n(8);
    test_op_n(9);
    test_op_n(10);
    test_op_n(11);
    test_op_n(12);
    test_op_n(13);
    test_op_n(14);
    test_op_n(15);
    test_op_n(16);
}

#[test]
fn test_op_1negate() {
    let program = "OP_1NEGATE";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(-1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

fn test_op_data(value: u8) {
    let mut hex_data: ByteArray = "0x";
    let mut i = 0;
    while i != value {
        hex_data.append_word(int_to_hex(i + 1), 2);
        i += 1;
    };

    let program = format!("OP_DATA_{} {}", value, hex_data);
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@hex_data)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
#[available_gas(1000000000000)]
fn test_op_data_all() {
    let mut n = 1;

    while n != 76 {
        test_op_data(n);
        n += 1;
    }
}

#[test]
fn test_op_push_data1() {
    let program = "OP_PUSHDATA1 0x01 0x42";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0x42")];
    check_expected_dstack(ref engine, expected_stack.span());

    let program = "OP_PUSHDATA1 0x02 0x4243";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0x4243")];
    check_expected_dstack(ref engine, expected_stack.span());

    let program = "OP_PUSHDATA1 0x10 0x42434445464748494A4B4C4D4E4F5051";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0x42434445464748494A4B4C4D4E4F5051")];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_push_data2() {
    let program = "OP_PUSHDATA2 0x0100 0x42";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0x42")];
    check_expected_dstack(ref engine, expected_stack.span());
    let program = "OP_PUSHDATA2 0x0200 0x4243";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0x4243")];
    check_expected_dstack(ref engine, expected_stack.span());
    let byte_data: ByteArray =
        "0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";
    let program = format!("OP_PUSHDATA2 0x0001 {}", byte_data);
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@byte_data)];
    check_expected_dstack(ref engine, expected_stack.span());
    // Test error case: data bytes fewer than specified in length field
    let program: ByteArray = "OP_PUSHDATA2 0x0300 0x4243";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_INVALID);
    // fail to pull data so nothing is pushed into the dstack.
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_push_data4() {
    let program = "OP_PUSHDATA4 0x01000000 0x42";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0x42")];
    check_expected_dstack(ref engine, expected_stack.span());

    let program = "OP_PUSHDATA4 0x02000000 0x4243";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0x4243")];
    check_expected_dstack(ref engine, expected_stack.span());

    let byte_data: ByteArray =
        "0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";
    let program = format!("OP_PUSHDATA4 0x00010000 {}", byte_data);
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@byte_data)];
    check_expected_dstack(ref engine, expected_stack.span());

    // Test error case: data bytes fewer than specified in length field
    let program = "OP_PUSHDATA4 0x01 0x4243";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_INVALID);
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_pushdata1_in_if() {
    let program =
        "OP_0 OP_IF OP_PUSHDATA1 0x4c 0x81818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181 OP_ENDIF OP_1";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_pushdata1_in_if_with_disabled() {
    let program =
        "OP_0 OP_IF OP_PUSHDATA1 0x4c 0x8181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181 OP_ENDIF OP_1";
    let mut engine = test_compile_and_run_err(program, Error::OPCODE_DISABLED);
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_pushdata2_in_if() {
    let program =
        "OP_0 OP_IF OP_PUSHDATA2 0x4c00 0x81818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181 OP_ENDIF OP_1";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_pushdata4_in_if() {
    let program =
        "OP_0 OP_IF OP_PUSHDATA4 0x4c000000 0x81818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181 OP_ENDIF OP_1";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

// File: ./packages/engine/src/opcodes/tests/test_crypto.cairo
//     test_compile_and_run, check_expected_dstack, check_dstack_size,
//     test_compile_and_run_with_tx_flags_err, mock_transaction_legacy_p2ms,
//     test_compile_and_run_with_tx_err, test_compile_and_run_with_tx, mock_transaction_legacy_p2pkh
// };

#[test]
fn test_opcode_sha256_1() {
    let program = "OP_1 OP_SHA256";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let hex_data: ByteArray = hex_to_bytecode(
        @"0x4BF5122F344554C53BDE2EBB8CD2B7E3D1600AD631C385A5D7CCE23C7785459A"
    );
    let expected_dstack = array![hex_data];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_opcode_sha256_2() {
    let program = "OP_2 OP_SHA256";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let hex_data: ByteArray = hex_to_bytecode(
        @"0xDBC1B4C900FFE48D575B5DA5C638040125F65DB0FE3E24494B76EA986457D986"
    );
    let expected_dstack = array![hex_data];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_opcode_sha256_data_8() {
    let program = "OP_DATA_8 0x0102030405060708 OP_SHA256";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let hex_data: ByteArray = hex_to_bytecode(
        @"0x66840DDA154E8A113C31DD0AD32F7F3A366A80E8136979D8F5A101D3D29D6F72"
    );
    let expected_dstack = array![hex_data];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_opcode_sha256_push_data_2() {
    let byte_data: ByteArray =
        "0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";
    let program = format!("OP_PUSHDATA2 0x0001 {} OP_SHA256", byte_data);
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let hex_data: ByteArray = hex_to_bytecode(
        @"0x40AFF2E9D2D8922E47AFD4648E6967497158785FBD1DA870E7110266BF944880"
    );
    let expected_dstack = array![hex_data];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_opcode_sha256_14_double_sha256() {
    let program = "OP_14 OP_SHA256 OP_SHA256";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let hex_data: ByteArray = hex_to_bytecode(
        @"0xD6CDF7C9478A78B29F16C7E6DDCC5612E827BEAF6F4AEF7C1BB6FEF56BBB9A0F"
    );
    let expected_dstack = array![hex_data];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_hash160() {
    // 0x5368696E6967616D69 == 'Shinigami'
    let program = "OP_PUSHDATA1 0x09 0x5368696E6967616D69 OP_HASH160";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0x122ACAB01A6C742866AA84B2DD65870BC1210769")];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_hash160_1() {
    let program = "OP_1 OP_HASH160";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0xC51B66BCED5E4491001BD702669770DCCF440982")];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_hash160_2() {
    let program = "OP_2 OP_HASH160";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0xA6BB94C8792C395785787280DC188D114E1F339B")];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_hash160_data_8() {
    let program = "OP_DATA_8 0x0102030405060708 OP_HASH160";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0x16421b3d07efa2543203d69c093984eba95f9d0d")];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_hash160_push_data_2() {
    let byte_data: ByteArray =
        "0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";
    let program = format!("OP_PUSHDATA2 0x0001 {} OP_HASH160", byte_data);
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_dstack = array![hex_to_bytecode(@"0x07A536D93E0B9A779874E1287A226B8230CDA46E")];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_hash160_14_double_hash160() {
    let program = "OP_14 OP_HASH160 OP_HASH160";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0x03DD47CAF3B9A1EC04C224DB9CB0E6AE0FEEC59E")];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_hash256() {
    // 0x5368696E6967616D69 == 'Shinigami'
    let program = "OP_PUSHDATA1 0x09 0x5368696E6967616D69 OP_HASH256";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![
        hex_to_bytecode(@"0x39C02658ED1416713CF4098382E80D07786EED7004FC3FD89B38C7165FDABC80")
    ];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_hash256_1() {
    let program = "OP_1 OP_HASH256";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![
        hex_to_bytecode(@"0x9C12CFDC04C74584D787AC3D23772132C18524BC7AB28DEC4219B8FC5B425F70")
    ];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_hash256_2() {
    let program = "OP_2 OP_HASH256";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![
        hex_to_bytecode(@"0x1CC3ADEA40EBFD94433AC004777D68150CCE9DB4C771BC7DE1B297A7B795BBBA")
    ];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_hash256_data_8() {
    let program = "OP_DATA_8 0x0102030405060708 OP_HASH256";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![
        hex_to_bytecode(@"0x2502FA942289B144EDB4CD31C0313624C030885420A86363CE91589D78F8295A")
    ];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_hash256_push_data_2() {
    let byte_data: ByteArray =
        "0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";
    let program = format!("OP_PUSHDATA2 0x0001 {} OP_HASH256", byte_data);
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let hex_data: ByteArray = hex_to_bytecode(
        @"0x60BD11C69262F84DDFEA5F0D116D40AF862C4DD8C2A92FB90E368B132E8FA89C"
    );
    let expected_dstack = array![hex_data];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_hash256_14_double_hash256() {
    let program = "OP_14 OP_HASH256 OP_HASH256";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let hex_data: ByteArray = hex_to_bytecode(
        @"0x26AA6C7A9B46E9C409F09C179F7DEFF54F7AF5571D38DE5E5D9BA3932B91F55B"
    );
    let expected_dstack = array![hex_data];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_ripemd160() {
    // 0x5368696E6967616D69 == 'Shinigami'
    let program = "OP_PUSHDATA1 0x09 0x5368696E6967616D69 OP_RIPEMD160";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0xE51F342A8246B579DAE6B574D161345865E3CE3D")];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_ripemd160_1() {
    let program = "OP_1 OP_RIPEMD160";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0xF291BA5015DF348C80853FA5BB0F7946F5C9E1B3")];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_ripemd160_2() {
    let program = "OP_2 OP_RIPEMD160";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0x1E9955C5DBF77215CC79235668861E435FA2C3AB")];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_ripemd160_data_8() {
    let program = "OP_DATA_8 0x0102030405060708 OP_RIPEMD160";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0xC9883EECE7DCA619B830DC9D87E82C38478111C0")];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_ripemd160_push_data_2() {
    let byte_data: ByteArray =
        "0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";
    let program = format!("OP_PUSHDATA2 0x0001 {} OP_RIPEMD160", byte_data);
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let hex_data: ByteArray = hex_to_bytecode(@"0x9C4FA072DB2C871A5635E37F791E93AB45049676");
    let expected_dstack = array![hex_data];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_ripemd160_14_double_ripemd160() {
    let program = "OP_14 OP_RIPEMD160 OP_RIPEMD160";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0xA407E5C9190ACA4F4A6C676D130F5A72CEFB0D60")];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_checksig_valid() {
    let script_sig =
        "OP_DATA_71 0x3044022008f4f37e2d8f74e18c1b8fde2374d5f28402fb8ab7fd1cc5b786aa40851a70cb02201f40afd1627798ee8529095ca4b205498032315240ac322c9d8ff0f205a93a5801 OP_DATA_33 0x024aeaf55040fa16de37303d13ca1dde85f4ca9baa36e2963a27a1c0c1165fe2b1";
    let script_pubkey =
        "OP_DUP OP_HASH160 OP_DATA_20 0x4299ff317fcd12ef19047df66d72454691797bfc OP_EQUALVERIFY OP_CHECKSIG";
    let mut transaction = mock_transaction_legacy_p2pkh(script_sig);
    let mut engine = test_compile_and_run_with_tx(script_pubkey, transaction);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_checksig_wrong_signature() {
    let script_sig =
        "OP_DATA_71 0x3044022008f4f37e2d8f74f18c1b8fde2374d5f28402fb8ab7fd1cc5b786aa40851a70cb02201f40afd1627798ee8529095ca4b205498032315240ac322c9d8ff0f205a93a5801 OP_DATA_33 0x024aeaf55040fa16de37303d13ca1dde85f4ca9baa36e2963a27a1c0c1165fe2b1";
    let script_pubkey =
        "OP_DUP OP_HASH160 OP_DATA_20 0x4299ff317fcd12ef19047df66d72454691797bfc OP_EQUALVERIFY OP_CHECKSIG";
    let mut transaction = mock_transaction_legacy_p2pkh(script_sig);
    let mut engine = test_compile_and_run_with_tx_err(
        script_pubkey, transaction, Error::SCRIPT_FAILED
    );
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_checksig_invalid_hash_type() {
    let script_sig =
        "OP_DATA_71 0x3044022008f4f37e2d8f74e18c1b8fde2374d5f28402fb8ab7fd1cc5b786aa40851a70cb02201f40afd1627798ee8529095ca4b205498032315240ac322c9d8ff0f205a93a5807 OP_DATA_33 0x024aeaf55040fa16de37303d13ca1dde85f4ca9baa36e2963a27a1c0c1165fe2b1";
    let script_pubkey =
        "OP_DUP OP_HASH160 OP_DATA_20 0x4299ff317fcd12ef19047df66d72454691797bfc OP_EQUALVERIFY OP_CHECKSIG";
    let mut transaction = mock_transaction_legacy_p2pkh(script_sig);
    let mut engine = test_compile_and_run_with_tx_err(
        script_pubkey, transaction, Error::SCRIPT_FAILED
    );
    check_dstack_size(ref engine, 1);
    let expected_stack = array![""];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_checksig_empty_signature() {
    let script_sig =
        "OP_0 OP_DATA_33 0x024aeaf55040fa16de37303d13ca1dde85f4ca9baa36e2963a27a1c0c1165fe2b1";
    let script_pubkey =
        "OP_DUP OP_HASH160 OP_DATA_20 0x4299ff317fcd12ef19047df66d72454691797bfc OP_EQUALVERIFY OP_CHECKSIG";
    let mut transaction = mock_transaction_legacy_p2pkh(script_sig);
    let mut engine = test_compile_and_run_with_tx_err(
        script_pubkey, transaction, Error::SCRIPT_FAILED
    );
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_checksig_too_short_signature() {
    let script_sig =
        "OP_1 OP_DATA_33 0x024aeaf55040fa16de37303d13ca1dde85f4ca9baa36e2963a27a1c0c1165fe2b1";
    let script_pubkey =
        "OP_DUP OP_HASH160 OP_DATA_20 0x4299ff317fcd12ef19047df66d72454691797bfc OP_EQUALVERIFY OP_CHECKSIG";
    let mut transaction = mock_transaction_legacy_p2pkh(script_sig);
    let mut engine = test_compile_and_run_with_tx_err(
        script_pubkey, transaction, Error::SCRIPT_FAILED
    );
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_sha1() {
    // 0x5368696E6967616D69 == 'Shinigami'
    let program = "OP_PUSHDATA1 0x09 0x5368696E6967616D69 OP_SHA1";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0x845AD2AB31A509E064B49D2360EB2A5C39BE4856")];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_sha1_1() {
    let program = "OP_1 OP_SHA1";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0xBF8B4530D8D246DD74AC53A13471BBA17941DFF7")];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_sha1_2() {
    let program = "OP_2 OP_SHA1";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0xC4EA21BB365BBEEAF5F2C654883E56D11E43C44E")];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_sha1_data_8() {
    let program = "OP_DATA_8 0x0102030405060708 OP_SHA1";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0xDD5783BCF1E9002BC00AD5B83A95ED6E4EBB4AD5")];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_sha1_push_data_2() {
    let byte_data: ByteArray =
        "0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";
    let program = format!("OP_PUSHDATA2 0x0001 {} OP_SHA1", byte_data);
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let hex_data: ByteArray = hex_to_bytecode(@"0x4916D6BDB7F78E6803698CAB32D1586EA457DFC8");
    let expected_dstack = array![hex_data];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_sha1_14_double_sha1() {
    let program = "OP_14 OP_SHA1 OP_SHA1";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![hex_to_bytecode(@"0xC0BDFDD54F44A37833C74DA7613B87A5BA9A8452")];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_checkmultisig_valid() {
    let script_sig =
        "OP_0 OP_DATA_72 0x3045022100AF204EF91B8DBA5884DF50F87219CCEF22014C21DD05AA44470D4ED800B7F6E40220428FE058684DB1BB2BFB6061BFF67048592C574EFFC217F0D150DAEDCF36787601 OP_DATA_72 0x3045022100E8547AA2C2A2761A5A28806D3AE0D1BBF0AEFF782F9081DFEA67B86CACB321340220771A166929469C34959DAF726A2AC0C253F9AFF391E58A3C7CB46D8B7E0FDC4801";
    let script_pubkey =
        "OP_2 OP_DATA_65 0x04D81FD577272BBE73308C93009EEC5DC9FC319FC1EE2E7066E17220A5D47A18314578BE2FAEA34B9F1F8CA078F8621ACD4BC22897B03DAA422B9BF56646B342A2 OP_DATA_65 0x04EC3AFFF0B2B66E8152E9018FE3BE3FC92B30BF886B3487A525997D00FD9DA2D012DCE5D5275854ADC3106572A5D1E12D4211B228429F5A7B2F7BA92EB0475BB1 OP_DATA_65 0x04B49B496684B02855BC32F5DAEFA2E2E406DB4418F3B86BCA5195600951C7D918CDBE5E6D3736EC2ABF2DD7610995C3086976B2C0C7B4E459D10B34A316D5A5E7 OP_3 OP_CHECKMULTISIG";
    let mut transaction = mock_transaction_legacy_p2ms(script_sig);
    let mut engine = test_compile_and_run_with_tx(script_pubkey, transaction);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_checkmultisig_wrong_signature() {
    let script_sig =
        "OP_0 OP_DATA_72 0x3045022100AF204EF91B8DBA5884DF50F87229CCEF22014C21DD05AA44470D4ED800B7F6E40220428FE058684DB1BB2BFB6061BFF67048592C574EFFC217F0D150DAEDCF36787601 OP_DATA_72 0x3045022100E8547AA2C2A2761A5A28806D3AE0D1BBF0AEFF782F9081DFEA67B86CACB321340220771A166929469C34959DAF726A2AC0C253F9AFF391E58A3C7CB46D8B7E0FDC4801";
    let script_pubkey =
        "OP_2 OP_DATA_65 0x04D81FD577272BBE73308C93009EEC5DC9FC319FC1EE2E7066E17220A5D47A18314578BE2FAEA34B9F1F8CA078F8621ACD4BC22897B03DAA422B9BF56646B342A2 OP_DATA_65 0x04EC3AFFF0B2B66E8152E9018FE3BE3FC92B30BF886B3487A525997D00FD9DA2D012DCE5D5275854ADC3106572A5D1E12D4211B228429F5A7B2F7BA92EB0475BB1 OP_DATA_65 0x04B49B496684B02855BC32F5DAEFA2E2E406DB4418F3B86BCA5195600951C7D918CDBE5E6D3736EC2ABF2DD7610995C3086976B2C0C7B4E459D10B34A316D5A5E7 OP_3 OP_CHECKMULTISIG";
    let mut transaction = mock_transaction_legacy_p2ms(script_sig);
    let mut engine = test_compile_and_run_with_tx_err(
        script_pubkey, transaction, Error::SCRIPT_FAILED
    );
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_checkmultisig_not_enough_sig() {
    let script_sig =
        "OP_0 OP_DATA_72 0x3045022100E8547AA2C2A2761A5A28806D3AE0D1BBF0AEFF782F9081DFEA67B86CACB321340220771A166929469C34959DAF726A2AC0C253F9AFF391E58A3C7CB46D8B7E0FDC4801";
    let script_pubkey =
        "OP_2 OP_DATA_65 0x04D81FD577272BBE73308C93009EEC5DC9FC319FC1EE2E7066E17220A5D47A18314578BE2FAEA34B9F1F8CA078F8621ACD4BC22897B03DAA422B9BF56646B342A2 OP_DATA_65 0x04EC3AFFF0B2B66E8152E9018FE3BE3FC92B30BF886B3487A525997D00FD9DA2D012DCE5D5275854ADC3106572A5D1E12D4211B228429F5A7B2F7BA92EB0475BB1 OP_DATA_65 0x04B49B496684B02855BC32F5DAEFA2E2E406DB4418F3B86BCA5195600951C7D918CDBE5E6D3736EC2ABF2DD7610995C3086976B2C0C7B4E459D10B34A316D5A5E7 OP_3 OP_CHECKMULTISIG";
    let mut transaction = mock_transaction_legacy_p2ms(script_sig);
    test_compile_and_run_with_tx_err(script_pubkey, transaction, Error::STACK_UNDERFLOW);
}

// Good signatures but bad order. Signatures must be in the same order as public keys.
#[test]
fn test_op_checkmultisig_bad_order() {
    let script_sig =
        "OP_0 OP_DATA_72 0x3045022100E8547AA2C2A2761A5A28806D3AE0D1BBF0AEFF782F9081DFEA67B86CACB321340220771A166929469C34959DAF726A2AC0C253F9AFF391E58A3C7CB46D8B7E0FDC4801 OP_DATA_72 0x3045022100AF204EF91B8DBA5884DF50F87219CCEF22014C21DD05AA44470D4ED800B7F6E40220428FE058684DB1BB2BFB6061BFF67048592C574EFFC217F0D150DAEDCF36787601";
    let script_pubkey =
        "OP_2 OP_DATA_65 0x04D81FD577272BBE73308C93009EEC5DC9FC319FC1EE2E7066E17220A5D47A18314578BE2FAEA34B9F1F8CA078F8621ACD4BC22897B03DAA422B9BF56646B342A2 OP_DATA_65 0x04EC3AFFF0B2B66E8152E9018FE3BE3FC92B30BF886B3487A525997D00FD9DA2D012DCE5D5275854ADC3106572A5D1E12D4211B228429F5A7B2F7BA92EB0475BB1 OP_DATA_65 0x04B49B496684B02855BC32F5DAEFA2E2E406DB4418F3B86BCA5195600951C7D918CDBE5E6D3736EC2ABF2DD7610995C3086976B2C0C7B4E459D10B34A316D5A5E7 OP_3 OP_CHECKMULTISIG";
    let mut transaction = mock_transaction_legacy_p2ms(script_sig);
    let mut engine = test_compile_and_run_with_tx_err(
        script_pubkey, transaction, Error::SCRIPT_FAILED
    );
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

// Test fail if dummy (OP_CHECKMULTISIG bug) is not present
#[test]
fn test_op_checkmultisig_miss_dummy() {
    let script_sig =
        "OP_DATA_72 0x3045022100AF204EF91B8DBA5884DF50F87219CCEF22014C21DD05AA44470D4ED800B7F6E40220428FE058684DB1BB2BFB6061BFF67048592C574EFFC217F0D150DAEDCF36787601 OP_DATA_72 0x3045022100E8547AA2C2A2761A5A28806D3AE0D1BBF0AEFF782F9081DFEA67B86CACB321340220771A166929469C34959DAF726A2AC0C253F9AFF391E58A3C7CB46D8B7E0FDC4801";
    let script_pubkey =
        "OP_2 OP_DATA_65 0x04D81FD577272BBE73308C93009EEC5DC9FC319FC1EE2E7066E17220A5D47A18314578BE2FAEA34B9F1F8CA078F8621ACD4BC22897B03DAA422B9BF56646B342A2 OP_DATA_65 0x04EC3AFFF0B2B66E8152E9018FE3BE3FC92B30BF886B3487A525997D00FD9DA2D012DCE5D5275854ADC3106572A5D1E12D4211B228429F5A7B2F7BA92EB0475BB1 OP_DATA_65 0x04B49B496684B02855BC32F5DAEFA2E2E406DB4418F3B86BCA5195600951C7D918CDBE5E6D3736EC2ABF2DD7610995C3086976B2C0C7B4E459D10B34A316D5A5E7 OP_3 OP_CHECKMULTISIG";
    let mut transaction = mock_transaction_legacy_p2ms(script_sig);
    test_compile_and_run_with_tx_err(script_pubkey, transaction, Error::STACK_UNDERFLOW);
}

// Test fail if dummy is not an empty ByteArray with the flag 'ScriptScriptMultiSig'
#[test]
fn test_op_checkmultisig_dummy_not_zero() {
    let script_sig =
        "OP_1 OP_DATA_72 0x3045022100AF204EF91B8DBA5884DF50F87219CCEF22014C21DD05AA44470D4ED800B7F6E40220428FE058684DB1BB2BFB6061BFF67048592C574EFFC217F0D150DAEDCF36787601 OP_DATA_72 0x3045022100E8547AA2C2A2761A5A28806D3AE0D1BBF0AEFF782F9081DFEA67B86CACB321340220771A166929469C34959DAF726A2AC0C253F9AFF391E58A3C7CB46D8B7E0FDC4801";
    let script_pubkey =
        "OP_2 OP_DATA_65 0x04D81FD577272BBE73308C93009EEC5DC9FC319FC1EE2E7066E17220A5D47A18314578BE2FAEA34B9F1F8CA078F8621ACD4BC22897B03DAA422B9BF56646B342A2 OP_DATA_65 0x04EC3AFFF0B2B66E8152E9018FE3BE3FC92B30BF886B3487A525997D00FD9DA2D012DCE5D5275854ADC3106572A5D1E12D4211B228429F5A7B2F7BA92EB0475BB1 OP_DATA_65 0x04B49B496684B02855BC32F5DAEFA2E2E406DB4418F3B86BCA5195600951C7D918CDBE5E6D3736EC2ABF2DD7610995C3086976B2C0C7B4E459D10B34A316D5A5E7 OP_3 OP_CHECKMULTISIG";
    let mut transaction = mock_transaction_legacy_p2ms(script_sig);
    let mut engine = test_compile_and_run_with_tx_flags_err(
        script_pubkey,
        transaction,
        ScriptFlags::ScriptStrictMultiSig.into(),
        Error::SCRIPT_STRICT_MULTISIG
    );
    check_dstack_size(ref engine, 0);
}

// File: ./packages/engine/src/opcodes/tests/utils.cairo

// Runs a basic bitcoin script as the script_pubkey with empty script_sig
pub fn test_compile_and_run(program: ByteArray) -> Engine<Transaction> {
    let mut compiler = CompilerImpl::new();
    let bytecode = compiler.compile(program).unwrap();
    // TODO: Nullable
    let mut engine = EngineInternalImpl::new(@bytecode, Default::default(), 0, 0, 0).unwrap();
    let res = EngineInternalTrait::execute(ref engine);
    assert!(res.is_ok(), "Execution of the program failed");
    engine
}

// Runs a bitcoin script `program` as script_pubkey with corresponding `transaction`
pub fn test_compile_and_run_with_tx(
    program: ByteArray, transaction: Transaction
) -> Engine<Transaction> {
    let mut compiler = CompilerImpl::new();
    let mut bytecode = compiler.compile(program).unwrap();
    let mut engine = EngineInternalImpl::new(@bytecode, transaction, 0, 0, 0).unwrap();
    let res = engine.execute();
    assert!(res.is_ok(), "Execution of the program failed");
    engine
}

// Runs a bitcoin script `program` as script_pubkey with corresponding `transaction` and 'flags'
pub fn test_compile_and_run_with_tx_flags(
    program: ByteArray, transaction: Transaction, flags: u32
) -> Engine<Transaction> {
    let mut compiler = CompilerImpl::new();
    let mut bytecode = compiler.compile(program).unwrap();
    let mut engine = EngineInternalImpl::new(@bytecode, transaction, 0, flags, 0).unwrap();
    let res = engine.execute();
    assert!(res.is_ok(), "Execution of the program failed");
    engine
}

// Runs a bitcoin script `program` as script_pubkey with empty script_sig expecting an error
pub fn test_compile_and_run_err(program: ByteArray, expected_err: felt252) -> Engine<Transaction> {
    let mut compiler = CompilerImpl::new();
    let bytecode = compiler.compile(program).unwrap();
    let mut engine = EngineInternalImpl::new(@bytecode, Default::default(), 0, 0, 0).unwrap();
    let res = engine.execute();
    assert!(res.is_err(), "Execution of the program did not fail as expected");
    let err = res.unwrap_err();
    assert_eq!(err, expected_err, "Program did not return the expected error");
    engine
}

// Runs a bitcoin script `program` as script_pubkey with corresponding `transaction` expecting an
// error
pub fn test_compile_and_run_with_tx_err(
    program: ByteArray, transaction: Transaction, expected_err: felt252
) -> Engine<Transaction> {
    let mut compiler = CompilerImpl::new();
    let mut bytecode = compiler.compile(program).unwrap();
    let mut engine = EngineInternalImpl::new(@bytecode, transaction, 0, 0, 0).unwrap();
    let res = engine.execute();
    assert!(res.is_err(), "Execution of the program did not fail as expected");
    let err = res.unwrap_err();
    assert_eq!(err, expected_err, "Program did not return the expected error");
    engine
}

// Runs a bitcoin script `program` as script_pubkey with corresponding `transaction` and 'flags'
// expecting an error
pub fn test_compile_and_run_with_tx_flags_err(
    program: ByteArray, transaction: Transaction, flags: u32, expected_err: felt252
) -> Engine<Transaction> {
    let mut compiler = CompilerImpl::new();
    let mut bytecode = compiler.compile(program).unwrap();
    let mut engine = EngineInternalImpl::new(@bytecode, transaction, 0, flags, 0).unwrap();
    let res = engine.execute();
    assert!(res.is_err(), "Execution of the program did not fail as expected");
    let err = res.unwrap_err();
    assert_eq!(err, expected_err, "Program did not return the expected error");
    engine
}

pub fn check_dstack_size(ref engine: Engine<Transaction>, expected_size: usize) {
    let dstack = engine.get_dstack();
    assert_eq!(dstack.len(), expected_size, "Dstack size is not as expected");
}

pub fn check_astack_size(ref engine: Engine<Transaction>, expected_size: usize) {
    let astack = engine.get_astack();
    assert_eq!(astack.len(), expected_size, "Astack size is not as expected");
}

pub fn check_expected_dstack(ref engine: Engine<Transaction>, expected: Span<ByteArray>) {
    let dstack = engine.get_dstack();
    assert_eq!(dstack, expected, "Dstack is not as expected");
}

pub fn check_expected_astack(ref engine: Engine<Transaction>, expected: Span<ByteArray>) {
    let astack = engine.get_astack();
    assert_eq!(astack, expected, "Astack is not as expected");
}

pub fn mock_transaction_input_with(
    outpoint: OutPoint, script_sig: ByteArray, witness: Array<ByteArray>, sequence: u32
) -> TransactionInput {
    let mut compiler = CompilerImpl::new();
    let script_sig = compiler.compile(script_sig).unwrap();
    TransactionInput {
        previous_outpoint: outpoint,
        signature_script: script_sig,
        witness: witness,
        sequence: sequence
    }
}

pub fn mock_transaction_input(script_sig: ByteArray) -> TransactionInput {
    let outpoint: OutPoint = OutPoint {
        txid: 0xb7994a0db2f373a29227e1d90da883c6ce1cb0dd2d6812e4558041ebbbcfa54b, vout: 0
    };
    mock_transaction_input_with(outpoint, script_sig, ArrayTrait::new(), 0xffffffff)
}

pub fn mock_transaction_output_with(value: i64, script_pubkey: ByteArray) -> TransactionOutput {
    TransactionOutput { value: value, publickey_script: script_pubkey }
}

pub fn mock_transaction_output() -> TransactionOutput {
    let output_script_u256: u256 = 0x76a914b3e2819b6262e0b1f19fc7229d75677f347c91ac88ac;
    let mut output_script: ByteArray = "";
    output_script.append_word(output_script_u256.high.into(), 9);
    output_script.append_word(output_script_u256.low.into(), 16);
    mock_transaction_output_with(15000, output_script)
}

pub fn mock_transaction_with(
    version: i32,
    tx_inputs: Array<TransactionInput>,
    tx_outputs: Array<TransactionOutput>,
    locktime: u32
) -> Transaction {
    Transaction {
        version: version,
        transaction_inputs: tx_inputs,
        transaction_outputs: tx_outputs,
        locktime: locktime,
    }
}

// Mock simple transaction '1d5308ff12cb6fdb670c3af673a6a1317e21fa14fc863d5827f9d704cd5e14dc'
pub fn mock_transaction(script_sig: ByteArray) -> Transaction {
    let mut inputs = ArrayTrait::<TransactionInput>::new();
    inputs.append(mock_transaction_input(script_sig));
    let mut outputs = ArrayTrait::<TransactionOutput>::new();
    outputs.append(mock_transaction_output());
    return mock_transaction_with(1, inputs, outputs, 0);
}

// Mock transaction '1d5308ff12cb6fdb670c3af673a6a1317e21fa14fc863d5827f9d704cd5e14dc'
// Legacy P2PKH
pub fn mock_transaction_legacy_p2pkh(script_sig: ByteArray) -> Transaction {
    mock_transaction(script_sig)
}

// Mock transaction '949591ad468cef5c41656c0a502d9500671ee421fadb590fbc6373000039b693'
// Legacy P2MS
pub fn mock_transaction_legacy_p2ms(script_sig: ByteArray) -> Transaction {
    let outpoint: OutPoint = OutPoint {
        txid: 0x10a5fee9786a9d2d72c25525e52dd70cbd9035d5152fac83b62d3aa7e2301d58, vout: 0
    };
    let mut inputs = ArrayTrait::<TransactionInput>::new();
    inputs.append(mock_transaction_input_with(outpoint, script_sig, ArrayTrait::new(), 0xffffffff));

    let mut outputs = ArrayTrait::<TransactionOutput>::new();
    let output_script_u256: u256 = 0x76a914971802edf585cdbc4e57017d6e5142515c1e502888ac;
    let mut output_script: ByteArray = "";
    output_script.append_word(output_script_u256.high.into(), 9);
    output_script.append_word(output_script_u256.low.into(), 16);
    outputs.append(mock_transaction_output_with(1680000, output_script));

    return mock_transaction_with(1, inputs, outputs, 0);
}

pub fn mock_witness_transaction() -> Transaction {
    let outpoint_0: OutPoint = OutPoint {
        txid: 0xac4994014aa36b7f53375658ef595b3cb2891e1735fe5b441686f5e53338e76a, vout: 1
    };
    let transaction_input_0: TransactionInput = TransactionInput {
        previous_outpoint: outpoint_0,
        signature_script: "",
        witness: ArrayTrait::<ByteArray>::new(),
        sequence: 0xffffffff
    };
    let mut transaction_inputs: Array<TransactionInput> = ArrayTrait::<TransactionInput>::new();
    transaction_inputs.append(transaction_input_0);
    let script_u256: u256 = 0x76a914ce72abfd0e6d9354a660c18f2825eb392f060fdc88ac;
    let mut script_byte: ByteArray = "";

    script_byte.append_word(script_u256.high.into(), 9);
    script_byte.append_word(script_u256.low.into(), 16);

    let output_0: TransactionOutput = TransactionOutput {
        value: 15000, publickey_script: script_byte
    };
    let mut transaction_outputs: Array<TransactionOutput> = ArrayTrait::<TransactionOutput>::new();
    transaction_outputs.append(output_0);

    Transaction {
        version: 2,
        transaction_inputs: transaction_inputs,
        transaction_outputs: transaction_outputs,
        locktime: 0,
    }
}

// Mock transaction with specified 'locktime' and with the 'sequence' field set to locktime
pub fn mock_transaction_legacy_locktime(script_sig: ByteArray, locktime: u32) -> Transaction {
    let mut inputs = ArrayTrait::<TransactionInput>::new();
    let outpoint = OutPoint { txid: 0, vout: 0 };
    let input = mock_transaction_input_with(outpoint, script_sig, ArrayTrait::new(), 0xfffffffe);
    inputs.append(input);
    let outputs = ArrayTrait::<TransactionOutput>::new();
    return mock_transaction_with(1, inputs, outputs, locktime);
}

// Mock transaction version 2 with the specified 'sequence'
pub fn mock_transaction_legacy_sequence_v2(script_sig: ByteArray, sequence: u32) -> Transaction {
    let mut inputs = ArrayTrait::<TransactionInput>::new();
    let outpoint = OutPoint { txid: 0, vout: 0 };
    let input = mock_transaction_input_with(outpoint, script_sig, ArrayTrait::new(), sequence);
    inputs.append(input);
    let outputs = ArrayTrait::<TransactionOutput>::new();
    return mock_transaction_with(2, inputs, outputs, 0);
}

// File: ./packages/engine/src/opcodes/tests/test_bitwise.cairo

#[test]
fn test_op_equal() {
    let program = "OP_1 OP_1 OP_EQUAL";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_equal_false() {
    let program = "OP_0 OP_1 OP_EQUAL";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

// File: ./packages/engine/src/opcodes/tests/test_reserved.cairo

#[test]
fn test_op_reserved() {
    let program = "OP_RESERVED";
    let mut engine = test_compile_and_run_err(program, Error::OPCODE_RESERVED);
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_reserved1() {
    let program = "OP_RESERVED1";
    let mut engine = test_compile_and_run_err(program, Error::OPCODE_RESERVED);
    check_dstack_size(ref engine, 0);
}


#[test]
fn test_op_reserved2() {
    let program = "OP_RESERVED2";
    let mut engine = test_compile_and_run_err(program, Error::OPCODE_RESERVED);
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_ver() {
    let program = "OP_VER";
    let mut engine = test_compile_and_run_err(program, Error::OPCODE_RESERVED);
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_verif() {
    let program = "OP_VERIF";
    let mut engine = test_compile_and_run_err(program, Error::OPCODE_RESERVED);
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_vernotif() {
    let program = "OP_VERNOTIF";
    let mut engine = test_compile_and_run_err(program, Error::OPCODE_RESERVED);
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_verif_if() {
    let program = "OP_0 OP_IF OP_VERIF OP_ENDIF OP_1";
    let mut engine = test_compile_and_run_err(program, Error::OPCODE_RESERVED);
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_vernotif_if() {
    let program = "OP_0 OP_IF OP_VERNOTIF OP_ENDIF OP_1";
    let mut engine = test_compile_and_run_err(program, Error::OPCODE_RESERVED);
    check_dstack_size(ref engine, 0);
}

// File: ./packages/engine/src/opcodes/tests/test_disabled.cairo

// TODO is there a way to define this as a const?
fn disabled_opcodes() -> core::array::Array<ByteArray> {
    let mut disabled_opcodes = ArrayTrait::<ByteArray>::new();
    disabled_opcodes.append("OP_CAT");
    disabled_opcodes.append("OP_SUBSTR");
    disabled_opcodes.append("OP_LEFT");
    disabled_opcodes.append("OP_RIGHT");
    disabled_opcodes.append("OP_INVERT");
    disabled_opcodes.append("OP_AND");
    disabled_opcodes.append("OP_OR");
    disabled_opcodes.append("OP_XOR");
    disabled_opcodes.append("OP_2MUL");
    disabled_opcodes.append("OP_2DIV");
    disabled_opcodes.append("OP_MUL");
    disabled_opcodes.append("OP_DIV");
    disabled_opcodes.append("OP_MOD");
    disabled_opcodes.append("OP_LSHIFT");
    disabled_opcodes.append("OP_RSHIFT");
    disabled_opcodes
}

#[test]
fn test_op_code_disabled() {
    let disabled_opcodes = disabled_opcodes();
    let mut i: usize = 0;
    while i != disabled_opcodes.len() {
        let mut engine = test_compile_and_run_err(
            disabled_opcodes.at(i).clone(), Error::OPCODE_DISABLED
        );
        check_dstack_size(ref engine, 0);
        i += 1;
    }
}

#[test]
fn test_disabled_opcodes_if_block() {
    let disabled_opcodes = disabled_opcodes();
    let mut i: usize = 0;
    while i != disabled_opcodes.len() {
        let program = format!(
            "OP_1 OP_IF {} OP_ELSE OP_DROP OP_ENDIF", disabled_opcodes.at(i).clone()
        );
        let mut engine = test_compile_and_run_err(program, Error::OPCODE_DISABLED);
        check_dstack_size(ref engine, 0);
        i += 1;
    }
}

#[test]
fn test_disabled_opcodes_else_block() {
    let disabled_opcodes = disabled_opcodes();
    let mut i: usize = 0;
    while i != disabled_opcodes.len() {
        let program = format!(
            "OP_0 OP_IF OP_DROP OP_ELSE {} OP_ENDIF", disabled_opcodes.at(i).clone()
        );
        let mut engine = test_compile_and_run_err(program, Error::OPCODE_DISABLED);
        check_dstack_size(ref engine, 0);
        i += 1;
    }
}


#[test]
fn test_disabled_opcode_in_unexecd_if_block() {
    let disabled_opcodes = disabled_opcodes();
    let mut i: usize = 0;
    while i != disabled_opcodes.len() {
        let program = format!(
            "OP_0 OP_IF {} OP_ELSE OP_DROP OP_ENDIF", disabled_opcodes.at(i).clone()
        );
        let mut engine = test_compile_and_run_err(program, Error::OPCODE_DISABLED);
        check_dstack_size(ref engine, 0);
        i += 1;
    }
}

// File: ./packages/engine/src/opcodes/tests/test_locktime.cairo

#[test]
fn test_opcode_checklocktime() {
    let mut program =
        "OP_DATA_4 0x8036BE26 OP_CHECKLOCKTIMEVERIFY"; // 0x8036BE26 == 650000000 in ScriptNum
    let mut tx = mock_transaction_legacy_locktime("", 700000000);

    let flags: u32 = ScriptFlags::ScriptVerifyCheckLockTimeVerify.into();
    let mut engine = test_compile_and_run_with_tx_flags(program, tx, flags);
    check_dstack_size(ref engine, 1);
}

#[test]
fn test_opcode_checklocktime_unsatisfied_fail() {
    let mut program =
        "OP_DATA_4 0x8036BE26 OP_CHECKLOCKTIMEVERIFY"; // 0x8036BE26 == 650000000 in ScriptNum
    let mut tx = mock_transaction_legacy_locktime("", 600000000);

    let flags: u32 = ScriptFlags::ScriptVerifyCheckLockTimeVerify.into();
    let mut engine = test_compile_and_run_with_tx_flags_err(
        program, tx, flags, Error::UNSATISFIED_LOCKTIME
    );
    check_dstack_size(ref engine, 1);
}

#[test]
fn test_opcode_checklocktime_block() {
    let program = "OP_16 OP_CHECKLOCKTIMEVERIFY";

    let mut tx = mock_transaction_legacy_locktime("", 20);

    let flags: u32 = ScriptFlags::ScriptVerifyCheckLockTimeVerify.into();
    let mut engine = test_compile_and_run_with_tx_flags(program, tx, flags);
    check_dstack_size(ref engine, 1);
}

// This test has value who failed with opcdoe checklocktimeverify but necessary flag is not set
// so OP_CHECKLOCKTIMEVERIFY behave as OP_NOP
#[test]
fn test_opcode_checklocktime_as_op_nop() {
    let program = "OP_16 OP_CHECKLOCKTIMEVERIFY";

    let mut tx = mock_transaction_legacy_locktime("", 10);

    // Running without the flag 'ScriptVerifyCheckLockTimeVerify' result as OP_NOP
    let mut engine = test_compile_and_run_with_tx(program, tx);
    check_dstack_size(ref engine, 1);
}

// The 'ScriptVerifyCheckLockTimeVerify' flag isn't set but 'ScriptDiscourageUpgradable' is. Should
// result as an error
#[test]
fn test_opcode_checklocktime_as_op_nop_fail() {
    let program = "OP_16 OP_CHECKLOCKTIMEVERIFY";

    let mut tx = mock_transaction_legacy_locktime("", 10);

    // Running without the flag 'ScriptVerifyCheckLockTimeVerify' result as OP_NOP behavior
    // 'ScriptDiscourageUpgradableNops' prevents to have OP_NOP behavior
    let flags: u32 = ScriptFlags::ScriptDiscourageUpgradableNops.into();
    let mut engine = test_compile_and_run_with_tx_flags_err(
        program, tx, flags, Error::SCRIPT_DISCOURAGE_UPGRADABLE_NOPS
    );
    check_dstack_size(ref engine, 1);
}

#[test]
fn test_opcode_checklocktime_max_sequence_fail() {
    let mut program =
        "OP_DATA_4 0x8036BE26 OP_CHECKLOCKTIMEVERIFY"; // 0x8036BE26 == 650000000 in ScriptNum
    // By default the sequence field is set to 0xFFFFFFFF
    let mut tx = mock_transaction("");
    tx.locktime = 700000000;

    let flags: u32 = ScriptFlags::ScriptVerifyCheckLockTimeVerify.into();
    let mut engine = test_compile_and_run_with_tx_flags_err(
        program, tx, flags, Error::FINALIZED_TX_CLTV
    );
    check_dstack_size(ref engine, 1);
}

#[test]
fn test_opcode_checksequence_block() {
    let mut program =
        "OP_DATA_4 0x40000000 OP_CHECKSEQUENCEVERIFY"; // 0x40000000 == 64 in ScriptNum
    let tx = mock_transaction_legacy_sequence_v2("", 2048);

    let flags: u32 = ScriptFlags::ScriptVerifyCheckSequenceVerify.into();
    let mut engine = test_compile_and_run_with_tx_flags(program, tx, flags);
    check_dstack_size(ref engine, 1);
}

#[test]
fn test_opcode_checksequence_time() {
    let mut program =
        "OP_DATA_4 0x00004000 OP_CHECKSEQUENCEVERIFY"; // 0x00004000 == 4194304 in ScriptNum
    let tx = mock_transaction_legacy_sequence_v2("", 5000000);

    let flags: u32 = ScriptFlags::ScriptVerifyCheckSequenceVerify.into();
    let mut engine = test_compile_and_run_with_tx_flags(program, tx, flags);
    check_dstack_size(ref engine, 1);
}

#[test]
fn test_opcode_checksequence_fail() {
    let mut program =
        "OP_DATA_4 0x40400000 OP_CHECKSEQUENCEVERIFY"; // 0x40400000 == 16448 in ScriptNum
    let tx = mock_transaction_legacy_sequence_v2("", 2048);

    let flags: u32 = ScriptFlags::ScriptVerifyCheckSequenceVerify.into();
    let mut engine = test_compile_and_run_with_tx_flags_err(
        program, tx, flags, Error::UNSATISFIED_LOCKTIME
    );
    check_dstack_size(ref engine, 1);
}

// This test has value who failed with opcdoe checksequenceverify but necessary flag is not set so
// OP_CHECKSEQUENCEVERIFY behave as OP_NOP
#[test]
fn test_opcode_checksequence_as_op_nop() {
    let mut program =
        "OP_DATA_4 0x40400000 OP_CHECKSEQUENCEVERIFY"; // 0x40400000 == 16448 in ScriptNum
    let tx = mock_transaction_legacy_sequence_v2("", 2048);

    // Running without the flag 'ScriptVerifyCheckLockTimeVerify' result as OP_NOP
    let mut engine = test_compile_and_run_with_tx(program, tx);
    check_dstack_size(ref engine, 1);
}

// The 'ScriptVerifyCheckSequenceVerify' flag isn't set but 'ScriptDiscourageUpgradable' is. Should
// result as an error
#[test]
fn test_opcode_checksequence_as_op_nop_fail() {
    let mut program =
        "OP_DATA_4 0x40400000 OP_CHECKSEQUENCEVERIFY"; // 0x40400000 == 16448 in ScriptNum
    let mut tx = mock_transaction_legacy_sequence_v2("", 2048);

    // Running without the flag 'ScriptVerifyCheckSequenceVerify' result as OP_NOP behavior
    // 'ScriptDiscourageUpgradableNops' prevents to have OP_NOP behavior
    let flags: u32 = ScriptFlags::ScriptDiscourageUpgradableNops.into();
    let mut engine = test_compile_and_run_with_tx_flags_err(
        program, tx, flags, Error::SCRIPT_DISCOURAGE_UPGRADABLE_NOPS
    );
    check_dstack_size(ref engine, 1);
}

#[test]
fn test_opcode_checksequence_tx_version_fail() {
    let mut program =
        "OP_DATA_4 0x40000000 OP_CHECKSEQUENCEVERIFY"; // 0x40000000 == 64 in ScriptNum
    let mut tx = mock_transaction("");

    // Running with tx v1
    let flags: u32 = ScriptFlags::ScriptVerifyCheckSequenceVerify.into();
    let mut engine = test_compile_and_run_with_tx_flags_err(
        program, tx, flags, Error::INVALID_TX_VERSION
    );
    check_dstack_size(ref engine, 1);
}

#[test]
fn test_opcode_checksequence_disabled_bit_stack() {
    let mut program = "OP_DATA_4 0x80000000 OP_CHECKSEQUENCEVERIFY";
    let tx = mock_transaction_legacy_sequence_v2("", 2048);

    let flags: u32 = ScriptFlags::ScriptVerifyCheckSequenceVerify.into();
    let mut engine = test_compile_and_run_with_tx_flags(program, tx, flags);
    check_dstack_size(ref engine, 1);
}

#[test]
fn test_opcode_checksequence_disabled_bit_tx_fail() {
    let mut program =
        "OP_DATA_4 0x00004000 OP_CHECKSEQUENCEVERIFY"; // 0x00004000 == 4194304 in ScriptNum
    let mut tx = mock_transaction_legacy_sequence_v2("", 2147483648);

    // Run with tx v1
    let flags: u32 = ScriptFlags::ScriptVerifyCheckSequenceVerify.into();
    let mut engine = test_compile_and_run_with_tx_flags_err(
        program, tx, flags, Error::UNSATISFIED_LOCKTIME
    );
    check_dstack_size(ref engine, 1);
}

// File: ./packages/engine/src/opcodes/tests/test_flow.cairo

#[test]
fn test_op_nop() {
    let program = "OP_NOP";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_EMPTY_STACK);
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_nop_with_add() {
    let program = "OP_1 OP_1 OP_ADD OP_NOP";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(2)];
    check_expected_dstack(ref engine, expected_stack.span());
}

fn test_op_if_false() {
    let program = "OP_0 OP_IF OP_1 OP_ENDIF";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_if_true() {
    let program = "OP_1 OP_IF OP_1 OP_ENDIF";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_notif_false() {
    let program = "OP_0 OP_NOTIF OP_1 OP_ENDIF";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_notif_true() {
    let program = "OP_1 OP_NOTIF OP_1 OP_ENDIF";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_EMPTY_STACK);
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_else_false() {
    let program = "OP_0 OP_IF OP_0 OP_ELSE OP_1 OP_ENDIF";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_else_true() {
    let program = "OP_1 OP_IF OP_0 OP_ELSE OP_1 OP_ENDIF";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

// TODO: No end_if, ...
// TODO: Nested if statements tests

#[test]
fn test_op_verify_empty_stack() {
    let program = "OP_VERIFY";
    let mut engine = test_compile_and_run_err(program, Error::STACK_UNDERFLOW);
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_verify_true() {
    let program = "OP_TRUE OP_VERIFY";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_EMPTY_STACK);
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_verify_false() {
    let program = "OP_0 OP_VERIFY";
    let mut engine = test_compile_and_run_err(program, Error::VERIFY_FAILED);
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_return() {
    let program = "OP_RETURN OP_1";
    let mut engine = test_compile_and_run_err(program, 'opcode_return: returned early');
    check_dstack_size(ref engine, 0);
}

fn test_op_nop_x(value: u8) {
    let program = format!("OP_NOP{}", value);
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_EMPTY_STACK);
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_nop_x_all() {
    test_op_nop_x(1);
    test_op_nop_x(4);
    test_op_nop_x(5);
    test_op_nop_x(6);
    test_op_nop_x(7);
    test_op_nop_x(8);
    test_op_nop_x(9);
    test_op_nop_x(10);
}

#[test]
fn test_data_op_in_if() {
    let program = "OP_0 OP_IF OP_DATA_1 0x81 OP_ENDIF OP_1";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

// File: ./packages/engine/src/opcodes/tests/test_stack.cairo

#[test]
fn test_op_toaltstack() {
    let program = "OP_1 OP_TOALTSTACK";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_EMPTY_STACK);
    check_dstack_size(ref engine, 0);
    // TODO: Do check of altstack before exiting the program
    check_astack_size(ref engine, 0);
    let expected_astack = array![];
    check_expected_astack(ref engine, expected_astack.span());
}

#[test]
fn test_op_toaltstack_underflow() {
    let program = "OP_TOALTSTACK";
    let mut engine = test_compile_and_run_err(program, Error::STACK_UNDERFLOW);
    check_dstack_size(ref engine, 0);
    check_astack_size(ref engine, 0);
}

#[test]
fn test_op_ifdup_zero_top_stack() {
    let program = "OP_0 OP_IFDUP";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 1);
    let expected_dstack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_ifdup_non_zero_top_stack() {
    let program = "OP_1 OP_IFDUP";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 2);
    let expected_dstack = array![ScriptNum::wrap(1), ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_ifdup_multi_non_zero_top_stack() {
    let program = "OP_0 OP_1 OP_2 OP_ADD OP_IFDUP";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 3);
    let expected_dstack = array![ScriptNum::wrap(0), ScriptNum::wrap(3), ScriptNum::wrap(3)];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_depth_empty_stack() {
    let program = "OP_DEPTH";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 1);
    let expected_dstack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_depth_one_item() {
    let program = "OP_1 OP_DEPTH";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 2);
    let expected_dstack = array![ScriptNum::wrap(1), ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_depth_multiple_items() {
    let program = "OP_1 OP_1 OP_ADD OP_1 OP_DEPTH";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 3);
    let expected_dstack = array![ScriptNum::wrap(2), ScriptNum::wrap(1), ScriptNum::wrap(2)];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_drop() {
    let program = "OP_1 OP_2 OP_DROP";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_dstack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_drop_underflow() {
    let program = "OP_DROP";
    let mut engine = test_compile_and_run_err(program, Error::STACK_UNDERFLOW);
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_dup() {
    let program = "OP_1 OP_2 OP_DUP";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 3);
    let expected_dstack = array![ScriptNum::wrap(1), ScriptNum::wrap(2), ScriptNum::wrap(2)];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_swap() {
    let program = "OP_1 OP_2 OP_3 OP_SWAP";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 3);
    let expected_dstack = array![ScriptNum::wrap(1), ScriptNum::wrap(3), ScriptNum::wrap(2)];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_swap_mid() {
    let program = "OP_1 OP_2 OP_3 OP_SWAP OP_4 OP_5";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 5);
    let expected_dstack = array![
        ScriptNum::wrap(1),
        ScriptNum::wrap(3),
        ScriptNum::wrap(2),
        ScriptNum::wrap(4),
        ScriptNum::wrap(5)
    ];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_opcode_tuck() {
    let program = "OP_1 OP_2 OP_TUCK";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 3);
    let expected_dstack = array![ScriptNum::wrap(2), ScriptNum::wrap(1), ScriptNum::wrap(2)];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_2drop() {
    let program = "OP_1 OP_2 OP_2DROP";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_EMPTY_STACK);
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_2drop_underflow() {
    let program = "OP_1 OP_2DROP";
    let mut engine = test_compile_and_run_err(program, Error::STACK_UNDERFLOW);
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_2dup() {
    let program = "OP_1 OP_2 OP_2DUP";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 4);
    let expected_dstack = array![
        ScriptNum::wrap(1), ScriptNum::wrap(2), ScriptNum::wrap(1), ScriptNum::wrap(2)
    ];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_3dup() {
    let program = "OP_1 OP_2 OP_3 OP_3DUP";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 6);
    let expected_dstack = array![
        ScriptNum::wrap(1),
        ScriptNum::wrap(2),
        ScriptNum::wrap(3),
        ScriptNum::wrap(1),
        ScriptNum::wrap(2),
        ScriptNum::wrap(3)
    ];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_2swap() {
    let program = "OP_1 OP_2 OP_3 OP_4 OP_2SWAP";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 4);
    let expected_dstack = array![
        ScriptNum::wrap(3), ScriptNum::wrap(4), ScriptNum::wrap(1), ScriptNum::wrap(2)
    ];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_2swap_mid() {
    let program = "OP_1 OP_2 OP_3 OP_4 OP_2SWAP OP_5 OP_6";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 6);
    let expected_dstack = array![
        ScriptNum::wrap(3),
        ScriptNum::wrap(4),
        ScriptNum::wrap(1),
        ScriptNum::wrap(2),
        ScriptNum::wrap(5),
        ScriptNum::wrap(6)
    ];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_2swap_underflow() {
    let program = "OP_1 OP_2 OP_3 OP_2SWAP";
    let _ = test_compile_and_run_err(program, Error::STACK_UNDERFLOW);
}

#[test]
fn test_op_nip() {
    let program = "OP_1 OP_2 OP_NIP";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_dstack = array![ScriptNum::wrap(2)];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_pick() {
    let program = "OP_2 OP_0 OP_PICK";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 2);
    let expected_dstack = array![ScriptNum::wrap(2), ScriptNum::wrap(2)];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_pick_2() {
    let program = "OP_1 OP_2 OP_3 OP_2 OP_PICK";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 4);
    let expected_dstack = array![
        ScriptNum::wrap(1), ScriptNum::wrap(2), ScriptNum::wrap(3), ScriptNum::wrap(1)
    ];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_nip_multi() {
    let program = "OP_1 OP_2 OP_3 OP_NIP";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 2);
    let expected_dstack = array![ScriptNum::wrap(1), ScriptNum::wrap(3)];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_nip_out_of_bounds() {
    let program = "OP_NIP";
    let mut engine = test_compile_and_run_err(program, Error::STACK_OUT_OF_RANGE);
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_rot() {
    let program = "OP_1 OP_2 OP_3 OP_ROT";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 3);
    let expected_dstack = array![ScriptNum::wrap(2), ScriptNum::wrap(3), ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_2rot() {
    let program = "OP_1 OP_2 OP_3 OP_4 OP_5 OP_6 OP_2ROT";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 6);
    let expected_dstack = array![
        ScriptNum::wrap(3),
        ScriptNum::wrap(4),
        ScriptNum::wrap(5),
        ScriptNum::wrap(6),
        ScriptNum::wrap(1),
        ScriptNum::wrap(2)
    ];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_rot_insufficient_items() {
    let program = "OP_1 OP_2 OP_ROT";
    let mut engine = test_compile_and_run_err(program, Error::STACK_OUT_OF_RANGE);
    check_dstack_size(ref engine, 2);
}

#[test]
fn test_op_2rot_insufficient_items() {
    let program = "OP_1 OP_2 OP_3 OP_4 OP_5 OP_2ROT";
    let mut engine = test_compile_and_run_err(program, Error::STACK_OUT_OF_RANGE);
    check_dstack_size(ref engine, 5);
}

#[test]
fn test_max_stack() {
    let mut program: ByteArray = "";
    let op_1_string = "OP_1 ";
    let mut index: u64 = 0;
    while index != 1000 {
        program.append(@op_1_string);
        index += 1;
    };
    let mut engine = test_compile_and_run(program);

    check_dstack_size(ref engine, 1000);
}

#[test]
fn test_exceed_stack() {
    let mut program: ByteArray = "";
    let op_1_string = "OP_1 ";
    let mut index: u64 = 0;
    while index != 1001 {
        program.append(@op_1_string);
        index += 1;
    };

    let mut engine = test_compile_and_run_err(program, Error::STACK_OVERFLOW);

    check_dstack_size(ref engine, 1001);
}

#[test]
fn test_op_roll() {
    let program = "OP_4 OP_3 OP_2 OP_1 OP_ROLL";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 3);
    let expected_dstack = array![ScriptNum::wrap(4), ScriptNum::wrap(2), ScriptNum::wrap(3)];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_op_roll_2() {
    let program = "OP_4 OP_3 OP_2 OP_2 OP_ROLL";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 3);
    let expected_dstack = array![ScriptNum::wrap(3), ScriptNum::wrap(2), ScriptNum::wrap(4)];
    check_expected_dstack(ref engine, expected_dstack.span());
}

fn test_opcode_over() {
    let program = "OP_1 OP_2 OP_OVER";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 3);
    let expected_dstack = array![ScriptNum::wrap(1), ScriptNum::wrap(2), ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_dstack.span());
}

#[test]
fn test_opcode_2over() {
    let program = "OP_1 OP_2 OP_3 OP_4 OP_2OVER";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 6);
    let expected_dstack = array![
        ScriptNum::wrap(1),
        ScriptNum::wrap(2),
        ScriptNum::wrap(3),
        ScriptNum::wrap(4),
        ScriptNum::wrap(1),
        ScriptNum::wrap(2)
    ];
    check_expected_dstack(ref engine, expected_dstack.span());
}

// File: ./packages/engine/src/opcodes/tests/test_splice.cairo

#[test]
fn test_op_size_zero_item() {
    let program = "OP_0 OP_SIZE";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 2);
    let expected_stack = array![ScriptNum::wrap(0), ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_size_one_item() {
    let program = "OP_1 OP_SIZE";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 2);
    let expected_stack = array![ScriptNum::wrap(1), ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

// File: ./packages/engine/src/opcodes/tests/test_arithmetic.cairo

#[test]
fn test_op_1add() {
    let program = "OP_1 OP_1ADD";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(2)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_1sub() {
    let program = "OP_2 OP_1SUB";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_negate_1() {
    let program = "OP_1 OP_NEGATE";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(-1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_negate_0() {
    let program = "OP_0 OP_NEGATE";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_negate_negative() {
    let program = "OP_1 OP_2 OP_SUB OP_NEGATE";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_abs_positive() {
    let program = "OP_2 OP_ABS";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(2)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_abs_negative() {
    let program = "OP_0 OP_1SUB OP_ABS";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_abs_zero() {
    let program = "OP_0 OP_ABS";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_not() {
    let program = "OP_1 OP_NOT";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_0_not_equal_one() {
    let program = "OP_1 OP_0NOTEQUAL";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_0_not_equal_five() {
    let program = "OP_5 OP_0NOTEQUAL";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_0_not_equal_zero() {
    let program = "OP_0 OP_0NOTEQUAL";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_add() {
    let program = "OP_1 OP_2 OP_ADD";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(3)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_sub() {
    let program = "OP_1 OP_1 OP_SUB";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());

    let program = "OP_3 OP_1 OP_SUB";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(2)];
    check_expected_dstack(ref engine, expected_stack.span());

    let program = "OP_1 OP_2 OP_SUB";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(-1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_bool_and_one() {
    let program = "OP_1 OP_3 OP_BOOLAND";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_bool_and_zero() {
    let program = "OP_0 OP_4 OP_BOOLAND";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_bool_or_one() {
    let program = "OP_0 OP_1 OP_BOOLOR";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_bool_or_zero() {
    let program = "OP_0 OP_0 OP_BOOLOR";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_bool_or_both() {
    let program = "OP_1 OP_1 OP_BOOLOR";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_numequal_true() {
    let program = "OP_2 OP_2 OP_NUMEQUAL";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_numequal_false() {
    let program = "OP_2 OP_3 OP_NUMEQUAL";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_numequalverify_true() {
    let program = "OP_2 OP_2 OP_NUMEQUALVERIFY";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_EMPTY_STACK);
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_numequalverify_false() {
    let program = "OP_2 OP_3 OP_NUMEQUALVERIFY";
    let mut engine = test_compile_and_run_err(program, Error::VERIFY_FAILED);
    check_dstack_size(ref engine, 0);
}

#[test]
fn test_op_numnotequal_true() {
    let program = "OP_2 OP_3 OP_NUMNOTEQUAL";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_numnotequal_false() {
    let program = "OP_3 OP_3 OP_NUMNOTEQUAL";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_lessthan() {
    let program = "OP_1 OP_2 OP_LESSTHAN";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_lessthan_reverse() {
    let program = "OP_2 OP_1 OP_LESSTHAN";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_lessthan_equal() {
    let program = "OP_1 OP_1 OP_LESSTHAN";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_greater_than_true() {
    let program = "OP_1 OP_0 OP_GREATERTHAN";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_greater_than_false() {
    let program = "OP_0 OP_1 OP_GREATERTHAN";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_greater_than_equal_false() {
    let program = "OP_1 OP_1 OP_GREATERTHAN";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_less_than_or_equal_true_for_less_than() {
    let program = "OP_2 OP_3 OP_LESSTHANOREQUAL";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_less_than_or_equal_true_for_equal() {
    let program = "OP_2 OP_2 OP_LESSTHANOREQUAL";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_less_than_or_equal_false_for_greater_than() {
    let program = "OP_3 OP_2 OP_LESSTHANOREQUAL";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_greater_than_or_equal_true_for_greater_than() {
    let program = "OP_3 OP_2 OP_GREATERTHANOREQUAL";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_greater_than_or_equal_true_for_equal() {
    let program = "OP_2 OP_2 OP_GREATERTHANOREQUAL";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_greater_than_or_equal_false_for_less_than() {
    let program = "OP_2 OP_3 OP_GREATERTHANOREQUAL";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_min_min_first() {
    let program = "OP_1 OP_2 OP_MIN";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_min_min_second() {
    let program = "OP_2 OP_1 OP_MIN";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_min_same_value() {
    let program = "OP_1 OP_1 OP_MIN";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_max() {
    let program = "OP_1 OP_0 OP_MAX";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_within_true() {
    let program = "OP_1 OP_0 OP_3 OP_WITHIN";
    let mut engine = test_compile_and_run(program);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(1)];
    check_expected_dstack(ref engine, expected_stack.span());
}

#[test]
fn test_op_within_false() {
    let program = "OP_2 OP_0 OP_1 OP_WITHIN";
    let mut engine = test_compile_and_run_err(program, Error::SCRIPT_FAILED);
    check_dstack_size(ref engine, 1);
    let expected_stack = array![ScriptNum::wrap(0)];
    check_expected_dstack(ref engine, expected_stack.span());
}

// File: ./packages/engine/src/opcodes/splice.cairo

pub fn opcode_size<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let top_element = engine.dstack.peek_byte_array(0)?;
    engine.dstack.push_int(top_element.len().into());
    return Result::Ok(());
}

// File: ./packages/engine/src/opcodes/flow.cairo

pub fn is_branching_opcode(opcode: u8) -> bool {
    if opcode == Opcode::OP_IF
        || opcode == Opcode::OP_NOTIF
        || opcode == Opcode::OP_ELSE
        || opcode == Opcode::OP_ENDIF {
        return true;
    }
    return false;
}

pub fn opcode_nop<T, +Drop<T>>(ref engine: Engine<T>, opcode: u8) -> Result<(), felt252> {
    if opcode != Opcode::OP_NOP
        && EngineExtrasTrait::<
            T
        >::has_flag(ref engine, ScriptFlags::ScriptDiscourageUpgradableNops) {
        return Result::Err(Error::SCRIPT_DISCOURAGE_UPGRADABLE_NOPS);
    }
    return Result::Ok(());
}

// TODO: MOve to cond_stack
const op_cond_false: u8 = 0;
const op_cond_true: u8 = 1;
const op_cond_skip: u8 = 2;
pub fn opcode_if<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let mut cond = op_cond_false;
    // TODO: Pop if bool
    if engine.cond_stack.branch_executing() {
        let ok = engine.pop_if_bool()?;
        if ok {
            cond = op_cond_true;
        }
    } else {
        cond = op_cond_skip;
    }
    engine.cond_stack.push(cond);
    return Result::Ok(());
}

pub fn opcode_notif<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let mut cond = op_cond_false;
    if engine.cond_stack.branch_executing() {
        let ok = engine.pop_if_bool()?;
        if !ok {
            cond = op_cond_true;
        }
    } else {
        cond = op_cond_skip;
    }
    engine.cond_stack.push(cond);
    return Result::Ok(());
}

pub fn opcode_else<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    if engine.cond_stack.len() == 0 {
        return Result::Err('opcode_else: no matching if');
    }

    engine.cond_stack.swap_condition();
    return Result::Ok(());
}

pub fn opcode_endif<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    if engine.cond_stack.len() == 0 {
        return Result::Err('opcode_endif: no matching if');
    }

    engine.cond_stack.pop()?;
    return Result::Ok(());
}

pub fn opcode_verify<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    abstract_verify(ref engine)?;
    return Result::Ok(());
}

pub fn opcode_return<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    return Result::Err('opcode_return: returned early');
}

// File: ./packages/engine/src/opcodes/opcodes.cairo

pub mod Opcode {
    pub const OP_0: u8 = 0;
    pub const OP_DATA_1: u8 = 1;
    pub const OP_DATA_2: u8 = 2;
    pub const OP_DATA_3: u8 = 3;
    pub const OP_DATA_4: u8 = 4;
    pub const OP_DATA_5: u8 = 5;
    pub const OP_DATA_6: u8 = 6;
    pub const OP_DATA_7: u8 = 7;
    pub const OP_DATA_8: u8 = 8;
    pub const OP_DATA_9: u8 = 9;
    pub const OP_DATA_10: u8 = 10;
    pub const OP_DATA_11: u8 = 11;
    pub const OP_DATA_12: u8 = 12;
    pub const OP_DATA_13: u8 = 13;
    pub const OP_DATA_14: u8 = 14;
    pub const OP_DATA_15: u8 = 15;
    pub const OP_DATA_16: u8 = 16;
    pub const OP_DATA_17: u8 = 17;
    pub const OP_DATA_18: u8 = 18;
    pub const OP_DATA_19: u8 = 19;
    pub const OP_DATA_20: u8 = 20;
    pub const OP_DATA_21: u8 = 21;
    pub const OP_DATA_22: u8 = 22;
    pub const OP_DATA_23: u8 = 23;
    pub const OP_DATA_24: u8 = 24;
    pub const OP_DATA_25: u8 = 25;
    pub const OP_DATA_26: u8 = 26;
    pub const OP_DATA_27: u8 = 27;
    pub const OP_DATA_28: u8 = 28;
    pub const OP_DATA_29: u8 = 29;
    pub const OP_DATA_30: u8 = 30;
    pub const OP_DATA_31: u8 = 31;
    pub const OP_DATA_32: u8 = 32;
    pub const OP_DATA_33: u8 = 33;
    pub const OP_DATA_34: u8 = 34;
    pub const OP_DATA_35: u8 = 35;
    pub const OP_DATA_36: u8 = 36;
    pub const OP_DATA_37: u8 = 37;
    pub const OP_DATA_38: u8 = 38;
    pub const OP_DATA_39: u8 = 39;
    pub const OP_DATA_40: u8 = 40;
    pub const OP_DATA_41: u8 = 41;
    pub const OP_DATA_42: u8 = 42;
    pub const OP_DATA_43: u8 = 43;
    pub const OP_DATA_44: u8 = 44;
    pub const OP_DATA_45: u8 = 45;
    pub const OP_DATA_46: u8 = 46;
    pub const OP_DATA_47: u8 = 47;
    pub const OP_DATA_48: u8 = 48;
    pub const OP_DATA_49: u8 = 49;
    pub const OP_DATA_50: u8 = 50;
    pub const OP_DATA_51: u8 = 51;
    pub const OP_DATA_52: u8 = 52;
    pub const OP_DATA_53: u8 = 53;
    pub const OP_DATA_54: u8 = 54;
    pub const OP_DATA_55: u8 = 55;
    pub const OP_DATA_56: u8 = 56;
    pub const OP_DATA_57: u8 = 57;
    pub const OP_DATA_58: u8 = 58;
    pub const OP_DATA_59: u8 = 59;
    pub const OP_DATA_60: u8 = 60;
    pub const OP_DATA_61: u8 = 61;
    pub const OP_DATA_62: u8 = 62;
    pub const OP_DATA_63: u8 = 63;
    pub const OP_DATA_64: u8 = 64;
    pub const OP_DATA_65: u8 = 65;
    pub const OP_DATA_66: u8 = 66;
    pub const OP_DATA_67: u8 = 67;
    pub const OP_DATA_68: u8 = 68;
    pub const OP_DATA_69: u8 = 69;
    pub const OP_DATA_70: u8 = 70;
    pub const OP_DATA_71: u8 = 71;
    pub const OP_DATA_72: u8 = 72;
    pub const OP_DATA_73: u8 = 73;
    pub const OP_DATA_74: u8 = 74;
    pub const OP_DATA_75: u8 = 75;
    pub const OP_PUSHDATA1: u8 = 76;
    pub const OP_PUSHDATA2: u8 = 77;
    pub const OP_PUSHDATA4: u8 = 78;
    pub const OP_1NEGATE: u8 = 79;
    pub const OP_RESERVED: u8 = 80;
    pub const OP_TRUE: u8 = 81;
    pub const OP_1: u8 = 81;
    pub const OP_2: u8 = 82;
    pub const OP_3: u8 = 83;
    pub const OP_4: u8 = 84;
    pub const OP_5: u8 = 85;
    pub const OP_6: u8 = 86;
    pub const OP_7: u8 = 87;
    pub const OP_8: u8 = 88;
    pub const OP_9: u8 = 89;
    pub const OP_10: u8 = 90;
    pub const OP_11: u8 = 91;
    pub const OP_12: u8 = 92;
    pub const OP_13: u8 = 93;
    pub const OP_14: u8 = 94;
    pub const OP_15: u8 = 95;
    pub const OP_16: u8 = 96;
    pub const OP_NOP: u8 = 97;
    pub const OP_VER: u8 = 98;
    pub const OP_IF: u8 = 99;
    pub const OP_NOTIF: u8 = 100;
    pub const OP_VERIF: u8 = 101;
    pub const OP_VERNOTIF: u8 = 102;
    pub const OP_ELSE: u8 = 103;
    pub const OP_ENDIF: u8 = 104;
    pub const OP_VERIFY: u8 = 105;
    pub const OP_RETURN: u8 = 106;
    pub const OP_TOALTSTACK: u8 = 107;
    pub const OP_FROMALTSTACK: u8 = 108;
    pub const OP_2DROP: u8 = 109;
    pub const OP_2DUP: u8 = 110;
    pub const OP_3DUP: u8 = 111;
    pub const OP_2OVER: u8 = 112;
    pub const OP_2ROT: u8 = 113;
    pub const OP_2SWAP: u8 = 114;
    pub const OP_IFDUP: u8 = 115;
    pub const OP_DEPTH: u8 = 116;
    pub const OP_DROP: u8 = 117;
    pub const OP_DUP: u8 = 118;
    pub const OP_NIP: u8 = 119;
    pub const OP_OVER: u8 = 120;
    pub const OP_PICK: u8 = 121;
    pub const OP_ROLL: u8 = 122;
    pub const OP_ROT: u8 = 123;
    pub const OP_SWAP: u8 = 124;
    pub const OP_TUCK: u8 = 125;
    pub const OP_CAT: u8 = 126;
    pub const OP_SUBSTR: u8 = 127;
    pub const OP_LEFT: u8 = 128;
    pub const OP_RIGHT: u8 = 129;
    pub const OP_SIZE: u8 = 130;
    pub const OP_INVERT: u8 = 131;
    pub const OP_AND: u8 = 132;
    pub const OP_OR: u8 = 133;
    pub const OP_XOR: u8 = 134;
    pub const OP_EQUAL: u8 = 135;
    pub const OP_EQUALVERIFY: u8 = 136;
    pub const OP_RESERVED1: u8 = 137;
    pub const OP_RESERVED2: u8 = 138;
    pub const OP_1ADD: u8 = 139;
    pub const OP_1SUB: u8 = 140;
    pub const OP_2MUL: u8 = 141;
    pub const OP_2DIV: u8 = 142;
    pub const OP_NEGATE: u8 = 143;
    pub const OP_ABS: u8 = 144;
    pub const OP_NOT: u8 = 145;
    pub const OP_0NOTEQUAL: u8 = 146;
    pub const OP_ADD: u8 = 147;
    pub const OP_SUB: u8 = 148;
    pub const OP_MUL: u8 = 149;
    pub const OP_DIV: u8 = 150;
    pub const OP_MOD: u8 = 151;
    pub const OP_LSHIFT: u8 = 152;
    pub const OP_RSHIFT: u8 = 153;
    pub const OP_BOOLAND: u8 = 154;
    pub const OP_BOOLOR: u8 = 155;
    pub const OP_NUMEQUAL: u8 = 156;
    pub const OP_NUMEQUALVERIFY: u8 = 157;
    pub const OP_NUMNOTEQUAL: u8 = 158;
    pub const OP_LESSTHAN: u8 = 159;
    pub const OP_GREATERTHAN: u8 = 160;
    pub const OP_LESSTHANOREQUAL: u8 = 161;
    pub const OP_GREATERTHANOREQUAL: u8 = 162;
    pub const OP_MIN: u8 = 163;
    pub const OP_MAX: u8 = 164;
    pub const OP_WITHIN: u8 = 165;
    pub const OP_RIPEMD160: u8 = 166;
    pub const OP_SHA1: u8 = 167;
    pub const OP_SHA256: u8 = 168;
    pub const OP_HASH160: u8 = 169;
    pub const OP_HASH256: u8 = 170;
    pub const OP_CODESEPARATOR: u8 = 171;
    pub const OP_CHECKSIG: u8 = 172;
    pub const OP_CHECKSIGVERIFY: u8 = 173;
    pub const OP_CHECKMULTISIG: u8 = 174;
    pub const OP_CHECKMULTISIGVERIFY: u8 = 175;
    pub const OP_NOP1: u8 = 176;
    pub const OP_CHECKLOCKTIMEVERIFY: u8 = 177;
    pub const OP_CHECKSEQUENCEVERIFY: u8 = 178;
    pub const OP_NOP4: u8 = 179;
    pub const OP_NOP5: u8 = 180;
    pub const OP_NOP6: u8 = 181;
    pub const OP_NOP7: u8 = 182;
    pub const OP_NOP8: u8 = 183;
    pub const OP_NOP9: u8 = 184;
    pub const OP_NOP10: u8 = 185;

    use crate::transaction::{
        EngineTransactionTrait, EngineTransactionInputTrait, EngineTransactionOutputTrait
    };
    use crate::opcodes::{
        constants, flow, stack, splice, bitwise, arithmetic, crypto, locktime, utils
    };

    pub fn execute<
        T,
        +Drop<T>,
        I,
        +Drop<I>,
        impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
        O,
        +Drop<O>,
        impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
        impl IEngineTransactionTrait: EngineTransactionTrait<
            T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
        >
    >(
        opcode: u8, ref engine: Engine<T>
    ) -> Result<(), felt252> {
        match opcode {
            0 => opcode_false(ref engine),
            1 => opcode_push_data(1, ref engine),
            2 => opcode_push_data(2, ref engine),
            3 => opcode_push_data(3, ref engine),
            4 => opcode_push_data(4, ref engine),
            5 => opcode_push_data(5, ref engine),
            6 => opcode_push_data(6, ref engine),
            7 => opcode_push_data(7, ref engine),
            8 => opcode_push_data(8, ref engine),
            9 => opcode_push_data(9, ref engine),
            10 => opcode_push_data(10, ref engine),
            11 => opcode_push_data(11, ref engine),
            12 => opcode_push_data(12, ref engine),
            13 => opcode_push_data(13, ref engine),
            14 => opcode_push_data(14, ref engine),
            15 => opcode_push_data(15, ref engine),
            16 => opcode_push_data(16, ref engine),
            17 => opcode_push_data(17, ref engine),
            18 => opcode_push_data(18, ref engine),
            19 => opcode_push_data(19, ref engine),
            20 => opcode_push_data(20, ref engine),
            21 => opcode_push_data(21, ref engine),
            22 => opcode_push_data(22, ref engine),
            23 => opcode_push_data(23, ref engine),
            24 => opcode_push_data(24, ref engine),
            25 => opcode_push_data(25, ref engine),
            26 => opcode_push_data(26, ref engine),
            27 => opcode_push_data(27, ref engine),
            28 => opcode_push_data(28, ref engine),
            29 => opcode_push_data(29, ref engine),
            30 => opcode_push_data(30, ref engine),
            31 => opcode_push_data(31, ref engine),
            32 => opcode_push_data(32, ref engine),
            33 => opcode_push_data(33, ref engine),
            34 => opcode_push_data(34, ref engine),
            35 => opcode_push_data(35, ref engine),
            36 => opcode_push_data(36, ref engine),
            37 => opcode_push_data(37, ref engine),
            38 => opcode_push_data(38, ref engine),
            39 => opcode_push_data(39, ref engine),
            40 => opcode_push_data(40, ref engine),
            41 => opcode_push_data(41, ref engine),
            42 => opcode_push_data(42, ref engine),
            43 => opcode_push_data(43, ref engine),
            44 => opcode_push_data(44, ref engine),
            45 => opcode_push_data(45, ref engine),
            46 => opcode_push_data(46, ref engine),
            47 => opcode_push_data(47, ref engine),
            48 => opcode_push_data(48, ref engine),
            49 => opcode_push_data(49, ref engine),
            50 => opcode_push_data(50, ref engine),
            51 => opcode_push_data(51, ref engine),
            52 => opcode_push_data(52, ref engine),
            53 => opcode_push_data(53, ref engine),
            54 => opcode_push_data(54, ref engine),
            55 => opcode_push_data(55, ref engine),
            56 => opcode_push_data(56, ref engine),
            57 => opcode_push_data(57, ref engine),
            58 => opcode_push_data(58, ref engine),
            59 => opcode_push_data(59, ref engine),
            60 => opcode_push_data(60, ref engine),
            61 => opcode_push_data(61, ref engine),
            62 => opcode_push_data(62, ref engine),
            63 => opcode_push_data(63, ref engine),
            64 => opcode_push_data(64, ref engine),
            65 => opcode_push_data(65, ref engine),
            66 => opcode_push_data(66, ref engine),
            67 => opcode_push_data(67, ref engine),
            68 => opcode_push_data(68, ref engine),
            69 => opcode_push_data(69, ref engine),
            70 => opcode_push_data(70, ref engine),
            71 => opcode_push_data(71, ref engine),
            72 => opcode_push_data(72, ref engine),
            73 => opcode_push_data(73, ref engine),
            74 => opcode_push_data(74, ref engine),
            75 => opcode_push_data(75, ref engine),
            76 => opcode_push_data_x(1, ref engine),
            77 => opcode_push_data_x(2, ref engine),
            78 => opcode_push_data_x(4, ref engine),
            79 => opcode_1negate(ref engine),
            80 => opcode_reserved("reserved", ref engine),
            81 => opcode_n(1, ref engine),
            82 => opcode_n(2, ref engine),
            83 => opcode_n(3, ref engine),
            84 => opcode_n(4, ref engine),
            85 => opcode_n(5, ref engine),
            86 => opcode_n(6, ref engine),
            87 => opcode_n(7, ref engine),
            88 => opcode_n(8, ref engine),
            89 => opcode_n(9, ref engine),
            90 => opcode_n(10, ref engine),
            91 => opcode_n(11, ref engine),
            92 => opcode_n(12, ref engine),
            93 => opcode_n(13, ref engine),
            94 => opcode_n(14, ref engine),
            95 => opcode_n(15, ref engine),
            96 => opcode_n(16, ref engine),
            97 => opcode_nop(ref engine, 97),
            98 => opcode_reserved("ver", ref engine),
            99 => opcode_if(ref engine),
            100 => opcode_notif(ref engine),
            101 => opcode_reserved("verif", ref engine),
            102 => opcode_reserved("vernotif", ref engine),
            103 => opcode_else(ref engine),
            104 => opcode_endif(ref engine),
            105 => opcode_verify(ref engine),
            106 => opcode_return(ref engine),
            107 => stack::opcode_toaltstack(ref engine),
            108 => stack::opcode_fromaltstack(ref engine),
            109 => stack::opcode_2drop(ref engine),
            110 => stack::opcode_2dup(ref engine),
            111 => stack::opcode_3dup(ref engine),
            112 => stack::opcode_2over(ref engine),
            113 => stack::opcode_2rot(ref engine),
            114 => stack::opcode_2swap(ref engine),
            115 => stack::opcode_ifdup(ref engine),
            116 => stack::opcode_depth(ref engine),
            117 => stack::opcode_drop(ref engine),
            118 => stack::opcode_dup(ref engine),
            119 => stack::opcode_nip(ref engine),
            120 => stack::opcode_over(ref engine),
            121 => stack::opcode_pick(ref engine),
            122 => stack::opcode_roll(ref engine),
            123 => stack::opcode_rot(ref engine),
            124 => stack::opcode_swap(ref engine),
            125 => stack::opcode_tuck(ref engine),
            126 => opcode_disabled(ref engine),
            127 => opcode_disabled(ref engine),
            128 => opcode_disabled(ref engine),
            129 => opcode_disabled(ref engine),
            130 => splice::opcode_size(ref engine),
            131 => opcode_disabled(ref engine),
            132 => opcode_disabled(ref engine),
            133 => opcode_disabled(ref engine),
            134 => opcode_disabled(ref engine),
            135 => bitwise::opcode_equal(ref engine),
            136 => bitwise::opcode_equal_verify(ref engine),
            137 => opcode_reserved("reserved1", ref engine),
            138 => opcode_reserved("reserved2", ref engine),
            139 => arithmetic::opcode_1add(ref engine),
            140 => arithmetic::opcode_1sub(ref engine),
            141 => opcode_disabled(ref engine),
            142 => opcode_disabled(ref engine),
            143 => arithmetic::opcode_negate(ref engine),
            144 => arithmetic::opcode_abs(ref engine),
            145 => arithmetic::opcode_not(ref engine),
            146 => arithmetic::opcode_0_not_equal(ref engine),
            147 => arithmetic::opcode_add(ref engine),
            148 => arithmetic::opcode_sub(ref engine),
            149 => opcode_disabled(ref engine),
            150 => opcode_disabled(ref engine),
            151 => opcode_disabled(ref engine),
            152 => opcode_disabled(ref engine),
            153 => opcode_disabled(ref engine),
            154 => arithmetic::opcode_bool_and(ref engine),
            155 => arithmetic::opcode_bool_or(ref engine),
            156 => arithmetic::opcode_numequal(ref engine),
            157 => arithmetic::opcode_numequalverify(ref engine),
            158 => arithmetic::opcode_numnotequal(ref engine),
            159 => arithmetic::opcode_lessthan(ref engine),
            160 => arithmetic::opcode_greater_than(ref engine),
            161 => arithmetic::opcode_less_than_or_equal(ref engine),
            162 => arithmetic::opcode_greater_than_or_equal(ref engine),
            163 => arithmetic::opcode_min(ref engine),
            164 => arithmetic::opcode_max(ref engine),
            165 => arithmetic::opcode_within(ref engine),
            166 => crypto::opcode_ripemd160(ref engine),
            167 => crypto::opcode_sha1(ref engine),
            168 => crypto::opcode_sha256(ref engine),
            169 => crypto::opcode_hash160(ref engine),
            170 => crypto::opcode_hash256(ref engine),
            171 => crypto::opcode_codeseparator(ref engine),
            172 => crypto::opcode_checksig(ref engine),
            173 => crypto::opcode_checksigverify(ref engine),
            174 => crypto::opcode_checkmultisig(ref engine),
            175 => crypto::opcode_checkmultisigverify(ref engine),
            176 => opcode_nop(ref engine, 176),
            177 => locktime::opcode_checklocktimeverify(ref engine),
            178 => locktime::opcode_checksequenceverify(ref engine),
            179 => opcode_nop(ref engine, 179),
            180 => opcode_nop(ref engine, 180),
            181 => opcode_nop(ref engine, 181),
            182 => opcode_nop(ref engine, 182),
            183 => opcode_nop(ref engine, 183),
            184 => opcode_nop(ref engine, 184),
            185 => opcode_nop(ref engine, 185),
            _ => not_implemented(ref engine)
        }
    }

    pub fn is_opcode_disabled<T, +Drop<T>>(
        opcode: u8, ref engine: Engine<T>
    ) -> Result<(), felt252> {
        if opcode == OP_CAT
            || opcode == OP_SUBSTR
            || opcode == OP_LEFT
            || opcode == OP_RIGHT
            || opcode == OP_INVERT
            || opcode == OP_AND
            || opcode == OP_OR
            || opcode == OP_XOR
            || opcode == OP_2MUL
            || opcode == OP_2DIV
            || opcode == OP_MUL
            || opcode == OP_DIV
            || opcode == OP_MOD
            || opcode == OP_LSHIFT
            || opcode == OP_RSHIFT {
            return opcode_disabled(ref engine);
        } else {
            return Result::Ok(());
        }
    }

    pub fn is_opcode_always_illegal<T, +Drop<T>>(
        opcode: u8, ref engine: Engine<T>
    ) -> Result<(), felt252> {
        if opcode == OP_VERIF {
            return opcode_reserved("verif", ref engine);
        } else if opcode == OP_VERNOTIF {
            return opcode_reserved("vernotif", ref engine);
        } else {
            return Result::Ok(());
        }
    }

    pub fn is_data_opcode(opcode: u8) -> bool {
        return (opcode >= OP_DATA_1 && opcode <= OP_DATA_75);
    }

    pub fn is_push_opcode(opcode: u8) -> bool {
        return (opcode == OP_PUSHDATA1 || opcode == OP_PUSHDATA2 || opcode == OP_PUSHDATA4);
    }

    pub fn is_canonical_push(opcode: u8, data: @ByteArray) -> bool {
        let data_len = data.len();
        if opcode > OP_16 {
            return true;
        }

        if opcode < OP_PUSHDATA1 && opcode > OP_0 && data_len == 1 && data[0] <= 16 {
            // Could have used OP_N
            return false;
        } else if opcode == OP_PUSHDATA1 && data_len < OP_PUSHDATA1.into() {
            // Could have used OP_DATA_N
            return false;
        } else if opcode == OP_PUSHDATA2 && data_len <= 0xFF {
            // Could have used OP_PUSHDATA1
            return false;
        } else if opcode == OP_PUSHDATA4 && data_len <= 0xFFFF {
            // Could have used OP_PUSHDATA2
            return false;
        }

        return true;
    }

    use crate::errors::Error;
    pub fn data_at(idx: usize, len: usize, script: @ByteArray) -> Result<ByteArray, felt252> {
        let mut data = "";
        let mut i = idx;
        let mut end = i + len;
        if end > script.len() {
            return Result::Err(Error::SCRIPT_INVALID);
        }
        while i != end {
            data.append_byte(script[i]);
            i += 1;
        };
        return Result::Ok(data);
    }

    pub fn data_len(idx: u32, script: @ByteArray) -> Result<usize, felt252> {
        let opcode: u8 = script[idx];
        if is_data_opcode(opcode) {
            return Result::Ok(opcode.into());
        }
        let mut push_data_len = 0;
        if opcode == OP_PUSHDATA1 {
            push_data_len = 1;
        } else if opcode == OP_PUSHDATA2 {
            push_data_len = 2;
        } else if opcode == OP_PUSHDATA4 {
            push_data_len = 4;
        } else {
            return Result::Ok(0);
        }
        return Result::Ok(
            super::byte_array_to_felt252_le(@data_at(idx + 1, push_data_len, script)?)
                .try_into()
                .unwrap()
                + push_data_len
        );
    }
}

// File: ./packages/engine/src/opcodes/crypto.cairo
//     EngineTransactionTrait, EngineTransactionInputTrait, EngineTransactionOutputTrait
// };

const MAX_KEYS_PER_MULTISIG: i64 = 20;

pub fn opcode_sha256<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let arr = @engine.dstack.pop_byte_array()?;
    let res = compute_sha256_byte_array(arr).span();
    let mut res_bytes: ByteArray = "";
    let mut i: usize = 0;
    while i != res.len() {
        res_bytes.append_word((*res[i]).into(), 4);
        i += 1;
    };
    engine.dstack.push_byte_array(res_bytes);
    return Result::Ok(());
}

pub fn opcode_hash160<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let m = engine.dstack.pop_byte_array()?;
    let res = compute_sha256_byte_array(@m).span();
    let mut res_bytes: ByteArray = "";
    let mut i: usize = 0;
    while i != res.len() {
        res_bytes.append_word((*res[i]).into(), 4);
        i += 1;
    };
    let h: ByteArray = ripemd160::ripemd160_hash(@res_bytes).into();
    engine.dstack.push_byte_array(h);
    return Result::Ok(());
}

pub fn opcode_hash256<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let m = engine.dstack.pop_byte_array()?;
    let res = compute_sha256_byte_array(@m).span();
    let mut res_bytes: ByteArray = "";
    let mut i: usize = 0;
    while i != res.len() {
        res_bytes.append_word((*res[i]).into(), 4);
        i += 1;
    };
    let res2 = compute_sha256_byte_array(@res_bytes).span();
    let mut res2_bytes: ByteArray = "";
    let mut j: usize = 0;
    while j != res2.len() {
        res2_bytes.append_word((*res2[j]).into(), 4);
        j += 1;
    };
    engine.dstack.push_byte_array(res2_bytes);
    return Result::Ok(());
}

pub fn opcode_ripemd160<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let m = engine.dstack.pop_byte_array()?;
    let h: ByteArray = ripemd160::ripemd160_hash(@m).into();
    engine.dstack.push_byte_array(h);
    return Result::Ok(());
}

pub fn opcode_checksig<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    ref engine: Engine<T>
) -> Result<(), felt252> {
    let pk_bytes = engine.dstack.pop_byte_array()?;
    let full_sig_bytes = engine.dstack.pop_byte_array()?;

    if full_sig_bytes.len() < 1 {
        engine.dstack.push_bool(false);
        return Result::Ok(());
    }

    // TODO: add witness context inside engine to check if witness is active
    //       if witness is active use BaseSigVerifier
    let mut is_valid: bool = false;
    let res = BaseSigVerifierTrait::new(ref engine, @full_sig_bytes, @pk_bytes);
    if res.is_err() {
        // TODO: Some errors can return an error code instead of pushing false?
        engine.dstack.push_bool(false);
        return Result::Ok(());
    }
    let mut sig_verifier = res.unwrap();

    if sig_verifier.verify(ref engine) {
        is_valid = true;
    } else {
        is_valid = false;
    }
    // else use BaseSigWitnessVerifier
    // let mut sig_verifier: BaseSigWitnessVerifier = BaseSigWitnessVerifierTrait::new(ref engine,
    // @full_sig_bytes, @pk_bytes)?;

    // if sig_verifier.verify(ref engine) {
    //     is_valid = true;
    // } else {
    //     is_valid = false;
    // }

    if !is_valid && engine.has_flag(ScriptFlags::ScriptVerifyNullFail) && full_sig_bytes.len() > 0 {
        return Result::Err(Error::SIG_NULLFAIL);
    }

    engine.dstack.push_bool(is_valid);
    return Result::Ok(());
}

pub fn opcode_checkmultisig<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    ref engine: Engine<T>
) -> Result<(), felt252> {
    // TODO Error on taproot exec

    // Get number of public keys and construct array
    let num_keys = engine.dstack.pop_int()?;
    let mut num_pub_keys: i64 = ScriptNum::to_int32(num_keys).into();
    if num_pub_keys < 0 {
        return Result::Err('check multisig: num pk < 0');
    }
    if num_pub_keys > MAX_KEYS_PER_MULTISIG {
        return Result::Err('check multisig: num pk > max');
    }
    engine.num_ops += num_pub_keys.try_into().unwrap();
    if engine.num_ops > 201 { // TODO: Hardcoded limit
        return Result::Err(Error::SCRIPT_TOO_MANY_OPERATIONS);
    }
    let mut pub_keys = ArrayTrait::<ByteArray>::new();
    let mut i: i64 = 0;
    let mut err: felt252 = 0;
    while i != num_pub_keys {
        match engine.dstack.pop_byte_array() {
            Result::Ok(pk) => pub_keys.append(pk),
            Result::Err(e) => err = e
        };
        i += 1;
    };
    if err != 0 {
        return Result::Err(err);
    }

    // Get number of required sigs and construct array
    let num_sig_base = engine.dstack.pop_int()?;
    let mut num_sigs: i64 = ScriptNum::to_int32(num_sig_base).into();
    if num_sigs < 0 {
        return Result::Err('check multisig: num sigs < 0');
    }
    if num_sigs > num_pub_keys {
        return Result::Err('check multisig: num sigs > pk');
    }
    let mut sigs = ArrayTrait::<ByteArray>::new();
    i = 0;
    err = 0;
    while i != num_sigs {
        match engine.dstack.pop_byte_array() {
            Result::Ok(s) => sigs.append(s),
            Result::Err(e) => err = e
        };
        i += 1;
    };
    if err != 0 {
        return Result::Err(err);
    }

    // Historical bug
    let dummy = engine.dstack.pop_byte_array()?;

    if engine.has_flag(ScriptFlags::ScriptStrictMultiSig) && dummy.len() != 0 {
        return Result::Err(Error::SCRIPT_STRICT_MULTISIG);
    }

    let mut script = engine.sub_script();

    // TODO: add witness context inside engine to check if witness is active
    let mut s: u32 = 0;
    while s != sigs.len() {
        script = signature::remove_signature(script, sigs.at(s));
        s += 1;
    };

    let mut success = true;
    num_pub_keys += 1; // Offset due to decrementing it in the loop
    let mut pub_key_idx: i64 = -1;
    let mut sig_idx: i64 = 0;

    while num_sigs != 0 {
        pub_key_idx += 1;
        num_pub_keys -= 1;
        if num_sigs > num_pub_keys {
            success = false;
            break;
        }

        let sig = sigs.at(sig_idx.try_into().unwrap());
        let pub_key = pub_keys.at(pub_key_idx.try_into().unwrap());
        if sig.len() == 0 {
            continue;
        }

        let res = signature::parse_base_sig_and_pk(ref engine, pub_key, sig);
        if res.is_err() {
            success = false;
            err = res.unwrap_err();
            break;
        }
        let (parsed_pub_key, parsed_sig, hash_type) = res.unwrap();
        let sig_hash: u256 = calc_signature_hash(
            @script, hash_type, ref engine.transaction, engine.tx_idx
        );
        if is_valid_signature(sig_hash, parsed_sig.r, parsed_sig.s, parsed_pub_key) {
            sig_idx += 1;
            num_sigs -= 1;
        }
    };
    if err != 0 {
        return Result::Err(err);
    }

    if !success && engine.has_flag(ScriptFlags::ScriptVerifyNullFail) {
        let mut err = '';
        for s in sigs {
            if s.len() > 0 {
                err = Error::SIG_NULLFAIL;
                break;
            }
        };
        if err != '' {
            return Result::Err(err);
        }
    }

    engine.dstack.push_bool(success);
    Result::Ok(())
}

pub fn opcode_codeseparator<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.last_code_sep = engine.opcode_idx;

    // TODO Disable OP_CODESEPARATOR for non-segwit scripts.
    // if engine.witness_program.len() == 0 &&
    // engine.has_flag(ScriptFlags::ScriptVerifyConstScriptCode) {

    // return Result::Err('opcode_codeseparator:non-segwit');
    // }

    Result::Ok(())
}

pub fn opcode_checksigverify<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    ref engine: Engine<T>
) -> Result<(), felt252> {
    opcode_checksig(ref engine)?;
    abstract_verify(ref engine)?;
    return Result::Ok(());
}

pub fn opcode_checkmultisigverify<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    ref engine: Engine<T>
) -> Result<(), felt252> {
    opcode_checkmultisig(ref engine)?;
    abstract_verify(ref engine)?;
    return Result::Ok(());
}

pub fn opcode_sha1<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let m = engine.dstack.pop_byte_array()?;
    let h: ByteArray = sha1::sha1_hash(@m).into();
    engine.dstack.push_byte_array(h);
    return Result::Ok(());
}

// File: ./packages/engine/src/opcodes/arithmetic.cairo

pub fn opcode_1add<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let value = engine.dstack.pop_int()?;
    let result = value + 1;
    engine.dstack.push_int(result);
    return Result::Ok(());
}

pub fn opcode_1sub<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    engine.dstack.push_int(a - 1);
    return Result::Ok(());
}

pub fn opcode_negate<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    engine.dstack.push_int(-a);
    return Result::Ok(());
}

pub fn opcode_abs<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let value = engine.dstack.pop_int()?;
    let abs_value = if value < 0 {
        -value
    } else {
        value
    };
    engine.dstack.push_int(abs_value);
    return Result::Ok(());
}

pub fn opcode_not<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let m = engine.dstack.pop_int()?;
    if m == 0 {
        engine.dstack.push_bool(true);
    } else {
        engine.dstack.push_bool(false);
    }
    return Result::Ok(());
}

pub fn opcode_0_not_equal<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;

    engine.dstack.push_int(if a != 0 {
        1
    } else {
        0
    });
    return Result::Ok(());
}

pub fn opcode_add<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    let b = engine.dstack.pop_int()?;
    engine.dstack.push_int(a + b);
    return Result::Ok(());
}

pub fn opcode_sub<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    let b = engine.dstack.pop_int()?;
    engine.dstack.push_int(b - a);
    return Result::Ok(());
}

pub fn opcode_bool_and<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    let b = engine.dstack.pop_int()?;
    engine.dstack.push_bool(if a != 0 && b != 0 {
        true
    } else {
        false
    });
    return Result::Ok(());
}

pub fn opcode_bool_or<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    let b = engine.dstack.pop_int()?;

    engine.dstack.push_bool(if a != 0 || b != 0 {
        true
    } else {
        false
    });
    return Result::Ok(());
}

pub fn opcode_numequal<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    let b = engine.dstack.pop_int()?;
    engine.dstack.push_bool(if a == b {
        true
    } else {
        false
    });
    return Result::Ok(());
}

pub fn opcode_numequalverify<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    opcode_numequal(ref engine)?;
    abstract_verify(ref engine)?;
    return Result::Ok(());
}

pub fn opcode_numnotequal<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    let b = engine.dstack.pop_int()?;
    engine.dstack.push_bool(if a != b {
        true
    } else {
        false
    });
    return Result::Ok(());
}

pub fn opcode_lessthan<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    let b = engine.dstack.pop_int()?;
    engine.dstack.push_bool(if b < a {
        true
    } else {
        false
    });
    return Result::Ok(());
}

pub fn opcode_greater_than<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    let b = engine.dstack.pop_int()?;
    engine.dstack.push_bool(if b > a {
        true
    } else {
        false
    });
    return Result::Ok(());
}

pub fn opcode_less_than_or_equal<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let v0 = engine.dstack.pop_int()?;
    let v1 = engine.dstack.pop_int()?;

    if v1 <= v0 {
        engine.dstack.push_bool(true);
    } else {
        engine.dstack.push_bool(false);
    }
    return Result::Ok(());
}

pub fn opcode_greater_than_or_equal<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let v0 = engine.dstack.pop_int()?;
    let v1 = engine.dstack.pop_int()?;

    if v1 >= v0 {
        engine.dstack.push_bool(true);
    } else {
        engine.dstack.push_bool(false);
    }
    return Result::Ok(());
}

pub fn opcode_min<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    let b = engine.dstack.pop_int()?;

    engine.dstack.push_int(if a < b {
        a
    } else {
        b
    });
    return Result::Ok(());
}

pub fn opcode_max<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    let b = engine.dstack.pop_int()?;
    engine.dstack.push_int(if a > b {
        a
    } else {
        b
    });
    return Result::Ok(());
}

pub fn opcode_within<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let max = engine.dstack.pop_int()?;
    let min = engine.dstack.pop_int()?;
    let value = engine.dstack.pop_int()?;
    engine.dstack.push_bool(if value >= min && value < max {
        true
    } else {
        false
    });
    return Result::Ok(());
}

// File: ./packages/engine/src/opcodes/constants.cairo

pub fn opcode_false<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.push_byte_array("");
    return Result::Ok(());
}

pub fn opcode_push_data<T, +Drop<T>>(n: usize, ref engine: Engine<T>) -> Result<(), felt252> {
    let data = EngineExtrasTrait::<T>::pull_data(ref engine, n)?;
    engine.dstack.push_byte_array(data);
    return Result::Ok(());
}

pub fn opcode_push_data_x<T, +Drop<T>>(n: usize, ref engine: Engine<T>) -> Result<(), felt252> {
    let data_len_bytes = EngineExtrasTrait::<T>::pull_data(ref engine, n)?;
    let data_len: usize = byte_array_to_felt252_le(@data_len_bytes).try_into().unwrap();
    let data = engine.pull_data(data_len)?;
    engine.dstack.push_byte_array(data);
    return Result::Ok(());
}

pub fn opcode_n<T, +Drop<T>>(n: i64, ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.push_int(n);
    return Result::Ok(());
}

pub fn opcode_1negate<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.push_int(-1);
    return Result::Ok(());
}

// File: ./packages/engine/src/opcodes/bitwise.cairo

pub fn opcode_equal<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_byte_array()?;
    let b = engine.dstack.pop_byte_array()?;
    engine.dstack.push_bool(if a == b {
        true
    } else {
        false
    });
    return Result::Ok(());
}

pub fn opcode_equal_verify<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    opcode_equal(ref engine)?;
    abstract_verify(ref engine)?;
    return Result::Ok(());
}

// File: ./packages/engine/src/opcodes/stack.cairo

pub fn opcode_toaltstack<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let value = engine.dstack.pop_byte_array()?;
    engine.astack.push_byte_array(value);
    return Result::Ok(());
}

pub fn opcode_fromaltstack<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.astack.pop_byte_array()?;
    engine.dstack.push_byte_array(a);
    return Result::Ok(());
}

pub fn opcode_depth<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let depth: i64 = engine.dstack.len().into();
    engine.dstack.push_int(depth);
    return Result::Ok(());
}

pub fn opcode_drop<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.pop_byte_array()?;
    return Result::Ok(());
}

pub fn opcode_dup<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.dup_n(1)?;
    return Result::Ok(());
}

pub fn opcode_swap<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_byte_array()?;
    let b = engine.dstack.pop_byte_array()?;
    engine.dstack.push_byte_array(a);
    engine.dstack.push_byte_array(b);
    return Result::Ok(());
}

pub fn opcode_nip<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.nip_n(1)?;
    return Result::Ok(());
}

pub fn opcode_pick<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    engine.dstack.pick_n(ScriptNum::to_int32(a))?;

    return Result::Ok(());
}

pub fn opcode_ifdup<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.peek_byte_array(0)?;

    if byte_array_to_bool(@a) {
        engine.dstack.push_byte_array(a);
    }
    return Result::Ok(());
}

pub fn opcode_tuck<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.tuck()?;
    return Result::Ok(());
}

pub fn opcode_2drop<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.pop_byte_array()?;
    engine.dstack.pop_byte_array()?;
    return Result::Ok(());
}

pub fn opcode_2dup<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.dup_n(2)?;
    return Result::Ok(());
}

pub fn opcode_3dup<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.dup_n(3)?;
    return Result::Ok(());
}

pub fn opcode_2swap<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_byte_array()?;
    let b = engine.dstack.pop_byte_array()?;
    let c = engine.dstack.pop_byte_array()?;
    let d = engine.dstack.pop_byte_array()?;
    engine.dstack.push_byte_array(b);
    engine.dstack.push_byte_array(a);
    engine.dstack.push_byte_array(d);
    engine.dstack.push_byte_array(c);
    return Result::Ok(());
}

pub fn opcode_2rot<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.rot_n(2)?;
    return Result::Ok(());
}

pub fn opcode_rot<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.rot_n(1)?;
    return Result::Ok(());
}

pub fn opcode_roll<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let value = engine.dstack.pop_int()?;
    engine.dstack.roll_n(ScriptNum::to_int32(value))?;
    return Result::Ok(());
}

pub fn opcode_over<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.over_n(1)?;
    return Result::Ok(());
}

pub fn opcode_2over<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.over_n(2)?;
    return Result::Ok(());
}

// File: ./packages/engine/src/utxo.cairo

#[derive(Debug, Drop)]
pub struct UTXO {
    pub amount: i64,
    pub pubkey_script: ByteArray,
    pub block_height: i32,
    // TODO: flags?
}
// TODO: implement UTXOSet?

// File: ./packages/engine/src/stack.cairo

#[derive(Destruct)]
pub struct ScriptStack {
    data: Felt252Dict<Nullable<ByteArray>>,
    len: usize,
    pub verify_minimal_data: bool,
}

#[generate_trait()]
pub impl ScriptStackImpl of ScriptStackTrait {
    fn new() -> ScriptStack {
        ScriptStack { data: Default::default(), len: 0, verify_minimal_data: false }
    }

    fn push_byte_array(ref self: ScriptStack, value: ByteArray) {
        self.data.insert(self.len.into(), NullableTrait::new(value));
        self.len += 1;
    }

    fn push_int(ref self: ScriptStack, value: i64) {
        let bytes = ScriptNum::wrap(value);
        self.push_byte_array(bytes);
    }

    fn push_bool(ref self: ScriptStack, value: bool) {
        if value {
            let mut v: ByteArray = Default::default();
            v.append_byte(1);
            self.push_byte_array(v);
        } else {
            self.push_byte_array(Default::default());
        }
    }

    fn pop_byte_array(ref self: ScriptStack) -> Result<ByteArray, felt252> {
        if self.len == 0 {
            return Result::Err(Error::STACK_UNDERFLOW);
        }
        self.len -= 1;
        let (entry, bytes) = self.data.entry(self.len.into());
        self.data = entry.finalize(NullableTrait::new(""));
        return Result::Ok(bytes.deref());
    }

    fn pop_int(ref self: ScriptStack) -> Result<i64, felt252> {
        let value = self.pop_byte_array()?;
        return Result::Ok(ScriptNum::try_into_num(value, self.verify_minimal_data)?);
    }

    fn pop_bool(ref self: ScriptStack) -> Result<bool, felt252> {
        let bytes = self.pop_byte_array()?;
        return Result::Ok(byte_array_to_bool(@bytes));
    }

    fn peek_byte_array(ref self: ScriptStack, idx: usize) -> Result<ByteArray, felt252> {
        if idx >= self.len {
            return Result::Err(Error::STACK_OUT_OF_RANGE);
        }
        let (entry, bytes) = self.data.entry((self.len - idx - 1).into());
        let bytes = bytes.deref();
        self.data = entry.finalize(NullableTrait::new(bytes.clone()));
        return Result::Ok(bytes);
    }

    fn peek_int(ref self: ScriptStack, idx: usize) -> Result<i64, felt252> {
        let bytes = self.peek_byte_array(idx)?;
        return Result::Ok(ScriptNum::try_into_num(bytes, self.verify_minimal_data)?);
    }

    fn peek_bool(ref self: ScriptStack, idx: usize) -> Result<bool, felt252> {
        let bytes = self.peek_byte_array(idx)?;
        return Result::Ok(byte_array_to_bool(@bytes));
    }

    fn len(ref self: ScriptStack) -> usize {
        self.len
    }

    fn depth(ref self: ScriptStack) -> usize {
        self.len
    }

    fn print_element(ref self: ScriptStack, idx: usize) {
        let (entry, arr) = self.data.entry(idx.into());
        let arr = arr.deref();
        if arr.len() == 0 {
            println!("stack[{}]: null", idx);
        } else {
            println!("stack[{}]: {}", idx, bytecode_to_hex(@arr.clone()));
        }
        self.data = entry.finalize(NullableTrait::new(arr));
    }

    fn print(ref self: ScriptStack) {
        let mut i = self.len;
        while i != 0 {
            i -= 1;
            self.print_element(i.into());
        }
    }

    fn json(ref self: ScriptStack) {
        let mut i = 0;
        print!("[");
        while i != self.len {
            let (entry, arr) = self.data.entry(i.into());
            let arr = arr.deref();
            print!("\"{}\"", bytecode_to_hex(@arr.clone()));
            self.data = entry.finalize(NullableTrait::new(arr));
            if i < self.len - 1 {
                print!(",");
            }
            i += 1;
        };
        println!("]");
    }

    fn rot_n(ref self: ScriptStack, n: u32) -> Result<(), felt252> {
        if n < 1 {
            return Result::Err('rot_n: invalid n value');
        }
        let mut err = '';
        let entry_index = 3 * n - 1;
        let mut i = n;
        while i != 0 {
            let res = self.nip_n(entry_index);
            if res.is_err() {
                err = res.unwrap_err();
                break;
            }
            self.push_byte_array(res.unwrap());
            i -= 1;
        };
        if err != '' {
            return Result::Err(err);
        }
        return Result::Ok(());
    }

    fn stack_to_span(ref self: ScriptStack) -> Span<ByteArray> {
        let mut result = array![];
        let mut i = 0;
        while i != self.len {
            let (entry, arr) = self.data.entry(i.into());
            let arr = arr.deref();
            result.append(arr.clone());
            self.data = entry.finalize(NullableTrait::new(arr));
            i += 1
        };

        return result.span();
    }

    fn dup_n(ref self: ScriptStack, n: u32) -> Result<(), felt252> {
        if (n < 1) {
            return Result::Err('dup_n: invalid n value');
        }
        let mut i = n;
        let mut err = '';
        while i != 0 {
            i -= 1;
            let value = self.peek_byte_array(n - 1);
            if value.is_err() {
                err = value.unwrap_err();
                break;
            }
            self.push_byte_array(value.unwrap());
        };
        if err != '' {
            return Result::Err(err);
        }
        return Result::Ok(());
    }

    fn tuck(ref self: ScriptStack) -> Result<(), felt252> {
        let top_element = self.pop_byte_array()?;
        let next_element = self.pop_byte_array()?;

        self.push_byte_array(top_element.clone());
        self.push_byte_array(next_element);
        self.push_byte_array(top_element);
        return Result::Ok(());
    }

    fn nip_n(ref self: ScriptStack, idx: usize) -> Result<ByteArray, felt252> {
        let value = self.peek_byte_array(idx)?;

        // Shift all elements above idx down by one
        let mut i = 0;
        while i != idx {
            let next_value = self.peek_byte_array(idx - i - 1).unwrap();
            let (entry, _) = self.data.entry((self.len - idx + i - 1).into());
            self.data = entry.finalize(NullableTrait::new(next_value));
            i += 1;
        };
        let (last_entry, _) = self.data.entry((self.len - 1).into());
        self.data = last_entry.finalize(NullableTrait::new(""));
        self.len -= 1;
        return Result::Ok(value);
    }

    fn pick_n(ref self: ScriptStack, idx: i32) -> Result<(), felt252> {
        if idx < 0 {
            return Result::Err(Error::STACK_OUT_OF_RANGE);
        }

        let idxU32: u32 = idx.try_into().unwrap();
        if idxU32 >= self.len {
            return Result::Err(Error::STACK_OUT_OF_RANGE);
        }

        let so = self.peek_byte_array(idxU32)?;

        self.push_byte_array(so);
        return Result::Ok(());
    }

    fn roll_n(ref self: ScriptStack, n: i32) -> Result<(), felt252> {
        if n < 0 {
            return Result::Err(Error::STACK_OUT_OF_RANGE);
        }
        let nU32: u32 = n.try_into().unwrap();
        if nU32 >= self.len {
            return Result::Err(Error::STACK_OUT_OF_RANGE);
        }

        let value = self.nip_n(nU32)?;
        self.push_byte_array(value);
        return Result::Ok(());
    }

    fn over_n(ref self: ScriptStack, mut n: u32) -> Result<(), felt252> {
        if n < 1 {
            return Result::Err('over_n: invalid n value');
        }
        let entry: u32 = (2 * n) - 1;
        let mut err = '';
        while n != 0 {
            let res = self.peek_byte_array(entry);
            if res.is_err() {
                err = res.unwrap_err();
                break;
            }

            self.push_byte_array(res.unwrap());
            n -= 1;
        };

        if err != '' {
            return Result::Err(err);
        }

        return Result::Ok(());
    }

    // Set stack to a new array of byte arrays
    fn set_stack(ref self: ScriptStack, stack: Span<ByteArray>, start: u32, len: u32) {
        self.data = Default::default();
        self.len = 0;
        let mut i = start;
        let end = start + len;
        while i != end {
            self.push_byte_array(stack.at(i).clone());
            i += 1;
        };
    }
}

// File: ./packages/compiler/src/utils.cairo

// Checks if item starts with 0x
// TODO: Check validity of hex?
pub fn is_hex(script_item: @ByteArray) -> bool {
    if script_item.len() < 2 {
        return false;
    }
    let byte_shift = 256;
    let first_two = script_item[0].into() * byte_shift + script_item[1].into();
    first_two == '0x'
}

// Checks if item surrounded with a single or double quote
pub fn is_string(script_item: @ByteArray) -> bool {
    if script_item.len() < 2 {
        return false;
    }
    let single_quote = '\'';
    let double_quote = '"';
    let first = script_item[0];
    let last = script_item[script_item.len() - 1];
    (first == single_quote && last == single_quote)
        || (first == double_quote && last == double_quote)
}

// Check if item is a number (starts with 0-9 or -)
pub fn is_number(script_item: @ByteArray) -> bool {
    if script_item.len() == 0 {
        return false;
    }
    let zero = '0';
    let nine = '9';
    let minus = '-';
    let first = script_item[0];
    if first == minus {
        return script_item.len() > 1;
    }
    if script_item.len() > 1 {
        let second = script_item[1];
        // Some opcodes start with a number; like 2ROT
        return first >= zero && first <= nine && second >= zero && second <= nine;
    }
    first >= zero && first <= nine
}

// File: ./packages/compiler/src/compiler.cairo

// Compiler that takes a Bitcoin Script program and compiles it into a bytecode
#[derive(Destruct)]
pub struct Compiler {
    // Dict containing opcode names to their bytecode representation
    opcodes: Felt252Dict<Nullable<u8>>
}

pub trait CompilerTrait {
    // Create a compiler, initializing the opcode dict
    fn new() -> Compiler;
    // Adds an opcode "OP_XXX" to the opcodes dict under: "OP_XXX" and "XXX"
    fn add_opcode(ref self: Compiler, name: felt252, opcode: u8);
    // Compiles a program like "OP_1 OP_2 OP_ADD" into a bytecode run by the Engine.
    fn compile(self: Compiler, script: ByteArray) -> Result<ByteArray, felt252>;
}

pub impl CompilerImpl of CompilerTrait {
    fn new() -> Compiler {
        let mut compiler = Compiler { opcodes: Default::default() };
        // Add the opcodes to the dict
        compiler.add_opcode('OP_0', Opcode::OP_0);
        compiler.add_opcode('OP_FALSE', Opcode::OP_0);
        compiler.add_opcode('OP_DATA_1', Opcode::OP_DATA_1);
        compiler.add_opcode('OP_DATA_2', Opcode::OP_DATA_2);
        compiler.add_opcode('OP_DATA_3', Opcode::OP_DATA_3);
        compiler.add_opcode('OP_DATA_4', Opcode::OP_DATA_4);
        compiler.add_opcode('OP_DATA_5', Opcode::OP_DATA_5);
        compiler.add_opcode('OP_DATA_6', Opcode::OP_DATA_6);
        compiler.add_opcode('OP_DATA_7', Opcode::OP_DATA_7);
        compiler.add_opcode('OP_DATA_8', Opcode::OP_DATA_8);
        compiler.add_opcode('OP_DATA_9', Opcode::OP_DATA_9);
        compiler.add_opcode('OP_DATA_10', Opcode::OP_DATA_10);
        compiler.add_opcode('OP_DATA_11', Opcode::OP_DATA_11);
        compiler.add_opcode('OP_DATA_12', Opcode::OP_DATA_12);
        compiler.add_opcode('OP_DATA_13', Opcode::OP_DATA_13);
        compiler.add_opcode('OP_DATA_14', Opcode::OP_DATA_14);
        compiler.add_opcode('OP_DATA_15', Opcode::OP_DATA_15);
        compiler.add_opcode('OP_DATA_16', Opcode::OP_DATA_16);
        compiler.add_opcode('OP_DATA_17', Opcode::OP_DATA_17);
        compiler.add_opcode('OP_DATA_18', Opcode::OP_DATA_18);
        compiler.add_opcode('OP_DATA_19', Opcode::OP_DATA_19);
        compiler.add_opcode('OP_DATA_20', Opcode::OP_DATA_20);
        compiler.add_opcode('OP_DATA_21', Opcode::OP_DATA_21);
        compiler.add_opcode('OP_DATA_22', Opcode::OP_DATA_22);
        compiler.add_opcode('OP_DATA_23', Opcode::OP_DATA_23);
        compiler.add_opcode('OP_DATA_24', Opcode::OP_DATA_24);
        compiler.add_opcode('OP_DATA_25', Opcode::OP_DATA_25);
        compiler.add_opcode('OP_DATA_26', Opcode::OP_DATA_26);
        compiler.add_opcode('OP_DATA_27', Opcode::OP_DATA_27);
        compiler.add_opcode('OP_DATA_28', Opcode::OP_DATA_28);
        compiler.add_opcode('OP_DATA_29', Opcode::OP_DATA_29);
        compiler.add_opcode('OP_DATA_30', Opcode::OP_DATA_30);
        compiler.add_opcode('OP_DATA_31', Opcode::OP_DATA_31);
        compiler.add_opcode('OP_DATA_32', Opcode::OP_DATA_32);
        compiler.add_opcode('OP_DATA_33', Opcode::OP_DATA_33);
        compiler.add_opcode('OP_DATA_34', Opcode::OP_DATA_34);
        compiler.add_opcode('OP_DATA_35', Opcode::OP_DATA_35);
        compiler.add_opcode('OP_DATA_36', Opcode::OP_DATA_36);
        compiler.add_opcode('OP_DATA_37', Opcode::OP_DATA_37);
        compiler.add_opcode('OP_DATA_38', Opcode::OP_DATA_38);
        compiler.add_opcode('OP_DATA_39', Opcode::OP_DATA_39);
        compiler.add_opcode('OP_DATA_40', Opcode::OP_DATA_40);
        compiler.add_opcode('OP_DATA_41', Opcode::OP_DATA_41);
        compiler.add_opcode('OP_DATA_42', Opcode::OP_DATA_42);
        compiler.add_opcode('OP_DATA_43', Opcode::OP_DATA_43);
        compiler.add_opcode('OP_DATA_44', Opcode::OP_DATA_44);
        compiler.add_opcode('OP_DATA_45', Opcode::OP_DATA_45);
        compiler.add_opcode('OP_DATA_46', Opcode::OP_DATA_46);
        compiler.add_opcode('OP_DATA_47', Opcode::OP_DATA_47);
        compiler.add_opcode('OP_DATA_48', Opcode::OP_DATA_48);
        compiler.add_opcode('OP_DATA_49', Opcode::OP_DATA_49);
        compiler.add_opcode('OP_DATA_50', Opcode::OP_DATA_50);
        compiler.add_opcode('OP_DATA_51', Opcode::OP_DATA_51);
        compiler.add_opcode('OP_DATA_52', Opcode::OP_DATA_52);
        compiler.add_opcode('OP_DATA_53', Opcode::OP_DATA_53);
        compiler.add_opcode('OP_DATA_54', Opcode::OP_DATA_54);
        compiler.add_opcode('OP_DATA_55', Opcode::OP_DATA_55);
        compiler.add_opcode('OP_DATA_56', Opcode::OP_DATA_56);
        compiler.add_opcode('OP_DATA_57', Opcode::OP_DATA_57);
        compiler.add_opcode('OP_DATA_58', Opcode::OP_DATA_58);
        compiler.add_opcode('OP_DATA_59', Opcode::OP_DATA_59);
        compiler.add_opcode('OP_DATA_60', Opcode::OP_DATA_60);
        compiler.add_opcode('OP_DATA_61', Opcode::OP_DATA_61);
        compiler.add_opcode('OP_DATA_62', Opcode::OP_DATA_62);
        compiler.add_opcode('OP_DATA_63', Opcode::OP_DATA_63);
        compiler.add_opcode('OP_DATA_64', Opcode::OP_DATA_64);
        compiler.add_opcode('OP_DATA_65', Opcode::OP_DATA_65);
        compiler.add_opcode('OP_DATA_66', Opcode::OP_DATA_66);
        compiler.add_opcode('OP_DATA_67', Opcode::OP_DATA_67);
        compiler.add_opcode('OP_DATA_68', Opcode::OP_DATA_68);
        compiler.add_opcode('OP_DATA_69', Opcode::OP_DATA_69);
        compiler.add_opcode('OP_DATA_70', Opcode::OP_DATA_70);
        compiler.add_opcode('OP_DATA_71', Opcode::OP_DATA_71);
        compiler.add_opcode('OP_DATA_72', Opcode::OP_DATA_72);
        compiler.add_opcode('OP_DATA_73', Opcode::OP_DATA_73);
        compiler.add_opcode('OP_DATA_74', Opcode::OP_DATA_74);
        compiler.add_opcode('OP_DATA_75', Opcode::OP_DATA_75);
        compiler.add_opcode('OP_PUSHBYTES_0', Opcode::OP_0);
        compiler.add_opcode('OP_PUSHBYTES_1', Opcode::OP_DATA_1);
        compiler.add_opcode('OP_PUSHBYTES_2', Opcode::OP_DATA_2);
        compiler.add_opcode('OP_PUSHBYTES_3', Opcode::OP_DATA_3);
        compiler.add_opcode('OP_PUSHBYTES_4', Opcode::OP_DATA_4);
        compiler.add_opcode('OP_PUSHBYTES_5', Opcode::OP_DATA_5);
        compiler.add_opcode('OP_PUSHBYTES_6', Opcode::OP_DATA_6);
        compiler.add_opcode('OP_PUSHBYTES_7', Opcode::OP_DATA_7);
        compiler.add_opcode('OP_PUSHBYTES_8', Opcode::OP_DATA_8);
        compiler.add_opcode('OP_PUSHBYTES_9', Opcode::OP_DATA_9);
        compiler.add_opcode('OP_PUSHBYTES_10', Opcode::OP_DATA_10);
        compiler.add_opcode('OP_PUSHBYTES_11', Opcode::OP_DATA_11);
        compiler.add_opcode('OP_PUSHBYTES_12', Opcode::OP_DATA_12);
        compiler.add_opcode('OP_PUSHBYTES_13', Opcode::OP_DATA_13);
        compiler.add_opcode('OP_PUSHBYTES_14', Opcode::OP_DATA_14);
        compiler.add_opcode('OP_PUSHBYTES_15', Opcode::OP_DATA_15);
        compiler.add_opcode('OP_PUSHBYTES_16', Opcode::OP_DATA_16);
        compiler.add_opcode('OP_PUSHBYTES_17', Opcode::OP_DATA_17);
        compiler.add_opcode('OP_PUSHBYTES_18', Opcode::OP_DATA_18);
        compiler.add_opcode('OP_PUSHBYTES_19', Opcode::OP_DATA_19);
        compiler.add_opcode('OP_PUSHBYTES_20', Opcode::OP_DATA_20);
        compiler.add_opcode('OP_PUSHBYTES_21', Opcode::OP_DATA_21);
        compiler.add_opcode('OP_PUSHBYTES_22', Opcode::OP_DATA_22);
        compiler.add_opcode('OP_PUSHBYTES_23', Opcode::OP_DATA_23);
        compiler.add_opcode('OP_PUSHBYTES_24', Opcode::OP_DATA_24);
        compiler.add_opcode('OP_PUSHBYTES_25', Opcode::OP_DATA_25);
        compiler.add_opcode('OP_PUSHBYTES_26', Opcode::OP_DATA_26);
        compiler.add_opcode('OP_PUSHBYTES_27', Opcode::OP_DATA_27);
        compiler.add_opcode('OP_PUSHBYTES_28', Opcode::OP_DATA_28);
        compiler.add_opcode('OP_PUSHBYTES_29', Opcode::OP_DATA_29);
        compiler.add_opcode('OP_PUSHBYTES_30', Opcode::OP_DATA_30);
        compiler.add_opcode('OP_PUSHBYTES_31', Opcode::OP_DATA_31);
        compiler.add_opcode('OP_PUSHBYTES_32', Opcode::OP_DATA_32);
        compiler.add_opcode('OP_PUSHBYTES_33', Opcode::OP_DATA_33);
        compiler.add_opcode('OP_PUSHBYTES_34', Opcode::OP_DATA_34);
        compiler.add_opcode('OP_PUSHBYTES_35', Opcode::OP_DATA_35);
        compiler.add_opcode('OP_PUSHBYTES_36', Opcode::OP_DATA_36);
        compiler.add_opcode('OP_PUSHBYTES_37', Opcode::OP_DATA_37);
        compiler.add_opcode('OP_PUSHBYTES_38', Opcode::OP_DATA_38);
        compiler.add_opcode('OP_PUSHBYTES_39', Opcode::OP_DATA_39);
        compiler.add_opcode('OP_PUSHBYTES_40', Opcode::OP_DATA_40);
        compiler.add_opcode('OP_PUSHBYTES_41', Opcode::OP_DATA_41);
        compiler.add_opcode('OP_PUSHBYTES_42', Opcode::OP_DATA_42);
        compiler.add_opcode('OP_PUSHBYTES_43', Opcode::OP_DATA_43);
        compiler.add_opcode('OP_PUSHBYTES_44', Opcode::OP_DATA_44);
        compiler.add_opcode('OP_PUSHBYTES_45', Opcode::OP_DATA_45);
        compiler.add_opcode('OP_PUSHBYTES_46', Opcode::OP_DATA_46);
        compiler.add_opcode('OP_PUSHBYTES_47', Opcode::OP_DATA_47);
        compiler.add_opcode('OP_PUSHBYTES_48', Opcode::OP_DATA_48);
        compiler.add_opcode('OP_PUSHBYTES_49', Opcode::OP_DATA_49);
        compiler.add_opcode('OP_PUSHBYTES_50', Opcode::OP_DATA_50);
        compiler.add_opcode('OP_PUSHBYTES_51', Opcode::OP_DATA_51);
        compiler.add_opcode('OP_PUSHBYTES_52', Opcode::OP_DATA_52);
        compiler.add_opcode('OP_PUSHBYTES_53', Opcode::OP_DATA_53);
        compiler.add_opcode('OP_PUSHBYTES_54', Opcode::OP_DATA_54);
        compiler.add_opcode('OP_PUSHBYTES_55', Opcode::OP_DATA_55);
        compiler.add_opcode('OP_PUSHBYTES_56', Opcode::OP_DATA_56);
        compiler.add_opcode('OP_PUSHBYTES_57', Opcode::OP_DATA_57);
        compiler.add_opcode('OP_PUSHBYTES_58', Opcode::OP_DATA_58);
        compiler.add_opcode('OP_PUSHBYTES_59', Opcode::OP_DATA_59);
        compiler.add_opcode('OP_PUSHBYTES_60', Opcode::OP_DATA_60);
        compiler.add_opcode('OP_PUSHBYTES_61', Opcode::OP_DATA_61);
        compiler.add_opcode('OP_PUSHBYTES_62', Opcode::OP_DATA_62);
        compiler.add_opcode('OP_PUSHBYTES_63', Opcode::OP_DATA_63);
        compiler.add_opcode('OP_PUSHBYTES_64', Opcode::OP_DATA_64);
        compiler.add_opcode('OP_PUSHBYTES_65', Opcode::OP_DATA_65);
        compiler.add_opcode('OP_PUSHBYTES_66', Opcode::OP_DATA_66);
        compiler.add_opcode('OP_PUSHBYTES_67', Opcode::OP_DATA_67);
        compiler.add_opcode('OP_PUSHBYTES_68', Opcode::OP_DATA_68);
        compiler.add_opcode('OP_PUSHBYTES_69', Opcode::OP_DATA_69);
        compiler.add_opcode('OP_PUSHBYTES_70', Opcode::OP_DATA_70);
        compiler.add_opcode('OP_PUSHBYTES_71', Opcode::OP_DATA_71);
        compiler.add_opcode('OP_PUSHBYTES_72', Opcode::OP_DATA_72);
        compiler.add_opcode('OP_PUSHBYTES_73', Opcode::OP_DATA_73);
        compiler.add_opcode('OP_PUSHBYTES_74', Opcode::OP_DATA_74);
        compiler.add_opcode('OP_PUSHBYTES_75', Opcode::OP_DATA_75);
        compiler.add_opcode('OP_PUSHDATA1', Opcode::OP_PUSHDATA1);
        compiler.add_opcode('OP_PUSHDATA2', Opcode::OP_PUSHDATA2);
        compiler.add_opcode('OP_PUSHDATA4', Opcode::OP_PUSHDATA4);
        compiler.add_opcode('OP_1NEGATE', Opcode::OP_1NEGATE);
        compiler.add_opcode('OP_1', Opcode::OP_1);
        compiler.add_opcode('OP_TRUE', Opcode::OP_TRUE);
        compiler.add_opcode('OP_2', Opcode::OP_2);
        compiler.add_opcode('OP_3', Opcode::OP_3);
        compiler.add_opcode('OP_4', Opcode::OP_4);
        compiler.add_opcode('OP_5', Opcode::OP_5);
        compiler.add_opcode('OP_6', Opcode::OP_6);
        compiler.add_opcode('OP_7', Opcode::OP_7);
        compiler.add_opcode('OP_8', Opcode::OP_8);
        compiler.add_opcode('OP_9', Opcode::OP_9);
        compiler.add_opcode('OP_10', Opcode::OP_10);
        compiler.add_opcode('OP_11', Opcode::OP_11);
        compiler.add_opcode('OP_12', Opcode::OP_12);
        compiler.add_opcode('OP_13', Opcode::OP_13);
        compiler.add_opcode('OP_14', Opcode::OP_14);
        compiler.add_opcode('OP_15', Opcode::OP_15);
        compiler.add_opcode('OP_16', Opcode::OP_16);
        compiler.add_opcode('OP_PUSHNUM_NEG1', Opcode::OP_1NEGATE);
        compiler.add_opcode('OP_PUSHNUM_1', Opcode::OP_1);
        compiler.add_opcode('OP_PUSHNUM_2', Opcode::OP_2);
        compiler.add_opcode('OP_PUSHNUM_3', Opcode::OP_3);
        compiler.add_opcode('OP_PUSHNUM_4', Opcode::OP_4);
        compiler.add_opcode('OP_PUSHNUM_5', Opcode::OP_5);
        compiler.add_opcode('OP_PUSHNUM_6', Opcode::OP_6);
        compiler.add_opcode('OP_PUSHNUM_7', Opcode::OP_7);
        compiler.add_opcode('OP_PUSHNUM_8', Opcode::OP_8);
        compiler.add_opcode('OP_PUSHNUM_9', Opcode::OP_9);
        compiler.add_opcode('OP_PUSHNUM_10', Opcode::OP_10);
        compiler.add_opcode('OP_PUSHNUM_11', Opcode::OP_11);
        compiler.add_opcode('OP_PUSHNUM_12', Opcode::OP_12);
        compiler.add_opcode('OP_PUSHNUM_13', Opcode::OP_13);
        compiler.add_opcode('OP_PUSHNUM_14', Opcode::OP_14);
        compiler.add_opcode('OP_PUSHNUM_15', Opcode::OP_15);
        compiler.add_opcode('OP_PUSHNUM_16', Opcode::OP_16);
        compiler.add_opcode('OP_NOP', Opcode::OP_NOP);
        compiler.add_opcode('OP_IF', Opcode::OP_IF);
        compiler.add_opcode('OP_NOTIF', Opcode::OP_NOTIF);
        compiler.add_opcode('OP_VERIF', Opcode::OP_VERIF);
        compiler.add_opcode('OP_VERNOTIF', Opcode::OP_VERNOTIF);
        compiler.add_opcode('OP_ELSE', Opcode::OP_ELSE);
        compiler.add_opcode('OP_ENDIF', Opcode::OP_ENDIF);
        compiler.add_opcode('OP_VERIFY', Opcode::OP_VERIFY);
        compiler.add_opcode('OP_RETURN', Opcode::OP_RETURN);
        compiler.add_opcode('OP_TOALTSTACK', Opcode::OP_TOALTSTACK);
        compiler.add_opcode('OP_FROMALTSTACK', Opcode::OP_FROMALTSTACK);
        compiler.add_opcode('OP_2DROP', Opcode::OP_2DROP);
        compiler.add_opcode('OP_2DUP', Opcode::OP_2DUP);
        compiler.add_opcode('OP_3DUP', Opcode::OP_3DUP);
        compiler.add_opcode('OP_DROP', Opcode::OP_DROP);
        compiler.add_opcode('OP_DUP', Opcode::OP_DUP);
        compiler.add_opcode('OP_NIP', Opcode::OP_NIP);
        compiler.add_opcode('OP_PICK', Opcode::OP_PICK);
        compiler.add_opcode('OP_EQUAL', Opcode::OP_EQUAL);
        compiler.add_opcode('OP_EQUALVERIFY', Opcode::OP_EQUALVERIFY);
        compiler.add_opcode('OP_2ROT', Opcode::OP_2ROT);
        compiler.add_opcode('OP_2SWAP', Opcode::OP_2SWAP);
        compiler.add_opcode('OP_IFDUP', Opcode::OP_IFDUP);
        compiler.add_opcode('OP_DEPTH', Opcode::OP_DEPTH);
        compiler.add_opcode('OP_SIZE', Opcode::OP_SIZE);
        compiler.add_opcode('OP_ROT', Opcode::OP_ROT);
        compiler.add_opcode('OP_SWAP', Opcode::OP_SWAP);
        compiler.add_opcode('OP_1ADD', Opcode::OP_1ADD);
        compiler.add_opcode('OP_1SUB', Opcode::OP_1SUB);
        compiler.add_opcode('OP_NEGATE', Opcode::OP_NEGATE);
        compiler.add_opcode('OP_ABS', Opcode::OP_ABS);
        compiler.add_opcode('OP_NOT', Opcode::OP_NOT);
        compiler.add_opcode('OP_0NOTEQUAL', Opcode::OP_0NOTEQUAL);
        compiler.add_opcode('OP_ADD', Opcode::OP_ADD);
        compiler.add_opcode('OP_SUB', Opcode::OP_SUB);
        compiler.add_opcode('OP_BOOLAND', Opcode::OP_BOOLAND);
        compiler.add_opcode('OP_NUMEQUAL', Opcode::OP_NUMEQUAL);
        compiler.add_opcode('OP_NUMEQUALVERIFY', Opcode::OP_NUMEQUALVERIFY);
        compiler.add_opcode('OP_NUMNOTEQUAL', Opcode::OP_NUMNOTEQUAL);
        compiler.add_opcode('OP_LESSTHAN', Opcode::OP_LESSTHAN);
        compiler.add_opcode('OP_GREATERTHAN', Opcode::OP_GREATERTHAN);
        compiler.add_opcode('OP_LESSTHANOREQUAL', Opcode::OP_LESSTHANOREQUAL);
        compiler.add_opcode('OP_GREATERTHANOREQUAL', Opcode::OP_GREATERTHANOREQUAL);
        compiler.add_opcode('OP_MIN', Opcode::OP_MIN);
        compiler.add_opcode('OP_MAX', Opcode::OP_MAX);
        compiler.add_opcode('OP_WITHIN', Opcode::OP_WITHIN);
        compiler.add_opcode('OP_RIPEMD160', Opcode::OP_RIPEMD160);
        compiler.add_opcode('OP_SHA1', Opcode::OP_SHA1);
        compiler.add_opcode('OP_RESERVED', Opcode::OP_RESERVED);
        compiler.add_opcode('OP_RESERVED1', Opcode::OP_RESERVED1);
        compiler.add_opcode('OP_RESERVED2', Opcode::OP_RESERVED2);
        compiler.add_opcode('OP_VER', Opcode::OP_VER);
        compiler.add_opcode('OP_TUCK', Opcode::OP_TUCK);
        compiler.add_opcode('OP_BOOLOR', Opcode::OP_BOOLOR);
        compiler.add_opcode('OP_CAT', Opcode::OP_CAT);
        compiler.add_opcode('OP_SUBSTR', Opcode::OP_SUBSTR);
        compiler.add_opcode('OP_LEFT', Opcode::OP_LEFT);
        compiler.add_opcode('OP_RIGHT', Opcode::OP_RIGHT);
        compiler.add_opcode('OP_INVERT', Opcode::OP_INVERT);
        compiler.add_opcode('OP_AND', Opcode::OP_AND);
        compiler.add_opcode('OP_OR', Opcode::OP_OR);
        compiler.add_opcode('OP_XOR', Opcode::OP_XOR);
        compiler.add_opcode('OP_2MUL', Opcode::OP_2MUL);
        compiler.add_opcode('OP_2DIV', Opcode::OP_2DIV);
        compiler.add_opcode('OP_MUL', Opcode::OP_MUL);
        compiler.add_opcode('OP_DIV', Opcode::OP_DIV);
        compiler.add_opcode('OP_MOD', Opcode::OP_MOD);
        compiler.add_opcode('OP_LSHIFT', Opcode::OP_LSHIFT);
        compiler.add_opcode('OP_RSHIFT', Opcode::OP_RSHIFT);
        compiler.add_opcode('OP_NOP1', Opcode::OP_NOP1);
        compiler.add_opcode('OP_NOP4', Opcode::OP_NOP4);
        compiler.add_opcode('OP_NOP5', Opcode::OP_NOP5);
        compiler.add_opcode('OP_NOP6', Opcode::OP_NOP6);
        compiler.add_opcode('OP_NOP7', Opcode::OP_NOP7);
        compiler.add_opcode('OP_NOP8', Opcode::OP_NOP8);
        compiler.add_opcode('OP_NOP9', Opcode::OP_NOP9);
        compiler.add_opcode('OP_NOP10', Opcode::OP_NOP10);
        compiler.add_opcode('OP_ROLL', Opcode::OP_ROLL);
        compiler.add_opcode('OP_OVER', Opcode::OP_OVER);
        compiler.add_opcode('OP_2OVER', Opcode::OP_2OVER);
        compiler.add_opcode('OP_SHA256', Opcode::OP_SHA256);
        compiler.add_opcode('OP_HASH160', Opcode::OP_HASH160);
        compiler.add_opcode('OP_HASH256', Opcode::OP_HASH256);
        compiler.add_opcode('OP_CHECKSIG', Opcode::OP_CHECKSIG);
        compiler.add_opcode('OP_CHECKSIGVERIFY', Opcode::OP_CHECKSIGVERIFY);
        compiler.add_opcode('OP_CHECKMULTISIG', Opcode::OP_CHECKMULTISIG);
        compiler.add_opcode('OP_CHECKMULTISIGVERIFY', Opcode::OP_CHECKMULTISIGVERIFY);
        compiler.add_opcode('OP_CODESEPARATOR', Opcode::OP_CODESEPARATOR);
        compiler.add_opcode('OP_CHECKLOCKTIMEVERIFY', Opcode::OP_CHECKLOCKTIMEVERIFY);
        compiler.add_opcode('OP_CLTV', Opcode::OP_CHECKLOCKTIMEVERIFY);
        compiler.add_opcode('OP_CHECKSEQUENCEVERIFY', Opcode::OP_CHECKSEQUENCEVERIFY);
        compiler.add_opcode('OP_CSV', Opcode::OP_CHECKSEQUENCEVERIFY);

        compiler
    }

    fn add_opcode(ref self: Compiler, name: felt252, opcode: u8) {
        // Insert opcode formatted like OP_XXX
        self.opcodes.insert(name, NullableTrait::new(opcode));

        // Remove OP_ prefix and insert opcode XXX
        let nameu256 = name.into();
        let mut name_mask: u256 = 1;
        while name_mask < nameu256 {
            name_mask = name_mask * 256; // Shift left 1 byte
        };
        name_mask = name_mask / 16_777_216; // Shift right 3 bytes
        self.opcodes.insert((nameu256 % name_mask).try_into().unwrap(), NullableTrait::new(opcode));
    }

    fn compile(mut self: Compiler, script: ByteArray) -> Result<ByteArray, felt252> {
        let mut bytecode = "";
        let seperator = ' ';

        // Split the script into opcodes / data
        let mut split_script: Array<ByteArray> = array![];
        let mut current = "";
        let mut i = 0;
        let script_len = script.len();
        while i != script_len {
            let char = script[i].into();
            if char == seperator {
                if current == "" {
                    i += 1;
                    continue;
                }
                split_script.append(current);
                current = "";
            } else {
                current.append_byte(char);
            }
            i += 1;
        };
        // Handle the last opcode
        if current != "" {
            split_script.append(current);
        }

        // Compile the script into bytecode
        let mut i = 0;
        let script_len = split_script.len();
        let mut err = '';
        while i != script_len {
            let script_item = split_script.at(i);
            if is_hex(script_item) {
                ByteArrayTrait::append(ref bytecode, @hex_to_bytecode(script_item));
            } else if is_string(script_item) {
                ByteArrayTrait::append(ref bytecode, @string_to_bytecode(script_item));
            } else if is_number(script_item) {
                ByteArrayTrait::append(ref bytecode, @number_to_bytecode(script_item));
            } else {
                let opcode_nullable = self.opcodes.get(byte_array_to_felt252_be(script_item));
                if opcode_nullable.is_null() {
                    err = 'Compiler error: unknown opcode';
                    break;
                }
                bytecode.append_byte(opcode_nullable.deref());
            }
            i += 1;
        };
        if err != '' {
            return Result::Err(err);
        }
        Result::Ok(bytecode)
    }
}

// Remove the surrounding quotes and add the corrent append opcodes to the front
// https://github.com/btcsuite/btcd/blob/b161cd6a199b4e35acec66afc5aad221f05fe1e3/txs
// cript/scriptbuilder.go#L159
pub fn string_to_bytecode(script_item: @ByteArray) -> ByteArray {
    let mut bytecode = "";
    let mut i = 1;
    let word_len = script_item.len() - 2;
    let end = script_item.len() - 1;
    if word_len == 0 || (word_len == 1 && script_item[1] == 0) {
        bytecode.append_byte(Opcode::OP_0);
        return bytecode;
    } else if word_len == 1 && script_item[1] <= 16 {
        bytecode.append_byte(Opcode::OP_1 - 1 + script_item[1]);
        return bytecode;
    } else if word_len == 1 && script_item[1] == 0x81 {
        bytecode.append_byte(Opcode::OP_1NEGATE);
        return bytecode;
    }

    if word_len < Opcode::OP_PUSHDATA1.into() {
        bytecode.append_byte(Opcode::OP_DATA_1 - 1 + word_len.try_into().unwrap());
    } else if word_len < 0x100 {
        bytecode.append_byte(Opcode::OP_PUSHDATA1);
        bytecode.append_byte(word_len.try_into().unwrap());
    } else if word_len < 0x10000 {
        bytecode.append_byte(Opcode::OP_PUSHDATA2);
        // TODO: Little-endian?
        bytecode.append(@ScriptNum::wrap(word_len.into()));
    } else {
        bytecode.append_byte(Opcode::OP_PUSHDATA4);
        bytecode.append(@ScriptNum::wrap(word_len.into()));
    }
    while i != end {
        bytecode.append_byte(script_item[i]);
        i += 1;
    };
    bytecode
}

// Convert a number to bytecode
pub fn number_to_bytecode(script_item: @ByteArray) -> ByteArray {
    let mut bytecode = "";
    let mut i = 0;
    let script_item_len = script_item.len();
    let zero = '0';
    let negative = '-';
    let mut is_negative = false;
    if script_item[0] == negative {
        is_negative = true;
        i += 1;
    }
    let mut value: i64 = 0;
    while i != script_item_len {
        value = value * 10 + script_item[i].into() - zero;
        i += 1;
    };
    if is_negative {
        value = -value;
    }
    // TODO: Negative info lost before this
    if value == -1 {
        bytecode.append_byte(Opcode::OP_1NEGATE);
    } else if value > 0 && value <= 16 {
        bytecode.append_byte(Opcode::OP_1 - 1 + value.try_into().unwrap());
    } else if value == 0 {
        bytecode.append_byte(Opcode::OP_0);
    } else {
        // TODO: always script num?
        let script_num = ScriptNum::wrap(value);
        let script_num_len = script_num.len();
        if script_num_len < Opcode::OP_PUSHDATA1.into() {
            bytecode.append_byte(Opcode::OP_DATA_1 - 1 + script_num_len.try_into().unwrap());
        } else if script_num_len < 0x100 {
            bytecode.append_byte(Opcode::OP_PUSHDATA1);
            bytecode.append_byte(script_num_len.try_into().unwrap());
        }
        bytecode.append(@script_num);
    }
    bytecode
}

// File: ./packages/compiler/src/tests/test_compiler.cairo

// TODO: More tests?

#[test]
fn test_compiler_unknown_opcode() {
    let mut compiler = CompilerImpl::new();
    let res = compiler.compile("OP_FAKE");
    assert!(res.is_err());
    assert_eq!(res.unwrap_err(), 'Compiler error: unknown opcode', "Error message mismatch");
}

// File: ./packages/compiler/src/lib.cairo
mod tests {
pub mod compiler;
pub mod utils;

#[cfg(test)]
    mod test_compiler;
}
