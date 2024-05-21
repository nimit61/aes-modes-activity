//! In Module 1, we discussed Block ciphers like AES. Block ciphers have a fixed length input.
//! Real wold data that we wish to encrypt _may_ be exactly the right length, but is probably not.
//! When your data is too short, you can simply pad it up to the correct length.
//! When your data is too long, you have some options.
//!
//! In this exercise, we will explore a few of the common ways that large pieces of data can be
//! broken up and combined in order to encrypt it with a fixed-length block cipher.
//!
//! WARNING: ECB MODE IS NOT SECURE.
//! Seriously, ECB is NOT secure. Don't use it irl. We are implementing it here to understand _why_
//! it is not secure and make the point that the most straight-forward approach isn't always the
//! best, and can sometimes be trivially broken.

use aes::{
	cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit},
	Aes128,
};
use rand::Rng;

///We're using AES 128 which has 16-byte (128 bit) blocks.
const BLOCK_SIZE: usize = 16;

fn main() {
	

	let key = [0u8; BLOCK_SIZE];
    let plain_text = b"Hello, This is Nimit. I am playing with encryption";

	let cipher_text = ecb_encrypt(plain_text.to_vec(), key);

	let plain_text = ecb_decrypt(cipher_text.clone(), key);

	println!("Plain Text after ecb decryption{:?}", String::from_utf8_lossy(&plain_text));

	let cipher_text = cbc_encrypt(plain_text.to_vec(), key);

	let plain_text = cbc_decrypt(cipher_text.clone(), key);

	println!("Plain Text after cbc decryption{:?}", String::from_utf8_lossy(&plain_text));

	let cipher_text = ctr_encrypt(plain_text.to_vec(), key);

	let plain_text = ctr_decrypt(cipher_text.clone(), key);

	println!("Plain Text after ctr decryption{:?}", String::from_utf8_lossy(&plain_text));
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_encrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
	// Convert the inputs to the necessary data type
	let mut block = GenericArray::from(data);
	let key = GenericArray::from(*key);

	let cipher = Aes128::new(&key);

	cipher.encrypt_block(&mut block);

	block.into()
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_decrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
	// Convert the inputs to the necessary data type
	let mut block = GenericArray::from(data);
	let key = GenericArray::from(*key);

	let cipher = Aes128::new(&key);

	cipher.decrypt_block(&mut block);

	block.into()
}

/// Before we can begin encrypting our raw data, we need it to be a multiple of the
/// block length which is 16 bytes (128 bits) in AES128.
///
/// The padding algorithm here is actually not trivial. The trouble is that if we just
/// naively throw a bunch of zeros on the end, there is no way to know, later, whether
/// those zeros are padding, or part of the message, or some of each.
///
/// The scheme works like this. If the data is not a multiple of the block length,  we
/// compute how many pad bytes we need, and then write that number into the last several bytes.
/// Later we look at the last byte, and remove that number of bytes.
///
/// But if the data _is_ a multiple of the block length, then we have a problem. We don't want
/// to later look at the last byte and remove part of the data. Instead, in this case, we add
/// another entire block containing the block length in each byte. In our case,
/// [16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
fn pad(mut data: Vec<u8>) -> Vec<u8> {
	// When twe have a multiple the second term is 0
	let number_pad_bytes = BLOCK_SIZE - data.len() % BLOCK_SIZE;

	for _ in 0..number_pad_bytes {
		data.push(number_pad_bytes as u8);
	}

	data
}

/// Groups the data into BLOCK_SIZE blocks. Assumes the data is already
/// a multiple of the block size. If this is not the case, call `pad` first.
fn group(data: Vec<u8>) -> Vec<[u8; BLOCK_SIZE]> {
	let mut blocks = Vec::new();
	let mut i = 0;
	while i < data.len() {
		let mut block: [u8; BLOCK_SIZE] = Default::default();
		block.copy_from_slice(&data[i..i + BLOCK_SIZE]);
		blocks.push(block);

		i += BLOCK_SIZE;
	}

	blocks
}

/// Does the opposite of the group function
fn un_group(blocks: Vec<[u8; BLOCK_SIZE]>) -> Vec<u8> {

	let mut data = Vec::new();

	for block in blocks {

		data.extend_from_slice(&block);
	}

	data
}

/// Does the opposite of the pad function.
fn un_pad(data: Vec<u8>) -> Vec<u8> {

	if data.is_empty() {
		return data
	}

	let pad_len = *data.last().unwrap() as usize;
	let data_len = data.len();

	let new_len = if pad_len <= BLOCK_SIZE && pad_len <= data_len {
        data_len - pad_len
    } else {
        data_len
    };

    data[..new_len].to_vec()
}

/// The first mode we will implement is the Electronic Code Book, or ECB mode.
/// Warning: THIS MODE IS NOT SECURE!!!!
///
/// This is probably the first thing you think of when considering how to encrypt
/// large data. In this mode we simply encrypt each block of data under the same key.
/// One good thing about this mode is that it is parallelizable. But to see why it is
/// insecure look at: https://www.ubiqsecurity.com/wp-content/uploads/2022/02/ECB2.png
fn ecb_encrypt(plain_text: Vec<u8>, key: [u8; 16]) -> Vec<u8> {

	let pad_text = pad(plain_text);

	let blocks = group(pad_text);

	let mut cipher_text = Vec::new();
    for block in blocks {
        cipher_text.extend_from_slice(&aes_encrypt(block, &key));
    }
    cipher_text
}

/// Opposite of ecb_encrypt.
fn ecb_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	
	let grouped_text = group(cipher_text);

	let mut plain_text = Vec::new();

	for block in grouped_text {

		plain_text.extend_from_slice(&aes_decrypt(block, &key))
	}
	
	un_pad(plain_text)
}

/// The next mode, which you can implement on your own is cipherblock chaining.
/// This mode actually is secure, and it often used in real world applications.
///
/// In this mode, the ciphertext from the first block is XORed with the
/// plaintext of the next block before it is encrypted.
///
/// For more information, and a very clear diagram,
/// see https://de.wikipedia.org/wiki/Cipher_Block_Chaining_Mode
///
/// You will need to generate a random initialization vector (IV) to encrypt the
/// very first block because it doesn't have a previous block. Typically this IV
/// is inserted as the first block of ciphertext.
fn cbc_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	// Remember to generate a random initialization vector for the first block.

	let padded_data = pad(plain_text);
    let blocks = group(padded_data);
    let mut cipher_text = Vec::new();
    let mut iv = [0u8; BLOCK_SIZE];

	rand::thread_rng().fill(&mut iv);
	cipher_text.extend_from_slice(&iv);

	let mut previous_block = iv;

	for block in blocks {

		let xor_block = xor_block(block, previous_block);

		let encrypted_block = aes_encrypt(xor_block, &key);
        cipher_text.extend_from_slice(&encrypted_block);
        previous_block = encrypted_block;
	}
	cipher_text
}

fn cbc_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {

	let (iv, cipher_blocks) = cipher_text.split_at(BLOCK_SIZE);

	let blocks = group(cipher_blocks.to_vec());

	let mut previous_block = *group(iv.to_vec()).first().unwrap();

	let mut plain_text = Vec::new();

	for block in blocks {

		let unencrypted_block = aes_decrypt(block, &key);

		let plain_text_block: [u8; 16] = xor_block(unencrypted_block, previous_block);

		plain_text.extend_from_slice(&plain_text_block);
		previous_block = block;
	}

	un_pad(plain_text)
}

fn xor_block(block1: [u8; 16], block2: [u8; BLOCK_SIZE]) -> [u8; 16] {
	
	let mut xor_block = [0u8; BLOCK_SIZE];

	for i in 0..BLOCK_SIZE {
		xor_block[i] = block1[i] ^ block2[i];
	}

	xor_block
}

/// Another mode which you can implement on your own is counter mode.
/// This mode is secure as well, and is used in real world applications.
/// It allows parallelized encryption and decryption, as well as random read access when decrypting.
///
/// In this mode, there is an index for each block being encrypted (the "counter"), as well as a random nonce.
/// For a 128-bit cipher, the nonce is 64 bits long.
///
/// For the ith block, the 128-bit value V of `nonce | counter` is constructed, where | denotes
/// concatenation. Then, V is encrypted with the key using ECB mode. Finally, the encrypted V is
/// XOR'd with the plaintext to produce the ciphertext.
///
/// A very clear diagram is present here:
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
///
/// Once again, you will need to generate a random nonce which is 64 bits long. This should be
/// inserted as the first block of the ciphertext.
fn ctr_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	// Remember to generate a random nonce

	let nonce: [u8; 8] = rand::thread_rng().gen();
    let mut cipher_text = Vec::new();
    cipher_text.extend_from_slice(&nonce);

	let padded_data = pad(plain_text);
    let blocks = group(padded_data);
    let mut cipher_text = Vec::new();

	//64 bits nonce added first
	cipher_text.extend_from_slice(&nonce);

	for (i, block) in blocks.iter().enumerate() {

		let counter: [u8; 8] = get_counter_from_index(i);

		//Concatenate Counter and Nonce
		let nonce_counter: [u8; BLOCK_SIZE] = concatenate_nonce_counter(nonce, counter);

		let encrypted_nonce_counter = aes_encrypt(nonce_counter, &key);

		let xor_block = xor_block(encrypted_nonce_counter, *block);
		cipher_text.extend_from_slice(&xor_block);
	}

	cipher_text
}

fn ctr_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {

	let (nonce, cipher_blocks) = cipher_text.split_at(BLOCK_SIZE/2);

	//Should Work since we have ensure nonce is 64 bits
	let nonce: [u8; BLOCK_SIZE/2] = nonce.try_into().unwrap();
    let blocks = group(cipher_blocks.to_vec());
    
	let mut plain_text = Vec::new();
    for (i, block) in blocks.iter().enumerate() {

        let counter: [u8; 8] = get_counter_from_index(i);
		let nonce_counter: [u8; BLOCK_SIZE] = concatenate_nonce_counter(nonce, counter);

        let encrypted_counter = aes_encrypt(nonce_counter, &key);

		let plain_block = xor_block(encrypted_counter, *block);
    
        plain_text.extend_from_slice(&plain_block);
    }
    un_pad(plain_text)
}

// Convert index into 64 bit counter.
fn get_counter_from_index(i : usize) -> [u8; BLOCK_SIZE/2] {

	(i as u64).to_be_bytes()
}

fn concatenate_nonce_counter(nonce: [u8; BLOCK_SIZE/2], counter: [u8; BLOCK_SIZE/2]) -> [u8; BLOCK_SIZE] {

	let mut result = [0u8; BLOCK_SIZE];

	result[..8].copy_from_slice(&nonce);
    result[8..].copy_from_slice(&counter);

	result
}