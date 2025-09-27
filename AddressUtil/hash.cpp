#include "AddressUtil.h"
#include "CryptoUtil.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static unsigned int endian(unsigned int x)
{
	return (x << 24) | ((x << 8) & 0x00ff0000) | ((x >> 8) & 0x0000ff00) | (x >> 24);
}

bool Address::verifyAddress(std::string address)
{
	// Check length
	if(address.length() > 34) {
		false;
	}

	// Check encoding
	if(!Base58::isBase58(address)) {
		return false;
	}

	std::string noPrefix = address.substr(1);

	secp256k1::uint256 value = Base58::toBigInt(noPrefix);
	unsigned int words[6];
	unsigned int hash[5];
	unsigned int checksum;

	value.exportWords(words, 6, secp256k1::uint256::BigEndian);
	memcpy(hash, words, sizeof(unsigned int) * 5);
	checksum = words[5];

	return crypto::checksum(hash) == checksum;
}

std::string Address::fromPublicKey(const secp256k1::ecpoint &p, bool compressed)
{
	unsigned int xWords[8] = { 0 };
	unsigned int yWords[8] = { 0 };

	p.x.exportWords(xWords, 8, secp256k1::uint256::BigEndian);
	p.y.exportWords(yWords, 8, secp256k1::uint256::BigEndian);

	unsigned int digest[5];

	if(compressed) {
		Hash::hashPublicKeyCompressed(xWords, yWords, digest);
	} else {
		Hash::hashPublicKey(xWords, yWords, digest);
	}

	unsigned int checksum = crypto::checksum(digest);

	unsigned int addressWords[8] = { 0 };
	for(int i = 0; i < 5; i++) {
		addressWords[2 + i] = digest[i];
	}
	addressWords[7] = checksum;

	secp256k1::uint256 addressBigInt(addressWords, secp256k1::uint256::BigEndian);

	return "1" + Base58::toBase58(addressBigInt);
}

void Hash::hashPublicKey(const secp256k1::ecpoint &p, unsigned int *digest)
{
	unsigned int xWords[8];
	unsigned int yWords[8];

	p.x.exportWords(xWords, 8, secp256k1::uint256::BigEndian);
	p.y.exportWords(yWords, 8, secp256k1::uint256::BigEndian);

	hashPublicKey(xWords, yWords, digest);
}


void Hash::hashPublicKeyCompressed(const secp256k1::ecpoint &p, unsigned int *digest)
{
	unsigned int xWords[8];
	unsigned int yWords[8];

	p.x.exportWords(xWords, 8, secp256k1::uint256::BigEndian);
	p.y.exportWords(yWords, 8, secp256k1::uint256::BigEndian);

	hashPublicKeyCompressed(xWords, yWords, digest);
}

void Hash::hashPublicKey(const unsigned int *x, const unsigned int *y, unsigned int *digest)
{
	unsigned int msg[16];
	unsigned int sha256Digest[8];

	// 0x04 || x || y
	msg[15] = (y[7] >> 8) | (y[6] << 24);
	msg[14] = (y[6] >> 8) | (y[5] << 24);
	msg[13] = (y[5] >> 8) | (y[4] << 24);
	msg[12] = (y[4] >> 8) | (y[3] << 24);
	msg[11] = (y[3] >> 8) | (y[2] << 24);
	msg[10] = (y[2] >> 8) | (y[1] << 24);
	msg[9] = (y[1] >> 8) | (y[0] << 24);
	msg[8] = (y[0] >> 8) | (x[7] << 24);
	msg[7] = (x[7] >> 8) | (x[6] << 24);
	msg[6] = (x[6] >> 8) | (x[5] << 24);
	msg[5] = (x[5] >> 8) | (x[4] << 24);
	msg[4] = (x[4] >> 8) | (x[3] << 24);
	msg[3] = (x[3] >> 8) | (x[2] << 24);
	msg[2] = (x[2] >> 8) | (x[1] << 24);
	msg[1] = (x[1] >> 8) | (x[0] << 24);
	msg[0] = (x[0] >> 8) | 0x04000000;


	crypto::sha256Init(sha256Digest);
	crypto::sha256(msg, sha256Digest);

	// Zero out the message
	for(int i = 0; i < 16; i++) {
		msg[i] = 0;
	}

	// Set first byte, padding, and length
	msg[0] = (y[7] << 24) | 0x00800000;
	msg[15] = 65 * 8;

	crypto::sha256(msg, sha256Digest);

	for(int i = 0; i < 16; i++) {
		msg[i] = 0;
	}

	// Swap to little-endian
	for(int i = 0; i < 8; i++) {
		msg[i] = endian(sha256Digest[i]);
	}

	// Message length, little endian
	msg[8] = 0x00000080;
	msg[14] = 256;
	msg[15] = 0;

	crypto::ripemd160(msg, digest);
}



void Hash::hashPublicKeyCompressed(const unsigned int *x, const unsigned int *y, unsigned int *digest)
{
	unsigned int msg[16] = { 0 };
	unsigned int sha256Digest[8];

	// Compressed public key format
	msg[15] = 33 * 8;

	msg[8] = (x[7] << 24) | 0x00800000;
	msg[7] = (x[7] >> 8) | (x[6] << 24);
	msg[6] = (x[6] >> 8) | (x[5] << 24);
	msg[5] = (x[5] >> 8) | (x[4] << 24);
	msg[4] = (x[4] >> 8) | (x[3] << 24);
	msg[3] = (x[3] >> 8) | (x[2] << 24);
	msg[2] = (x[2] >> 8) | (x[1] << 24);
	msg[1] = (x[1] >> 8) | (x[0] << 24);

	if(y[7] & 0x01) {
		msg[0] = (x[0] >> 8) | 0x03000000;
	} else {
		msg[0] = (x[0] >> 8) | 0x02000000;
	}

	crypto::sha256Init(sha256Digest);
	crypto::sha256(msg, sha256Digest);

	for(int i = 0; i < 16; i++) {
		msg[i] = 0;
	}

	// Swap to little-endian
	for(int i = 0; i < 8; i++) {
		msg[i] = endian(sha256Digest[i]);
	}

	// Message length, little endian
	msg[8] = 0x00000080;
	msg[14] = 256;
	msg[15] = 0;

	crypto::ripemd160(msg, digest);
}

static void writeUint32BE(unsigned int x, unsigned char *out)
{
	out[0] = (unsigned char)((x >> 24) & 0xff);
	out[1] = (unsigned char)((x >> 16) & 0xff);
	out[2] = (unsigned char)((x >> 8) & 0xff);
	out[3] = (unsigned char)(x & 0xff);
}

static void doubleSha256(const unsigned char *data, size_t len, unsigned char out[32])
{
	// First SHA256
	unsigned int msg[16] = { 0 };
	unsigned int digest[8] = { 0 };

	// Copy data into 512-bit block (big-endian words)
	unsigned char buf[64] = { 0 };
	for(size_t i = 0; i < len && i < 64; i++) {
		buf[i] = data[i];
	}
	// Padding
	if(len < 64) {
		buf[len] = 0x80;
	}
	uint64_t bitLen = (uint64_t)len * 8ULL;
	// Write length in last 8 bytes (big endian)
	buf[63] = (unsigned char)(bitLen & 0xff);
	buf[62] = (unsigned char)((bitLen >> 8) & 0xff);
	buf[61] = (unsigned char)((bitLen >> 16) & 0xff);
	buf[60] = (unsigned char)((bitLen >> 24) & 0xff);
	buf[59] = (unsigned char)((bitLen >> 32) & 0xff);
	buf[58] = (unsigned char)((bitLen >> 40) & 0xff);
	buf[57] = (unsigned char)((bitLen >> 48) & 0xff);
	buf[56] = (unsigned char)((bitLen >> 56) & 0xff);

	// Convert to words
	for(int i = 0; i < 16; i++) {
		msg[i] = ((unsigned int)buf[i * 4] << 24) | ((unsigned int)buf[i * 4 + 1] << 16) | ((unsigned int)buf[i * 4 + 2] << 8) | (unsigned int)buf[i * 4 + 3];
	}

	crypto::sha256Init(digest);
	crypto::sha256(msg, digest);

	// Second SHA256 over 32-byte digest
	unsigned int msg2[16] = { 0 };
	unsigned int digest2[8] = { 0 };
	// Put digest as bytes big-endian into msg2
	unsigned char buf2[64] = { 0 };
	for(int i = 0; i < 8; i++) {
		writeUint32BE(digest[i], &buf2[i * 4]);
	}
	buf2[32] = 0x80;
	// length = 256 bits
	buf2[63] = 0x00;
	buf2[62] = 0x00;
	buf2[61] = 0x01;
	buf2[60] = 0x00; // 256
	for(int i = 0; i < 16; i++) {
		msg2[i] = ((unsigned int)buf2[i * 4] << 24) | ((unsigned int)buf2[i * 4 + 1] << 16) | ((unsigned int)buf2[i * 4 + 2] << 8) | (unsigned int)buf2[i * 4 + 3];
	}
	crypto::sha256Init(digest2);
	crypto::sha256(msg2, digest2);

	for(int i = 0; i < 8; i++) {
		writeUint32BE(digest2[i], &out[i * 4]);
	}
}

std::string Address::privateKeyToWIF(const secp256k1::uint256 &privKey, bool compressed)
{
	// Build payload: 0x80 || 32-byte priv || optional 0x01
	unsigned char payload[35] = { 0 };
	int payloadLen = 33;
	payload[0] = 0x80;

	unsigned int words[8] = { 0 };
	privKey.exportWords(words, 8, secp256k1::uint256::BigEndian);
	for(int i = 0; i < 8; i++) {
		writeUint32BE(words[i], &payload[1 + i * 4]);
	}
	if(compressed) {
		payload[33] = 0x01;
		payloadLen = 34;
	}

	unsigned char digest[32];
	doubleSha256(payload, payloadLen, digest);

	unsigned char full[39] = { 0 };
	for(int i = 0; i < payloadLen; i++) {
		full[i] = payload[i];
	}
	// Append first 4 bytes of checksum
	for(int i = 0; i < 4; i++) {
		full[payloadLen + i] = digest[i];
	}

	return Base58::encode(full, payloadLen + 4);
}