#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

typedef struct{
    uint32_t eK[44], dK[44];    // encKey, decKey // 10round need 11 keys and one word have 4bytes so is 44
    int Nr; // 10 rounds
}AesKey;

#define BLOCKSIZE 16

// uint8_t y[4] -> uint32_t x
#define LOAD32H(x, y) \
do { (x) = ((uint32_t)((y)[0] & 0xff)<<24) | ((uint32_t)((y)[1] & 0xff)<<16) | \
((uint32_t)((y)[2] & 0xff)<<8)  | ((uint32_t)((y)[3] & 0xff));} while(0)

// uint32_t x -> uint8_t y[4]
#define STORE32H(x, y) \
do { (y)[0] = (uint8_t)(((x)>>24) & 0xff); (y)[1] = (uint8_t)(((x)>>16) & 0xff);   \
(y)[2] = (uint8_t)(((x)>>8) & 0xff); (y)[3] = (uint8_t)((x) & 0xff); } while(0)

#define BYTE(x, n) (((x) >> (8 * (n))) & 0xff)

/* for keyExpansion */
#define MIX(x) (((S[BYTE(x, 2)] << 24) & 0xff000000) ^ ((S[BYTE(x, 1)] << 16) & 0xff0000) ^ \
((S[BYTE(x, 0)] << 8) & 0xff00) ^ (S[BYTE(x, 3)] & 0xff))

#define ROF32(x, n)  (((x) << (n)) | ((x) >> (32-(n))))

#define ROR32(x, n)  (((x) >> (n)) | ((x) << (32-(n))))

/* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
static const uint32_t rcon[10] = {
    0x01000000UL, 0x02000000UL, 0x04000000UL, 0x08000000UL, 0x10000000UL,
    0x20000000UL, 0x40000000UL, 0x80000000UL, 0x1B000000UL, 0x36000000UL
};
// S table
unsigned char S[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

unsigned char inv_S[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

//to load a 4*4 matrix which is the state
int loadStateArray(uint8_t (*state)[4], const uint8_t *in) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[j][i] = *in++;
        }
    }
    return 0;
}

//copy state[4][4] to out[16]
int storeStateArray(uint8_t (*state)[4], uint8_t *out) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            *out++ = state[j][i];
        }
    }
    return 0;
}

int keyExpansion(const uint8_t *key, uint32_t keyLen, AesKey *aesKey) {
    
    if (NULL == key || NULL == aesKey){
        printf("keyExpansion param is NULL\n");
        return -1;
    }
    
    if (keyLen != 16){
        printf("keyExpansion keyLen = %d, Not support.\n", keyLen);
        return -1;
    }
    
    uint32_t *w = aesKey->eK;
    uint32_t *v = aesKey->dK;
    
    for (int i = 0; i < 4; ++i) {
        LOAD32H(w[i], key + 4*i);
    }
    
    for (int i = 0; i < 10; ++i) {
        w[4] = w[0] ^ MIX(w[3]) ^ rcon[i];
        w[5] = w[1] ^ w[4];
        w[6] = w[2] ^ w[5];
        w[7] = w[3] ^ w[6];
        w += 4;
    }
    
    w = aesKey->eK+44 - 4;
    
    for (int j = 0; j < 11; ++j) {
        
        for (int i = 0; i < 4; ++i) {
            v[i] = w[i];
        }
        w -= 4;
        v += 4;
    }
    
    return 0;
}


int addRoundKey(uint8_t (*state)[4], const uint32_t *key) {
    uint8_t k[4][4];
    
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            k[i][j] = (uint8_t) BYTE(key[j], 3 - i);
            state[i][j] ^= k[i][j];
        }
    }
    
    return 0;
}

int subBytes(uint8_t (*state)[4]) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = S[state[i][j]];
        }
    }
    
    return 0;
}

int invSubBytes(uint8_t (*state)[4]) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = inv_S[state[i][j]];
        }
    }
    return 0;
}


int shiftRows(uint8_t (*state)[4]) {
    uint32_t block[4] = {0};
    for (int i = 0; i < 4; ++i) {
        
        LOAD32H(block[i], state[i]);
        block[i] = ROF32(block[i], 8*i);
        STORE32H(block[i], state[i]);
    }
    
    return 0;
}


int invShiftRows(uint8_t (*state)[4]) {
    uint32_t block[4] = {0};
    for (int i = 0; i < 4; ++i) {
        LOAD32H(block[i], state[i]);
        block[i] = ROR32(block[i], 8*i);
        STORE32H(block[i], state[i]);
    }
    
    return 0;
}

/* Galois Field (256) Multiplication of two Bytes */

uint8_t GMul(uint8_t u, uint8_t v) {
    uint8_t p = 0;
    
    for (int i = 0; i < 8; ++i) {
        if (u & 0x01) {    //
            p ^= v;
        }
        
        int flag = (v & 0x80);
        v <<= 1;
        if (flag) {
            v ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
        }
        
        u >>= 1;
    }
    
    return p;
}

// ¡–ªÏ∫œ
int mixColumns(uint8_t (*state)[4]) {
    uint8_t tmp[4][4];
    uint8_t M[4][4] = {{0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02}};
    
    /* copy state[4][4] to tmp[4][4] */
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j){
            tmp[i][j] = state[i][j];
        }
    }
    
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = GMul(M[i][0], tmp[0][j]) ^ GMul(M[i][1], tmp[1][j])
            ^ GMul(M[i][2], tmp[2][j]) ^ GMul(M[i][3], tmp[3][j]);
        }
    }
    
    return 0;
}


int invMixColumns(uint8_t (*state)[4]) {
    uint8_t tmp[4][4];
    uint8_t M[4][4] = {{0x0E, 0x0B, 0x0D, 0x09},
        {0x09, 0x0E, 0x0B, 0x0D},
        {0x0D, 0x09, 0x0E, 0x0B},
        {0x0B, 0x0D, 0x09, 0x0E}};
    
    /* copy state[4][4] to tmp[4][4] */
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j){
            tmp[i][j] = state[i][j];
        }
    }
    
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = GMul(M[i][0], tmp[0][j]) ^ GMul(M[i][1], tmp[1][j])
            ^ GMul(M[i][2], tmp[2][j]) ^ GMul(M[i][3], tmp[3][j]);
        }
    }
    
    return 0;
}


int aesEncrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *pt, uint8_t *ct, uint32_t len) {
    
    AesKey aesKey;
    uint8_t *pos = ct;
    const uint32_t *rk = aesKey.eK;
    uint8_t out[BLOCKSIZE] = {0};
    uint8_t actualKey[16] = {0};
    uint8_t state[4][4] = {0};
    
    if (NULL == key || NULL == pt || NULL == ct){
        printf("param err.\n");
        return -1;
    }
    
    if (keyLen > 16){
        printf("keyLen must be 16.\n");
        return -1;
    }
    
    if (len % BLOCKSIZE){
        printf("inLen is invalid.\n");
        return -1;
    }
    
    memcpy(actualKey, key, keyLen);
    keyExpansion(actualKey, 16, &aesKey);
    for (int i = 0; i < len; i += BLOCKSIZE) {
        
        loadStateArray(state, pt);
        
        addRoundKey(state, rk);
        
        for (int j = 1; j < 10; ++j) {
            rk += 4;
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, rk);
        }
        
        subBytes(state);    // byte replacement
        shiftRows(state);  // rows shift
        // add round key
        addRoundKey(state, rk+4);
        
        // convert 4*4 state matrix to uint8_t one-dimensional array output and save.
        storeStateArray(state, pos);
        
        pos += BLOCKSIZE;
        pt += BLOCKSIZE;
        rk = aesKey.eK;
    }
    return 0;
}

// AES128 decryption. The requirements of parameter are the same as encryption.
int aesDecrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *ct, uint8_t *pt, uint32_t len) {
    AesKey aesKey;
    uint8_t *pos = pt;//plaintext to *pos
    const uint32_t *rk = aesKey.dK;  //decrypt key point
    uint8_t out[BLOCKSIZE] = {0};
    uint8_t actualKey[16] = {0};
    uint8_t state[4][4] = {0};
    
    if (NULL == key || NULL == ct || NULL == pt){
        printf("param err.\n");
        return -1;
    }
    
    if (keyLen > 16){
        printf("keyLen must be 16.\n");
        return -1;
    }
    
    if (len % BLOCKSIZE){
        printf("inLen is invalid.\n");
        return -1;
    }
    
    memcpy(actualKey, key, keyLen);//copy keylen number from key to actualKey
    keyExpansion(actualKey, 16, &aesKey);  //key expansion, same as encryption
    
    for (int i = 0; i < len; i += BLOCKSIZE) {
        // convert 16-byte ciphertext to 4*4 state matrix for processing 
        loadStateArray(state, ct);
        // add round key
        addRoundKey(state, rk);
        
        for (int j = 1; j < 10; ++j) {
            rk += 4;
            invShiftRows(state);    // retrograde shift
            invSubBytes(state);     // inverse byte replacement, the order of these two steps can be reversed
            addRoundKey(state, rk); // add round key, which is similar to encryption
            invMixColumns(state);   // inverse column mixing
        }
        
        invSubBytes(state);   // replace inverese byte
        invShiftRows(state);  // reverse shift
        // there is no inverese mixing here
        addRoundKey(state, rk+4);  // add round key
        
        storeStateArray(state, pos);  // save plaintext data
        pos += BLOCKSIZE;  //  output data memory pointer shift packey length
        ct += BLOCKSIZE;   //  input data memory pointer shift packet length
        rk = aesKey.dK;    // restore the rk pointer to the initial location of the key
    }
    return 0;
}

void printHex(uint8_t *ptr, int len, char *tag) {
    printf("%s\ndata[%d]: ", tag, len);
    for (int i = 0; i < len; ++i) {
        printf("%.2X ", *ptr++);
    }
    printf("\n");
}


int aesEncryptCBC(const uint8_t *key, uint32_t keyLen, uint8_t *pt, uint8_t *ct, uint32_t len, uint8_t *initialV) {
    
    AesKey aesKey;
    uint8_t *pos = ct;
    const uint32_t *rk = aesKey.eK;  //decrypt the pointer of key 
    uint8_t out[BLOCKSIZE] = {0};
    uint8_t actualKey[16] = {0};
    uint8_t state[4][4] = {0};
    uint8_t *initialVector = initialV;
    
    if (NULL == key || NULL == pt || NULL == ct){
        printf("param err.\n");
        return -1;
    }
    
    if (keyLen > 16){
        printf("keyLen must be 16.\n");
        return -1;
    }
    
    if (len % BLOCKSIZE){
        printf("inLen is invalid.\n");
        return -1;
    }
    
    memcpy(actualKey, key, keyLen);
    keyExpansion(actualKey, 16, &aesKey);  // from aesKey to actualKey
    
    
    //  cyclic encryption of multiple packet length data using ECB mode
    for (int i = 0; i < len; i += BLOCKSIZE) { // BLOCKSIZE = 16 , every 16 bytes one circle
        
        //initialVector XOR
        for(int z = 0; z < 16; z++){
            pt[z] = pt[z] ^ initialVector[z];
            //printf("%x ",pt[z]);
        }
        
        loadStateArray(state, pt);// convert 16 bytes of plaintext to a 4*4 state matrix for processing
        // add round key
        addRoundKey(state, rk);
        
        
        for (int j = 1; j < 10; ++j) {
            rk += 4;
            subBytes(state);   // byte replacement
            shiftRows(state);  // row shift
            mixColumns(state); // column mix
            addRoundKey(state, rk); // add round key
        }
        
        subBytes(state);    // byte replacement
        shiftRows(state);  // row shift
        // no column mixing is done here
        addRoundKey(state, rk+4); // add round key
        
        // convert 4*4 state matrix to uint8_t one-dimensional array output save
        storeStateArray(state, pos);
        storeStateArray(state, initialVector);
        
        
        pos += BLOCKSIZE;  // encrypted data memory pointer moves to next packet
        pt += BLOCKSIZE;   // plaintext data pointer moves to next packet
        rk = aesKey.eK;    // restore the rk pointer to the initial location of the key
    }
    return 0;
}

//int aesDecryptCBC(const uint8_t *key, uint32_t keyLen, uint8_t *ct, uint8_t *pt, uint32_t len) {
int aesDecryptCBC(const uint8_t *key, uint32_t keyLen, uint8_t *ct, uint8_t *pt, uint32_t len, uint8_t *initialV) {
    AesKey aesKey;
    uint8_t *pos = pt;//plaintext to *pos
    const uint32_t *rk = aesKey.dK;  //Ω‚√‹√ÿ‘ø÷∏’Î
    uint8_t out[BLOCKSIZE] = {0};
    uint8_t actualKey[16] = {0};
    uint8_t state[4][4] = {0};
    uint8_t storeMatrix[4][4] = {0};
    
    //uint8_t initialVector[16] = {0x60,0xef,0x17,0x10,0xd7,0xcc,0x28,0xf8,0x56,0xbd,0xe4,0x8b,0xa1,0xce,0xb0,0x87};
    uint8_t *initialVector = initialV;
    
    uint8_t store[16] = {};
    uint8_t store2[16] = {};
    int count = 0;
    
    if (NULL == key || NULL == ct || NULL == pt){
        printf("param err.\n");
        return -1;
    }
    
    if (keyLen > 16){
        printf("keyLen must be 16.\n");
        return -1;
    }
    
    if (len % BLOCKSIZE){
        printf("inLen is invalid.\n");
        return -1;
    }
    
    memcpy(actualKey, key, keyLen);//copy keylen number from key to actualKey
    keyExpansion(actualKey, 16, &aesKey);  //expand private key
    
    for (int i = 0; i < len; i += BLOCKSIZE) {
        
        // convery 16-byte ciphertext to 4*4 state matrix for processing
        loadStateArray(state,ct);
        
        storeStateArray(state, store2);//ct to store2 for a while
        
        count = count + 1;
        // add round key
        addRoundKey(state, rk);
        
        for (int j = 1; j < 10; ++j) {
            rk += 4;
            invShiftRows(state);    // retrograde shift
            invSubBytes(state);     // inverse byte replacement, the order of thses two steps can be reversed.
            addRoundKey(state, rk); // add round key, same as encrypthion
            invMixColumns(state);   // reverse column mixing
        }
        
        invSubBytes(state);   // replace inverse byte
        invShiftRows(state);  // retrograde shift
        // no inverse mixing here
        addRoundKey(state, rk+4);  // round key plus
        
        storeStateArray(state, store); // state to store and easy to XOR
        //initialVector XOR
        for(int z = 0; z < 16; z++){
            store[z] = store[z] ^ initialVector[z];
            //printf("the initialVector for %d round: %x \n", count, initialVector[z]);
        }
        loadStateArray(state, store);//store back to state, then will put in pos
        
        loadStateArray(storeMatrix, store2); // the store2, the pt in the begining become new inital vector
        storeStateArray(storeMatrix, initialVector);
        
        
        
        storeStateArray(state, pos);  // save plaintext data
        
        
        pos += BLOCKSIZE;  //  output data memory pointer shift packet length
        ct += BLOCKSIZE;   //  input data memory pointer shift packet length
        rk = aesKey.dK;    //  restore the rk pointer to the initial location of the key
        
    }
    return 0;
}
void transform(char* c, uint8_t *pt, long le){
    int *z = new int [le];
    int *r = new int [le/2];
    int s = 10;
    for(int i = 0; i < le; i++){
        if(c[i] == '0')
            z[i] = 0;
        if(c[i] == '1')
            z[i] = 1;
        if(c[i] == '2')
            z[i] = 2;
        if(c[i] == '3')
            z[i] = 3;
        if(c[i] == '4')
            z[i] = 4;
        if(c[i] == '5')
            z[i] = 5;
        if(c[i] == '6')
            z[i] = 6;
        if(c[i] == '7')
            z[i] = 7;
        if(c[i] == '8')
            z[i] = 8;
        if(c[i] == '9')
            z[i] = 9;
        if(c[i] == 'a' || c[i] == 'A')
            z[i] = 10;
        if(c[i] == 'b' || c[i] == 'B')
            z[i] = 11;
        if(c[i] == 'c' || c[i] == 'C')
            z[i] = 12;
        if(c[i] == 'd'|| c[i] == 'D')
            z[i] = 13;
        if(c[i] == 'f'|| c[i] == 'F')
            z[i] = 15;
        if(c[i] == 'e'|| c[i] == 'E')
            z[i] = 14;
    }
    for(int i = 0; i <le; i += 2){
        r[i/2] = z[i] * 16 + z[i+1] * 1;
    }
    for(int q = 0; q < le/2; q++){
        pt[q] = (uint8_t)r[q];
    }
    
    
}

int main() {
    /* the lenght is actually predefined 16 bytes 32 hex characters */
    //the key used for aes (load the key at the very first) all these four forms of AES need a key to start
    char *k;
    int length;
    k = (char*)malloc(sizeof(char));
    //there must be 32 characters in the key which are 16 bytes
    printf("Please input your key here (in the form of 16):\n");//
    scanf("%s",k);
    length = strlen(k);
    if(length != 32){
        printf("key must be 16 ! \n");//
        return -1;
    }
    //clear the buffer area in case of error
    fflush(stdin);
    //malloc memory for the key (16 bytes) length/2=16
    uint8_t *key = (uint8_t*)malloc(sizeof(uint8_t) * length / 2);
    //transform the string into key (16 bytes)
    transform(k, key, 32);
    
    
    int num;
    printf("Please input a corresponding number to decide the form of input(1 for file 2 for text):");
    scanf("%d", & num);
    //1 for file 2 for text
    switch (num) {
            
        case 1:{
            char file[256];//file name
            long le = 0;//declare the length variable
            printf("Please input the name of the txt file here:\n");
            scanf("%s",file);

            FILE *fp;
            fp = fopen(file, "r");
            if(fp == NULL)    {
                printf("NO such file, please try again! \n");
            }

            fseek(fp,0,SEEK_END);
            
            //get the length of the file
            le = ftell(fp);
            fseek(fp,0,SEEK_SET);
            
            //temply store the file into the char input[]
            char *input = new char[le];
            for(int i = 0; i < le; i++){
                fscanf(fp,"%c",&input[i]);
            }

            //all these variables are of le/2 (le is the length of the file)
            uint8_t *pt = new uint8_t [le/2];//declare plain text before encryption
            uint8_t *ct = new uint8_t [le/2];//declare cipher text
            uint8_t *plain = new uint8_t [le/2];//declare plain text after decryption
            transform(input,pt,le);//transform the input char which is the plain text in the file into form of uint8_t (bytes)
            
            //print out the plaintext to compare
            printHex(pt, le/2, "Plain text:");
            
            
            char tmp[100];
            printf("Please type in the method of AES (ECB or CBC):");
            scanf("%s", & tmp);
            if(strcmp(tmp, "ECB")==0){
                double duration_1,duration_2;
                clock_t start1,start2,end1,end2;
                start1 = clock();
                //encrypt the plain text (*pt) and store it in *ct (cipher text) cipher text changes every single round in AESuntil the end of the whole process
                aesEncrypt(key, 16, pt, ct, le/2);
                //print out the final cipher text(after 10 rounds)
                end1 = clock(); 
                duration_1 = (double)(end1-start1)/CLOCKS_PER_SEC;
                //printHex(ct, le/2, "After encryption:");
                printf("The time of ECB encryption is: %fs. \n",duration_1);
                start2 = clock();
                //the process of decryption, store the text after decryption into plain
                aesDecrypt(key, 16, ct, plain, le/2);
                end2 = clock();
                duration_2 = (double)(end2-start2)/CLOCKS_PER_SEC;
                //printHex(plain, le/2, "After decryption:");
                printf("The time of ECB encryption is: %fs. \n",duration_2);
            }
            else if (strcmp(tmp, "CBC")==0){
                //
                char *IV;
                int lenIV;
                IV = (char*)malloc(sizeof(char));
                printf("Please input your initial vector here:\n");
                scanf("%s",IV);
                lenIV = strlen(IV);
                if(lenIV != 32){
                printf("Invalid initial vector! \n");
                return -1;
                }
                fflush(stdin);
                uint8_t *InitialV = new uint8_t [lenIV/2];
                uint8_t *InitialVD = new uint8_t [lenIV/2];
                transform(IV, InitialV, 32);
                transform(IV, InitialVD, 32);

                double duration_1,duration_2;
                clock_t start1,start2,end1,end2;
                start1 = clock();
                aesEncryptCBC(key, 16, pt, ct, le/2, InitialV);
                end1 = clock(); 
                duration_1 = (double)(end1-start1)/CLOCKS_PER_SEC;
                printHex(ct, le/2, "After encryption:");
                printf("The time of CBC encryption is: %fs. \n",duration_1);
                start2 = clock();
                aesDecryptCBC(key, 16, ct, plain, le/2, InitialVD);
                end2 = clock();
                duration_2 = (double)(end2-start2)/CLOCKS_PER_SEC;
                //print out the text after decryption
                printHex(plain, le/2, "After decryption:");
                printf("The time of CBC encryption is: %fs. \n",duration_2);
            }
            else{
                printf("Invalid input!");
            }

            
            
            
            
            break;
            }
            
            
        case 2:{
            char *plaintext;
            //malloc memory for char pt
            plaintext = (char*)malloc(sizeof(char)*1000);
            printf("Please input your plaintext here(in the length of 16 or multiple of 16 bytes) \n");
            scanf("%s",plaintext);
            
            int ptlen;
            //get the length of the plain text
            ptlen = strlen(plaintext);
            
            //char *input = new char[ptlen];//32 default
            
            //declare pt used for aes
            uint8_t *pt = new uint8_t [ptlen/2];
            //transform the plain text (string) into form of bytes
            transform(plaintext, pt, ptlen);
            //declare ct used for aes
            uint8_t *ct = new uint8_t [ptlen/2];
            //declare plain text after the decryption
            uint8_t *plain = new uint8_t [ptlen/2];

            //print out the plain text to compare
            printHex(pt, ptlen/2, "Plain text:");
            
            char tmp[100];
                  printf("Please type in the method of AES (ECB or CBC):");
                  scanf("%s", & tmp);
                  if(strcmp(tmp, "ECB")==0){
                      //similar to above
                      double duration_1,duration_2;
                      clock_t start1,start2,end1,end2;
                      start1 = clock();
                      aesEncrypt(key, 16, pt, ct, ptlen/2);
                      end1 = clock(); 
                      duration_1 = (double)(end1-start1)/CLOCKS_PER_SEC;
                      printHex(ct, ptlen/2, "After encryption:");
                      printf("The time of ECB encryption is: %fs. \n",duration_1);
                      start2 = clock();
                      aesDecrypt(key, 16, ct, plain, ptlen/2);
                      end2 = clock();
                      duration_2 = (double)(end2-start2)/CLOCKS_PER_SEC;
                      printHex(plain, ptlen/2, "After decryption:");
                      printf("The time of ECB decryption is: %fs. \n",duration_2);
                  }
                  else if (strcmp(tmp, "CBC")==0){
                     char *IV;
                     int lenIV;
                     IV = (char*)malloc(sizeof(char)*1000);
                     printf("Please input your initial vector here:\n");
                     scanf("%s",IV);
                     lenIV = strlen(IV);
                     if(lenIV != 32){
                         printf("Invalid initial vector! \n");
                         return -1;
                     }
                     fflush(stdin);
                     uint8_t *InitialV = new uint8_t [lenIV/2];
                     uint8_t *InitialVD = new uint8_t [lenIV/2];
                     transform(IV, InitialV, 32);
                     transform(IV, InitialVD, 32);
                     
                     double duration_1,duration_2;
                     clock_t start1,start2,end1,end2;
                     start1 = clock();
                     aesEncryptCBC(key, 16, pt, ct, ptlen/2, InitialV); // encrypt key is key[16], 16 is key length
                     end1 = clock();
                     duration_1 = (double)(end1-start1)/CLOCKS_PER_SEC;

                     printHex(ct, ptlen/2, "After encryption:");
                     //aesDecryptCBC(key, 16, ct, plain, ptlen/2);
                     printf("The time of CBC encryption is: %fs. \n",duration_1);
                     start2 = clock();
                     aesDecryptCBC(key, 16, ct, plain, ptlen/2, InitialVD);// decrypt
                     end2 = clock();
                     duration_2 = (double)(end2-start2)/CLOCKS_PER_SEC;
                     printHex(plain, ptlen/2, "After decryption:");
                     printf("The time of ECB decryption is: %fs. \n",duration_2);
                  }
                  else{
                      printf("Invalid input!");
                  }
            //printHex(plain, ptlen/2, "After decryption:");
            
            break;
        }
        default:
            break;
    }
    
}
