import ripemd128 from '../lib/ripemd128';

/*
 * Decrypt encrypted data block of keyword index (attrs.Encrypted = "2").
 * @see https://github.com/zhansliu/writemdict/blob/master/fileformat.md#keyword-index-encryption
 * @param buf an ArrayBuffer containing source data
 * @param key an ArrayBuffer holding decryption key, which will be supplied to ripemd128() before decryption
 * @return an ArrayBuffer carrying decrypted data, occupying the same memory space of source buffer
 */
export function decrypt(buf, key) {
    key = ripemd128(key);
    let byte, keylen = key.length, prev = 0x36, i = 0, len = buf.length;
    for (; i < len; i++) {
        byte = buf[i];
        byte = ((byte >> 4) | (byte << 4));                  // & 0xFF;  <-- it's already a byte
        byte = byte ^ prev ^ (i & 0xFF) ^ key[i % keylen];
        prev = buf[i];
        buf[i] = byte;
    }
    return buf;
}