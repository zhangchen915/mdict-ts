import {
    conseq,
} from './util'

import {lzo} from '../lib/lzo1x';
import pako from 'pako'

export class Scan {
    constructor(attrs) {
        attrs.Encoding = attrs.Encoding || 'UTF-16';

        this.searchTextLen = (dv, offset) => {
            let mark = offset;
            if (attrs.Encoding === 'UTF-16') {
                while (this.dv.getUint16(offset)) {
                    offset += this.bpu
                    /* scan for \u0000 */
                }
                return offset - mark;
            } else {
                while (dv.getUint8(offset++)) { /* scan for NUL */
                }
                return offset - mark - 1;
            }
        };

        this.decoder = new TextDecoder(attrs.Encoding || 'UTF-16LE');

        this.bpu = (attrs.Encoding === 'UTF-16') ? 2 : 1;

        this.readShort = () => this.readUint8();
        // read a "short" number representing kewword text size, 8-bit for version < 2, 16-bit for version >= 2

        this.readNum = () => this.readInt();

        if (parseInt(attrs.GeneratedByEngineVersion, 10) >= 2.0) {
            this.v2 = true;
            this.tail = this.bpu;

            // HUGE dictionary file (>4G) is not supported, take only lower 32-bit
            this.readNum = () => {
                this.forward(4);
                return this.readInt();
            };
            this.readShort = () => this.readUint16();
            this.checksumV2 = () => this.checksum()
        } else {
            this.tail = 0;
        }
    }

    init(buf) {
        this.offset = 0;
        this.buf = buf;
        this.dv = new DataView(buf);
        return this;
    }

    forward(len) {
        this.offset += len;
        return this;
    }

    // MDict file format uses big endian to store number
    // 32-bit unsigned int
    readInt() {
        return conseq(this.dv.getUint32(this.offset), this.forward(4));
    }

    readUint16() {
        return conseq(this.dv.getUint16(this.offset), this.forward(2));
    }

    readUint8() {
        return conseq(this.dv.getUint8(this.offset), this.forward(1));
    }

    // Read data to an Uint8Array and decode it to text with specified encoding.
    // Text length in bytes is determined by searching terminated NUL.
    // NOTE: After decoding the text, it is need to forward extra "tail" bytes according to specified encoding.
    readText() {
        let len = this.searchTextLen(this.dv, this.offset);
        return conseq(this.decoder.decode(new Uint8Array(this.buf, this.offset, len)), this.forward(len + this.bpu));
    }

    // Read data to an Uint8Array and decode it to text with specified encoding.
    // @param len length in basic unit, need to multiply byte per unit to get length in bytes
    // NOTE: After decoding the text, it is need to forward extra "tail" bytes according to specified encoding.
    readTextSized(len) {
        len *= this.bpu;
        return conseq(this.decoder.decode(new Uint8Array(this.buf, this.offset, len)), this.forward(len + this.tail));
    }

    // Skip checksum, just ignore it anyway.
    checksum() {
        this.forward(4);
    }

    // Read data block of keyword index, key block or record content.
    // These data block are maybe in compressed (gzip or lzo) format, while keyword index maybe be encrypted.
    // @see https://github.com/zhansliu/writemdict/blob/master/fileformat.md#compression (with typo mistake)
    readBlock(len, expectedBufSize, decryptor) {
        let comp_type = this.dv.getUint8(this.offset);  // compression type, 0 = non, 1 = lzo, 2 = gzip
        if (comp_type === 0) {
            if (this.v2) this.forward(8);  // for version >= 2, skip comp_type (4 bytes with tailing \x00) and checksum (4 bytes)
            return this;
        } else {
            // skip comp_type (4 bytes with tailing \x00) and checksum (4 bytes)
            this.offset += 8;
            len -= 8;
            let tmp = new Uint8Array(this.buf, this.offset, len);
            if (decryptor) {
                let passkey = new Uint8Array(8);
                passkey.set(new Uint8Array(this.buf, this.offset - 4, 4));  // key part 1: checksum
                passkey.set([0x95, 0x36, 0x00, 0x00], 4);         // key part 2: fixed data
                tmp = decryptor(tmp, passkey);
            }

            tmp = comp_type === 2 ? pako.inflate(tmp) : lzo.decompress(tmp, expectedBufSize, 1308672);
            this.forward(len);
            return this.init(tmp.buffer, tmp.length);
        }
    }

    // Read raw data as Uint8Array from current this.offset with specified length in bytes
    readRaw(len) {
        return conseq(new Uint8Array(this.buf, this.offset, len), this.forward(len === undefined ? this.buf.length - this.offset : len));
    }
}