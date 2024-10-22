import {HeaderSection} from "./mdict-parser";

export const isBrowser = typeof window !== "undefined";

let dataView, textDecoder, parse;
if (!isBrowser) {
    dataView = require('buffer-dataview');
    textDecoder = require('text-encoding').TextDecoder;
    parse = require('xmldom').DOMParser;
} else {
    dataView = DataView;
    textDecoder = TextDecoder;
    parse = DOMParser;
}

export {dataView, textDecoder};

export function resolve(value: any[]) {
    return Promise.resolve(value);
}

export function newUint8Array(buf, offset, len) {
    if (!isBrowser) {
        const ret = new Uint8Array(len);
        buf.copy(ret, 0, offset, offset + len);
        return ret;
    } else {
        return new Uint8Array(buf, offset, len)
    }
}


export async function readFile(file, offset: number, len: number) {
    if (isBrowser) {
        return new Promise(resolve => {
            const reader = new FileReader();
            reader.onload = () => {
                resolve(reader.result)
            };
            reader.readAsArrayBuffer(file.slice(offset, offset + len));
        });
    } else {
        const fs = require('fs');
        return new Promise(resolve => {
            fs.open(file, 'r', (err, fd) => {
                if (err) throw err;
                const res = Buffer.alloc(len);
                fs.read(fd, res, 0, len, offset, (err, bytesRead, buffer) => {
                    if (err) throw err;
                    resolve(buffer);
                });
            });
        });
    }
}

export const getExtension = filename => /(?:\.([^.]+))?$/.exec(filename)[1];

export const REGEXP_STRIPKEY = {
    'mdx': /[()., '/\\@_-]()/g,
    'mdd': /([.][^.]*$)|[()., '/\\@_-]/g        // strip '.' before file extension that is keeping the last period
};

export function parseXml(xml) {
    return new parse().parseFromString(xml, 'text/xml');
}

export function isTrue(v) {
    v = ((v || false) + '').toLowerCase();
    return v === 'yes' || v === 'true';
}

export function readUTF16(buf, len) {
    return new textDecoder('utf-16le').decode(newUint8Array(buf, 0, len));
}

export function getAdaptKey(attrs: HeaderSection, ext) {
    let regexp = REGEXP_STRIPKEY[ext];
    if (isTrue(attrs.KeyCaseSensitive)) {
        return key => {
            return isTrue(attrs.StripKey) ? key.replace(regexp, '$1') : key;
        }
    } else {
        return key => {
            return isTrue(attrs.StripKey || (this.v2 ? '' : 'yes')) ?
                key.toLowerCase().replace(regexp, '$1') :
                key.toLowerCase();
        }
    }
}

/*
 * Create a Record Block Table object to load record block info from record section in mdx/mdd file.
 * Retrived data is stored in an Uint32Array which contains N pairs of (offset_comp, offset_decomp) value,
 * where N is number of record blocks.
 *
 * When looking up a given key for its definition:
 *   1. Search KEY_INDEX to locate keyword block containing the given key.
 *   2. Scanning the found keyword block to get its record offset and size.
 *   3. Search RECORD_BLOCK_TABLE to get record block containing the record.
 *   4. Load the found record block, using its offset and size to retrieve record content.
 *
 * @see https://github.com/zhansliu/writemdict/blob/master/fileformat.md#record-section
 */
export function createRecordBlockTable() {
    let pos = 0, // current position
        arr;     // backed Uint32Array
    return {
        // Allocate required ArrayBuffer for storing record block table, where len is number of record blocks.
        alloc: function (len: number) {
            arr = new Uint32Array(len * 2);
        },
        // Store offset pair value (compressed & decompressed) for a record block
        // NOTE: offset_comp is absolute offset counted from start of mdx/mdd file.
        put: function (offset_comp: any, offset_decomp: any) {
            arr[pos++] = offset_comp;
            arr[pos++] = offset_decomp;
        },
        // Given offset of a keyword after decompression, return a record block info containing it, else undefined if not found.
        find: function (keyAt: number) {
            let hi = (arr.length >> 1) - 1, lo = 0, i = (lo + hi) >> 1, val = arr[(i << 1) + 1];

            if (keyAt > arr[(hi << 1) + 1] || keyAt < 0) return;

            while (true) {
                if (hi - lo <= 1) {
                    if (i < hi) {
                        return {
                            block_no: i,
                            comp_offset: arr[i <<= 1],
                            comp_size: arr[i + 2] - arr[i],
                            decomp_offset: arr[i + 1],
                            decomp_size: arr[i + 3] - arr[i + 1]
                        };
                    } else {
                        return;
                    }
                }

                (keyAt < val) ? hi = i : lo = i;
                i = (lo + hi) >> 1;
                val = arr[(i << 1) + 1];
            }
        },
    };
}

export function getGlobalStyle(stylesheet: string) {
    let res = [], i = 0;
    stylesheet.split(' ').forEach(e => {
        if (!e) return;
        if (isNaN(Number(e))) {
            if (!res[i]) res[i] = [''];
            e.indexOf('/') < 0 ? res[i][0] += (' ' + e) : res[i].push(e)
        } else {
            i++;
        }
    });

    return res;
}

export function parseRes(str: string, style) {
    let result = '';
    let split = str.split('`');
    for (let k = 0; k < split.length; k++) {
        let num = Number(split[k]);
        if (split[k] && num) result += (style[num][0] + split[++k] + style[num][1])
    }

    return result;
}
