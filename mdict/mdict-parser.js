/*
 * Based on:
 *  - An Analysis of MDX/MDD File Format by Xiaoqiang Wang (xwang)
 *    https://bitbucket.org/xwang/mdict-analysis/ 
 *  - GitHub: zhansliu/writemdict
 *    https://github.com/zhansliu/writemdict/blob/master/fileformat.md
 *  - Source code of mdictparser.cc, part of goldendict
 *    https://github.com/goldendict/goldendict/blob/master/mdictparser.cc
 * 
 * This is free software released under terms of the MIT License.
 * You can get a copy on http://opensource.org/licenses/MIT.
 *
 * NOTE - Unsupported features:
 *
 *    i. 64-bit number used in data offset or length.
 *       Only lower 32-bit is recognized that validate value must be lower than 2^32 or 4G, 
 *       due to number format supported in current Javascript standard (ECMAScript5).
 *       Huge dictionary file larger than 4G is considered out of scope for a web app IMHO.
 *
 *   ii. Encrypted keyword header which requires external or embedded regkey.
 *       Most of shared MDict dictionary files are not encrypted,
 *       and I have no intention to break protected ones.
 *       However keyword index encryption is common and supported.
 */
import {
    conseq,
    parseXml,
    readFile,
    getAdaptKey,
    createRecordBlockTable,
    getExtension,
    readUTF16, getGlobalStyle
} from './util'
import {decrypt} from './crypt'
import {Scan} from './Scan'
import {Lookup} from './lookup'

/**
 * Parse a MDict dictionary/resource file (mdx/mdd).
 * @param file a File/Blob object
 * @return Q.Promise<Lookup> | never>{num_blocks: *, num_entries: *, index_len: *, blocks_len: *, len: *} | never | never>{num_blocks: *, num_entries: *, index_len: *, blocks_len: *, len: (*|number)} | never | never> Promise object which will resolve to a lookup function.
 */
export function parse_mdict(file) {
    let KEY_INDEX,                                       // keyword index array
        RECORD_BLOCK_TABLE = createRecordBlockTable();   // record block table
    const ext = getExtension(file.name);
    let scan;
    let _adaptKey, _keywordIndexDecryptor, stylesheet, slicedKeyBlock;

    /**
     * Read header section, parse dictionary attributes and config scanner according to engine version attribute.
     * @see https://github.com/zhansliu/writemdict/blob/master/fileformat.md#header-section
     * @param input sliced file (start = 4, length = len + 48), header string + header section (max length 48)
     * @param len lenghth of header_str
     * @return [remained length of header section (header_str and checksum, = len + 4), original input]
     */
    function read_header_sect(input, len) {
        let header_str = readUTF16(input, len).replace(/\0$/, ''); // need to remove tailing NUL
        // parse dictionary attributes
        let xml = parseXml(header_str).querySelector('Dictionary, Library_Data').attributes;
        let attrs = {};
        for (let i = 0, item; i < xml.length; i++) {
            item = xml.item(i);
            attrs[item.nodeName] = item.nodeValue;
        }

        attrs.Encrypted = parseInt(attrs.Encrypted, 10) || 0;

        scan = new Scan(attrs);
        if (attrs.Encrypted & 0x02) _keywordIndexDecryptor = decrypt;

        _adaptKey = getAdaptKey(attrs, ext);
        stylesheet = getGlobalStyle(attrs.StyleSheet);
        return len + 4;
    }

    /**
     * Read keyword summary at the begining of keyword section.
     * @see https://github.com/zhansliu/writemdict/blob/master/fileformat.md#keyword-section
     * @param input sliced file, same as input passed to read_header_sect()
     * @param offset start position of keyword section in sliced file, equals to length of header string plus checksum.\
     * @return {num_blocks: *, num_entries: *, key_index_decomp_len: *, key_index_comp_len: *, key_blocks_len: *, chksum: *, len: number} object
     */
    function read_keyword_summary(input, offset) {
        const scanner = scan.init(input).forward(offset);
        return {
            num_blocks: scanner.readNum(),
            num_entries: scanner.readNum(),
            key_index_decomp_len: scanner.v2 && scanner.readNum(),  // Ver >= 2.0 only
            key_index_comp_len: scanner.readNum(),
            key_blocks_len: scanner.readNum(),
            chksum: scanner.checksumV2(),
            // extra field
            len: scanner.offset - offset,  // actual length of keyword section, letying with engine version attribute
        };
    }

    /**
     * Read keyword index part of keyword section.
     * @see https://github.com/zhansliu/writemdict/blob/master/fileformat.md#keyword-header-encryption
     * @see https://github.com/zhansliu/writemdict/blob/master/fileformat.md#keyword-index
     * @param input sliced file, remained part of keyword section after keyword summary which can also be used to read following key blocks.
     * @param keyword_summary
     * @return [keyword_summary, array of keyword index]
     */
    function read_keyword_index(input, keyword_summary) {
        let scanner = scan.init(input).readBlock(keyword_summary.key_index_comp_len, keyword_summary.key_index_decomp_len, _keywordIndexDecryptor),
            keyword_index = Array(keyword_summary.num_blocks),
            offset = 0;

        for (let i = 0, size; i < keyword_summary.num_blocks; i++) {
            keyword_index[i] = {
                num_entries: conseq(scanner.readNum(), size = scanner.readShort()),
                // UNUSED, can be ignored
                //          first_size:  size = scanner.readShort(),
                first_word: conseq(scanner.readTextSized(size), size = scanner.readShort()),
                // UNUSED, can be ignored
                //          last_size:   size = scanner.readShort(),
                last_word: scanner.readTextSized(size),
                comp_size: size = scanner.readNum(),
                decomp_size: scanner.readNum(),
                // extra fields
                offset: offset,     // offset of the first byte for the target key block in mdx/mdd file
                index: i            // index of this key index, used to search previous/next block
            };
            offset += size;
        }
        return keyword_index;
    }

    /**
     * Read record summary at the begining of record section.
     * @see https://github.com/zhansliu/writemdict/blob/master/fileformat.md#record-section
     * @param input sliced file, start = begining of record section, length = 32 (max length of record summary)
     * @param pos begining of record section
     * @returj record summary object
     */
    function read_record_summary(input, pos) {
        let scanner = scan.init(input),
            record_summary = {
                num_blocks: scanner.readNum(),
                num_entries: scanner.readNum(),
                index_len: scanner.readNum(),
                blocks_len: scanner.readNum(),
                // extra field
                len: scanner.offset,   // actual length of record section (excluding record block index), letying with engine version attribute
            };

        // start position of record block from head of mdx/mdd file
        record_summary.block_pos = pos + record_summary.index_len + record_summary.len;

        return record_summary;
    }

    /**
     * Read record block index part in record section, and fill RECORD_BLOCK_TABLE
     * @see https://github.com/zhansliu/writemdict/blob/master/fileformat.md#record-section
     * @param input sliced file, start = begining of record block index, length = record_summary.index_len
     * @param record_summary record summary object
     */
    function read_record_block(input, record_summary) {
        let scanner = scan.init(input),
            size = record_summary.num_blocks,
            record_index = Array(size),
            p0 = record_summary.block_pos,
            p1 = 0;

        RECORD_BLOCK_TABLE.alloc(size + 1);
        for (let i = 0, rdx; i < size; i++) {
            record_index[i] = rdx = {
                comp_size: scanner.readNum(),
                decomp_size: scanner.readNum()
            };
            RECORD_BLOCK_TABLE.put(p0, p1);
            p0 += rdx.comp_size;
            p1 += rdx.decomp_size;
        }
        RECORD_BLOCK_TABLE.put(p0, p1);
    }


    // ------------------------------------------
    // start to load mdx/mdd file
    // ------------------------------------------
    let pos = 0;
    const read = readFile.bind(null, file);

    return read(0, 4).then(data => {
        return new DataView(data).getUint32(0);
    }).then(async headerLength => {
        const res = await read(4, headerLength + 48);
        const headerRemainLen = await read_header_sect(res, headerLength);
        pos += headerRemainLen + 4;
        return read_keyword_summary(res, headerRemainLen);
    }).then(async keyword => {
        pos += keyword.len;
        const res = await read(pos, keyword.key_index_comp_len);
        KEY_INDEX = await read_keyword_index(res, keyword);

        pos += keyword.key_index_comp_len;
        slicedKeyBlock = read(pos, keyword.key_blocks_len);

        pos += keyword.key_blocks_len;
        return read_record_summary(await read(pos, 32), pos)
    }).then(async recordSummary => {
        pos += recordSummary.len;
        await read_record_block(await read(pos, recordSummary.index_len), recordSummary);

        // LOOKUP[ext].description = attrs.Description;
        return new Lookup(read, RECORD_BLOCK_TABLE, _adaptKey, slicedKeyBlock, KEY_INDEX, scan, stylesheet, ext)
    });
}