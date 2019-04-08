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
    readFile,
    getAdaptKey,
    createRecordBlockTable,
    getExtension,
    readUTF16,
    getGlobalStyle, parseXml, dataView
} from './util'
import {
    decrypt
} from './crypt'
import {
    Scan
} from './Scan'
import {
    Mdict
} from './mdict'

export interface HeaderSection {
    GeneratedByEngineVersion: string;
    RequiredEngineVersion: string;
    Encrypted: number;
    Format: string;
    CreationDate: string;
    Compact: string;
    Compat: string;
    KeyCaseSensitive: string;
    Description: string;
    Title: string;
    DataSourceFormat: string;
    StyleSheet: string;
    RegisterBy: string;
    RegCode: string;
    StripKey: string;
}

export interface Keyword {
    num_blocks: number,
    num_entries: number,
    key_index_decomp_len: number,
    key_index_comp_len: number,
    key_blocks_len: number,
    chksum: number,
    len: number,
}


/**
 * Parse a MDictParser dictionary/resource file (mdx/mdd).
 * @param file a File/Blob object
 * @return Q.Promise<Mdict> | never>{num_blocks: *, num_entries: *, index_len: *, blocks_len: *, len: *} | never | never>{num_blocks: *, num_entries: *, index_len: *, blocks_len: *, len: (*|number)} | never | never> Promise object which will resolve to a lookup private.
 */
export class MDictParser {
    file: string;
    headerSection;
    KEY_INDEX;
    RECORD_BLOCK_TABLE = createRecordBlockTable(); // record block table
    ext;
    read;
    scan;
    adaptKey;
    private keywordIndexDecryptor;
    StyleSheet;
    slicedKeyBlock;

    constructor(file: string) {
        let pos = 0;
        this.file = file;
        this.ext = getExtension(file);
        this.read = readFile.bind(null, this.file);

        this.read(0, 4).then(async (data: ArrayBuffer) => {
            const headerLength = new dataView(data).getUint32(0);
            const res = await this.read(4, headerLength + 48);
            const headerRemainLen = await this.read_header_sect(res, headerLength);
            pos += headerRemainLen + 4;
            return this.read_keyword_summary(res, headerRemainLen);
        }).then(async (keyword: Keyword) => {
            pos += keyword.len;
            const res = await this.read(pos, keyword.key_index_comp_len);
            this.KEY_INDEX = await this.read_keyword_index(res, keyword);

            pos += keyword.key_index_comp_len;
            this.slicedKeyBlock = this.read(pos, keyword.key_blocks_len);

            pos += keyword.key_blocks_len;
            return this.read_record_summary(await this.read(pos, 32), pos)
        }).then(async (recordSummary: { len: number; index_len: any; }) => {
            pos += recordSummary.len;
            await this.read_record_block(await this.read(pos, recordSummary.index_len), recordSummary);
        });
    }

    /**
     * Read header section, parse dictionary attributes and config scanner according to engine version attribute.
     * @see https://github.com/zhansliu/writemdict/blob/master/fileformat.md#header-section
     * @param input sliced file (start = 4, length = len + 48), header string + header section (max length 48)
     * @param len lenghth of header_str
     * @return [remained length of header section (header_str and checksum, = len + 4), original input]
     */
    private read_header_sect(input: any, len: number) {
        let header_str = readUTF16(input, len).replace(/\0$/, ''); // need to remove tailing NUL
        const doc = parseXml(header_str);// parse dictionary attributes
        let xml = doc.getElementsByTagName('Dictionary')[0];
        if (!xml) xml = doc.getElementsByTagName('Library_Data')[0];
        let attrs: HeaderSection = {
            GeneratedByEngineVersion: '',
            RequiredEngineVersion: '',
            Encrypted: 0,
            Format: '',
            CreationDate: '',
            Compact: '',
            Compat: '',
            KeyCaseSensitive: '',
            Description: '',
            Title: '',
            DataSourceFormat: '',
            StyleSheet: '',
            RegisterBy: '',
            RegCode: '',
            StripKey: ''
        };
        for (let i = 0, item; i < xml.attributes.length; i++) {
            item = xml.attributes[i];
            attrs[item.nodeName] = item.nodeValue;
        }
        this.headerSection = attrs;
        attrs.Encrypted = parseInt(String(attrs.Encrypted), 10) || 0;

        this.scan = new Scan(attrs);
        if (attrs.Encrypted & 0x02) this.keywordIndexDecryptor = decrypt;

        this.adaptKey = getAdaptKey(attrs, this.ext);
        this.StyleSheet = getGlobalStyle(attrs.StyleSheet);
        return len + 4;
    }

    /**
     * Read keyword summary at the begining of keyword section.
     * @see https://github.com/zhansliu/writemdict/blob/master/fileformat.md#keyword-section
     * @param input sliced file, same as input passed to read_header_sect()
     * @param offset start position of keyword section in sliced file, equals to length of header string plus checksum.\
     * @return {num_blocks: *, num_entries: *, key_index_decomp_len: *, key_index_comp_len: *, key_blocks_len: *, chksum: *, len: number} object
     */
    private read_keyword_summary(input: any, offset: number): Keyword {
        const scanner = this.scan.init(input).forward(offset);
        return {
            num_blocks: scanner.readNum(),
            num_entries: scanner.readNum(),
            key_index_decomp_len: scanner.v2 && scanner.readNum(), // Ver >= 2.0 only
            key_index_comp_len: scanner.readNum(),
            key_blocks_len: scanner.readNum(),
            chksum: scanner.checksumV2(),
            // extra field
            len: scanner.offset - offset, // actual length of keyword section, letying with engine version attribute
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
    private read_keyword_index(input: any, keyword_summary: Keyword) {
        let scanner = this.scan.init(input).readBlock(keyword_summary.key_index_comp_len, keyword_summary.key_index_decomp_len, this.keywordIndexDecryptor),
            keyword_index = Array(keyword_summary.num_blocks),
            offset = 0;

        for (let i = 0, size; i < keyword_summary.num_blocks; i++) {
            keyword_index[i] = {
                num_entries: [scanner.readNum(), size = scanner.readShort()][0],
                // UNUSED, can be ignored
                //          first_size:  size = scanner.readShort(),
                first_word: [scanner.readTextSized(size), size = scanner.readShort()][0],
                // UNUSED, can be ignored
                //          last_size:   size = scanner.readShort(),
                last_word: scanner.readTextSized(size),
                comp_size: size = scanner.readNum(),
                decomp_size: scanner.readNum(),
                // extra fields
                offset: offset, // offset of the first byte for the target key block in mdx/mdd file
                index: i // index of this key index, used to search previous/next block
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
    private read_record_summary(input: any, pos: number) {
        let scanner = this.scan.init(input),
            record_summary = {
                num_blocks: scanner.readNum(),
                num_entries: scanner.readNum(),
                index_len: scanner.readNum(),
                blocks_len: scanner.readNum(),
                // extra field
                len: scanner.offset, // actual length of record section (excluding record block index), letying with engine version attribute
                block_pos: 0
            };

        // start position of record block from head of mdx/mdd file
        record_summary.block_pos = pos + record_summary.index_len + record_summary.len;

        return record_summary;
    }

    /**
     * Read record block index part in record section, and fill this.RECORD_BLOCK_TABLE
     * @see https://github.com/zhansliu/writemdict/blob/master/fileformat.md#record-section
     * @param input sliced file, start = begining of record block index, length = record_summary.index_len
     * @param record_summary record summary object
     */
    private read_record_block(input: any, record_summary: { len?: number; index_len?: any; num_blocks?: any; block_pos?: any; }) {
        let scanner = this.scan.init(input),
            size = record_summary.num_blocks,
            record_index = Array(size),
            p0 = record_summary.block_pos,
            p1 = 0;

        this.RECORD_BLOCK_TABLE.alloc(size + 1);
        for (let i = 0, rdx; i < size; i++) {
            record_index[i] = rdx = {
                comp_size: scanner.readNum(),
                decomp_size: scanner.readNum()
            };
            this.RECORD_BLOCK_TABLE.put(p0, p1);
            p0 += rdx.comp_size;
            p1 += rdx.decomp_size;
        }
        this.RECORD_BLOCK_TABLE.put(p0, p1);
    }
}