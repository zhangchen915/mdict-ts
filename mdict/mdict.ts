import {resolve, parseRes} from "./util";
import {MDictParser} from "./mdict-parser";

export type WordList = Promise<Array<{ word: string, offset: number }>>

export class Mdict extends MDictParser {
    cached_keys; // cache latest keys
    mutual_ticket = 0;// a oneway increased ticket used to cancel unfinished pattern match
    trail = null;// store latest visited record block & position when search for candidate keys

    constructor(file: string) {
        super(file);
    }

    /**
     * Reduce the key index array to an element which contains or is the nearest one matching a given phrase.
     */
    private reduce(arr, phrase) {
        let len = arr.length;
        if (len > 1) {
            len = len >> 1;
            return phrase > this.adaptKey(arr[len - 1].last_word) ?
                this.reduce(arr.slice(len), phrase) :
                this.reduce(arr.slice(0, len), phrase);
        } else {
            return arr[0];
        }
    }

    /**
     * Reduce the array to index of an element which contains or is the nearest one matching a given phrase.
     */
    private shrink(arr, phrase) {
        let len = arr.length,
            sub;
        if (len > 1) {
            len = len >> 1;
            let key = this.adaptKey(arr[len].word);
            if (phrase < key) {
                sub = arr.slice(0, len);
                sub.pos = arr.pos;
            } else {
                sub = arr.slice(len);
                sub.pos = (arr.pos || 0) + len;
            }
            return this.shrink(sub, phrase);
        } else {
            return (arr.pos || 0) + (phrase <= this.adaptKey(arr[0].word) ? 0 : 1);
        }
    }

    /**
     * Load keys for a keyword index object from mdx/mdd file.
     * @param kdx keyword index object
     */
    private loadKeys(kdx): WordList {
        if (this.cached_keys && this.cached_keys.pilot === kdx.first_word) {
            return resolve(this.cached_keys.list);
        } else {
            return this.slicedKeyBlock.then(input => {
                let scanner = this.scan.init(input),
                    list = Array(kdx.num_entries);
                scanner.forward(kdx.offset);
                scanner = scanner.readBlock(kdx.comp_size, kdx.decomp_size);

                for (let i = 0; i < kdx.num_entries; i++) {
                    let offset = scanner.readNum();
                    list[i] = {
                        word: scanner.readText(),
                        offset
                    };
                    if (i > 0) list[i - 1].size = offset - list[i - 1].offset;
                }
                this.cached_keys = {
                    list,
                    pilot: kdx.first_word
                };
                return list;
            });
        }
    }

    /**
     * Search for the first keyword match given phrase.
     */
    private seekVanguard(phrase) {
        phrase = this.adaptKey(phrase);
        let kdx = this.reduce(this.KEY_INDEX, phrase);

        // look back for the first record block containing keyword for the specified phrase
        if (phrase <= this.adaptKey(kdx.last_word)) {
            let index = kdx.index - 1,
                prev;
            while (prev = this.KEY_INDEX[index]) {
                if (this.adaptKey(prev.last_word) !== this.adaptKey(kdx.last_word)) break;
                kdx = prev;
                index--;
            }
        }

        return this.loadKeys(kdx).then(list => {
            let idx = this.shrink(list, phrase);
            // look back for the first matched keyword position
            while (idx > 0) {
                if (this.adaptKey(list[--idx].word) !== this.adaptKey(phrase)) {
                    idx++;
                    break;
                }
            }
            return [kdx, Math.min(idx, list.length - 1), list];
        });
    }

    // TODO: have to restrict max count to improve response
    /**
     * Append more to word list according to a filter or expected size.
     */
    private appendMore(word, list, nextKdx, expectedSize, filter, ticket) {
        if (ticket !== this.mutual_ticket) throw 'force terminated';

        if (filter) {
            if (this.trail.count < expectedSize && nextKdx && nextKdx.first_word.substr(0, word.length) === word) {
                return this.loadKeys(nextKdx).then(more => {
                    this.trail.offset = 0;
                    this.trail.block = nextKdx.index;
                    Array.prototype.push.apply(list, more.filter(filter, this.trail));
                    return this.appendMore(word, list, this.KEY_INDEX[nextKdx.index + 1], expectedSize, filter, ticket);
                });
            } else {
                if (list.length === 0) this.trail.exhausted = true;
                return resolve(list);
            }
        } else {
            let shortage = expectedSize - list.length;
            if (shortage > 0 && nextKdx) {
                console.log('go next', nextKdx);
                this.trail.block = nextKdx.index;
                return this.loadKeys(nextKdx).then(more => {
                    this.trail.offset = 0;
                    this.trail.pos = Math.min(shortage, more.length);
                    Array.prototype.push.apply(list, more.slice(0, shortage));
                    console.log('$$ ' + more[shortage - 1], shortage);
                    return this.appendMore(word, list, this.KEY_INDEX[nextKdx.index + 1], expectedSize, filter, ticket);
                });
            } else {
                if (this.trail.pos > expectedSize) {
                    this.trail.pos = expectedSize;
                }
                list = list.slice(0, expectedSize);
                this.trail.count = list.length;
                this.trail.total += this.trail.count;
                return resolve(list);
            }
        }
    }

    private followUp() {
        let kdx = this.KEY_INDEX[this.trail.block];
        return this.loadKeys(kdx).then(list => {
            return [kdx, Math.min(this.trail.offset + this.trail.pos, list.length - 1), list];
        });
    }

    private matchKeys(phrase: string, expectedSize = 0, follow: boolean) {
        let filter;
        expectedSize = Math.max(expectedSize, 10);
        let str = phrase.trim().toLowerCase(),
            m = /([^?*]+)[?*]+/.exec(str),
            word;
        if (m) {
            word = m[1];
            const wildcard = new RegExp('^' +
                str.replace(/([.\\+\[^\]$()])/g, '\\$1')
                    .replace(/\*+/g, '.*')
                    .replace(/\?/g, '.') + '$'),
                tester = phrase[phrase.length - 1] === ' ' ? s => wildcard.test(s) : s => wildcard.test(s) && !/ /.test(s);
            filter = (s, i) => {
                if (this.trail.count < expectedSize && tester(s)) {
                    this.trail.count++;
                    this.trail.total++;
                    this.trail.pos = i + 1;
                    return true;
                }
                return false;
            };
        } else {
            word = phrase.trim();
        }

        if (this.trail && this.trail.phrase !== phrase) follow = false;
        if (follow && this.trail && this.trail.exhausted) return resolve([]);

        let startFrom = follow && this.trail ? this.followUp() : this.seekVanguard(word);

        return startFrom.then(([kdx, idx, list]) => {
            console.log('start  ', kdx);
            list = list.slice(idx);
            this.trail = {
                phrase: phrase,
                block: kdx.index,
                offset: idx,
                pos: list.length,
                count: 0,
                total: follow ? this.trail && this.trail.total || 0 : 0
            };
            if (filter) list = list.filter(filter, this.trail);

            return this.appendMore(word, list, this.KEY_INDEX[kdx.index + 1], expectedSize, filter, ++this.mutual_ticket)
                .then(result => {
                    if (this.trail.block === this.KEY_INDEX.length - 1) {
                        if (this.trail.offset + this.trail.pos >= this.KEY_INDEX[this.trail.block].num_entries) {
                            this.trail.exhausted = true;
                            console.log('EXHAUSTED!!!!');
                        }
                    }
                    console.log('trail: ', this.trail);
                    return result;
                });
        });
    }

    /**
     * Match the first element in list with given offset.
     */
    private matchOffset(list, offset) {
        return list.some(el => {
            el.offset === offset ? list = [el] : false;
        }) ? list : [];
    }

    /**
     * Read definition in text for given keyinfo object.
     * @param input record block sliced from the file
     * @param block record block index
     * @param offset
     * @return definition in text
     */
    private readDefinition(input, block, offset) {
        let scanner = this.scan.init(input).readBlock(block.comp_size, block.decomp_size);
        scanner.forward(offset - block.decomp_offset);
        return scanner.readText();
    }

    /**
     * Following link to find actual definition of keyword.
     * @param definition maybe starts with "@@@LINK=" which links to another keyword
     * @return resolved actual definition
     */
    private async redirects(definition: string) {
        return (definition.substring(0, 8) !== '@@@LINK=') ?
            definition :
            await this.mdx(definition.substring(8));
    }

    /**
     * Read content in ArrayBuffer for give keyInfo object
     * @param input record block sliced from the file
     * @param block record block index
     * @param keyInfo a object with property of record's offset and optional size for the given keyword
     * @return an ArrayBuffer containing resource of image/audio/css/font etc.
     */
    private read_object(input, block, keyInfo) {
        if (input.byteLength > 0) {
            let scanner = this.scan.init(input).readBlock(block.comp_size, block.decomp_size);
            scanner.forward(keyInfo.offset - block.decomp_offset);
            return scanner.readRaw(keyInfo.size);
        } else {
            throw '* OUT OF FILE RANGE * ' + keyInfo + ' @offset=' + block.comp_offset;
        }
    }

    /**
     * Find resource (image, sound etc.) for given keyinfo object.
     * @param keyInfo a object with property of record's offset and optional size for the given keyword
     * @return a promise object which will resolve to an ArrayBuffer containing resource of image/audio/css/font etc.
     * TODO: Follow link, maybe it's too expensive and a rarely used feature?
     */
    private async findResource(keyInfo) {
        let block = this.RECORD_BLOCK_TABLE.find(keyInfo.offset);
        return await this.read(block.comp_offset, block.comp_size).then(res => this.read_object(res, block, keyInfo))
    }

    private mdx(query, offset?) {
        if (typeof query === 'string' || query instanceof String) {
            this.trail = null;
            let word = query.trim().toLowerCase();

            return this.seekVanguard(word).then(([kdx, idx, list]) => {
                list = list.slice(idx);
                if (offset) list = this.matchOffset(list, offset);
                return list;
            });
        } else {
            return this.matchKeys(query.word, query.max, query.follow);
        }
    }

    // TODO: chain multiple mdd file
    private mdd(query: string) {
        let word = query.trim().toLowerCase();
        word = '\\' + word.replace(/(^[/\\])|([/]$)/, '');
        word = word.replace(/\//g, '\\');
        return this.seekVanguard(word).then(([kdx, idx, list]) => {
            return list.slice(idx).filter(e => e.toLowerCase() === word);
        }).then(candidates => {
            if (candidates.length === 0) {
                throw '*RESOURCE NOT FOUND* ' + query;
            } else {
                return this.findResource(candidates[0]);
            }
        });
    }

    public getWordList(query, offset?): WordList {
        return this.ext === 'mdx' ? this.mdx(query, offset) : this.mdd(query);
    }

    /**
     * Find word definition for given keyinfo object.
     * @return Q.Promise<resolved> | never> | never> promise object which will resolve to definition in text. Link to other keyword is followed to get actual definition.
     * @param offset
     */
    public getDefinition(offset): Promise<string> {
        let block = this.RECORD_BLOCK_TABLE.find(offset);
        return this.read(block.comp_offset, block.comp_size).then((data: any) => {
            return this.readDefinition(data, block, offset);
        }).then((definition: string) => {
            if (this.StyleSheet.length) definition = parseRes(definition, this.StyleSheet);
            return this.redirects(definition)
        });
    }
}

module.exports = Mdict;