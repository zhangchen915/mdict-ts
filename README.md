## mdict-ts

mdict (*.mdx, *.mdd) file reader
rewrite form [mdict-js](https://github.com/fengdh/mdict-js)

#### Note:

Because of TextDecoder API , mdict-ts don't support IE and Edge , but you can use polyfill such as `text-encoding`.

#### Installation:

`npm i mdict-ts`

#### Usage:

```ts
    import {Mdict} from 'mdict-ts'
    const mdict = new Mdict(file: File)
    
    mdict.getWordList(query, offset?): Promise<Array<{ word: string, offset: number }>>
    mdict.getDefinition(offset): Promise<string> 
```