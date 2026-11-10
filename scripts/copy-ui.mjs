import {cp,mkdir} from 'node:fs/promises';
const target=new URL('../dist/ui/',import.meta.url);
await mkdir(target,{recursive:true});
await cp(new URL('../src/ui/',import.meta.url),target,{recursive:true});
