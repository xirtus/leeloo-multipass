import { lookup } from 'node:dns';
import { Agent } from 'undici';
import ipaddr from 'ipaddr.js';
import { ApiError } from './types.ts';
export function publicAddress(address: string): boolean {
  try { return ipaddr.process(address).range() === 'unicast'; } catch { return false; }
}
export function publicUrl(value: string): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw new ApiError(400,'invalid_network','Use a public HTTPS server or profile URL.'); }
  const host=url.hostname.replace(/^\[|\]$/g,'');
  if(url.protocol!=='https:' || url.username || url.password || (url.port && url.port!=='443') || host==='localhost' || host.endsWith('.localhost') || (ipaddr.isValid(host)&&!publicAddress(host))) throw new ApiError(400,'invalid_network','Network connections require a public HTTPS server.');
  return url;
}
// Validate the actual DNS addresses used by each socket, including redirected
// destinations. A pre-flight lookup alone would allow DNS rebinding.
const agent = new Agent({ connect: { lookup(hostname, options, callback) {
  lookup(hostname,{all:true},(error,addresses)=>{
    if(error){callback(error,'',4);return;}
    if(!addresses.length || addresses.some(a=>!publicAddress(a.address))){callback(new Error('Private or reserved network addresses are not allowed'),'',4);return;}
    if((options as {all?:boolean}).all) (callback as (...args:unknown[])=>void)(null,addresses);
    else { const first=addresses[0]!; callback(null,first.address,first.family); }
  });
} } });
export const networkFetch: typeof fetch = async (input,init) => {
  let request=new Request(input,init);
  for(let redirects=0;redirects<5;redirects++){
    publicUrl(request.url);
    const response=await fetch(request,{dispatcher:agent,redirect:'manual',signal:AbortSignal.any([request.signal,AbortSignal.timeout(15000)])} as unknown as RequestInit);
    if([301,302,303,307,308].includes(response.status)){
      if(!['GET','HEAD'].includes(request.method)) throw new ApiError(502,'network_redirect','Provider redirected a credential request.');
      const target=response.headers.get('location'); if(!target) return response;
      const url=publicUrl(new URL(target,request.url).href); const headers=new Headers(request.headers);
      if(url.origin!==new URL(request.url).origin) headers.delete('authorization');
      await response.body?.cancel();request=new Request(url,{method:request.method,headers});continue;
    }
    const chunks:Uint8Array[]=[];let size=0;const reader=response.body?.getReader();
    if(reader) while(true){const result=await reader.read();if(result.done)break;size+=result.value.byteLength;if(size>2*1024*1024){await reader.cancel();throw new ApiError(502,'network_response_size','Provider response was too large.');}chunks.push(result.value);}
    const headers=new Headers(response.headers);headers.delete('content-encoding');headers.delete('content-length');
    const bounded=new Response([204,205,304].includes(response.status)?null:Buffer.concat(chunks),{status:response.status,statusText:response.statusText,headers});
    Object.defineProperty(bounded,'url',{value:response.url});return bounded;
  }
  throw new ApiError(502,'network_redirects','Too many provider redirects.');
};
export async function networkJson<T=Record<string,unknown>>(url:string,init?:RequestInit):Promise<T>{
  const response=await networkFetch(url,init);
  if(!response.ok) throw new ApiError(502,'network_provider_error',`Network provider returned HTTP ${response.status}.`);
  return response.json() as Promise<T>;
}
