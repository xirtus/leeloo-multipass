import {getConfig} from './config.ts';
import {generateKeyPairSync,createSign,randomBytes} from 'node:crypto';
import {one,query} from './db.ts';
import {seal,unseal,stateStore,networkAccount} from './network-accounts.ts';
import {networkJson,networkFetch,publicUrl} from './network-http.ts';
import {ApiError} from './types.ts';
const base=()=>getConfig().publicUrl;
type SigningKeys={publicKey:string,privateKey:string};
let keysPromise:Promise<SigningKeys>|undefined;
async function signingKeys(){return keysPromise??=(async()=>{
 const found=await one<{ciphertext:string}>("SELECT ciphertext FROM passport_network_state WHERE key='activitypub-signing-key'");if(found)return unseal<SigningKeys>(found.ciphertext);
 const keys=generateKeyPairSync('rsa',{modulusLength:2048,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
 await query("INSERT INTO passport_network_state(key,ciphertext,expires_at) VALUES('activitypub-signing-key',$1,'infinity') ON CONFLICT DO NOTHING",[seal(keys)]);
 return unseal<SigningKeys>((await one<{ciphertext:string}>("SELECT ciphertext FROM passport_network_state WHERE key='activitypub-signing-key'"))!.ciphertext);
})().catch(error=>{keysPromise=undefined;throw error;});}
export async function instanceActor(){const id=base()+'/v1/networks/actor';return {'@context':['https://www.w3.org/ns/activitystreams','https://w3id.org/security/v1'],id,type:'Application',name:'Leeloo Multipass ownership verifier',preferredUsername:'passport',inbox:base()+'/v1/networks/inbox',outbox:base()+'/v1/networks/outbox',followers:base()+'/v1/networks/followers',manuallyApprovesFollowers:true,summary:'Service actor for signed public-profile ownership checks. It does not post or bridge private messages.',publicKey:{id:id+'#main-key',owner:id,publicKeyPem:(await signingKeys()).publicKey}};}
export async function signedActor(urlValue:string){
 const url=publicUrl(urlValue);const date=new Date().toUTCString();const signature=createSign('RSA-SHA256').update(`(request-target): get ${url.pathname+url.search}\nhost: ${url.host}\ndate: ${date}`).sign((await signingKeys()).privateKey,'base64');
 const response=await networkFetch(url,{headers:{accept:'application/activity+json','user-agent':`LeelooMultipass/0.1 (+${base()})`,date,signature:`keyId="${base()}/v1/networks/actor#main-key",algorithm="rsa-sha256",headers="(request-target) host date",signature="${signature}"`}});
 if(!response.ok)throw new ApiError(502,'activitypub_unavailable','The ActivityPub profile could not be fetched. Confirm fediverse sharing is enabled and retry after the provider updates.');
 return response.json() as Promise<{id:string,type?:string,summary?:string,name?:string,url?:string}>;
}
export async function discoverActor(address:string){
 const match=/^@?([^@\s]+)@([a-z0-9.-]+)$/i.exec(address);
 if(!match)throw new ApiError(400,'activitypub_address','Use a full federated address, such as @alice@social.example.');
 const origin=publicUrl('https://'+match[2]).origin;const acct=`${match[1]}@${new URL(origin).hostname}`;
 const finger=await networkJson<{subject:string,links?:Array<{rel:string,type?:string,href?:string}>}>(origin+'/.well-known/webfinger?'+new URLSearchParams({resource:'acct:'+acct}),{headers:{accept:'application/jrd+json'}});
 if(finger.subject?.toLowerCase()!==('acct:'+acct).toLowerCase())throw new ApiError(502,'activitypub_subject','The server returned a different account.');
 const actor=finger.links?.find(link=>link.rel==='self'&&['application/activity+json','application/ld+json; profile="https://www.w3.org/ns/activitystreams"'].includes(link.type||''))?.href;
 if(!actor)throw new ApiError(400,'activitypub_not_enabled','This address has no ActivityPub profile. Enable fediverse sharing on the network first.');
 return {actorUrl:publicUrl(actor).href,profileUrl:finger.links?.find(link=>link.rel==='http://webfinger.net/rel/profile-page')?.href,account:networkAccount('fediverse','@'+acct)};
}
export type ProfileProof={principalId:string,address:string,actorUrl:string,code:string};
export const profileProofs=stateStore<ProfileProof>('profile-proof:',3600);
export const newProfileCode=()=> 'multipass-'+randomBytes(18).toString('hex');
