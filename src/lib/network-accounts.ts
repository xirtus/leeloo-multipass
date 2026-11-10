import { createCipheriv,createDecipheriv,createHash,randomBytes } from 'node:crypto';
import { query,one,tx } from './db.ts';
import { ApiError } from './types.ts';
import { publicUrl } from './network-http.ts';
import {getConfig} from './config.ts';
export type NetworkProvider='bluesky'|'mastodon'|'matrix'|'fediverse';
export function networkAccount(provider:NetworkProvider,raw:string){
 const address=raw.trim();
 if(provider==='bluesky'){
  const handle=address.replace(/^@/,'').toLowerCase();
  if(handle.length>253||!/^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$/.test(handle))throw new ApiError(400,'invalid_handle','Use a full Bluesky handle, such as alice.example.social.');
  return {provider,address:handle,network:'atproto',profileUrl:`https://bsky.app/profile/${handle}`};
 }
 if(provider==='matrix'){
  const match=/^@([^\s:]+):([a-z0-9.-]+)$/i.exec(address);
  if(!match)throw new ApiError(400,'invalid_mxid','Use a full Matrix address, such as @alice:matrix.example.');
  const network=publicUrl('https://'+match[2]!.toLowerCase()).origin;
  return {provider,address:`@${match[1]}:${new URL(network).hostname}`,network,profileUrl:'https://matrix.to/#/'+encodeURIComponent(address)};
 }
 if(provider==='mastodon'){
  let username:string,server:string;
  if(address.startsWith('https://')){const url=publicUrl(address);server=url.hostname;username=url.pathname.replace(/^\/@/,'').replace(/\/$/,'');}
  else {const match=/^@?([A-Za-z0-9_]+)@([a-z0-9.-]+)$/i.exec(address);if(!match)throw new ApiError(400,'invalid_mastodon','Use @name@server or your HTTPS profile URL.');username=match[1]!;server=match[2]!;}
  if(!/^[A-Za-z0-9_]+$/.test(username))throw new ApiError(400,'invalid_mastodon','Use the account’s @name profile URL.');
  const network=publicUrl('https://'+server.toLowerCase()).origin;
  return {provider,address:`@${username}@${new URL(network).hostname}`,network,profileUrl:`${network}/@${username}`};
 }
 const fed=/^@?([^@\s]+)@([a-z0-9.-]+)$/i.exec(address);
 if(fed){const url=publicUrl('https://'+fed[2]!.toLowerCase());return {provider,address:`@${fed[1]}@${url.hostname}`,network:url.origin,profileUrl:`${url.origin}/@${encodeURIComponent(fed[1]!)}`};}
 const url=publicUrl(address);url.hash='';return {provider,address:url.href,network:url.origin,profileUrl:url.href};
}
function key(){const secret=getConfig().storageKey;if(!secret||secret.length<32)throw new ApiError(503,'network_key_unconfigured','Network linking needs a host-side encryption key.');return createHash('sha256').update('passport-network-state-v1:'+secret).digest();}
export function seal(value:unknown){const iv=randomBytes(12);const cipher=createCipheriv('aes-256-gcm',key(),iv);const content=Buffer.concat([cipher.update(JSON.stringify(value),'utf8'),cipher.final()]);return Buffer.concat([iv,cipher.getAuthTag(),content]).toString('base64url');}
export function unseal<T>(value:string):T{const bytes=Buffer.from(value,'base64url');const decipher=createDecipheriv('aes-256-gcm',key(),bytes.subarray(0,12));decipher.setAuthTag(bytes.subarray(12,28));return JSON.parse(Buffer.concat([decipher.update(bytes.subarray(28)),decipher.final()]).toString('utf8')) as T;}
export function stateStore<T>(prefix:string,seconds=1200){return {
 async set(id:string,value:T){await query('DELETE FROM passport_network_state WHERE expires_at < now()');await query(`INSERT INTO passport_network_state(key,ciphertext,expires_at) VALUES($1,$2,now()+$3*interval '1 second') ON CONFLICT(key) DO UPDATE SET ciphertext=EXCLUDED.ciphertext,expires_at=EXCLUDED.expires_at`,[prefix+id,seal(value),seconds]);},
 async get(id:string){const row=await one<{ciphertext:string}>('SELECT ciphertext FROM passport_network_state WHERE key=$1 AND expires_at>now()',[prefix+id]);return row?unseal<T>(row.ciphertext):undefined;},
 async del(id:string){await query('DELETE FROM passport_network_state WHERE key=$1',[prefix+id]);},
 async consume(id:string){const row=await one<{ciphertext:string}>('DELETE FROM passport_network_state WHERE key=$1 AND expires_at>now() RETURNING ciphertext',[prefix+id]);return row?unseal<T>(row.ciphertext):undefined;}
};}
export async function networkAccounts(principalId:string){return (await query(`SELECT id,provider,network,address,profile_url AS "profileUrl",added_at AS "addedAt",verified_at AS "verifiedAt" FROM passport_network_accounts WHERE principal_id=$1 ORDER BY added_at`,[principalId])).rows;}
export async function saveNetwork(principalId:string,account:ReturnType<typeof networkAccount>,subject?:string){
 try{return await tx(async client=>{
  if(subject){
   const existing=(await client.query<{id:string,principal_id:string}>(`SELECT id,principal_id FROM passport_network_accounts WHERE provider=$1 AND network=$2 AND subject=$3 AND verified_at IS NOT NULL FOR UPDATE`,[account.provider,account.network,subject])).rows[0];
   if(existing){
    if(existing.principal_id!==principalId)throw new ApiError(409,'network_already_linked','That verified account belongs to another Passport. Disconnect it there first.');
    await client.query('DELETE FROM passport_network_accounts WHERE principal_id=$1 AND provider=$2 AND address=$3 AND id<>$4 AND verified_at IS NULL',[principalId,account.provider,account.address,existing.id]);
    await client.query('UPDATE passport_network_accounts SET address=$2,profile_url=$3,verified_at=now() WHERE id=$1',[existing.id,account.address,account.profileUrl]);
    return {id:existing.id};
   }
  }
  return (await client.query(`INSERT INTO passport_network_accounts(principal_id,provider,network,address,profile_url,subject,verified_at) VALUES($1,$2,$3,$4,$5,$6,CASE WHEN $6::text IS NULL THEN NULL ELSE now() END) ON CONFLICT(principal_id,provider,address) DO UPDATE SET subject=COALESCE(EXCLUDED.subject,passport_network_accounts.subject), verified_at=CASE WHEN EXCLUDED.subject IS NULL THEN passport_network_accounts.verified_at ELSE now() END,profile_url=EXCLUDED.profile_url RETURNING id`,[principalId,account.provider,account.network,account.address,account.profileUrl,subject??null])).rows[0];
 });}
 catch(error){if((error as {code?:string}).code==='23505')throw new ApiError(409,'network_already_linked','That verified account is already linked. Refresh your Passport before retrying.');throw error;}
}
