import {getConfig} from '../lib/config.ts';
import {instanceActor,discoverActor,signedActor,profileProofs,newProfileCode} from '../lib/activitypub.ts';
import type {FastifyInstance,FastifyRequest,FastifyReply} from 'fastify';
import {randomBytes,createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {z} from 'zod';
import {NodeOAuthClient,type NodeSavedState,type NodeSavedSession} from '@atproto/oauth-client-node';
import {query,one} from '../lib/db.ts';
import {ApiError} from '../lib/types.ts';
import {networkAccount,networkAccounts,saveNetwork,stateStore,type NetworkProvider} from '../lib/network-accounts.ts';
import {networkJson,networkFetch,publicUrl} from '../lib/network-http.ts';
const COOKIE='multipass_network_link';
const providerSchema=z.enum(['bluesky','mastodon','matrix','fediverse']);
const accountSchema=z.object({provider:providerSchema,address:z.string().min(1).max(512)});
type Flow={principalId:string,provider:NetworkProvider,address:string,network:string,profileUrl:string,verifier?:string,clientId?:string,clientSecret?:string,homeserver?:string,expectedDid?:string};
const flows=stateStore<Flow>('network-flow:');
const bskyState=stateStore<NodeSavedState>('bsky-state:');
const bskySessions=stateStore<NodeSavedSession>('bsky-session:',3600);
const base=()=>getConfig().publicUrl;
const callback=(provider:string)=>`${base()}/v1/networks/callback/${provider}`;
const oauthLocks=new Map<string,Promise<void>>();
async function requestLock<T>(name:string,fn:()=>T|PromiseLike<T>):Promise<T>{
 const previous=oauthLocks.get(name)||Promise.resolve();let release!:()=>void;const current=new Promise<void>(resolve=>{release=resolve;});oauthLocks.set(name,current);await previous;
 try{return await fn();}finally{release();if(oauthLocks.get(name)===current)oauthLocks.delete(name);}
}
let bsky:NodeOAuthClient|undefined;
function bluesky(){return bsky??=new NodeOAuthClient({clientMetadata:{client_id:`${base()}/v1/networks/bluesky-client.json`,client_name:'Leeloo Multipass network stamps',client_uri:base()+'/',redirect_uris:[callback('bluesky') as `https://${string}`],grant_types:['authorization_code','refresh_token'],response_types:['code'],scope:'atproto',application_type:'web',token_endpoint_auth_method:'none',dpop_bound_access_tokens:true},stateStore:bskyState,sessionStore:bskySessions,requestLock,fetch:networkFetch});}
const form=(value:Record<string,string>)=>({method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams(value)});
export function registerNetworkRoutes(app:FastifyInstance,deps:{requireSession:(req:FastifyRequest)=>Promise<{principalId:string}>}){
 async function owner(req:FastifyRequest){const auth=await deps.requireSession(req);await query('INSERT INTO passport_principals(id) VALUES($1) ON CONFLICT DO NOTHING',[auth.principalId]);return auth;}
 function sameOrigin(req:FastifyRequest){if(req.headers.origin!==new URL(base()).origin)throw new ApiError(403,'network_origin','Open network connections from your trusted Passport page.');}
 app.get('/v1/networks',async req=>networkAccounts((await owner(req)).principalId));
 app.get('/v1/networks/actor',async(_req,reply)=>reply.type('application/activity+json').send(await instanceActor()));
 app.get('/v1/networks/outbox',async()=>({'@context':'https://www.w3.org/ns/activitystreams',type:'OrderedCollection',totalItems:0,orderedItems:[]}));
 app.get('/v1/networks/followers',async()=>({'@context':'https://www.w3.org/ns/activitystreams',type:'OrderedCollection',totalItems:0,orderedItems:[]}));
 app.post('/v1/networks/inbox',async(_req,reply)=>reply.status(405).send({error:'ownership_verifier_only'}));
 app.post('/v1/networks/activitypub/challenge',async req=>{
  sameOrigin(req);const auth=await owner(req);const {address}=z.object({address:z.string().min(3).max(512)}).parse(req.body);
  const discovery=await discoverActor(address);const id=randomBytes(24).toString('base64url');const code=newProfileCode();
  await profileProofs.set(id,{principalId:auth.principalId,address:discovery.account.address,actorUrl:discovery.actorUrl,code});
  await saveNetwork(auth.principalId,discovery.account);
  return {id,code,address:discovery.account.address,actorUrl:discovery.actorUrl,profileUrl:discovery.profileUrl?publicUrl(discovery.profileUrl).href:discovery.account.profileUrl,expiresIn:3600,instructions:'Sign into this network and temporarily add this code to your public profile bio. Enable fediverse sharing for Threads. Then check the stamp. You can remove the code after verification.'};
 });
 app.post('/v1/networks/activitypub/verify',async req=>{
  sameOrigin(req);const auth=await owner(req);const {id}=z.object({id:z.string().min(20).max(100)}).parse(req.body);const proof=await profileProofs.get(id);
  if(!proof||proof.principalId!==auth.principalId)throw new ApiError(400,'proof_expired','This profile proof expired or belongs to another Passport.');
  const discovery=await discoverActor(proof.address);if(discovery.actorUrl!==proof.actorUrl)throw new ApiError(400,'actor_changed','The account’s ActivityPub actor changed. Start a new proof.');
  const actor=await signedActor(proof.actorUrl);
  if(actor.id!==proof.actorUrl)throw new ApiError(502,'actor_mismatch','The server returned a different ActivityPub actor.');
  if(typeof actor.summary!=='string'||!actor.summary.includes(proof.code))throw new ApiError(400,'proof_missing','The code is not in the federated profile bio yet. Save it on the network, allow time for updates, and try again.');
  const result=await saveNetwork(auth.principalId,discovery.account,actor.id);await profileProofs.del(id);return result;
 });

 app.get('/v1/networks/bluesky-client.json',async (_req,reply)=>{reply.header('Access-Control-Allow-Origin','*');return bluesky().clientMetadata;});
 app.get('/v1/networks/font',async(_req,reply)=>reply.type('font/woff2').header('Cache-Control','public, max-age=86400').send(await readFile(new URL('../ui/geist-variable.woff2',import.meta.url))));
 app.get('/v1/networks/ui',async (_req,reply)=>{return reply.header('Content-Security-Policy',`default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors ${getConfig().frameAncestors.join(' ')}`).header('Referrer-Policy','no-referrer').header('Cache-Control','no-store').type('text/html').send(await readFile(new URL('../ui/networks.html',import.meta.url),'utf8'));});
 for(const [path,file,type]of [['script','networks.js','text/javascript'],['style','networks.css','text/css'],['symbols','network-symbols.js','text/javascript']])app.get(`/v1/networks/${path}`,async(_req,reply)=>reply.type(type!).header('Cache-Control','no-cache').send(await readFile(new URL(`../ui/${file}`,import.meta.url),'utf8')));
 app.post('/v1/networks/save',async req=>{sameOrigin(req);const auth=await owner(req);const input=accountSchema.parse(req.body);return saveNetwork(auth.principalId,networkAccount(input.provider,input.address));});
 app.post('/v1/networks/disconnect',async req=>{sameOrigin(req);const auth=await owner(req);const {id}=z.object({id:z.string().uuid()}).parse(req.body);await query('DELETE FROM passport_network_accounts WHERE id=$1 AND principal_id=$2',[id,auth.principalId]);return {ok:true};});
 app.post('/v1/networks/connect',async (req,reply)=>{
  sameOrigin(req);const auth=await owner(req);const input=accountSchema.parse(req.body);const account=networkAccount(input.provider,input.address);
  if(account.provider==='fediverse')throw new ApiError(400,'unsupported_provider','Save this profile as a reference. Verified stamps currently support Bluesky, Mastodon-compatible servers and Matrix SSO.');
  const state=randomBytes(32).toString('base64url');const flow:Flow={...account,principalId:auth.principalId};let url:URL;
  if(account.provider==='bluesky'){
   flow.expectedDid=(await bluesky().identityResolver.resolve(account.address)).did;
   url=await bluesky().authorize(account.address,{state,scope:'atproto'});
  }else if(account.provider==='mastodon'){
   const apps=stateStore<{client_id:string,client_secret:string}>('mastodon-app:',30*86400);let client=await apps.get(account.network);
   if(!client){client=await networkJson<{client_id:string,client_secret:string}>(account.network+'/api/v1/apps',form({client_name:'Leeloo Multipass network stamps',redirect_uris:callback('mastodon'),scopes:'read:accounts',website:base()}));if(client.client_id&&client.client_secret)await apps.set(account.network,client);}
   if(!client.client_id||!client.client_secret)throw new ApiError(502,'invalid_provider','Server did not return valid application credentials.');
   flow.clientId=client.client_id;flow.clientSecret=client.client_secret;flow.verifier=randomBytes(32).toString('base64url');
   url=new URL(account.network+'/oauth/authorize');url.search=new URLSearchParams({client_id:client.client_id,redirect_uri:callback('mastodon'),response_type:'code',scope:'read:accounts',state,code_challenge:createHash('sha256').update(flow.verifier).digest('base64url'),code_challenge_method:'S256'}).toString();
  }else{
   let homeserver=account.network;
   const discovery=await networkFetch(account.network+'/.well-known/matrix/client');
   if(discovery.ok){const metadata=await discovery.json() as {'m.homeserver'?:{base_url?:string}};if(metadata['m.homeserver']?.base_url)homeserver=publicUrl(metadata['m.homeserver'].base_url).origin;}
   const login=await networkJson<{flows:Array<{type:string}>}>(homeserver+'/_matrix/client/v3/login');
   if(!login.flows?.some(flow=>flow.type==='m.login.sso'))throw new ApiError(400,'matrix_sso_unavailable','This homeserver does not expose browser SSO. You can save the address without a verified stamp. No password is requested by Passport.');
   flow.homeserver=homeserver;url=new URL(homeserver+'/_matrix/client/v3/login/sso/redirect');const back=new URL(callback('matrix'));back.searchParams.set('state',state);url.searchParams.set('redirectUrl',back.href);
  }
  publicUrl(url.href);await flows.set(state,flow);reply.setCookie(COOKIE,state,{path:'/v1/networks',httpOnly:true,secure:true,sameSite:'lax',maxAge:1200});
  return {url:url.href};
 });
 async function completion(req:FastifyRequest,reply:FastifyReply,provider:NetworkProvider){
  reply.header('Cache-Control','no-store').header('Referrer-Policy','no-referrer');
  try{
   const auth=await owner(req);const params=new URLSearchParams(req.url.split('?')[1]||'');const cookie=req.cookies[COOKIE];
   if(!cookie)throw new ApiError(400,'link_expired','The linking request expired. Start again in your Passport.');
   const pending=await flows.get(cookie);
   if(!pending||pending.principalId!==auth.principalId||pending.provider!==provider)throw new ApiError(400,'link_mismatch','This linking request belongs to a different Passport or provider.');
   if(provider!=='bluesky'&&params.get('state')!==cookie)throw new ApiError(400,'link_state','The linking state did not match.');
   const flow=await flows.consume(cookie);if(!flow)throw new ApiError(400,'link_used','That linking request was already used.');
   reply.clearCookie(COOKIE,{path:'/v1/networks'});
   if(params.has('error'))throw new ApiError(400,'link_declined','Network connection was canceled or declined.');
   if(provider==='bluesky'){
    const result=await bluesky().callback(params);
    try{
     if(result.session.did!==flow.expectedDid)throw new ApiError(400,'link_wrong_account','You authorized a different Bluesky account. Start again with its handle.');
     if(result.state!==cookie)throw new ApiError(400,'link_state','The linking state did not match.');
     const account={...networkAccount('bluesky',flow.address),profileUrl:'https://bsky.app/profile/'+result.session.did};
     await saveNetwork(auth.principalId,account,result.session.did);
    }finally{await result.session.signOut();await bskySessions.del(result.session.did);}
   }else if(provider==='mastodon'){
    const code=params.get('code');if(!code)throw new ApiError(400,'link_code','Provider returned no authorization code.');
    const token=await networkJson<{access_token:string}>(flow.network+'/oauth/token',form({grant_type:'authorization_code',client_id:flow.clientId!,client_secret:flow.clientSecret!,redirect_uri:callback(provider),code,code_verifier:flow.verifier!}));
    if(!token.access_token)throw new ApiError(502,'link_token','Provider returned no access token.');
    try{
     const profile=await networkJson<{id:string,username:string,acct:string,url:string}>(flow.network+'/api/v1/accounts/verify_credentials',{headers:{authorization:'Bearer '+token.access_token}});
     if(!profile.id||!profile.username||profile.acct.includes('@'))throw new ApiError(502,'link_profile','Provider did not return a local account.');
     const account=networkAccount('mastodon',`@${profile.username}@${new URL(flow.network).hostname}`);
     if(account.address.toLowerCase()!==flow.address.toLowerCase())throw new ApiError(400,'link_wrong_account','You signed into a different Mastodon account. Start again with its address.');
     await saveNetwork(auth.principalId,account,profile.id);
    }finally{await networkJson(flow.network+'/oauth/revoke',form({client_id:flow.clientId!,client_secret:flow.clientSecret!,token:token.access_token}));}
   }else{
    const token=params.get('loginToken');if(!token)throw new ApiError(400,'link_token','Homeserver returned no sign-in token.');
    const login=await networkJson<{user_id:string,access_token:string}>(flow.homeserver+'/_matrix/client/v3/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({type:'m.login.token',token,initial_device_display_name:'Leeloo Multipass ownership check'})});
    if(!login.access_token)throw new ApiError(502,'link_token','Homeserver returned no access token.');
    try{
     const who=await networkJson<{user_id:string}>(flow.homeserver+'/_matrix/client/v3/account/whoami',{headers:{authorization:'Bearer '+login.access_token}});
     if(who.user_id!==flow.address)throw new ApiError(400,'link_wrong_account','You signed into a different Matrix account. Start again with its address.');
     await saveNetwork(auth.principalId,networkAccount('matrix',who.user_id),who.user_id);
    }finally{await networkJson(flow.homeserver+'/_matrix/client/v3/logout',{method:'POST',headers:{authorization:'Bearer '+login.access_token,'content-type':'application/json'},body:'{}'});}
   }
   await query(`INSERT INTO passport_audit_events(principal_id,action,target) VALUES($1,'network.verified',$2)`,[auth.principalId,provider]);
   return reply.redirect('/v1/networks/ui?linked='+provider);
  }catch(error){
   req.log.warn({provider,error:error instanceof ApiError?error.code:'provider_failed'},'network linking did not complete');
   const message=error instanceof ApiError?error.message:'The provider could not complete the connection. Check your stamps before retrying.';
   return reply.redirect('/v1/networks/ui?error='+encodeURIComponent(message));
  }
 }
 for(const provider of ['bluesky','mastodon','matrix'] as const)app.get(`/v1/networks/callback/${provider}`,(req,reply)=>completion(req,reply,provider));
}
