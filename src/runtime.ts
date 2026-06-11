import { createHash, randomUUID } from "node:crypto";
import pg from "pg";
import { z } from "zod";

export const jobStates = ["RECEIVED","VALIDATED","ACCEPTED","PAID","QUEUED","COLLECTING","ANALYZING","WAITING_DEPENDENCY","WAITING_GENLAYER","DELIVERING","COMPLETED","REJECTED","FAILED_RETRYABLE","FAILED_FINAL","EXPIRED"] as const;
export type JobState = typeof jobStates[number];
export type Job = { id:string; crooOrderId:string; state:JobState; input:unknown; result?:unknown; error?:string; attempts:number; createdAt:string; updatedAt:string };
export type Source = { id:string; type:string; uri:string; observed_at:string; block_number?:number; hash?:string };

export const deliveryEnvelopeSchema = z.object({
  schema_version: z.literal("1.0.0"),
  service: z.object({ agent_id:z.string(), service_id:z.string(), version:z.string() }),
  order: z.object({ order_id:z.string(), started_at:z.string(), completed_at:z.string() }),
  result: z.unknown(),
  evidence: z.object({ sources:z.array(z.unknown()), block_numbers:z.record(z.string(),z.number()), dependency_orders:z.array(z.unknown()), genlayer_attestation:z.unknown().nullable() }),
  quality: z.object({ confidence:z.number().min(0).max(100), data_freshness:z.record(z.string(),z.string()), degraded_sources:z.array(z.string()), limitations:z.array(z.string()) }),
  result_hash:z.string().regex(/^sha256:[0-9a-f]{64}$/)
});

export function canonicalJson(value:unknown):string {
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  if (value && typeof value === "object") return "{" + Object.entries(value).sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>JSON.stringify(k)+":"+canonicalJson(v)).join(",") + "}";
  return JSON.stringify(value);
}
export function sha256(value:unknown){ return "sha256:"+createHash("sha256").update(canonicalJson(value)).digest("hex"); }
export function redact(value:string){ return value.replace(/(croo_sk_|ghp_|AIza|0x)[A-Za-z0-9_-]{20,}/g,"[REDACTED]"); }
export function assertPublicHttpUrl(raw:string){
  const url=new URL(raw);
  if(!["https:"].includes(url.protocol)) throw new Error("Only HTTPS URLs are allowed");
  const h=url.hostname.toLowerCase();
  if(h==="localhost" || h.endsWith(".local") || h==="0.0.0.0" || h.startsWith("127.") || h.startsWith("10.") || h.startsWith("192.168.") || /^172\.(1[6-9]|2\d|3[01])\./.test(h)) throw new Error("Private network URLs are blocked");
  return url;
}

export interface JobStore {
  create(orderId:string,input:unknown):Promise<Job>;
  get(orderId:string):Promise<Job|null>;
  transition(orderId:string,state:JobState,patch?:Partial<Job>):Promise<Job>;
  recoverable():Promise<Job[]>;
}

export class MemoryJobStore implements JobStore {
  private jobs=new Map<string,Job>();
  async create(crooOrderId:string,input:unknown){ const existing=this.jobs.get(crooOrderId); if(existing)return existing; const now=new Date().toISOString(); const job={id:randomUUID(),crooOrderId,state:"RECEIVED" as JobState,input,attempts:0,createdAt:now,updatedAt:now};this.jobs.set(crooOrderId,job);return job; }
  async get(id:string){return this.jobs.get(id)??null;}
  async transition(id:string,state:JobState,patch={}){const job=this.jobs.get(id);if(!job)throw new Error("Job not found");const next={...job,...patch,state,updatedAt:new Date().toISOString()};this.jobs.set(id,next);return next;}
  async recoverable(){return [...this.jobs.values()].filter(j=>!["COMPLETED","REJECTED","FAILED_FINAL","EXPIRED"].includes(j.state));}
}

export class PostgresJobStore implements JobStore {
  private pool:pg.Pool;
  constructor(url:string){this.pool=new pg.Pool({connectionString:url,max:5});}
  async migrate(){await this.pool.query(`CREATE TABLE IF NOT EXISTS jobs(id uuid PRIMARY KEY,croo_order_id text UNIQUE NOT NULL,state text NOT NULL,input jsonb NOT NULL,result jsonb,error text,attempts int NOT NULL DEFAULT 0,created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL); CREATE TABLE IF NOT EXISTS dependency_orders(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),parent_order_id text NOT NULL,service_id text NOT NULL,payment_attempted boolean NOT NULL DEFAULT false,payment_hash text,delivery_hash text,UNIQUE(parent_order_id,service_id));`);}
  private map(r:any):Job{return {id:r.id,crooOrderId:r.croo_order_id,state:r.state,input:r.input,result:r.result,error:r.error,attempts:r.attempts,createdAt:r.created_at.toISOString(),updatedAt:r.updated_at.toISOString()};}
  async create(orderId:string,input:unknown){const now=new Date();const r=await this.pool.query("INSERT INTO jobs(id,croo_order_id,state,input,created_at,updated_at) VALUES($1,$2,'RECEIVED',$3,$4,$4) ON CONFLICT(croo_order_id) DO UPDATE SET croo_order_id=EXCLUDED.croo_order_id RETURNING *",[randomUUID(),orderId,input,now]);return this.map(r.rows[0]);}
  async get(id:string){const r=await this.pool.query("SELECT * FROM jobs WHERE croo_order_id=$1",[id]);return r.rowCount?this.map(r.rows[0]):null;}
  async transition(id:string,state:JobState,patch:Partial<Job>={}){const r=await this.pool.query("UPDATE jobs SET state=$2,result=COALESCE($3,result),error=COALESCE($4,error),attempts=COALESCE($5,attempts),updated_at=now() WHERE croo_order_id=$1 RETURNING *",[id,state,patch.result??null,patch.error??null,patch.attempts??null]);if(!r.rowCount)throw new Error("Job not found");return this.map(r.rows[0]);}
  async recoverable(){const r=await this.pool.query("SELECT * FROM jobs WHERE state <> ALL($1)",[["COMPLETED","REJECTED","FAILED_FINAL","EXPIRED"]]);return r.rows.map(x=>this.map(x));}
}

export type ServiceHandler = (input:unknown, context:{orderId:string; transition:(s:JobState)=>Promise<void>})=>Promise<{result:unknown;sources?:Source[];confidence?:number;limitations?:string[];dependencies?:unknown[];attestation?:unknown}>;

export class Lifecycle {
  constructor(private store:JobStore,private handler:ServiceHandler,private identity:{agentId:string;serviceId:string;version:string}){}
  async process(orderId:string,input:unknown){
    const existing=await this.store.get(orderId); if(existing?.state==="COMPLETED")return existing.result;
    const job=await this.store.create(orderId,input);
    const transition=async(s:JobState)=>{await this.store.transition(orderId,s);};
    try{
      await transition("VALIDATED"); await transition("PAID"); await transition("QUEUED");
      const output=await this.handler(input,{orderId,transition});
      await transition("DELIVERING");
      const completedAt=new Date().toISOString();
      const unsigned={schema_version:"1.0.0" as const,service:{agent_id:this.identity.agentId,service_id:this.identity.serviceId,version:this.identity.version},order:{order_id:orderId,started_at:job.createdAt,completed_at:completedAt},result:output.result,evidence:{sources:output.sources??[],block_numbers:{},dependency_orders:output.dependencies??[],genlayer_attestation:output.attestation??null},quality:{confidence:output.confidence??70,data_freshness:{generated_at:completedAt},degraded_sources:[],limitations:output.limitations??[]}};
      const envelope={...unsigned,result_hash:sha256(unsigned)};
      deliveryEnvelopeSchema.parse(envelope);
      await this.store.transition(orderId,"COMPLETED",{result:envelope});
      return envelope;
    }catch(error){await this.store.transition(orderId,"FAILED_FINAL",{error:redact(error instanceof Error?error.message:String(error)),attempts:job.attempts+1});throw error;}
  }
}

export async function rpc(url:string,method:string,params:unknown[]){
  const response=await fetch(url,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",id:1,method,params}),signal:AbortSignal.timeout(15000)});
  if(!response.ok)throw new Error("RPC HTTP "+response.status);
  const body=await response.json() as any;if(body.error)throw new Error("RPC "+body.error.message);return body.result;
}

export async function geminiText(prompt:string,fallback:string){
  const key=process.env.GEMINI_API_KEY;if(!key)return fallback;
  const model=process.env.GEMINI_MODEL??"gemini-2.5-flash";
  const response=await fetch("https://generativelanguage.googleapis.com/v1beta/models/"+model+":generateContent?key="+encodeURIComponent(key),{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({contents:[{parts:[{text:prompt}]}],generationConfig:{temperature:0.2,maxOutputTokens:800}}),signal:AbortSignal.timeout(30000)});
  if(!response.ok)return fallback;const body=await response.json() as any;return body.candidates?.[0]?.content?.parts?.[0]?.text??fallback;
}

export class SpendingGuard {
  private spent=0;
  constructor(private perOrderMicrousdc:number,private dailyMicrousdc:number){}
  authorize(amount:number){if(!Number.isInteger(amount)||amount<0)throw new Error("Invalid amount");if(amount>this.perOrderMicrousdc)throw new Error("Per-order spending cap exceeded");if(this.spent+amount>this.dailyMicrousdc)throw new Error("Daily spending cap exceeded");this.spent+=amount;}
}

export async function purchaseCrooService(serviceId:string,requirements:unknown,maxPriceMicrousdc:number,guard:SpendingGuard){
  guard.authorize(maxPriceMicrousdc);
  const sdkKey=process.env.CROO_SDK_KEY;if(!sdkKey)throw new Error("CROO_SDK_KEY is required for dependency purchases");
  const sdk:any=await import("@croo-network/sdk");
  const client=new sdk.AgentClient({baseURL:process.env.CROO_API_URL??"https://api.croo.network",wsURL:process.env.CROO_WS_URL??"wss://api.croo.network/ws",rpcURL:process.env.BASE_RPC_URL},sdkKey);
  const negotiation=await client.negotiateOrder({serviceId,requirements:JSON.stringify(requirements)});
  const deadline=Date.now()+Number(process.env.DEPENDENCY_TIMEOUT_MS??300000);let order:any;
  while(Date.now()<deadline){const orders=await client.listOrders({role:"requester",pageSize:100});order=orders.find((x:any)=>x.negotiationId===negotiation.negotiationId);if(order)break;await new Promise(r=>setTimeout(r,2000));}
  if(!order)throw new Error("Dependency negotiation did not produce an order");
  const price=Number(order.price??order.feeAmount??0);if(price>maxPriceMicrousdc)throw new Error("Dependency price exceeds authorized cap");
  if(order.status==="created")await client.payOrder(order.orderId);
  while(Date.now()<deadline){order=await client.getOrder(order.orderId);if(order.status==="completed"){const delivery=await client.getDelivery(order.orderId);return {order_id:order.orderId,payment_hash:order.payTxHash,delivery_hash:delivery.contentHash,service_id:serviceId,delivery:JSON.parse(delivery.deliverableText)};}if(["rejected","expired","pay_failed","deliver_failed"].includes(order.status))throw new Error("Dependency order failed: "+order.status);await new Promise(r=>setTimeout(r,2500));}
  throw new Error("Dependency order timed out");
}

export async function createCrooAdapter(lifecycle:Lifecycle){
  const sdkKey=process.env.CROO_SDK_KEY;if(!sdkKey)throw new Error("CROO_SDK_KEY is required");
  const sdk:any=await import("@croo-network/sdk");const client=new sdk.AgentClient({baseURL:process.env.CROO_API_URL??"https://api.croo.network",wsURL:process.env.CROO_WS_URL??"wss://api.croo.network/ws",rpcURL:process.env.BASE_RPC_URL},sdkKey);
  const stream=await client.connectWebSocket();
  stream.on(sdk.EventType.NegotiationCreated,async(e:any)=>{const n=await client.getNegotiation(e.negotiation_id);try{JSON.parse(n.requirements);await client.acceptNegotiation(e.negotiation_id);}catch(error){await client.rejectNegotiation(e.negotiation_id,error instanceof Error?error.message:"Invalid requirements");}});
  stream.on(sdk.EventType.OrderPaid,async(e:any)=>{const order=await client.getOrder(e.order_id);const negotiation=await client.getNegotiation(order.negotiationId);const result=await lifecycle.process(order.orderId,JSON.parse(negotiation.requirements));await client.deliverOrder(order.orderId,{deliverableType:sdk.DeliverableType.Text,deliverableText:JSON.stringify(result)});});
  const reconcile=async()=>{for(const order of await client.listOrders({role:"provider",status:"paid",pageSize:100})){const n=await client.getNegotiation(order.negotiationId);const result=await lifecycle.process(order.orderId,JSON.parse(n.requirements));await client.deliverOrder(order.orderId,{deliverableType:sdk.DeliverableType.Text,deliverableText:JSON.stringify(result)});}};
  const timer=setInterval(()=>reconcile().catch(console.error),30000);process.on("SIGTERM",()=>{clearInterval(timer);stream.close();});
  return client;
}
