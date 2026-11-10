import pg from 'pg';
import { getConfig } from './config.ts';
export type Client = pg.PoolClient;
let pool: pg.Pool | null = null;
export function getPool(): pg.Pool {
  return pool ??= new pg.Pool({ connectionString: getConfig().databaseUrl, max: 10, connectionTimeoutMillis: 5000, idleTimeoutMillis: 30000, statement_timeout: 10000 });
}
export async function closePool(): Promise<void> { if (pool) { await pool.end(); pool = null; } }
export async function query<R extends pg.QueryResultRow = pg.QueryResultRow>(text: string, params: unknown[] = []): Promise<pg.QueryResult<R>> { return getPool().query<R>(text, params); }
export async function one<R extends pg.QueryResultRow = pg.QueryResultRow>(text: string, params: unknown[] = []): Promise<R | null> { return (await query<R>(text, params)).rows[0] ?? null; }
export async function tx<T>(fn: (client: Client) => Promise<T>): Promise<T> {
  const client = await getPool().connect();
  try { await client.query('BEGIN'); const value = await fn(client); await client.query('COMMIT'); return value; }
  catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; }
  finally { client.release(); }
}
