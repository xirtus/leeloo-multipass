import { readdir, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tx, closePool } from './db.ts';
export async function migrate(): Promise<string[]> {
  const root = new URL('../../migrations/', import.meta.url);
  const files = (await readdir(root)).filter(file => /^\d+.*\.sql$/.test(file)).sort();
  return tx(async client => {
    await client.query('SELECT pg_advisory_xact_lock(1084165623)');
    await client.query('CREATE TABLE IF NOT EXISTS multipass_schema_migrations(name text PRIMARY KEY,checksum text NOT NULL,applied_at timestamptz NOT NULL DEFAULT now())');
    const applied: string[] = [];
    for (const file of files) {
      const sql = await readFile(new URL(file, root), 'utf8');
      const checksum = createHash('sha256').update(sql).digest('hex');
      const prior = (await client.query<{ checksum: string }>('SELECT checksum FROM multipass_schema_migrations WHERE name=$1', [file])).rows[0];
      if (prior) { if (prior.checksum !== checksum) throw Error(`Applied migration ${file} changed; add a new migration.`); continue; }
      await client.query(sql); await client.query('INSERT INTO multipass_schema_migrations(name,checksum) VALUES($1,$2)', [file, checksum]); applied.push(file);
    }
    return applied;
  });
}
if (/\/migrate\.(ts|js)$/.test(process.argv[1] ?? '')) {
  try { console.log(JSON.stringify({ applied: await migrate() })); } finally { await closePool(); }
}
