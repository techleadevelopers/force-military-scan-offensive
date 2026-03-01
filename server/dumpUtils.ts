import * as fs from 'fs';
import * as path from 'path';
import { DUMPS_DIR } from './admin';

export function writeDumpFile(filename: string, content: string): number {
  const filePath = path.join(DUMPS_DIR, filename);
  fs.writeFileSync(filePath, content, "utf-8");
  return Buffer.byteLength(content, "utf-8");
}

export function generateDumpId(): string {
  return `dump-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
}

export function extractRawSecrets(text: string): string[] {
  // Mover de admin.ts para cá
}