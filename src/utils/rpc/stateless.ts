import * as crypto from "crypto";
import * as sshpk from "sshpk";
import * as nacl from "tweetnacl";
import type { RpcRequest } from "~viem/types/rpc.js";
// import { type GetLogsReturnType } from "~viem/actions/index.js";

/**
 * An attestation consists of the signature of the attester and cryptographic proof
 */
export type Attestation = {
    /**
     * The signature of the attester
     */
    signature: string;
    signatures: string[];
    
    /**
     * The signature format (i.e. "ssh-ed25519")
     */
    signatureFormat: string; 

    /**
     * The hashing algorithm used to hash the data (i.e. "sha256")
     */
    hashAlgo: string;

    /**
     * The hashed message data
     */
    msg: string;
    msgs: string[];

    /**
     * The identifier of the attester
     */
    identity: string;
};

/**
*  A JSON-RPC result, which are returned on success from a JSON-RPC server.
*/
export type AttestedJsonRpcResult =  {
     /**
     *  The response ID to match it to the relevant request.
     */
     id: number;

     /**
      *  The response result.
      */
     result: any;
    /**
     * Attestation data for the request.
     */
    attestations: Array<Attestation>;
};

export type LogsAndBlockRange = {
  Logs: any[];
  StartingBlock: string;
  EndingBlock: string;
};

export type LogsAndBlockRangeM = {
  logs: any[];
  startingBlock: string;
  endingBlock: string;
};

// function transformFirstToSecond(input: LogsAndBlockRange): LogsAndBlockRangeM {
//   const { Logs, StartingBlock, EndingBlock } = input;
//   return {
//     logs,
//     blockRange: {
//       start: startingBlock,
//       end: endingBlock
//     }
//   };
// }

function isLogsAndBlockRange(value: any): value is LogsAndBlockRange {
  return (
    value &&
    typeof value === 'object' &&
    Array.isArray(value.Logs) &&
    typeof value.StartingBlock === 'string' &&
    typeof value.EndingBlock === 'string'
  );
}

export async function handleAndBlockNumberReqs(resp: any): Promise<any> {
  if (!Array.isArray(resp)) {
    resp = await handleResp(resp)
  }

  for (let i = 0; i < resp.length; i++) {
    resp[i] = await handleResp(resp[i])
  }

  return resp
}

async function handleResp(response: AttestedJsonRpcResult): Promise<AttestedJsonRpcResult> {
  let change: boolean = false;
  let resultToChange: any;
  if (response.result instanceof Object) {
    if (Object.keys(response.result).length == 2) {
      for (const [key, value] of Object.entries(response.result)) {
        if (key == 'blockNumber') {
          change = true
        } else {
          resultToChange = value
        }
      }
    }
    if (Object.keys(response.result).length == 3) {
      for (const [key, value] of Object.entries(response.result)) {
        if (key == 'StartingBlock' || key == 'EndingBlock') {
          console.log('lo cambie pa atras')
          change = true
        } else {
          resultToChange = value
        }
      }
    }
  }

  if (change) {
    response.result = resultToChange
  }

  return response
}

export async function handleAttestations(resp: any, minimumRequiredAttestations: number = 1,
  identities?: string[]): Promise<void> {
    // If the response is not an array, convert it to an array
    if (!Array.isArray(resp)) {
        resp = [resp];
    }
 
    // Loop through each result in the response array
    for (let i = 0; i < resp.length; i++) {
        const result = resp[i];
 
        // Verify the attested JSON-RPC response
        const isValid = await verifyAttestedJsonRpcResponse(
            result,
            minimumRequiredAttestations,
            identities
        );
 
        // If the response does not meet the attestation threshold, throw an error
        if (!isValid) {
            throw new Error(`Request did not meet the attestation threshold of ${minimumRequiredAttestations}.`);
        }
        console.log('paso la verificacion')
    }
};

async function verifyAttestedJsonRpcResponse(
    response: AttestedJsonRpcResult,
    minimumRequiredAttestations: number = 1,
    identities?: string[]
  ): Promise<boolean> {
    console.log('ta verificando')
    let resultHashes: string[] = [];

    if (isLogsAndBlockRange(response.result)) {
      console.log('se fue por attestations de logs')
      // response.result = 
      for (const log of response.result.Logs) {
        const stringifiedResult = JSON.stringify(log);
        // console.log(stringifiedResult)
        const resultBytes = Buffer.from(stringifiedResult);
        const hash = crypto.createHash("sha256").update(resultBytes).digest("hex");
        resultHashes.push(hash);
      }
    } else {
      const resultBytes = Buffer.from(JSON.stringify(response.result));
      const hash = crypto.createHash("sha256").update(resultBytes).digest("hex");
      resultHashes = [hash];
    }

    const validAttestations: Attestation[] = [];
  
    for (let i = 0; i < response.attestations.length; i++) {
      const attestation = response.attestations[i];
      // There's a chance the attestation does not have an identity if it's a batch response
      // In that case, use the provided identities
      if (identities && !attestation.identity) {
        attestation.identity = identities[i];
      }

      // If identities are provided, only use attestations from those identities
      if (identities && !identities.includes(attestation.identity)) {
        continue;
      }

      const sshPublicKeyStr = await publicKeyFromIdentity(attestation.identity);
      const key = sshpk.parseKey(sshPublicKeyStr, "ssh");

      if (key.type !== "ed25519") {
        throw new Error("The provided key is not an ed25519 key");
      }
      // @ts-ignore
      const publicKeyUint8Array = new Uint8Array(key.part.A.data);

      if (!verifyAttestation(attestation, publicKeyUint8Array, resultHashes)) {
        continue;
      }

      validAttestations.push(attestation);
    }

    // Count the number of attestations for each message
    const msgCounts: { [key: string]: number } = {};
    for (const attestation of validAttestations) {
      msgCounts[attestation.msg] = (msgCounts[attestation.msg] || 0) + 1;
    }

    // Determine if consensus threshold is met
    return Object.values(msgCounts).some(
      (count) => count >= minimumRequiredAttestations
    );
}

async function publicKeyFromIdentity(identity: string): Promise<string> {
  const url = `${identity}/.well-known/stateless-key`;

  try {
      // Fetch data from the URL
      const response = await fetch(url);

      // Check if the response is successful (status code 2xx)
      if (!response.ok) {
          throw new Error(`Could not fetch public key from ${url}. Status code: ${response.status}`);
      }

      // Read and return the response body as text
      return await response.text();
  } catch (error) {
      // Handle any errors that occur during the fetch operation
      throw new Error(`Error fetching public key from ${url}: ${(error as Error).message}`);
  }
}

function verifyAttestation(
  attestation: Attestation,
  publicKey: Uint8Array,
  resultHashes: string[]
): boolean {
  // Calls like `eth_getLogs` return a list of message hashes and signatures,
  // so we need to make sure the logs returned in the response are backed by the minimum amount of required attestations
  if (attestation.msgs && attestation.msgs.length > 0 && attestation.signatures) {
    // attestation.msgs.pop();
    // attestation.signatures.pop();
    console.log(resultHashes)
    console.log(attestation.msgs)
    const isSubset = resultHashes.every(hash => attestation.msgs?.includes(hash));
    if (!isSubset) {
      console.log('no es subset')
      return false;
    }

    return attestation.msgs.every((msg, index) => {
      // console.log(index)
      if (!attestation.signatures) return false;
      return verifySignature(msg, attestation.signatures[index], publicKey, attestation.hashAlgo);
    });

  } else if (attestation.msg && attestation.signature) {
    const isHashInResult = resultHashes.includes(attestation.msg);
    return isHashInResult && verifySignature(attestation.msg, attestation.signature, publicKey, attestation.hashAlgo);
  }
  return false;
}

function verifySignature(msgHash: string, signature: string, publicKey: Uint8Array, hashAlgo: string): boolean {
  try {
    if (!publicKey) throw new Error("Public key is undefined.");
    if (!msgHash) throw new Error("Message hash is undefined.");
    if (!signature) throw new Error("Signature is undefined.");

    const signatureBytes = Buffer.from(signature, "hex");
    const signatureUint8Array = new Uint8Array(signatureBytes);
    const msgHashBytes = Buffer.from(msgHash, 'hex');

    return nacl.sign.detached.verify(msgHashBytes, signatureUint8Array, publicKey);
  } catch (error) {
    console.error("Verification failed:", error);
    return false;
  }
}

 