import {
  HttpRequestError,
  type HttpRequestErrorType as HttpRequestErrorType_,
  TimeoutError,
  type TimeoutErrorType,
} from '../../errors/request.js'
import type { ErrorType } from '../../errors/utils.js'
import type { RpcRequest, RpcResponse } from '../../types/rpc.js'
import {
  type WithTimeoutErrorType,
  withTimeout,
} from '../promise/withTimeout.js'
import { stringify } from '../stringify.js'
import { idCache } from './id.js'
import { handleAttestations, handleAndBlockNumberReqs } from './stateless.js'

export type HttpRpcClientOptions = {
  /** Request configuration to pass to `fetch`. */
  fetchOptions?: Omit<RequestInit, 'body'> | undefined
  /** A callback to handle the request. */
  onRequest?: ((request: Request) => Promise<void> | void) | undefined
  /** A callback to handle the response. */
  onResponse?: ((response: Response) => Promise<void> | void) | undefined
  /** The timeout (in ms) for the request. */
  timeout?: number | undefined
  /** stateless config */
  minimumRequiredAttestations?: number | undefined
	identities?: string[] | undefined
}

export type HttpRequestParameters<
  TBody extends RpcRequest | RpcRequest[] = RpcRequest,
> = {
  /** The RPC request body. */
  body: TBody
  /** Request configuration to pass to `fetch`. */
  fetchOptions?: HttpRpcClientOptions['fetchOptions'] | undefined
  /** A callback to handle the response. */
  onRequest?: ((request: Request) => Promise<void> | void) | undefined
  /** A callback to handle the response. */
  onResponse?: ((response: Response) => Promise<void> | void) | undefined
  /** The timeout (in ms) for the request. */
  timeout?: HttpRpcClientOptions['timeout'] | undefined
  /** stateless config */
  minimumRequiredAttestations?: number | undefined
	identities?: string[] | undefined
}

export type HttpRequestReturnType<
  TBody extends RpcRequest | RpcRequest[] = RpcRequest,
> = TBody extends RpcRequest[] ? RpcResponse[] : RpcResponse

export type HttpRequestErrorType =
  | HttpRequestErrorType_
  | TimeoutErrorType
  | WithTimeoutErrorType
  | ErrorType

export type HttpRpcClient = {
  request<TBody extends RpcRequest | RpcRequest[]>(
    params: HttpRequestParameters<TBody>,
  ): Promise<HttpRequestReturnType<TBody>>
}

export function getHttpRpcClient(
  url: string,
  options: HttpRpcClientOptions = {},
): HttpRpcClient {
  return {
    async request(params) {
      const {
        body,
        onRequest = options.onRequest,
        onResponse = options.onResponse,
        timeout = options.timeout ?? 10_000,
        minimumRequiredAttestations = options.minimumRequiredAttestations,
        identities = options.identities,
      } = params

      const fetchOptions = {
        ...(options.fetchOptions ?? {}),
        ...(params.fetchOptions ?? {}),
      }

      const { headers, method, signal: signal_ } = fetchOptions

      try {
        const response = await withTimeout(
          async ({ signal }) => {
            let result;

            if (Array.isArray(body)) {
              body.forEach((bodyItem) => {
                if (bodyItem.method === 'eth_getLogs') {
                  bodyItem.method = 'eth_getLogsAndBlockRange';
                }
              });

              result = stringify(
                body.map((bodyItem) => ({
                  jsonrpc: '2.0',
                  id: bodyItem.id ?? idCache.take(),
                  ...bodyItem,
                })),
              );
            } else {
              if (body.method === 'eth_getLogs') {
                console.log('lo cambie')
                body.method = 'eth_getLogsAndBlockRange';
              }

              result = stringify({
                jsonrpc: '2.0',
                id: body.id ?? idCache.take(),
                ...body,
              });
            }

            const init: RequestInit = {
              ...fetchOptions,
              body: result,
              headers: {
                ...headers,
                'Content-Type': 'application/json',
              },
              method: method || 'POST',
              signal: signal_ || (timeout > 0 ? signal : null),
            }
            const request = new Request(url, init)
            if (onRequest) await onRequest(request)
            const response = await fetch(url, init)
            return response
          },
          {
            errorInstance: new TimeoutError({ body, url }),
            timeout,
            signal: true,
          },
        )

        if (onResponse) await onResponse(response)

        let data: any
        if (
          response.headers.get('Content-Type')?.startsWith('application/json')
        )
          data = await response.json()
        else {
          data = await response.text()
          data = JSON.parse(data || '{}')
        }

        if (minimumRequiredAttestations != undefined) await handleAttestations(data, minimumRequiredAttestations, identities)
        
        data = await handleAndBlockNumberReqs(data)

        if (!response.ok) {
          throw new HttpRequestError({
            body,
            details: stringify(data.error) || response.statusText,
            headers: response.headers,
            status: response.status,
            url,
          })
        }

        return data
      } catch (err) {
        if (err instanceof HttpRequestError) throw err
        if (err instanceof TimeoutError) throw err
        throw new HttpRequestError({
          body,
          details: (err as Error).message,
          url,
        })
      }
    },
  }
}
