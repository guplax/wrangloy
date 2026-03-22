// Cloudflare Worker 反代Backblaze B2
//
// 环境变量配置（在Cloudflare Worker中设置）：
// B2_ENDPOINT=s3.us-west-004.backblazeb2.com  // 必需：B2 S3兼容端点
// BUCKET_NAME=my-bucket  // 必需：B2存储桶名称
// B2_APPLICATION_KEY_ID=xxx  // 必需：B2应用密钥ID
// B2_APPLICATION_KEY=xxx  // 必需：B2应用密钥
//
// 缓存控制（可选）：
// CACHE_ENABLED=true  // 是否启用缓存（默认true）
// CACHE_TTL=86400  // Worker缓存时间（秒，默认24小时）
// CDN_CACHE_TTL=2592000  // CDN边缘缓存时间（秒，默认30天）
//
// 安全控制（可选）：
// ALLOWED_REFERERS=https://yourdomain.com  // 允许的来源域名（防盗链）
//
// 其他配置（可选）：
// ALLOW_LIST_BUCKET=false  // 是否允许列出存储桶
// ALLOWED_HEADERS=content-type,range  // 自定义允许的请求头
var encoder = new TextEncoder();
var HOST_SERVICES = {
  appstream2: "appstream",
  cloudhsmv2: "cloudhsm",
  email: "ses",
  marketplace: "aws-marketplace",
  mobile: "AWSMobileHubService",
  pinpoint: "mobiletargeting",
  queue: "sqs",
  "git-codecommit": "codecommit",
  "mturk-requester-sandbox": "mturk-requester",
  "personalize-runtime": "personalize",
};
var UNSIGNABLE_HEADERS = /* @__PURE__ */ new Set([
  "authorization",
  "content-type",
  "content-length",
  "user-agent",
  "presigned-expires",
  "expect",
  "x-amzn-trace-id",
  "range",
  "connection",
]);
var AwsClient = class {
  constructor({ accesskeyID, secretAccessKey, sessionToken, service, region, cache, retries, initRetryMs }) {
    if (accesskeyID == null) throw new TypeError("accesskeyID is a required option");
    if (secretAccessKey == null) throw new TypeError("secretAccessKey is a required option");
    this.accesskeyID = accesskeyID;
    this.secretAccessKey = secretAccessKey;
    this.sessionToken = sessionToken;
    this.service = service;
    this.region = region;
    this.cache = cache || /* @__PURE__ */ new Map();
    this.retries = retries != null ? retries : 10;
    this.initRetryMs = initRetryMs || 50;
  }
  async sign(input, init) {
    if (input instanceof Request) {
      const { method, url, headers, body } = input;
      init = Object.assign({ method, url, headers }, init);
      if (init.body == null && headers.has("Content-Type")) {
        init.body = body != null && headers.has("X-Amz-Content-Sha256") ? body : await input.clone().arrayBuffer();
      }
      input = url;
    }
    const signer = new AwsV4Signer(Object.assign({ url: input }, init, this, init && init.aws));
    const signed = Object.assign({}, init, await signer.sign());
    delete signed.aws;
    try {
      return new Request(signed.url.toString(), signed);
    } catch (e) {
      if (e instanceof TypeError) {
        return new Request(signed.url.toString(), Object.assign({ duplex: "half" }, signed));
      }
      throw e;
    }
  }
  async fetch(input, init) {
    for (let i = 0; i <= this.retries; i++) {
      const fetched = fetch(await this.sign(input, init));
      if (i === this.retries) {
        return fetched;
      }
      const res = await fetched;
      if (res.status < 500 && res.status !== 429) {
        return res;
      }
      await new Promise((resolve) => setTimeout(resolve, Math.random() * this.initRetryMs * Math.pow(2, i)));
    }
    throw new Error("An unknown error occurred, ensure retries is not negative");
  }
};
var AwsV4Signer = class {
  constructor({
    method,
    url,
    headers,
    body,
    accesskeyID,
    secretAccessKey,
    sessionToken,
    service,
    region,
    cache,
    datetime,
    signQuery,
    appendSessionToken,
    allHeaders,
    singleEncode,
  }) {
    if (url == null) throw new TypeError("url is a required option");
    if (accesskeyID == null) throw new TypeError("accesskeyID is a required option");
    if (secretAccessKey == null) throw new TypeError("secretAccessKey is a required option");
    this.method = method || (body ? "POST" : "GET");
    this.url = new URL(url);
    this.headers = new Headers(headers || {});
    this.body = body;
    this.accesskeyID = accesskeyID;
    this.secretAccessKey = secretAccessKey;
    this.sessionToken = sessionToken;
    let guessedService, guessedRegion;
    if (!service || !region) {
      [guessedService, guessedRegion] = guessServiceRegion(this.url, this.headers);
    }
    this.service = service || guessedService || "";
    this.region = region || guessedRegion || "us-east-1";
    this.cache = cache || /* @__PURE__ */ new Map();
    this.datetime = datetime || /* @__PURE__ */ new Date().toISOString().replace(/[:-]|\.\d{3}/g, "");
    this.signQuery = signQuery;
    this.appendSessionToken = appendSessionToken || this.service === "iotdevicegateway";
    this.headers.delete("Host");
    if (this.service === "s3" && !this.signQuery && !this.headers.has("X-Amz-Content-Sha256")) {
      this.headers.set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD");
    }
    const params = this.signQuery ? this.url.searchParams : this.headers;
    params.set("X-Amz-Date", this.datetime);
    if (this.sessionToken && !this.appendSessionToken) {
      params.set("X-Amz-Security-Token", this.sessionToken);
    }
    this.signableHeaders = ["host", ...this.headers.keys()].filter((header) => allHeaders || !UNSIGNABLE_HEADERS.has(header)).sort();
    this.signedHeaders = this.signableHeaders.join(";");
    this.canonicalHeaders = this.signableHeaders
      .map((header) => header + ":" + (header === "host" ? this.url.host : (this.headers.get(header) || "").replace(/\s+/g, " ")))
      .join("\n");
    this.credentialString = [this.datetime.slice(0, 8), this.region, this.service, "aws4_request"].join("/");
    if (this.signQuery) {
      if (this.service === "s3" && !params.has("X-Amz-Expires")) {
        params.set("X-Amz-Expires", "86400");
      }
      params.set("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
      params.set("X-Amz-Credential", this.accesskeyID + "/" + this.credentialString);
      params.set("X-Amz-SignedHeaders", this.signedHeaders);
    }
    if (this.service === "s3") {
      try {
        this.encodedPath = decodeURIComponent(this.url.pathname.replace(/\+/g, " "));
      } catch (e) {
        this.encodedPath = this.url.pathname;
      }
    } else {
      this.encodedPath = this.url.pathname.replace(/\/+/g, "/");
    }
    if (!singleEncode) {
      this.encodedPath = encodeURIComponent(this.encodedPath).replace(/%2F/g, "/");
    }
    this.encodedPath = encodeRfc3986(this.encodedPath);
    const seenKeys = /* @__PURE__ */ new Set();
    this.encodedSearch = [...this.url.searchParams]
      .filter(([k]) => {
        if (!k) return false;
        if (this.service === "s3") {
          if (seenKeys.has(k)) return false;
          seenKeys.add(k);
        }
        return true;
      })
      .map((pair) => pair.map((p) => encodeRfc3986(encodeURIComponent(p))))
      .sort(([k1, v1], [k2, v2]) => (k1 < k2 ? -1 : k1 > k2 ? 1 : v1 < v2 ? -1 : v1 > v2 ? 1 : 0))
      .map((pair) => pair.join("="))
      .join("&");
  }
  async sign() {
    if (this.signQuery) {
      this.url.searchParams.set("X-Amz-Signature", await this.signature());
      if (this.sessionToken && this.appendSessionToken) {
        this.url.searchParams.set("X-Amz-Security-Token", this.sessionToken);
      }
    } else {
      this.headers.set("Authorization", await this.authHeader());
    }
    return {
      method: this.method,
      url: this.url,
      headers: this.headers,
      body: this.body,
    };
  }
  async authHeader() {
    return ["AWS4-HMAC-SHA256 Credential=" + this.accesskeyID + "/" + this.credentialString, "SignedHeaders=" + this.signedHeaders, "Signature=" + (await this.signature())].join(
      ", "
    );
  }
  async signature() {
    const date = this.datetime.slice(0, 8);
    const cacheKey = [this.secretAccessKey, date, this.region, this.service].join();
    let kCredentials = this.cache.get(cacheKey);
    if (!kCredentials) {
      const kDate = await hmac("AWS4" + this.secretAccessKey, date);
      const kRegion = await hmac(kDate, this.region);
      const kService = await hmac(kRegion, this.service);
      kCredentials = await hmac(kService, "aws4_request");
      this.cache.set(cacheKey, kCredentials);
    }
    return buf2hex(await hmac(kCredentials, await this.stringToSign()));
  }
  async stringToSign() {
    return ["AWS4-HMAC-SHA256", this.datetime, this.credentialString, buf2hex(await hash(await this.canonicalString()))].join("\n");
  }
  async canonicalString() {
    return [this.method.toUpperCase(), this.encodedPath, this.encodedSearch, this.canonicalHeaders + "\n", this.signedHeaders, await this.hexBodyHash()].join("\n");
  }
  async hexBodyHash() {
    let hashHeader = this.headers.get("X-Amz-Content-Sha256") || (this.service === "s3" && this.signQuery ? "UNSIGNED-PAYLOAD" : null);
    if (hashHeader == null) {
      if (this.body && typeof this.body !== "string" && !("byteLength" in this.body)) {
        throw new Error("body must be a string, ArrayBuffer or ArrayBufferView, unless you include the X-Amz-Content-Sha256 header");
      }
      hashHeader = buf2hex(await hash(this.body || ""));
    }
    return hashHeader;
  }
};
async function hmac(key, string) {
  const cryptoKey = await crypto.subtle.importKey("raw", typeof key === "string" ? encoder.encode(key) : key, { name: "HMAC", hash: { name: "SHA-256" } }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(string));
}
async function hash(content) {
  return crypto.subtle.digest("SHA-256", typeof content === "string" ? encoder.encode(content) : content);
}
function buf2hex(buffer) {
  return Array.prototype.map.call(new Uint8Array(buffer), (x) => ("0" + x.toString(16)).slice(-2)).join("");
}
function encodeRfc3986(urlEncodedStr) {
  return urlEncodedStr.replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}
function guessServiceRegion(url, headers) {
  const { hostname, pathname } = url;
  if (hostname.endsWith(".r2.cloudflarestorage.com")) {
    return ["s3", "auto"];
  }
  if (hostname.endsWith(".backblazeb2.com")) {
    const match2 = hostname.match(/^(?:[^.]+\.)?s3\.([^.]+)\.backblazeb2\.com$/);
    return match2 != null ? ["s3", match2[1]] : ["", ""];
  }
  const match = hostname.replace("dualstack.", "").match(/([^.]+)\.(?:([^.]*)\.)?amazonaws\.com(?:\.cn)?$/);
  let [service, region] = (match || ["", ""]).slice(1, 3);
  if (region === "us-gov") {
    region = "us-gov-west-1";
  } else if (region === "s3" || region === "s3-accelerate") {
    region = "us-east-1";
    service = "s3";
  } else if (service === "iot") {
    if (hostname.startsWith("iot.")) {
      service = "execute-api";
    } else if (hostname.startsWith("data.jobs.iot.")) {
      service = "iot-jobs-data";
    } else {
      service = pathname === "/mqtt" ? "iotdevicegateway" : "iotdata";
    }
  } else if (service === "autoscaling") {
    const targetPrefix = (headers.get("X-Amz-Target") || "").split(".")[0];
    if (targetPrefix === "AnyScaleFrontendService") {
      service = "application-autoscaling";
    } else if (targetPrefix === "AnyScaleScalingPlannerFrontendService") {
      service = "autoscaling-plans";
    }
  } else if (region == null && service.startsWith("s3-")) {
    region = service.slice(3).replace(/^fips-|^external-1/, "");
    service = "s3";
  } else if (service.endsWith("-fips")) {
    service = service.slice(0, -5);
  } else if (region && /-\d$/.test(service) && !/-\d$/.test(region)) {
    [service, region] = [region, service];
  }
  return [HOST_SERVICES[service] || service, region];
}

// index.js
var UNSIGNABLE_HEADERS2 = [
  // These headers appear in the request, but are not passed upstream
  "x-forwarded-proto",
  "x-real-ip",
  // We can't include accept-encoding in the signature because Cloudflare
  // sets the incoming accept-encoding header to "gzip, br", then modifies
  // the outgoing request to set accept-encoding to "gzip".
  // Not cool, Cloudflare!
  "accept-encoding",
];
var HTTPS_PROTOCOL = "https:";
var HTTPS_PORT = "443";
var RANGE_RETRY_ATTEMPTS = 3;

// CORS配置
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "Range, If-Modified-Since, If-None-Match, Content-Type, Authorization",
  "Access-Control-Expose-Headers": "Content-Length, Content-Range, Accept-Ranges, Last-Modified, ETag, X-Cache-Status",
  "Access-Control-Max-Age": "86400",
};

/**
 * 获取缓存设置
 * @param {Object} env - 环境变量
 * @returns {Object} 缓存设置
 */
function getCacheSettings(env) {
  // 从环境变量获取缓存时间，如果没有设置则使用默认值
  const cacheTtl = parseInt(env.CACHE_TTL) || 86400; // 默认24小时
  const cdnCacheTtl = parseInt(env.CDN_CACHE_TTL) || 2592000; // 默认30天

  return {
    ttl: cacheTtl,
    cdnTtl: cdnCacheTtl,
  };
}

/**
 * 判断是否应该缓存请求
 * @param {string} method - HTTP方法
 * @param {URL} url - 请求URL
 * @param {Headers} headers - 请求头
 * @param {Object} env - 环境变量
 * @returns {boolean} 是否应该缓存
 */
function shouldCache(method, url, headers, env) {
  // 检查是否启用缓存
  if (env.CACHE_ENABLED === "false") {
    return false;
  }

  // 只缓存GET和HEAD请求
  if (!["GET", "HEAD"].includes(method)) {
    return false;
  }

  // Range请求缓存策略：
  if (headers.has("Range")) {
    console.log(`Range请求，允许缓存以优化视频播放体验: ${url.pathname}`);
    // 允许缓存Range请求
  }

  return true;
}

/**
 * 生成统一的缓存键（基于文件路径，忽略查询参数）
 * @param {URL} url - 请求URL
 * @param {string} method - HTTP方法
 * @returns {Request} 缓存键
 */
function generateCacheKey(url, method) {
  // 使用文件路径作为缓存键，忽略查询参数
  const cacheUrl = new URL(url);
  cacheUrl.search = ""; // 清除所有查询参数

  return new Request(cacheUrl.toString(), {
    method: method,
    headers: new Headers(), // 空头部，确保缓存键一致
  });
}

/**
 * 检查是否为下载请求
 * @param {URL} url - 请求URL
 * @returns {boolean} 是否为下载请求
 */
function isDownloadRequest(url) {
  return url.searchParams.has("response-content-disposition") || url.searchParams.get("response-content-disposition")?.includes("attachment");
}

/**
 * 处理下载响应头部
 * @param {Response} response - 原始响应
 * @param {URL} originalUrl - 原始请求URL
 * @returns {Response} 处理后的响应
 */
function processDownloadResponse(response, originalUrl) {
  // 如果不是下载请求，直接返回
  if (!isDownloadRequest(originalUrl)) {
    return response;
  }

  // 检查是否已经有Content-Disposition头部
  if (response.headers.has("Content-Disposition")) {
    return response;
  }

  // 从URL参数中获取Content-Disposition
  const contentDisposition = originalUrl.searchParams.get("response-content-disposition");
  if (contentDisposition) {
    const newHeaders = new Headers(response.headers);
    newHeaders.set("Content-Disposition", decodeURIComponent(contentDisposition));

    // 检查其他response-*参数
    const responseContentType = originalUrl.searchParams.get("response-content-type");
    if (responseContentType && !response.headers.get("Content-Type")) {
      newHeaders.set("Content-Type", decodeURIComponent(responseContentType));
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    });
  }

  return response;
}

/**
 * 添加CORS头部到响应
 * @param {Response} response - 原始响应
 * @param {string} cacheStatus - 缓存状态
 * @returns {Response} 添加了CORS头部的响应
 */
function addCorsHeaders(response, cacheStatus = "MISS") {
  const newResponse = new Response(response.body, response);

  // 添加CORS头部
  Object.entries(CORS_HEADERS).forEach(([key, value]) => {
    newResponse.headers.set(key, value);
  });

  // 添加缓存状态头部
  newResponse.headers.set("X-Cache-Status", cacheStatus);
  newResponse.headers.set("X-Served-By", "Cloudflare-Worker-B2");

  return newResponse;
}

/**
 * 处理OPTIONS预检请求
 * @returns {Response} CORS预检响应
 */
function handleOptions() {
  return new Response(null, {
    status: 200,
    headers: CORS_HEADERS,
  });
}

/**
 * 处理缓存请求（优化版）
 * @param {Request} request - 请求对象
 * @param {URL} originalUrl - 原始URL
 * @param {Object} env - 环境变量
 * @param {Object} ctx - 执行上下文
 * @returns {Response} 响应
 */
async function handleCachedRequest(request, originalUrl, env, ctx) {
  const cache = caches.default;

  // 生成统一的缓存键（基于文件路径，忽略查询参数）
  const cacheKey = generateCacheKey(originalUrl, request.method);

  // 尝试从缓存获取
  let cachedResponse = await cache.match(cacheKey);

  if (cachedResponse) {
    console.log(`缓存命中: ${originalUrl.pathname}`);

    // 处理下载响应头部（如果是下载请求）
    const processedResponse = processDownloadResponse(cachedResponse, originalUrl);

    return addCorsHeaders(processedResponse, "HIT");
  }

  // 缓存未命中，处理请求到B2
  console.log(`缓存未命中，处理请求到B2: ${originalUrl.pathname}`);

  let response = await handleB2Request(request, originalUrl, env);

  // 检查是否应该缓存响应
  if (response.ok && shouldCache(request.method, originalUrl, request.headers, env)) {
    const cacheSettings = getCacheSettings(env);
    const cacheTtl = cacheSettings.ttl;
    const cdnCacheTtl = cacheSettings.cdnTtl;

    // 克隆响应用于缓存（移除下载相关头部，保存纯净内容）
    const headersToCache = new Headers(response.headers);
    headersToCache.delete("Content-Disposition"); // 移除下载头部，缓存纯净内容
    headersToCache.set("Cache-Control", `public, max-age=${cacheTtl}`);
    headersToCache.set("CDN-Cache-Control", `public, max-age=${cdnCacheTtl}`);
    headersToCache.set("X-Cache-Time", new Date().toISOString());

    const responseToCache = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: headersToCache,
    });

    // 异步存储到缓存
    ctx.waitUntil(cache.put(cacheKey, responseToCache.clone()));

    // 处理下载响应头部（如果是下载请求）
    const processedResponse = processDownloadResponse(responseToCache, originalUrl);

    return addCorsHeaders(processedResponse, "MISS");
  }

  // 处理下载响应头部（如果是下载请求）
  const processedResponse = processDownloadResponse(response, originalUrl);

  return addCorsHeaders(processedResponse, "BYPASS");
}

/**
 * 处理B2请求（原有逻辑封装）
 * @param {Request} request - 请求对象
 * @param {URL} originalUrl - 原始URL
 * @param {Object} env - 环境变量
 * @returns {Response} B2响应
 */
async function handleB2Request(request, originalUrl, env) {
  const url = new URL(originalUrl);
  url.protocol = HTTPS_PROTOCOL;
  url.port = HTTPS_PORT;
  let path = url.pathname.replace(/^\//, "");
  path = path.replace(/\/$/, "");
  const pathSegments = path.split("/");

  if (env.ALLOW_LIST_BUCKET !== "true") {
    if ((env.BUCKET_NAME === "$path" && pathSegments.length < 2) || (env.BUCKET_NAME !== "$path" && path.length === 0)) {
      return new Response(null, {
        status: 404,
        statusText: "Not Found",
      });
    }
  }

  switch (env.BUCKET_NAME) {
    case "$path":
      url.hostname = env.B2_ENDPOINT;
      break;
    case "$host":
      url.hostname = url.hostname.split(".")[0] + "." + env.B2_ENDPOINT;
      break;
    default:
      url.hostname = env.BUCKET_NAME + "." + env.B2_ENDPOINT;
      break;
  }

  const headers = filterHeaders(request.headers, env);

  // 区分预览和下载请求
  const hasSignature = url.searchParams.has("X-Amz-Signature");

  let forwardRequest;

  if (hasSignature) {
    // 有签名的请求（通常是下载）：直接转发预签名URL
    console.log(`转发预签名URL到B2: ${url.toString()}`);
    forwardRequest = new Request(url.toString(), {
      method: request.method,
      headers: headers,
      body: request.body,
    });
  } else {
    // 无签名的请求（通常是预览）：需要生成预签名URL
    console.log(`无签名请求，生成预签名URL: ${url.pathname}`);

    const endpointRegex = /^s3\.([a-zA-Z0-9-]+)\.backblazeb2\.com$/;
    const [, aws_region] = env.B2_ENDPOINT.match(endpointRegex);
    const client = new AwsClient({
      accesskeyID: env.B2_APPLICATION_KEY_ID,
      secretAccessKey: env.B2_APPLICATION_KEY,
      service: "s3",
      region: aws_region,
    });

    const signedRequest = await client.sign(url.toString(), {
      method: request.method,
      headers,
    });

    forwardRequest = new Request(signedRequest.url, {
      method: signedRequest.method,
      headers: signedRequest.headers,
      body: request.body,
    });
  }

  // 处理Range请求的特殊逻辑
  if (forwardRequest.headers.has("range")) {
    let attempts = RANGE_RETRY_ATTEMPTS;
    let response;
    do {
      let controller = new AbortController();
      response = await fetch(forwardRequest.url, {
        method: forwardRequest.method,
        headers: forwardRequest.headers,
        signal: controller.signal,
      });
      if (response.headers.has("content-range")) {
        if (attempts < RANGE_RETRY_ATTEMPTS) {
          console.log(`Retry for ${forwardRequest.url} succeeded - response has content-range header`);
        }
        break;
      } else if (response.ok) {
        attempts -= 1;
        console.error(`Range header in request for ${forwardRequest.url} but no content-range header in response. Will retry ${attempts} more times`);
        if (attempts > 0) {
          controller.abort();
        }
      } else {
        break;
      }
    } while (attempts > 0);
    if (attempts <= 0) {
      console.error(`Tried range request for ${forwardRequest.url} ${RANGE_RETRY_ATTEMPTS} times, but no content-range in response.`);
    }
    return processResponse(response, originalUrl);
  }

  // 普通请求
  const response = await fetch(forwardRequest);
  return processResponse(response, originalUrl);
}
function filterHeaders(headers, env) {
  return new Headers(
    Array.from(headers.entries()).filter(
      (pair) => !UNSIGNABLE_HEADERS2.includes(pair[0]) && !pair[0].startsWith("cf-") && !("ALLOWED_HEADERS" in env && !env.ALLOWED_HEADERS.includes(pair[0]))
    )
  );
}

/**
 * 处理响应，检查B2是否正确处理了response参数
 * @param {Response} response - 原始响应
 * @param {URL} originalUrl - 原始请求URL
 * @returns {Response} 处理后的响应
 */
function processResponse(response, originalUrl) {
  // 如果响应不成功，直接返回
  if (!response.ok) {
    return response;
  }

  // 检查B2是否正确处理了response-content-disposition参数
  const responseContentDisposition = originalUrl.searchParams.get("response-content-disposition");

  if (responseContentDisposition) {
    const actualContentDisposition = response.headers.get("Content-Disposition");
    if (actualContentDisposition) {
      console.log(`B2正确处理了Content-Disposition: ${actualContentDisposition}`);
      return response;
    } else {
      console.log(`B2未设置Content-Disposition，Worker手动设置: ${responseContentDisposition}`);
      const responseHeaders = new Headers(response.headers);
      responseHeaders.set("Content-Disposition", decodeURIComponent(responseContentDisposition));

      // 检查其他response-*参数
      const responseContentType = originalUrl.searchParams.get("response-content-type");
      if (responseContentType && !response.headers.get("Content-Type")) {
        responseHeaders.set("Content-Type", decodeURIComponent(responseContentType));
      }

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    }
  }

  // 没有response参数，直接返回原始响应
  return response;
}
var my_proxy_default = {
  async fetch(request, env, ctx) {
    // 处理OPTIONS预检请求
    if (request.method === "OPTIONS") {
      return handleOptions();
    }

    // 只允许GET和HEAD请求
    if (!["GET", "HEAD"].includes(request.method)) {
      return new Response(
        JSON.stringify({
          error: "方法不允许",
          message: "只支持GET和HEAD请求",
        }),
        {
          status: 405,
          headers: {
            "Content-Type": "application/json",
            ...CORS_HEADERS,
          },
        }
      );
    }

    try {
      const originalUrl = new URL(request.url);

      // 检查是否应该使用缓存
      if (shouldCache(request.method, originalUrl, request.headers, env)) {
        return await handleCachedRequest(request, originalUrl, env, ctx);
      } else {
        // 不缓存，直接处理
        console.log(`直接转发（不缓存）: ${originalUrl.pathname}`);
        const response = await handleB2Request(request, originalUrl, env);

        // 处理下载响应头部（如果是下载请求）
        const processedResponse = processDownloadResponse(response, originalUrl);

        return addCorsHeaders(processedResponse, "BYPASS");
      }
    } catch (error) {
      console.error("Worker处理错误:", error);
      return new Response(
        JSON.stringify({
          error: "内部服务器错误",
          message: error.message,
        }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json",
            ...CORS_HEADERS,
          },
        }
      );
    }
  },
};
export { my_proxy_default as default };
