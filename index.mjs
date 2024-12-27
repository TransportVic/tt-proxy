import http from 'http'
import https from 'https'
import tls from 'tls'
import fs from 'fs/promises'
import { createReadStream } from 'fs'
import path from 'path'
import config from './config.json' with { type: 'json' }

let secureContexts = {}
let server = {
  "host": config.host,
  "useHTTPS": true,
  "dropHeaders": [ "host" ],
  "destination": "ws2.tramtracker.com.au",
  "port": 443,
  "sslCertPath": config.sslCertPath
}

async function createSecureContext(certInfo) {
  try {
    let certPath = certInfo.sslCertPath
    let certHost = certInfo.host

    let sslCertPath = path.join(certPath, 'fullchain.pem')
    let sslKeyPath = path.join(certPath, 'privkey.pem')
    let caPath = path.join(certPath, 'chain.pem')

    let context = tls.createSecureContext({
      cert: await fs.readFile(sslCertPath),
      key: await fs.readFile(sslKeyPath),
      ca: await fs.readFile(caPath),
      minVersion: 'TLSv1.2'
    })

    secureContexts[certHost] = context
  } catch (e) {
    console.log('Registration for', certInfo.host, 'failed');
    console.log(e);
    certInfo.failed = true
  }
}

function getSecureContext(hostname) {
  return secureContexts[hostname]
}

function createSNICallback() {
  return (hostname, callback) => {
    callback(null, getSecureContext(hostname))
  }
}

function determineDestinationServer(req) {
  return server
}

function handleRequest(req, res) {
  if (req.ended) return

  let destinationServer = determineDestinationServer(req)

  if (destinationServer) {
    let headers = {}

    let excludedHeaders = destinationServer.dropHeaders || []
    for (let headerName of Object.keys(req.headers)) {
      if (!excludedHeaders.includes(headerName)) headers[headerName] = req.headers[headerName]
    }

    let proxyRequest = (destinationServer.useHTTPS ? https : http).request({
      host: destinationServer.destination,
      port: destinationServer.port,
      path: req.url,
      method: req.method,
      headers,
      timeout: 30 * 1000
    }, proxyResponse => {
      res.writeHead(proxyResponse.statusCode, proxyResponse.headers)
      proxyResponse.pipe(res)
    })

    proxyRequest.on('error', error => {
      res.writeHead(503)
      res.end('Error: Could not proxy request to server')
    })

    req.pipe(proxyRequest)
  }
}

let httpServer = http.createServer()
let httpsServer = config.httpsPort ? https.createServer({
  SNICallback: createSNICallback()
}) : null

function handleWebroot(req, res) {
  if (req.url.match(/\/.well-known\/acme-challenge\/[^\/]*/)) {
    let filePath = path.join(config.webrootPath, req.url)

    let stream = createReadStream(filePath)

    stream.on('open', () => {
      res.writeHead(200)
      stream.pipe(res)
    })
    
    stream.on('error', err => {
      res.writeHead(404).end('404')
    })
    
    return req.ended = true
  }
}

httpServer.on('request', handleWebroot)

if (httpsServer) {
  httpServer.on('request', (req, res) => {
    if (req.ended) return

    let redirectedURL = 'https://' + req.headers.host + req.url

    res.writeHead(308, { Location: redirectedURL })
    res.end()
  })

  await createSecureContext(server)

  httpServer.listen(config.httpPort)

  httpsServer.on('request', handleWebroot)
  httpsServer.on('request', handleRequest)
  httpsServer.listen(config.httpsPort)
} else {
  httpServer.on('request', handleRequest)
  httpServer.listen(config.httpPort)
}
