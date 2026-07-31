import 'dotenv/config';

import express from 'express';
import https from 'node:https';
import { Buffer } from 'node:buffer';
import { constants } from 'node:crypto';

import cors from 'cors';
import compression from 'compression';
import helmet from 'helmet';
import morgan from 'morgan';

const app = express();

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const AUTH_KEY = process.env.AUTH_KEY || 'uma-chave-secreta-bem-longa';
const SEFAZ_TIMEOUT_MS = Number(process.env.SEFAZ_TIMEOUT_MS || 30000);

app.disable('x-powered-by');

app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(morgan('combined'));

app.get('/health', (req, res) => {
  return res.status(200).json({
    status: 'ok',
    message: 'Bridge SEFAZ operacional',
    timestamp: new Date().toISOString()
  });
});

app.post('/consultar-sefaz-direto', async (req, res) => {
  let responseSent = false;

  const sendResponse = (statusCode, payload) => {
    if (responseSent || res.headersSent) {
      return;
    }

    responseSent = true;
    return res.status(statusCode).json(payload);
  };

  try {
    const receivedApiKey = req.headers['x-api-key'];

    if (!receivedApiKey || receivedApiKey !== AUTH_KEY) {
      console.warn('[Bridge] Tentativa de acesso com chave inválida');

      return sendResponse(403, {
        success: false,
        error: 'Acesso negado: chave de API inválida'
      });
    }

    const {
      pfxBase64,
      password,
      endpoint,
      soapAction,
      soapEnvelope
    } = req.body;

    if (!pfxBase64 || !password || !endpoint || !soapEnvelope) {
      return sendResponse(400, {
        success: false,
        error: 'Dados incompletos: pfxBase64, password, endpoint e soapEnvelope são obrigatórios'
      });
    }

    let url;

    try {
      url = new URL(endpoint);
    } catch {
      return sendResponse(400, {
        success: false,
        error: 'Endpoint inválido'
      });
    }

    if (url.protocol !== 'https:') {
      return sendResponse(400, {
        success: false,
        error: 'O endpoint da SEFAZ deve utilizar HTTPS'
      });
    }

    const pfxBuffer = Buffer.from(pfxBase64, 'base64');

    if (!pfxBuffer.length) {
      return sendResponse(400, {
        success: false,
        error: 'Certificado digital inválido ou vazio'
      });
    }

    const requestPath = `${url.pathname}${url.search}`;

    const options = {
      hostname: url.hostname,
      port: url.port || 443,
      path: requestPath,
      method: 'POST',

      pfx: pfxBuffer,
      passphrase: password,

      headers: {
        'Content-Type': 'application/soap+xml; charset=utf-8',
        'SOAPAction': soapAction || '',
        'Content-Length': Buffer.byteLength(soapEnvelope)
      },

      /*
       * Mantido compatível com o comportamento atual.
       *
       * Em produção, o ideal é utilizar:
       * rejectUnauthorized: true
       *
       * depois de validar corretamente a cadeia de certificados da SEFAZ.
       */
      rejectUnauthorized: process.env.SEFAZ_REJECT_UNAUTHORIZED === 'true',

      secureOptions:
        constants.SSL_OP_NO_TLSv1 |
        constants.SSL_OP_NO_TLSv1_1,

      ciphers: 'DEFAULT:!DH'
    };

    console.log(`[Bridge] Iniciando requisição mTLS para: ${endpoint}`);

    const sefazRequest = https.request(options, (sefazResponse) => {
      let responseBody = '';

      console.log(`[Bridge] Status SEFAZ: ${sefazResponse.statusCode}`);

      sefazResponse.setEncoding('utf8');

      sefazResponse.on('data', (chunk) => {
        responseBody += chunk;
      });

      sefazResponse.on('end', () => {
        console.log(
          `[Bridge] Resposta concluída. Tamanho: ${Buffer.byteLength(responseBody)} bytes`
        );

        return sendResponse(sefazResponse.statusCode || 502, {
          success: sefazResponse.statusCode === 200,
          xmlResponse: responseBody,
          statusCode: sefazResponse.statusCode
        });
      });

      sefazResponse.on('error', (error) => {
        console.error('[Bridge] Erro ao ler resposta da SEFAZ:', error);

        return sendResponse(502, {
          success: false,
          error: 'Erro ao ler resposta da SEFAZ'
        });
      });
    });

    sefazRequest.on('error', (error) => {
      console.error('[Bridge] Erro na conexão HTTPS:', error.message);

      return sendResponse(502, {
        success: false,
        error: `Erro na conexão com SEFAZ: ${error.message}`
      });
    });

    sefazRequest.setTimeout(SEFAZ_TIMEOUT_MS, () => {
      console.error('[Bridge] Timeout na requisição SEFAZ');

      sefazRequest.destroy();

      return sendResponse(504, {
        success: false,
        error: 'Timeout na comunicação com a SEFAZ'
      });
    });

    sefazRequest.write(soapEnvelope);
    sefazRequest.end();
  } catch (error) {
    console.error('[Bridge] Erro inesperado:', error);

    return sendResponse(500, {
      success: false,
      error: `Erro interno no bridge: ${error.message}`
    });
  }
});

app.use((req, res) => {
  return res.status(404).json({
    success: false,
    error: 'Rota não encontrada'
  });
});

app.use((error, req, res, next) => {
  console.error('[Bridge] Erro crítico:', error);

  if (res.headersSent) {
    return next(error);
  }

  return res.status(500).json({
    success: false,
    error: 'Erro interno crítico'
  });
});

app.listen(PORT, HOST, () => {
  console.log(`[Bridge] Servidor rodando em http://${HOST}:${PORT}`);
  console.log('[Bridge] Endpoint legado disponível em POST /consultar-sefaz-direto');
});
