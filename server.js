import 'dotenv/config';
import express from 'express';
import https from 'node:https';
import { Buffer } from 'node:buffer';
import { constants } from 'node:crypto';
import cors from 'cors';

const app = express();

const PORT = process.env.PORT || 3000;
const AUTH_KEY = process.env.AUTH_KEY || 'uma-chave-secreta-bem-longa';

app.use(cors());

app.use(
  express.json({
    limit: '10mb'
  })
);

app.use((req, res, next) => {
  console.log(
    `[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`
  );

  next();
});

app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    message: 'Bridge SEFAZ operacional',
    timestamp: new Date().toISOString()
  });
});

app.post('/consultar-sefaz-direto', async (req, res) => {
  try {
    const apiKey = req.headers['x-api-key'];

    if (!apiKey || apiKey !== AUTH_KEY) {
      console.warn('[Bridge] Tentativa de acesso com chave inválida');

      return res.status(403).json({
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
      return res.status(400).json({
        success: false,
        error:
          'Dados incompletos: pfxBase64, password, endpoint e soapEnvelope são obrigatórios'
      });
    }

    let url;

    try {
      url = new URL(endpoint);
    } catch {
      return res.status(400).json({
        success: false,
        error: 'Endpoint inválido'
      });
    }

    const pfxBuffer = Buffer.from(pfxBase64, 'base64');

    const requestOptions = {
      hostname: url.hostname,
      port: url.port || 443,
      path: `${url.pathname}${url.search}`,
      method: 'POST',
      pfx: pfxBuffer,
      passphrase: password,
      rejectUnauthorized: false,
      secureOptions:
        constants.SSL_OP_NO_TLSv1 | constants.SSL_OP_NO_TLSv1_1,
      ciphers: 'DEFAULT:!DH',
      headers: {
        'Content-Type': 'application/soap+xml; charset=utf-8',
        SOAPAction: soapAction || '',
        Accept: 'application/soap+xml, text/xml, */*',
        'Content-Length': Buffer.byteLength(soapEnvelope)
      }
    };

    console.log(`[Bridge] Iniciando requisição mTLS para: ${endpoint}`);

    const sefazRequest = https.request(
      requestOptions,
      (sefazResponse) => {
        let responseBody = '';

        console.log(
          `[Bridge] Status SEFAZ: ${sefazResponse.statusCode}`
        );

        sefazResponse.setEncoding('utf8');

        sefazResponse.on('data', (chunk) => {
          responseBody += chunk;
        });

        sefazResponse.on('end', () => {
          console.log(
            `[Bridge] Resposta concluída. Tamanho: ${responseBody.length} caracteres`
          );

          if (res.headersSent) {
            return;
          }

          return res.status(sefazResponse.statusCode || 500).json({
            success: sefazResponse.statusCode === 200,
            xmlResponse: responseBody,
            statusCode: sefazResponse.statusCode
          });
        });
      }
    );

    sefazRequest.setTimeout(30000, () => {
      console.error('[Bridge] Timeout na requisição SEFAZ');

      sefazRequest.destroy();

      if (!res.headersSent) {
        res.status(504).json({
          success: false,
          error: 'Timeout na comunicação com a SEFAZ'
        });
      }
    });

    sefazRequest.on('error', (error) => {
      console.error(
        '[Bridge] Erro na conexão HTTPS:',
        error.message
      );

      if (!res.headersSent) {
        res.status(502).json({
          success: false,
          error: `Erro na conexão com a SEFAZ: ${error.message}`
        });
      }
    });

    sefazRequest.write(soapEnvelope);
    sefazRequest.end();
  } catch (error) {
    console.error('[Bridge] Erro inesperado:', error);

    if (!res.headersSent) {
      res.status(500).json({
        success: false,
        error: `Erro interno no bridge: ${error.message}`
      });
    }
  }
});

app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Rota não encontrada'
  });
});

app.use((error, req, res, next) => {
  console.error('[Bridge] Erro crítico:', error);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    success: false,
    error: 'Erro interno crítico'
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[Bridge] Servidor rodando na porta ${PORT}`);
  console.log('[Bridge] Endpoint de saúde: /health');
});
