import 'dotenv/config';

import express from 'express';
import https from 'node:https';
import { Buffer } from 'node:buffer';
import { constants } from 'node:crypto';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';

const app = express();

const PORT = Number(process.env.PORT || 3000);
const AUTH_KEY = process.env.AUTH_KEY;

if (!AUTH_KEY) {
  console.warn(
    '[Bridge] ATENÇÃO: a variável AUTH_KEY não foi configurada.'
  );
}

app.disable('x-powered-by');

app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(morgan('combined'));

app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    message: 'Bridge SEFAZ operacional',
    timestamp: new Date().toISOString()
  });
});

app.post('/consultar-sefaz-direto', async (req, res) => {
  let respostaEnviada = false;

  try {
    const chaveRecebida = req.headers['x-api-key'];

    if (!AUTH_KEY || chaveRecebida !== AUTH_KEY) {
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

    if (url.protocol !== 'https:') {
      return res.status(400).json({
        success: false,
        error: 'O endpoint deve utilizar HTTPS'
      });
    }

    const pfxBuffer = Buffer.from(pfxBase64, 'base64');

    if (!pfxBuffer.length) {
      return res.status(400).json({
        success: false,
        error: 'Certificado PFX inválido ou vazio'
      });
    }

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
        'Content-Length': Buffer.byteLength(soapEnvelope, 'utf8')
      }
    };

    console.log(`[Bridge] Iniciando requisição para: ${url.hostname}`);

    const sefazRequest = https.request(
      requestOptions,
      (sefazResponse) => {
        let responseBody = '';

        console.log(
          `[Bridge] Status recebido da SEFAZ: ${sefazResponse.statusCode}`
        );

        sefazResponse.setEncoding('utf8');

        sefazResponse.on('data', (chunk) => {
          responseBody += chunk;
        });

        sefazResponse.on('end', () => {
          if (res.headersSent) {
            return;
          }

          respostaEnviada = true;

          console.log(
            `[Bridge] Resposta concluída. Tamanho: ${Buffer.byteLength(
              responseBody,
              'utf8'
            )} bytes`
          );

          res.status(sefazResponse.statusCode || 502).json({
            success: sefazResponse.statusCode === 200,
            xmlResponse: responseBody,
            statusCode: sefazResponse.statusCode
          });
        });
      }
    );

    sefazRequest.setTimeout(30000, () => {
      console.error('[Bridge] Timeout na comunicação com a SEFAZ');
      sefazRequest.destroy(new Error('Timeout na comunicação com a SEFAZ'));

      if (!res.headersSent) {
        respostaEnviada = true;

        res.status(504).json({
          success: false,
          error: 'Timeout na comunicação com a SEFAZ'
        });
      }
    });

    sefazRequest.on('error', (error) => {
      console.error('[Bridge] Erro na conexão HTTPS:', error.message);

      if (!res.headersSent && !respostaEnviada) {
        respostaEnviada = true;

        res.status(502).json({
          success: false,
          error: `Erro na conexão com a SEFAZ: ${error.message}`
        });
      }
    });

    sefazRequest.write(soapEnvelope, 'utf8');
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
  console.error('[Bridge] Erro global:', error);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    success: false,
    error: 'Erro interno do servidor'
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[Bridge] Servidor rodando na porta ${PORT}`);
  console.log('[Bridge] Endpoint de saúde: /health');
  console.log('[Bridge] Bridge SEFAZ pronta');
});
