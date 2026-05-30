import express from 'express';
import https from 'node:https';
import { Buffer } from 'node:buffer';
import { constants } from 'node:crypto';
import cors from 'cors';

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Chave de segurança para evitar acesso não autorizado
const AUTH_KEY = process.env.AUTH_KEY || "uma-chave-secreta-bem-longa";

// Middleware de logs
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// Endpoint de verificação de integridade
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: 'Bridge SEFAZ operacional',
    timestamp: new Date().toISOString() 
  });
});

/**
 * Endpoint principal para consulta direta à SEFAZ via mTLS
 */
app.post('/consultar-sefaz-direto', async (req, res) => {
  try {
    // Validação da chave de API
    if (req.headers['x-api-key'] !== AUTH_KEY) {
      console.warn('[Bridge] Tentativa de acesso com chave inválida');
      return res.status(403).json({ success: false, error: "Acesso negado: Chave de API inválida" });
    }

    const { pfxBase64, password, endpoint, soapAction, soapEnvelope } = req.body;

    if (!pfxBase64 || !password || !endpoint || !soapEnvelope) {
      return res.status(400).json({ success: false, error: "Dados incompletos: pfxBase64, password, endpoint e soapEnvelope são obrigatórios" });
    }

    const pfxBuffer = Buffer.from(pfxBase64, 'base64');
    const url = new URL(endpoint);

    const options = {
      hostname: url.hostname,
      port: 443,
      path: url.pathname + url.search,
      method: 'POST',
      pfx: pfxBuffer,
      passphrase: password,
      headers: {
        'Content-Type': 'application/soap+xml; charset=utf-8',
        'SOAPAction': soapAction || '',
        'Content-Length': Buffer.byteLength(soapEnvelope)
      },
      // Configurações para mTLS SEFAZ
      rejectUnauthorized: false,
      secureOptions: constants.SSL_OP_NO_TLSv1 | constants.SSL_OP_NO_TLSv1_1, // Forçar TLS 1.2+
      ciphers: 'DEFAULT:!DH'
    };

    console.log(`[Bridge] Iniciando requisição mTLS para: ${endpoint}`);
    
    const sefazReq = https.request(options, (sefazRes) => {
      let body = '';
      console.log(`[Bridge] Status SEFAZ: ${sefazRes.statusCode}`);
      
      sefazRes.on('data', (chunk) => body += chunk);
      sefazRes.on('end', () => {
        console.log(`[Bridge] Resposta concluída. Tamanho: ${body.length} bytes`);
        res.status(sefazRes.statusCode).json({ 
          success: sefazRes.statusCode === 200,
          xmlResponse: body,
          statusCode: sefazRes.statusCode
        });
      });
    });

    sefazReq.on('error', (e) => {
      console.error('[Bridge] Erro na conexão HTTPS:', e.message);
      res.status(500).json({ success: false, error: "Erro na conexão com SEFAZ: " + e.message });
    });

    // Definir timeout para a requisição
    sefazReq.setTimeout(30000, () => {
      console.error('[Bridge] Timeout na requisição SEFAZ');
      sefazReq.destroy();
      res.status(504).json({ success: false, error: "Timeout na comunicação com a SEFAZ" });
    });

    sefazReq.write(soapEnvelope);
    sefazReq.end();

  } catch (err) {
    console.error('[Bridge] Erro inesperado:', err);
    res.status(500).json({ success: false, error: "Erro interno no bridge: " + err.message });
  }
});

// Middleware para capturar erros 404
app.use((req, res) => {
  res.status(404).json({ success: false, error: "Rota não encontrada" });
});

// Middleware de erro global
app.use((err, req, res, next) => {
  console.error('[Bridge] Erro Crítico:', err);
  res.status(500).json({ success: false, error: "Erro interno crítico: " + err.message });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[Bridge] Servidor rodando em http://0.0.0.0:${PORT}`);
  console.log(`[Bridge] Pronto para processar requisições mTLS`);
});
