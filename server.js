import 'dotenv/config';
import express from 'express';
import tls from 'node:tls';
import https from 'node:https';
import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';

const app = express();
const PORT = Number(process.env.PORT || 3000);

// ================================
// CONFIGURAÇÃO DE CHAVES E LOG INICIAL
// ================================
const AUTH_KEY = process.env.AUTH_KEY;
const XML_KEY = process.env.XML_KEY;

console.log("====================================");
console.log("BRIDGE SEFAZ INICIANDO");
console.log("AUTH_KEY carregada:", !!AUTH_KEY);
console.log("XML_KEY carregada:", !!XML_KEY);
console.log("NODE_ENV:", process.env.NODE_ENV || "development");
console.log("====================================");

// ================================
// MIDDLEWARES GERAIS
// ================================
app.disable('x-powered-by');
app.use(helmet());
app.use(cors({ origin: "*" }));
app.use(compression());
app.use(express.json({ limit: "20mb" }));
app.use(morgan("combined"));

// ================================
// RATE LIMIT
// ================================
const limiter = rateLimit({
    windowMs: 60 * 1000, // 1 minuto
    max: 120, // 120 requests
    message: {
        success: false,
        error: "Muitas requisições"
    }
});

app.use("/api", limiter);
app.use("/backend", limiter);
app.use("/rpa", limiter);

// ================================
// UTILS
// ================================
function sanitizarBase64(b64) {
    if (typeof b64 !== 'string') return '';
    // Remove prefixo Data URI se presente e limpa espaços/quebras de linha
    return b64.replace(/^data:.*;base64,/, '').replace(/\s+/g, '');
}

// ================================
// ENDPOINTS DE MONITORAMENTO
// ================================
app.get("/health", (req, res) => {
    res.json({
        status: "online",
        service: "Bridge SEFAZ",
        node: process.version,
        timestamp: new Date()
    });
});

app.get("/api/info", (req, res) => {
    res.json({
        success: true,
        service: "Bridge SEFAZ",
        version: "1.0.0",
        node: process.version,
        uptime: process.uptime(),
        authKeyConfigured: !!AUTH_KEY,
        xmlKeyConfigured: !!XML_KEY,
        timestamp: new Date().toISOString()
    });
});

app.get("/version", (req, res) => {
    res.json({
        service: "Bridge SEFAZ",
        version: "1.0.0",
        node: process.version,
        uptime: process.uptime()
    });
});

// ================================
// VALIDAÇÃO API KEY E XML KEY
// ================================
function validarAPI(req, res, next) {
    const apiKey = req.headers["x-api-key"];
    const xmlKey = req.headers["x-xml-key"];

    if (!AUTH_KEY) {
        console.error("AUTH_KEY não configurada no servidor.");
        return res.status(500).json({ success: false, error: "AUTH_KEY não configurada no servidor" });
    }
    if (apiKey !== AUTH_KEY) {
        return res.status(403).json({ success: false, error: "API Key inválida" });
    }
    if (XML_KEY && xmlKey !== XML_KEY) {
        return res.status(403).json({ success: false, error: "XML Key inválida" });
    }

    next();
}

// ================================
// TESTE DE AUTENTICAÇÃO E CERTIFICADO
// ================================
app.get("/api/test-auth", validarAPI, (req, res) => {
    res.json({
        success: true,
        message: "Autenticação OK",
        node: process.version,
        timestamp: new Date().toISOString()
    });
});

app.post("/api/sefaz/test-cert", validarAPI, async (req, res) => {
    try {
        const { pfxBase64, password } = req.body;

        if (!pfxBase64 || !password) {
            return res.status(400).json({ success: false, error: "PFX ou senha não informados." });
        }

        const b64Limpo = sanitizarBase64(pfxBase64);
        const certificado = Buffer.from(b64Limpo, "base64");
        
        tls.createSecureContext({
            pfx: certificado,
            passphrase: password
        });

        return res.json({ success: true, message: "Certificado carregado e senha validada com sucesso." });
    } catch (error) {
        // AJUSTE: Exibindo o erro real do OpenSSL
        console.error("Falha ao abrir PFX no test-cert:", error.message);
        return res.status(400).json({ success: false, error: "Certificado ou senha inválidos: " + error.message });
    }
});

// ================================
// HANDLER GENÉRICO: CONSULTA SEFAZ MTLS
// ================================
const consultarSefaz = async (req, res, dadosCustom = null) => {
    let finalizado = false;
    const requestId = crypto.randomUUID();

    console.log(`\n[${requestId}] ========== NOVA CONSULTA INICIADA ==========`);

    try {
        const payload = dadosCustom || req.body;
        const {
            pfxBase64,
            password,
            endpoint,
            soapAction,
            soapEnvelope,
            empresaId
        } = payload;

        if (!pfxBase64 || !password || !endpoint || !soapEnvelope) {
            return res.status(400).json({ success: false, requestId, error: "Campos obrigatórios ausentes" });
        }

        const url = new URL(endpoint);

        if (url.protocol !== "https:") {
            return res.status(400).json({ success: false, requestId, error: "Somente HTTPS permitido" });
        }

        const host = url.hostname.toLowerCase();
        const dominiosPermitidos = ["sefaz", "nfe", "fazenda", "svrs", "svc", "gov.br"];
        const permitido = dominiosPermitidos.some(d => host.includes(d));
        
        if (!permitido) {
            console.warn(`[${requestId}] Tentativa de acesso a host não permitido: ${host}`);
            return res.status(400).json({ success: false, requestId, error: "Endpoint não permitido." });
        }

        let certificado;
        try {
            const b64Limpo = sanitizarBase64(pfxBase64);
            certificado = Buffer.from(b64Limpo, "base64");
        } catch {
            return res.status(400).json({ success: false, requestId, error: "Base64 do certificado inválido." });
        }

        if (!certificado.length) {
            return res.status(400).json({ success: false, requestId, error: "Certificado vazio" });
        }

        try {
            tls.createSecureContext({
                pfx: certificado,
                passphrase: password
            });
        } catch (err) {
            // AJUSTE: Logando e retornando a mensagem real do OpenSSL
            console.error(`[${requestId}] Falha ao abrir PFX REAL:`, err.message);
            return res.status(400).json({ success: false, requestId, error: "Erro PFX: " + err.message });
        }

        console.log(`[${requestId}] Empresa: ${empresaId || "N/A"}`);
        console.log(`[${requestId}] Servidor: ${url.hostname}`);

        const options = {
            hostname: url.hostname,
            port: url.port || 443,
            path: url.pathname + url.search,
            method: "POST",
            pfx: certificado,
            passphrase: password,
            minVersion: "TLSv1.2",
            rejectUnauthorized: true, 
            secureOptions: crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1,
            headers: {
                "Content-Type": 'application/soap+xml; charset=utf-8',
                SOAPAction: soapAction || "",
                Accept: "application/soap+xml,text/xml,*/*",
                "User-Agent": "Bridge-SEFAZ/1.0",
                "Content-Length": Buffer.byteLength(soapEnvelope)
            }
        };

        const sefazRequest = https.request(options, (sefazResponse) => {
            let body = "";
            sefazResponse.setEncoding("utf8");

            console.log(`[${requestId}] SEFAZ STATUS: ${sefazResponse.statusCode}`);

            sefazResponse.on("data", (chunk) => {
                body += chunk;
            });

            sefazResponse.on("end", () => {
                if (finalizado) return;
                finalizado = true;

                res.status(sefazResponse.statusCode || 502).json({
                    success: sefazResponse.statusCode === 200,
                    statusCode: sefazResponse.statusCode,
                    requestId,
                    empresaId,
                    xmlSize: Buffer.byteLength(body, 'utf8'),
                    xmlResponse: body
                });
                
                console.log(`[${requestId}] Consulta finalizada com sucesso.`);
            });
        });

        sefazRequest.setTimeout(60000, () => {
            console.error(`[${requestId}] Timeout SEFAZ`);
            sefazRequest.destroy();

            if (!finalizado) {
                finalizado = true;
                res.status(504).json({ success: false, requestId, error: "Timeout de 60s ao comunicar com a SEFAZ" });
            }
        });

        sefazRequest.on("error", (error) => {
            console.error(`[${requestId}] Erro HTTPS:`, error.message);

            if (!finalizado) {
                finalizado = true;
                res.status(502).json({ success: false, requestId, error: error.message });
            }
        });

        sefazRequest.on("close", () => {
            console.log(`[${requestId}] Conexão HTTPS com a SEFAZ encerrada.`);
        });

        sefazRequest.write(soapEnvelope, "utf8");
        sefazRequest.end();

    } catch (error) {
        console.error(`[${requestId}] Erro não tratado na Bridge:`, error);

        if (!res.headersSent) {
            res.status(500).json({ success: false, requestId, error: error.message });
        }
    }
};

// ================================
// ENDPOINT: NFeDistribuicaoDFe (OPÇÃO A)
// ================================
app.post("/api/sefaz/distribuicao", validarAPI, async (req, res) => {
    const { cnpj, pfxBase64, password, ultimoNsu, ufIbge, empresaId } = req.body;

    if (!cnpj || !pfxBase64 || !password || ultimoNsu === undefined) {
        return res.status(400).json({
            success: false,
            error: "Campos obrigatórios ausentes: cnpj, pfxBase64, password, ultimoNsu"
        });
    }

    const cnpjLimpo = String(cnpj).replace(/\D/g, '');
    const nsuFormatado = String(ultimoNsu).padStart(15, '0');
    const cUF = ufIbge || "91";

    const soapEnvelope = `<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <nfeDistDFeInteresse xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe">
      <nfeDadosMsg>
        <distDFeInt versao="1.01" xmlns="http://www.portalfiscal.inf.br/nfe">
          <tpAmb>1</tpAmb>
          <cUFAutor>${cUF}</cUFAutor>
          <CNPJ>${cnpjLimpo}</CNPJ>
          <distNSU>
            <ultNSU>${nsuFormatado}</ultNSU>
          </distNSU>
        </distDFeInt>
      </nfeDadosMsg>
    </nfeDistDFeInteresse>
  </soap12:Body>
</soap12:Envelope>`;

    const payloadSefaz = {
        pfxBase64,
        password,
        empresaId,
        endpoint: "https://www1.nfe.fazenda.gov.br/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx",
        soapAction: "http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe/nfeDistDFeInteresse",
        soapEnvelope
    };

    return consultarSefaz(req, res, payloadSefaz);
});

// ================================
// REGISTRO DE ROTAS DE CONSULTA GENÉRICA
// ================================
app.post("/api/sefaz/consultar", validarAPI, (req, res) => consultarSefaz(req, res));
app.post("/backend/v1/xml/sync", validarAPI, (req, res) => consultarSefaz(req, res));
app.post("/rpa/xml/sync", validarAPI, (req, res) => consultarSefaz(req, res));

// ================================
// 404 - ENDPOINT INEXISTENTE
// ================================
app.use((req, res) => {
    res.status(404).json({ success: false, error: "Endpoint inexistente" });
});

// ================================
// ERRO GLOBAL
// ================================
app.use((error, req, res, next) => {
    console.error("Erro Global:", error);
    res.status(500).json({ success: false, error: "Erro interno do servidor" });
});

// ================================
// START
// ================================
app.listen(PORT, "0.0.0.0", () => {
    console.log("====================================");
    console.log("BRIDGE SEFAZ ONLINE");
    console.log("Node:", process.version);
    console.log("Porta:", PORT);
    console.log("AUTH_KEY:", AUTH_KEY ? "OK" : "NÃO CONFIGURADA");
    console.log("XML_KEY:", XML_KEY ? "OK" : "NÃO CONFIGURADA");
    console.log("Distribuição Simplificada Ativa: /api/sefaz/distribuicao");
    console.log("====================================");
});
