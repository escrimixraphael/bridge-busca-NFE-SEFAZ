import 'dotenv/config';
import express from 'express';
import tls from 'node:tls';
import https from 'node:https';
import crypto from 'node:crypto';
import zlib from 'node:zlib'; // Adicionado para descompactar o GZIP da SEFAZ
import { Buffer } from 'node:buffer';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';

const app = express();
const PORT = Number(process.env.PORT || 3000);

// ================================
// CONFIGURAÇÃO DE PROXY (OBRIGATÓRIO RENDER)
// ================================
app.set('trust proxy', 1); // Corrige o erro de Validação do X-Forwarded-For no Express Rate Limit

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
    windowMs: 60 * 1000,
    max: 120,
    message: { success: false, error: "Muitas requisições" }
});

app.use("/api", limiter);
app.use("/backend", limiter);
app.use("/rpa", limiter);

// ================================
// UTILS
// ================================
function sanitizarBase64(b64) {
    if (typeof b64 !== 'string') return '';
    return b64.replace(/^data:.*;base64,/, '').replace(/\s+/g, '');
}

// NOVO: Função para extrair e descompactar os docZip da resposta SOAP
function processarRespostaSefaz(soapXml) {
    const retorno = {
        cStat: '',
        ultNSU: '',
        maxNSU: '',
        docs: []
    };

    if (typeof soapXml !== 'string') return retorno;

    // Extrair códigos de status básicos
    const cStatMatch = soapXml.match(/<cStat[^>]*>(.*?)<\/cStat>/);
    if (cStatMatch) retorno.cStat = cStatMatch[1];

    const ultNSUMatch = soapXml.match(/<ultNSU[^>]*>(.*?)<\/ultNSU>/);
    if (ultNSUMatch) retorno.ultNSU = ultNSUMatch[1];

    const maxNSUMatch = soapXml.match(/<maxNSU[^>]*>(.*?)<\/maxNSU>/);
    if (maxNSUMatch) retorno.maxNSU = maxNSUMatch[1];

    // Se achou documentos, extrai e descompacta todos os docZip
    const docRegex = /<docZip[^>]*NSU="([^"]+)"[^>]*schema="([^"]+)"[^>]*>(.*?)<\/docZip>/g;
    let match;

    while ((match = docRegex.exec(soapXml)) !== null) {
        const nsu = match[1];
        const schema = match[2];
        const b64Zipped = match[3];

        try {
            const bufferZip = Buffer.from(b64Zipped, 'base64');
            const unzipped = zlib.gunzipSync(bufferZip).toString('utf8');
            
            retorno.docs.push({
                nsu: nsu,
                schema: schema,
                xml: unzipped
            });
        } catch (e) {
            console.error(`Erro ao descompactar documento NSU ${nsu}:`, e.message);
        }
    }

    return retorno;
}

// ================================
// ENDPOINTS DE MONITORAMENTO
// ================================
app.get("/health", (req, res) => res.json({ status: "online", node: process.version, timestamp: new Date() }));
app.get("/api/info", (req, res) => res.json({ success: true, service: "Bridge SEFAZ", version: "1.1.0", authKeyConfigured: !!AUTH_KEY }));
app.get("/version", (req, res) => res.json({ service: "Bridge SEFAZ", version: "1.1.0", node: process.version }));

// ================================
// VALIDAÇÃO API KEY (Flexível para x-api-key e x-xml-key)
// ================================
function validarAPI(req, res, next) {
    const apiKey = req.headers["x-api-key"] || req.headers["x-xml-key"];
    if (!AUTH_KEY) return res.status(500).json({ success: false, error: "AUTH_KEY não configurada" });
    if (apiKey !== AUTH_KEY) return res.status(403).json({ success: false, error: "API Key inválida" });
    next();
}

app.get("/api/test-auth", validarAPI, (req, res) => res.json({ success: true, message: "Autenticação OK" }));

app.post("/api/sefaz/test-cert", validarAPI, async (req, res) => {
    try {
        const { pfxBase64, password } = req.body;
        if (!pfxBase64 || !password) return res.status(400).json({ success: false, error: "PFX ou senha não informados." });

        const b64Limpo = sanitizarBase64(pfxBase64);
        const certificado = Buffer.from(b64Limpo, "base64");
        
        tls.createSecureContext({ pfx: certificado, passphrase: password });
        return res.json({ success: true, message: "Certificado validado com sucesso." });
    } catch (error) {
        console.error("Falha ao abrir PFX:", error.message);
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
        const { pfxBase64, password, endpoint, soapAction, soapEnvelope, empresaId } = payload;

        if (!pfxBase64 || !password || !endpoint || !soapEnvelope) {
            return res.status(400).json({ success: false, requestId, error: "Campos obrigatórios ausentes" });
        }

        const url = new URL(endpoint);
        let certificado;
        
        try {
            const b64Limpo = sanitizarBase64(pfxBase64);
            certificado = Buffer.from(b64Limpo, "base64");
        } catch {
            return res.status(400).json({ success: false, requestId, error: "Base64 do certificado inválido." });
        }

        try {
            tls.createSecureContext({ pfx: certificado, passphrase: password });
        } catch (err) {
            console.error(`[${requestId}] Falha ao abrir PFX REAL:`, err.message);
            return res.status(400).json({ success: false, requestId, error: "Erro PFX: " + err.message });
        }

        console.log(`[${requestId}] Endpoint: ${url.hostname}`);

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
                "User-Agent": "Bridge-SEFAZ/1.1",
                "Content-Length": Buffer.byteLength(soapEnvelope)
            }
        };

        const sefazRequest = https.request(options, (sefazResponse) => {
            let body = "";
            sefazResponse.setEncoding("utf8");

            sefazResponse.on("data", (chunk) => body += chunk);

            sefazResponse.on("end", () => {
                if (finalizado) return;
                finalizado = true;

                // Processar a resposta e extrair GZIPs
                const processado = processarRespostaSefaz(body);
                
                res.status(sefazResponse.statusCode || 502).json({
                    success: sefazResponse.statusCode === 200,
                    statusCode: sefazResponse.statusCode,
                    cStat: processado.cStat,
                    ultNSU: processado.ultNSU,
                    maxNSU: processado.maxNSU, // Incluído para compatibilidade total
                    docs: processado.docs,
                    soapResponse: body
                });
                
                console.log(`[${requestId}] Consulta finalizada. cStat: ${processado.cStat}. Documentos extraídos: ${processado.docs.length}`);
            });
        });

        sefazRequest.setTimeout(60000, () => {
            sefazRequest.destroy();
            if (!finalizado) {
                finalizado = true;
                res.status(504).json({ success: false, error: "Timeout SEFAZ" });
            }
        });

        sefazRequest.on("error", (error) => {
            if (!finalizado) {
                finalizado = true;
                res.status(502).json({ success: false, error: error.message });
            }
        });

        sefazRequest.write(soapEnvelope, "utf8");
        sefazRequest.end();

    } catch (error) {
        if (!res.headersSent) res.status(500).json({ success: false, error: error.message });
    }
};

// ================================
// ROTAS CORRIGIDAS (Agora todas apontam para a função)
// ================================
app.post("/api/sefaz/distribuicao", validarAPI, (req, res) => consultarSefaz(req, res));
app.post("/api/sefaz/consultar", validarAPI, (req, res) => consultarSefaz(req, res));
app.post("/backend/v1/xml/sync", validarAPI, (req, res) => consultarSefaz(req, res));
app.post("/rpa/xml/sync", validarAPI, (req, res) => consultarSefaz(req, res));

app.use((req, res) => res.status(404).json({ success: false, error: "Endpoint inexistente" }));

app.listen(PORT, "0.0.0.0", () => {
    console.log("BRIDGE SEFAZ ONLINE (GZIP Ativo) - Porta:", PORT);
});
