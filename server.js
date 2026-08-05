import 'dotenv/config';
import express from 'express';
import tls from 'node:tls';
import https from 'node:https';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { Buffer } from 'node:buffer';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';

// NOVAS DEPENDÊNCIAS PARA ASSINATURA DE XML
import forge from 'node-forge';
import { SignedXml } from 'xml-crypto';
import { DOMParser } from '@xmldom/xmldom';

const app = express();
const PORT = Number(process.env.PORT || 3000);

// ================================
// CONFIGURAÇÃO DE PROXY (OBRIGATÓRIO RENDER)
// ================================
app.set('trust proxy', 1);

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

function processarRespostaSefaz(soapXml) {
    const retorno = {
        cStat: '',
        ultNSU: '',
        maxNSU: '',
        docs: []
    };

    if (typeof soapXml !== 'string') return retorno;

    const cStatMatch = soapXml.match(/<cStat[^>]*>(.*?)<\/cStat>/);
    if (cStatMatch) retorno.cStat = cStatMatch[1];

    const ultNSUMatch = soapXml.match(/<ultNSU[^>]*>(.*?)<\/ultNSU>/);
    if (ultNSUMatch) retorno.ultNSU = ultNSUMatch[1];

    const maxNSUMatch = soapXml.match(/<maxNSU[^>]*>(.*?)<\/maxNSU>/);
    if (maxNSUMatch) retorno.maxNSU = maxNSUMatch[1];

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
app.get("/api/info", (req, res) => res.json({ success: true, service: "Bridge SEFAZ", version: "1.2.0", authKeyConfigured: !!AUTH_KEY }));
app.get("/version", (req, res) => res.json({ service: "Bridge SEFAZ", version: "1.2.0", node: process.version }));

// ================================
// VALIDAÇÃO API KEY
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
        const { pfxBase64, password, endpoint, soapEnvelope } = payload;
        
        const soapAction = payload.soapAction || "http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe/nfeDistDFeInteresse";

        if (!pfxBase64 || !password || !endpoint || !soapEnvelope) {
            console.error(`[${requestId}] Erro: Campos obrigatórios ausentes no payload.`);
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

        console.log(`[${requestId}] Endpoint: ${url.hostname} | SOAPAction: ${soapAction}`);

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
                "Content-Type": `application/soap+xml; charset=utf-8; action="${soapAction}"`,
                SOAPAction: soapAction,
                "User-Agent": "Bridge-SEFAZ/1.2",
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

                // Se o res já tem os dados (como na Manifestação), evitamos processar como Distribuição
                if (dadosCustom && dadosCustom.isManifest) {
                    const cStatMatch = body.match(/<cStat[^>]*>(.*?)<\/cStat>/g);
                    // Pega o cStat do Lote e o cStat do Evento
                    const cStatLote = cStatMatch && cStatMatch.length > 0 ? cStatMatch[0].replace(/<\/?cStat[^>]*>/g, '') : '';
                    const cStatEvento = cStatMatch && cStatMatch.length > 1 ? cStatMatch[1].replace(/<\/?cStat[^>]*>/g, '') : '';
                    
                    const isSuccess = sefazResponse.statusCode === 200 && (cStatEvento === '135' || cStatEvento === '136');
                    
                    return res.status(isSuccess ? 200 : 400).json({
                        success: isSuccess,
                        message: isSuccess ? "Manifestação registrada com sucesso" : "Rejeitado pela SEFAZ",
                        cStat: cStatEvento || cStatLote,
                        soapResponse: body
                    });
                }

                // Processamento padrão (Distribuição)
                const processado = processarRespostaSefaz(body);
                const isSuccess = sefazResponse.statusCode === 200;
                const statusToReturn = isSuccess ? 200 : 422;

                res.status(statusToReturn).json({
                    success: isSuccess,
                    statusCode: sefazResponse.statusCode,
                    cStat: processado.cStat,
                    ultNSU: processado.ultNSU,
                    maxNSU: processado.maxNSU,
                    docs: processado.docs,
                    soapResponse: body
                });
                
                console.log(`[${requestId}] Consulta finalizada. SEFAZ Status: ${sefazResponse.statusCode} | cStat: ${processado.cStat}. Documentos: ${processado.docs.length}`);
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
// ASSINATURA DIGITAL DO EVENTO (MANIFESTAÇÃO)
// ================================
function gerarManifestacaoXML(cnpj, chave, tipoManifestacao, pfxBase64, password) {
    const mapaEventos = {
        'confirmada': { tp: '210200', desc: 'Confirmacao da Operacao' },
        'ciencia': { tp: '210210', desc: 'Ciencia da Operacao' },
        'desconhecida': { tp: '210220', desc: 'Desconhecimento da Operacao' },
        'nao_realizada': { tp: '210240', desc: 'Operacao nao Realizada' }
    };
    
    const evt = mapaEventos[tipoManifestacao];
    if (!evt) throw new Error("Tipo de manifestação inválido.");

    // 1. Extração da Chave Privada e Certificado via node-forge
    const pfxDer = forge.util.decode64(sanitizarBase64(pfxBase64));
    const p12Asn1 = forge.asn1.fromDer(pfxDer);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);

    let privateKeyPem, certPem;
    for (const safeContents of p12.safeContents) {
        for (const safeBag of safeContents.safeBags) {
            if (safeBag.type === forge.pki.oids.keyBag || safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag) {
                privateKeyPem = forge.pki.privateKeyToPem(safeBag.key);
            } else if (safeBag.type === forge.pki.oids.certBag) {
                if (!certPem) certPem = forge.pki.certificateToPem(safeBag.cert);
            }
        }
    }
    if (!privateKeyPem || !certPem) throw new Error("Não foi possível extrair a chave do certificado.");
    
    const certB64 = certPem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\r|\n/g, '');

    // 2. Montagem do ID e Data UTC-3 padrão SEFAZ
    const idEvento = `ID${evt.tp}${chave}01`;
    
    const date = new Date();
    const tzo = -date.getTimezoneOffset();
    const dif = tzo >= 0 ? '+' : '-';
    const pad = (num) => (num < 10 ? '0' : '') + num;
    const dhEvento = date.getFullYear() +
        '-' + pad(date.getMonth() + 1) +
        '-' + pad(date.getDate()) +
        'T' + pad(date.getHours()) +
        ':' + pad(date.getMinutes()) +
        ':' + pad(date.getSeconds()) +
        dif + pad(Math.floor(Math.abs(tzo) / 60)) +
        ':' + pad(Math.abs(tzo) % 60);

    const justificativaXML = evt.tp === '210240' ? '<xJust>Operacao nao realizada pelo destinatario</xJust>' : '';

    // 3. Montagem estrita do infEvento com o namespace padrão da SEFAZ
    const xmlInfEvento = `<infEvento Id="${idEvento}" xmlns="http://www.portalfiscal.inf.br/nfe">` +
        `<cOrgao>91</cOrgao>` +
        `<tpAmb>1</tpAmb>` +
        `<CNPJ>${cnpj}</CNPJ>` +
        `<chNFe>${chave}</chNFe>` +
        `<dhEvento>${dhEvento}</dhEvento>` +
        `<tpEvento>${evt.tp}</tpEvento>` +
        `<nSeqEvento>1</nSeqEvento>` +
        `<verEvento>1.00</verEvento>` +
        `<detEvento versao="1.00">` +
        `<descEvento>${evt.desc}</descEvento>` +
        justificativaXML +
        `</detEvento>` +
        `</infEvento>`;

    // 4. Assinatura Digital do infEvento
    const sig = new SignedXml();
    sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    sig.addReference({
        xpath: `//*[@Id='${idEvento}']`,
        transforms: [
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        ],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1"
    });
    
    sig.privateKey = privateKeyPem;
    sig.keyInfoProvider = {
        getKeyInfo: () => `<X509Data><X509Certificate>${certB64}</X509Certificate></X509Data>`
    };
    sig.computeSignature(xmlInfEvento);
    
    let signatureXml = sig.getSignedXml();
    
    // Normaliza os namespaces da assinatura exigidos rigidamente pela SEFAZ
    signatureXml = signatureXml
        .replace('<Signature>', '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">')
        .replace('<SignedInfo>', '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">')
        .replace('<CanonicalizationMethod', '<CanonicalizationMethod xmlns="http://www.w3.org/2000/09/xmldsig#"')
        .replace('<SignatureMethod', '<SignatureMethod xmlns="http://www.w3.org/2000/09/xmldsig#"')
        .replace('<Reference', '<Reference xmlns="http://www.w3.org/2000/09/xmldsig#"')
        .replace('<Transforms>', '<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#">')
        .replace('<Transform', '<Transform xmlns="http://www.w3.org/2000/09/xmldsig#"')
        .replace('<DigestMethod', '<DigestMethod xmlns="http://www.w3.org/2000/09/xmldsig#"')
        .replace('<DigestValue>', '<DigestValue xmlns="http://www.w3.org/2000/09/xmldsig#">')
        .replace('<SignatureValue>', '<SignatureValue xmlns="http://www.w3.org/2000/09/xmldsig#">')
        .replace('<KeyInfo>', '<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">')
        .replace('<X509Data>', '<X509Data xmlns="http://www.w3.org/2000/09/xmldsig#">')
        .replace('<X509Certificate>', '<X509Certificate xmlns="http://www.w3.org/2000/09/xmldsig#">');

    // 5. Estrutura limpa e oficial do evento (evento encapsula infEvento e Signature no mesmo nível)
    const xmlLimpoInf = xmlInfEvento.replace(' xmlns="http://www.portalfiscal.inf.br/nfe"', '');
    const xmlEventoAssinado = `<evento xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.00">` +
        xmlLimpoInf +
        signatureXml +
        `</evento>`;

    // 6. Envelope SOAP oficial do WebService NFeRecepcaoEvento4
    const soap = `<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
    <soap12:Body>
        <nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4">
            <envEvento versao="1.00" xmlns="http://www.portalfiscal.inf.br/nfe">
                <idLote>1</idLote>
                ${xmlEventoAssinado}
            </envEvento>
        </nfeDadosMsg>
    </soap12:Body>
</soap12:Envelope>`;

    return soap;
}

// ================================
// ROTAS DE INTEGRAÇÃO
// ================================
app.post("/api/sefaz/distribuicao", validarAPI, (req, res) => consultarSefaz(req, res));
app.post("/api/sefaz/consultar", validarAPI, (req, res) => consultarSefaz(req, res));
app.post("/backend/v1/xml/sync", validarAPI, (req, res) => consultarSefaz(req, res));

// ================================
// ROTA DE MANIFESTAÇÃO INDEPENDENTE
// ================================
app.post("/rpa/xml/manifest", validarAPI, async (req, res) => {
    let finalizado = false;
    try {
        const { pfxBase64, password, cnpj, chave, tipoManifestacao } = req.body;
        
        if (!pfxBase64 || !password || !cnpj || !chave || !tipoManifestacao) {
            return res.status(400).json({ success: false, error: "Dados incompletos para a manifestação." });
        }

        const soapEnvelope = gerarManifestacaoXML(cnpj, chave, tipoManifestacao, pfxBase64, password);
        const endpointUrl = new URL("https://www1.nfe.fazenda.gov.br/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx");
        const soapAction = "http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4/nfeRecepcaoEvento";

        const b64Limpo = sanitizarBase64(pfxBase64);
        const certificado = Buffer.from(b64Limpo, "base64");

        const options = {
            hostname: endpointUrl.hostname,
            port: endpointUrl.port || 443,
            path: endpointUrl.pathname + endpointUrl.search,
            method: "POST",
            pfx: certificado,
            passphrase: password,
            minVersion: "TLSv1.2",
            rejectUnauthorized: true,
            secureOptions: crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1,
            headers: {
                "Content-Type": `application/soap+xml; charset=utf-8; action="${soapAction}"`,
                SOAPAction: soapAction,
                "User-Agent": "Bridge-SEFAZ/1.2",
                "Content-Length": Buffer.byteLength(soapEnvelope)
            }
        };

        const sefazReq = https.request(options, (sefazRes) => {
            let body = "";
            sefazRes.setEncoding("utf8");
            sefazRes.on("data", (chunk) => body += chunk);
            sefazRes.on("end", () => {
                if (finalizado) return;
                finalizado = true;

                // Loga a resposta crua no console do Render para diagnóstico definitivo
                console.log("=== RESPOSTA CRUA SEFAZ (MANIFESTAÇÃO) ===");
                console.log(body);
                console.log("==========================================");

                const cStatMatch = body.match(/<cStat[^>]*>(.*?)<\/cStat>/g);
                const cStatLote = cStatMatch && cStatMatch.length > 0 ? cStatMatch[0].replace(/<\/?cStat[^>]*>/g, '') : '';
                const cStatEvento = cStatMatch && cStatMatch.length > 1 ? cStatMatch[1].replace(/<\/?cStat[^>]*>/g, '') : '';
                const cStatFinal = cStatEvento || cStatLote;

                const xMotivoMatch = body.match(/<xMotivo[^>]*>(.*?)<\/xMotivo>/g);
                const xMotivo = xMotivoMatch && xMotivoMatch.length > 0 ? xMotivoMatch[xMotivoMatch.length - 1].replace(/<\/?xMotivo[^>]*>/g, '') : null;

                // Fallback para capturar erros de SOAP Fault caso existam
                let faultString = '';
                if (!xMotivo) {
                    const faultMatch = body.match(/<faultstring[^>]*>(.*?)<\/faultstring>/i) || body.match(/<reason[^>]*>(.*?)<\/reason>/i);
                    if (faultMatch) faultString = faultMatch[1];
                }

                const motivoFinal = xMotivo || faultString || (body.length < 300 ? body : 'Resposta incompatível da SEFAZ');

                const isSuccess = sefazRes.statusCode === 200 && (cStatFinal === '135' || cStatFinal === '136');

                if (isSuccess) {
                    return res.json({
                        success: true,
                        message: `Manifestação registrada com sucesso: ${motivoFinal}`,
                        cStat: cStatFinal
                    });
                } else {
                    return res.status(400).json({
                        success: false,
                        error: `SEFAZ (${cStatFinal || sefazRes.statusCode}): ${motivoFinal}`
                    });
                }
            });
        });

        sefazReq.setTimeout(60000, () => {
            sefazReq.destroy();
            if (!finalizado) {
                finalizado = true;
                return res.status(504).json({ success: false, error: "Timeout ao conectar com a SEFAZ" });
            }
        });

        sefazReq.on("error", (err) => {
            if (!finalizado) {
                finalizado = true;
                return res.status(502).json({ success: false, error: "Erro de conexão: " + err.message });
            }
        });

        sefazReq.write(soapEnvelope, "utf8");
        sefazReq.end();

    } catch (error) {
        console.error("Erro na rota de manifestação:", error);
        return res.status(500).json({ success: false, error: "Falha interna no Bridge: " + error.message });
    }
});
