import "dotenv/config";

import express from "express";
import tls from "node:tls";
import https from "node:https";
import crypto from "node:crypto";
import zlib from "node:zlib";
import { Buffer } from "node:buffer";

import cors from "cors";
import helmet from "helmet";
import compression from "compression";
import morgan from "morgan";
import rateLimit from "express-rate-limit";
import forge from "node-forge";
import { SignedXml } from "xml-crypto";
import PDFDocument from "pdfkit";

const app = express();
const PORT = Number(process.env.PORT || 3000);

const AUTH_KEY = process.env.AUTH_KEY;
const XML_KEY = process.env.XML_KEY;

const NFE_NAMESPACE = "http://www.portalfiscal.inf.br/nfe";
const NFE_EVENTO_WSDL_NAMESPACE =
    "http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4";

const NFE_EVENTO_SOAP_ACTION =
    "http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4/nfeRecepcaoEvento";

process.on("uncaughtException", (error) => {
    console.error("ERRO NÃO TRATADO:", error);
});

process.on("unhandledRejection", (reason) => {
    console.error("PROMISE REJEITADA:", reason);
});

app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use(
    helmet({
        crossOriginResourcePolicy: false
    })
);

app.use(cors({ origin: "*" }));
app.use(compression());
app.use(express.json({ limit: "20mb" }));
app.use(morgan("combined"));

const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        error: "Muitas requisições. Tente novamente mais tarde."
    }
});

app.use("/api", limiter);
app.use("/backend", limiter);
app.use("/rpa", limiter);

console.log("====================================");
console.log("BRIDGE SEFAZ INICIANDO");
console.log("AUTH_KEY carregada:", Boolean(AUTH_KEY));
console.log("XML_KEY carregada:", Boolean(XML_KEY));
console.log("NODE_ENV:", process.env.NODE_ENV || "development");
console.log("====================================");

/* ============================================================
   FUNÇÕES GERAIS
============================================================ */

function sanitizarBase64(valor) {
    if (typeof valor !== "string") return "";

    return valor
        .replace(/^data:.*?;base64,/i, "")
        .replace(/\s+/g, "")
        .trim();
}

function escapeXml(valor) {
    return String(valor ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&apos;");
}

function decodeXml(valor) {
    if (!valor) return "";

    return String(valor)
        .replace(/&amp;/g, "&")
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&quot;/g, '"')
        .replace(/&apos;/g, "'")
        .replace(/&#(\d+);/g, (_, code) =>
            String.fromCharCode(Number(code))
        )
        .replace(/&#x([0-9a-f]+);/gi, (_, code) =>
            String.fromCharCode(parseInt(code, 16))
        )
        .trim();
}

function extrairTagXml(xml, tag, origem = null) {
    if (!xml) return "";

    const conteudo = origem || xml;

    const regex = new RegExp(
        `<(?:[\\w.-]+:)?${tag}\\b[^>]*>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?${tag}>`,
        "i"
    );

    const match = conteudo.match(regex);
    return match ? decodeXml(match[1]) : "";
}

function extrairTagsXml(xml, tag) {
    if (!xml) return [];

    const regex = new RegExp(
        `<(?:[\\w.-]+:)?${tag}\\b[^>]*>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?${tag}>`,
        "gi"
    );

    const valores = [];
    let match;

    while ((match = regex.exec(xml)) !== null) {
        valores.push(decodeXml(match[1]));
    }

    return valores;
}

function extrairBlocoXml(xml, tag) {
    if (!xml) return "";

    const regex = new RegExp(
        `<(?:[\\w.-]+:)?${tag}\\b[^>]*>[\\s\\S]*?<\\/(?:[\\w.-]+:)?${tag}>`,
        "i"
    );

    const match = xml.match(regex);
    return match ? match[0] : "";
}

function extrairTodosBlocosXml(xml, tag) {
    if (!xml) return [];

    const regex = new RegExp(
        `<(?:[\\w.-]+:)?${tag}\\b[^>]*>[\\s\\S]*?<\\/(?:[\\w.-]+:)?${tag}>`,
        "gi"
    );

    return xml.match(regex) || [];
}

function formatarMoeda(valor) {
    const numero = Number(String(valor || "0").replace(",", "."));

    if (!Number.isFinite(numero)) {
        return "R$ 0,00";
    }

    return numero.toLocaleString("pt-BR", {
        style: "currency",
        currency: "BRL"
    });
}

function formatarNumero(valor, casas = 2) {
    const numero = Number(String(valor || "0").replace(",", "."));

    if (!Number.isFinite(numero)) return "0,00";

    return numero.toLocaleString("pt-BR", {
        minimumFractionDigits: casas,
        maximumFractionDigits: casas
    });
}

function formatarData(valor) {
    if (!valor) return "";

    const data = new Date(valor);

    if (Number.isNaN(data.getTime())) {
        return valor;
    }

    return data.toLocaleString("pt-BR");
}

function somenteDigitos(valor) {
    return String(valor || "").replace(/\D/g, "");
}

function quebrarTexto(valor, tamanho = 90) {
    const texto = String(valor || "").trim();

    if (!texto) return "";

    const partes = [];

    for (let i = 0; i < texto.length; i += tamanho) {
        partes.push(texto.substring(i, i + tamanho));
    }

    return partes.join("\n");
}

/* ============================================================
   AUTENTICAÇÃO
============================================================ */

function validarAPI(req, res, next) {
    const apiKey = req.headers["x-api-key"] || req.headers["x-xml-key"];

    if (!AUTH_KEY) {
        return res.status(500).json({
            success: false,
            error: "AUTH_KEY não configurada no ambiente."
        });
    }

    if (!apiKey || apiKey !== AUTH_KEY) {
        return res.status(403).json({
            success: false,
            error: "API Key inválida."
        });
    }

    next();
}

/* ============================================================
   HEALTHCHECK
============================================================ */

app.get("/health", (req, res) => {
    res.json({
        status: "online",
        node: process.version,
        timestamp: new Date().toISOString()
    });
});

app.get("/api/info", (req, res) => {
    res.json({
        success: true,
        service: "Bridge SEFAZ",
        version: "1.4.0",
        authKeyConfigured: Boolean(AUTH_KEY),
        xmlKeyConfigured: Boolean(XML_KEY)
    });
});

app.get("/version", (req, res) => {
    res.json({
        service: "Bridge SEFAZ",
        version: "1.4.0",
        node: process.version
    });
});

app.get("/api/test-auth", validarAPI, (req, res) => {
    res.json({
        success: true,
        message: "Autenticação OK"
    });
});

/* ============================================================
   DISTRIBUIÇÃO DF-E
============================================================ */

function processarRespostaSefaz(soapXml) {
    const retorno = {
        cStat: "",
        xMotivo: "",
        ultNSU: "",
        maxNSU: "",
        docs: []
    };

    if (typeof soapXml !== "string") {
        return retorno;
    }

    retorno.cStat = extrairTagXml(soapXml, "cStat");
    retorno.xMotivo = extrairTagXml(soapXml, "xMotivo");
    retorno.ultNSU = extrairTagXml(soapXml, "ultNSU");
    retorno.maxNSU = extrairTagXml(soapXml, "maxNSU");

    const docRegex =
        /<docZip\b[^>]*NSU="([^"]+)"[^>]*schema="([^"]+)"[^>]*>([\s\S]*?)<\/docZip>/gi;

    let match;

    while ((match = docRegex.exec(soapXml)) !== null) {
        const nsu = match[1];
        const schema = match[2];
        const conteudoBase64 = match[3].replace(/\s+/g, "");

        try {
            const zipBuffer = Buffer.from(conteudoBase64, "base64");
            const xmlDescompactado = zlib.gunzipSync(zipBuffer).toString("utf8");

            retorno.docs.push({
                nsu,
                schema,
                xml: xmlDescompactado
            });
        } catch (error) {
            console.error(
                `Erro ao descompactar documento NSU ${nsu}:`,
                error.message
            );
        }
    }

    return retorno;
}

async function consultarSefaz(req, res, dadosCustom = null) {
    let finalizado = false;
    const requestId = crypto.randomUUID();

    try {
        const payload = dadosCustom || req.body;

        const {
            pfxBase64,
            password,
            endpoint,
            soapEnvelope
        } = payload;

        const soapAction =
            payload.soapAction ||
            "http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe/nfeDistDFeInteresse";

        if (!pfxBase64 || !password || !endpoint || !soapEnvelope) {
            return res.status(400).json({
                success: false,
                requestId,
                error: "pfxBase64, password, endpoint e soapEnvelope são obrigatórios."
            });
        }

        const endpointUrl = new URL(endpoint);

        if (endpointUrl.protocol !== "https:") {
            return res.status(400).json({
                success: false,
                requestId,
                error: "O endpoint SEFAZ precisa utilizar HTTPS."
            });
        }

        const certificado = Buffer.from(
            sanitizarBase64(pfxBase64),
            "base64"
        );

        try {
            tls.createSecureContext({
                pfx: certificado,
                passphrase: password
            });
        } catch (error) {
            return res.status(400).json({
                success: false,
                requestId,
                error: "Erro no certificado PFX: " + error.message
            });
        }

        const soapBuffer = Buffer.from(soapEnvelope, "utf8");

        const options = {
            hostname: endpointUrl.hostname,
            port: endpointUrl.port || 443,
            path: endpointUrl.pathname + endpointUrl.search,
            method: "POST",
            pfx: certificado,
            passphrase: password,
            minVersion: "TLSv1.2",
            rejectUnauthorized: true,
            headers: {
                "Content-Type": `application/soap+xml; charset=utf-8; action="${soapAction}"`,
                SOAPAction: soapAction,
                Accept: "application/soap+xml, text/xml, */*",
                "User-Agent": "Bridge-SEFAZ/1.4",
                "Content-Length": soapBuffer.length
            }
        };

        const sefazRequest = https.request(options, (sefazResponse) => {
            let body = "";

            sefazResponse.setEncoding("utf8");

            sefazResponse.on("data", (chunk) => {
                body += chunk;
            });

            sefazResponse.on("end", () => {
                if (finalizado) return;

                finalizado = true;

                const processado = processarRespostaSefaz(body);
                const sucesso = sefazResponse.statusCode === 200;

                return res.status(sucesso ? 200 : 422).json({
                    success: sucesso,
                    requestId,
                    statusCode: sefazResponse.statusCode,
                    cStat: processado.cStat,
                    xMotivo: processado.xMotivo,
                    ultNSU: processado.ultNSU,
                    maxNSU: processado.maxNSU,
                    docs: processado.docs,
                    soapResponse: body
                });
            });
        });

        sefazRequest.setTimeout(60000, () => {
            sefazRequest.destroy();

            if (!finalizado) {
                finalizado = true;

                return res.status(504).json({
                    success: false,
                    requestId,
                    error: "Timeout na comunicação com a SEFAZ."
                });
            }
        });

        sefazRequest.on("error", (error) => {
            if (!finalizado) {
                finalizado = true;

                return res.status(502).json({
                    success: false,
                    requestId,
                    error: "Erro de comunicação com a SEFAZ: " + error.message
                });
            }
        });

        sefazRequest.write(soapBuffer);
        sefazRequest.end();
    } catch (error) {
        if (!res.headersSent) {
            return res.status(500).json({
                success: false,
                requestId,
                error: error.message
            });
        }
    }
}

app.post(
    "/api/sefaz/distribuicao",
    validarAPI,
    (req, res) => consultarSefaz(req, res)
);

app.post(
    "/api/sefaz/consultar",
    validarAPI,
    (req, res) => consultarSefaz(req, res)
);

app.post(
    "/backend/v1/xml/sync",
    validarAPI,
    (req, res) => consultarSefaz(req, res)
);

// ============================================================
// GERAÇÃO DE DANFE PDF
// Endpoint público somente para renderização de PDF
// Os demais endpoints continuam protegidos por API Key
// ============================================================
app.post("/api/xml/render-pdf", async (req, res) => {
    try {
        const { xmlBase64, tipo } = req.body || {};

        if (!xmlBase64 || typeof xmlBase64 !== "string") {
            return res.status(400).json({
                success: false,
                error: "xmlBase64 não fornecido"
            });
        }

        const base64Limpo = sanitizarBase64(xmlBase64);

        let xmlString;

        try {
            xmlString = Buffer
                .from(base64Limpo, "base64")
                .toString("utf8")
                .replace(/^\uFEFF/, "")
                .trim();
        } catch (error) {
            return res.status(400).json({
                success: false,
                error: "Base64 inválido"
            });
        }

        // Impede que HTML, JSON ou página do frontend sejam processados como XML
        const pareceXml =
            xmlString.startsWith("<?xml") ||
            xmlString.startsWith("<nfeProc") ||
            xmlString.startsWith("<NFe") ||
            xmlString.includes("<nfeProc") ||
            xmlString.includes("<infNFe");

        if (!pareceXml) {
            return res.status(400).json({
                success: false,
                error: "O conteúdo enviado não é um XML NF-e válido",
                recebido: xmlString.substring(0, 120)
            });
        }

        function escaparTexto(valor) {
            return String(valor || "")
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&apos;");
        }

        function extrairTag(xml, tag) {
            const regex = new RegExp(
                `<(?:[\\w-]+:)?${tag}\\b[^>]*>([\\s\\S]*?)<\\/(?:[\\w-]+:)?${tag}>`,
                "i"
            );

            const match = xml.match(regex);
            return match ? match[1].trim() : "";
        }

        function extrairChave(xml) {
            const chaveDireta =
                extrairTag(xml, "chNFe") ||
                extrairTag(xml, "chCTe") ||
                extrairTag(xml, "chMDFe");

            if (chaveDireta) {
                return chaveDireta.replace(/\D/g, "");
            }

            const idMatch = xml.match(/Id=["'](?:NFe|CTe|MDFe)?([0-9]{44})["']/i);

            return idMatch ? idMatch[1] : "";
        }

        function formatarMoeda(valor) {
            const numero = Number(
                String(valor || "0")
                    .replace(/\./g, "")
                    .replace(",", ".")
            );

            if (!Number.isFinite(numero)) return "R$ 0,00";

            return numero.toLocaleString("pt-BR", {
                style: "currency",
                currency: "BRL"
            });
        }

        function formatarData(valor) {
            if (!valor) return "N/D";

            const data = String(valor)
                .replace("T", " ")
                .replace(/[+-]\d{2}:\d{2}$/, "");

            return data;
        }

        const chave = extrairChave(xmlString) || "N/D";
        const cnpjEmitente = extrairTag(xmlString, "CNPJ") || "N/D";
        const nomeEmitente = extrairTag(xmlString, "xNome") || "N/D";
        const fantasia = extrairTag(xmlString, "xFant");
        const endereco = extrairTag(xmlString, "xLgr");
        const numero = extrairTag(xmlString, "nro");
        const bairro = extrairTag(xmlString, "xBairro");
        const cidade = extrairTag(xmlString, "xMun");
        const uf = extrairTag(xmlString, "UF");
        const cep = extrairTag(xmlString, "CEP");

        const cnpjDestinatario =
            extrairTag(xmlString, "dest") &&
            (
                extrairTag(
                    xmlString.substring(xmlString.indexOf("<dest")),
                    "CNPJ"
                ) ||
                extrairTag(
                    xmlString.substring(xmlString.indexOf("<dest")),
                    "CPF"
                )
            );

        const numeroNF = extrairTag(xmlString, "nNF") || "N/D";
        const serie = extrairTag(xmlString, "serie") || "N/D";
        const dataEmissao =
            extrairTag(xmlString, "dhEmi") ||
            extrairTag(xmlString, "dEmi") ||
            "N/D";

        const naturezaOperacao =
            extrairTag(xmlString, "natOp") || "N/D";

        const valorProdutos =
            extrairTag(xmlString, "vProd") || "0";

        const valorFrete =
            extrairTag(xmlString, "vFrete") || "0";

        const valorDesconto =
            extrairTag(xmlString, "vDesc") || "0";

        const valorNota =
            extrairTag(xmlString, "vNF") || "0";

        const protocolo =
            extrairTag(xmlString, "nProt") ||
            extrairTag(xmlString, "nProt") ||
            "N/D";

        const doc = new PDFDocument({
            size: "A4",
            margin: 28,
            bufferPages: true
        });

        const chunks = [];

        doc.on("data", (chunk) => chunks.push(chunk));

        doc.on("error", (error) => {
            console.error("Erro interno do PDFKit:", error);
        });

        doc.on("end", () => {
            const pdfBuffer = Buffer.concat(chunks);

            return res.status(200).json({
                success: true,
                tipo: tipo || "NFe",
                chave,
                pdfBase64: pdfBuffer.toString("base64")
            });
        });

        const larguraPagina = 595;
        const margem = 28;
        const larguraUtil = larguraPagina - margem * 2;

        function linha(y) {
            doc
                .moveTo(margem, y)
                .lineTo(larguraPagina - margem, y)
                .lineWidth(0.7)
                .strokeColor("#222222")
                .stroke();
        }

        function caixa(x, y, largura, altura, titulo) {
            doc
                .rect(x, y, largura, altura)
                .lineWidth(0.7)
                .strokeColor("#222222")
                .stroke();

            if (titulo) {
                doc
                    .font("Helvetica-Bold")
                    .fontSize(7)
                    .fillColor("#222222")
                    .text(titulo, x + 5, y + 4, {
                        width: largura - 10,
                        height: 10
                    });
            }
        }

        function texto(label, valor, x, y, largura, tamanho = 8) {
            doc
                .font("Helvetica-Bold")
                .fontSize(7)
                .fillColor("#333333")
                .text(label, x, y, {
                    width: largura
                });

            doc
                .font("Helvetica")
                .fontSize(tamanho)
                .fillColor("#000000")
                .text(valor || "N/D", x, y + 9, {
                    width: largura,
                    ellipsis: true
                });
        }

        // Cabeçalho DANFE
        doc
            .font("Helvetica-Bold")
            .fontSize(13)
            .fillColor("#000000")
            .text("DANFE", margem, 30, {
                width: 90,
                align: "center"
            });

        doc
            .font("Helvetica")
            .fontSize(7)
            .text("Documento Auxiliar da Nota Fiscal Eletrônica", margem, 47, {
                width: 90,
                align: "center"
            });

        doc
            .font("Helvetica-Bold")
            .fontSize(9)
            .text("0 - ENTRADA     1 - SAÍDA", 130, 32, {
                width: 160,
                align: "center"
            });

        doc
            .font("Helvetica-Bold")
            .fontSize(10)
            .text(`NF-e Nº ${numeroNF}`, 340, 30, {
                width: 200,
                align: "right"
            });

        doc
            .font("Helvetica")
            .fontSize(8)
            .text(`Série: ${serie}`, 340, 45, {
                width: 200,
                align: "right"
            });

        linha(68);

        // Identificação do emitente
        caixa(margem, 76, larguraUtil, 78, "IDENTIFICAÇÃO DO EMITENTE");

        doc
            .font("Helvetica-Bold")
            .fontSize(11)
            .text(nomeEmitente, margem + 8, 94, {
                width: 270
            });

        if (fantasia) {
            doc
                .font("Helvetica")
                .fontSize(8)
                .text(`Nome fantasia: ${fantasia}`, margem + 8, 110, {
                    width: 270
                });
        }

        doc
            .font("Helvetica")
            .fontSize(8)
            .text(
                `CNPJ: ${cnpjEmitente}`,
                margem + 8,
                127,
                { width: 270 }
            );

        doc
            .font("Helvetica")
            .fontSize(8)
            .text(
                `${endereco || "Endereço não informado"}, ${numero || "S/N"}`,
                315,
                94,
                { width: 235 }
            );

        doc
            .font("Helvetica")
            .fontSize(8)
            .text(
                `${bairro || ""} - ${cidade || ""}/${uf || ""}`,
                315,
                110,
                { width: 235 }
            );

        doc
            .font("Helvetica")
            .fontSize(8)
            .text(
                `CEP: ${cep || "N/D"}`,
                315,
                127,
                { width: 235 }
            );

        // Dados da NF-e
        caixa(margem, 162, larguraUtil, 68, "DADOS DA NF-e");

        texto("CHAVE DE ACESSO", chave, margem + 8, 180, 350, 8);

        doc
            .font("Helvetica-Bold")
            .fontSize(8)
            .text("PROTOCOLO DE AUTORIZAÇÃO", 400, 180, {
                width: 150
            });

        doc
            .font("Helvetica")
            .fontSize(8)
            .text(protocolo, 400, 190, {
                width: 150
            });

        texto(
            "NATUREZA DA OPERAÇÃO",
            naturezaOperacao,
            margem + 8,
            207,
            270,
            8
        );

        texto(
            "DATA DE EMISSÃO",
            formatarData(dataEmissao),
            315,
            207,
            120,
            8
        );

        texto(
            "TIPO",
            tipo || "NFe",
            450,
            207,
            90,
            8
        );

        // Destinatário
        caixa(margem, 238, larguraUtil, 62, "DESTINATÁRIO / REMETENTE");

        texto(
            "DOCUMENTO",
            cnpjDestinatario || "N/D",
            margem + 8,
            256,
            180,
            8
        );

        texto(
            "CHAVE DE ACESSO",
            chave,
            220,
            256,
            315,
            8
        );

        // Totais
        caixa(margem, 308, larguraUtil, 65, "CÁLCULO DO IMPOSTO");

        texto(
            "VALOR DOS PRODUTOS",
            formatarMoeda(valorProdutos),
            margem + 8,
            326,
            130,
            8
        );

        texto(
            "VALOR DO FRETE",
            formatarMoeda(valorFrete),
            170,
            326,
            110,
            8
        );

        texto(
            "DESCONTO",
            formatarMoeda(valorDesconto),
            295,
            326,
            100,
            8
        );

        texto(
            "VALOR TOTAL DA NF",
            formatarMoeda(valorNota),
            410,
            326,
            125,
            9
        );

        // Informações adicionais
        caixa(margem, 381, larguraUtil, 94, "INFORMAÇÕES ADICIONAIS");

        doc
            .font("Helvetica")
            .fontSize(8)
            .text(
                "Documento gerado automaticamente pelo sistema.",
                margem + 8,
                402,
                {
                    width: larguraUtil - 16
                }
            );

        doc
            .font("Helvetica")
            .fontSize(8)
            .text(
                `Chave de acesso: ${chave}`,
                margem + 8,
                420,
                {
                    width: larguraUtil - 16
                }
            );

        doc
            .font("Helvetica")
            .fontSize(8)
            .text(
                `Emitente: ${nomeEmitente}`,
                margem + 8,
                438,
                {
                    width: larguraUtil - 16
                }
            );

        // Rodapé
        linha(505);

        doc
            .font("Helvetica")
            .fontSize(7)
            .fillColor("#555555")
            .text(
                "DANFE gerado automaticamente pelo Bridge SEFAZ.",
                margem,
                518,
                {
                    width: larguraUtil,
                    align: "center"
                }
            );

        doc
            .font("Helvetica")
            .fontSize(7)
            .text(
                `Gerado em ${new Date().toLocaleString("pt-BR")}`,
                margem,
                532,
                {
                    width: larguraUtil,
                    align: "center"
                }
            );

        doc.end();
    } catch (error) {
        console.error("Erro ao gerar DANFE PDF:", error);

        if (!res.headersSent) {
            return res.status(500).json({
                success: false,
                error: error.message || "Erro interno ao gerar PDF"
            });
        }
    }
});

/* ============================================================
   MANIFESTAÇÃO DO DESTINATÁRIO
============================================================ */

function obterAmbienteNFe() {
    return process.env.NFE_AMBIENTE === "2" ? "2" : "1";
}

function obterEndpointManifestacao(endpointFornecido = null) {
    if (endpointFornecido) {
        const url = new URL(endpointFornecido);

        if (url.protocol !== "https:") {
            throw new Error("Endpoint precisa utilizar HTTPS.");
        }

        return endpointFornecido;
    }

    if (obterAmbienteNFe() === "1") {
        return "https://www.nfe.fazenda.gov.br/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx";
    }

    return "https://hom.nfe.fazenda.gov.br/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx";
}

function normalizarCNPJ(cnpj) {
    const valor = somenteDigitos(cnpj);

    if (valor.length !== 14) {
        throw new Error("CNPJ inválido. Esperados 14 dígitos.");
    }

    return valor;
}

function normalizarChaveNFe(chave) {
    const valor = somenteDigitos(chave);

    if (valor.length !== 44) {
        throw new Error("Chave NF-e inválida. Esperados 44 dígitos.");
    }

    return valor;
}

function gerarDhEvento() {
    const agora = new Date();
    const offset = -agora.getTimezoneOffset();
    const sinal = offset >= 0 ? "+" : "-";
    const absoluto = Math.abs(offset);

    const pad = (numero) => String(numero).padStart(2, "0");

    return (
        agora.getFullYear() +
        "-" +
        pad(agora.getMonth() + 1) +
        "-" +
        pad(agora.getDate()) +
        "T" +
        pad(agora.getHours()) +
        ":" +
        pad(agora.getMinutes()) +
        ":" +
        pad(agora.getSeconds()) +
        sinal +
        pad(Math.floor(absoluto / 60)) +
        ":" +
        pad(absoluto % 60)
    );
}

function gerarIdLote() {
    return String(Date.now()).slice(-15);
}

const TIPOS_MANIFESTACAO = {
    confirmada: {
        codigo: "210200",
        descricao: "Confirmacao da Operacao"
    },
    ciencia: {
        codigo: "210210",
        descricao: "Ciencia da Operacao"
    },
    desconhecida: {
        codigo: "210220",
        descricao: "Desconhecimento da Operacao"
    },
    nao_realizada: {
        codigo: "210240",
        descricao: "Operacao nao Realizada"
    }
};

function extrairCertificadoA1(pfxBase64, password) {
    if (!pfxBase64) {
        throw new Error("Certificado PFX não informado.");
    }

    if (!password) {
        throw new Error("Senha do certificado não informada.");
    }

    try {
        const pfxDer = forge.util.decode64(sanitizarBase64(pfxBase64));
        const pfxAsn1 = forge.asn1.fromDer(pfxDer);
        const p12 = forge.pkcs12.pkcs12FromAsn1(
            pfxAsn1,
            false,
            password
        );

        let privateKey = null;
        let certificate = null;

        for (const safeContents of p12.safeContents) {
            for (const safeBag of safeContents.safeBags) {
                if (
                    safeBag.type === forge.pki.oids.keyBag ||
                    safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag
                ) {
                    if (safeBag.key) {
                        privateKey = safeBag.key;
                    }
                }

                if (
                    safeBag.type === forge.pki.oids.certBag &&
                    safeBag.cert &&
                    !certificate
                ) {
                    certificate = safeBag.cert;
                }
            }
        }

        if (!privateKey) {
            throw new Error("Chave privada não encontrada.");
        }

        if (!certificate) {
            throw new Error("Certificado X509 não encontrado.");
        }

        const privateKeyPem = forge.pki.privateKeyToPem(privateKey);

        const certPem = forge.pki.certificateToPem(certificate);

        const certBase64 = certPem
            .replace(/-----BEGIN CERTIFICATE-----/g, "")
            .replace(/-----END CERTIFICATE-----/g, "")
            .replace(/\r?\n/g, "")
            .trim();

        return {
            privateKeyPem,
            certBase64
        };
    } catch (error) {
        throw new Error("Erro ao abrir certificado A1: " + error.message);
    }
}

function gerarEventoManifestacaoAssinado(
    cnpj,
    chave,
    tipoManifestacao,
    pfxBase64,
    password
) {
    const evento = TIPOS_MANIFESTACAO[tipoManifestacao];

    if (!evento) {
        throw new Error(
            "Tipo de manifestação inválido: " + tipoManifestacao
        );
    }

    const cnpjLimpo = normalizarCNPJ(cnpj);
    const chaveLimpa = normalizarChaveNFe(chave);
    const idEvento =
        "ID" + evento.codigo + chaveLimpa + "01";

    let detalheExtra = "";

    if (evento.codigo === "210240") {
        detalheExtra =
            "<xJust>Operacao nao realizada pelo destinatario</xJust>";
    }

    const infEvento =
        `<infEvento Id="${idEvento}">` +
        `<cOrgao>91</cOrgao>` +
        `<tpAmb>${obterAmbienteNFe()}</tpAmb>` +
        `<CNPJ>${cnpjLimpo}</CNPJ>` +
        `<chNFe>${chaveLimpa}</chNFe>` +
        `<dhEvento>${gerarDhEvento()}</dhEvento>` +
        `<tpEvento>${evento.codigo}</tpEvento>` +
        `<nSeqEvento>1</nSeqEvento>` +
        `<verEvento>1.00</verEvento>` +
        `<detEvento versao="1.00">` +
        `<descEvento>${evento.descricao}</descEvento>` +
        detalheExtra +
        `</detEvento>` +
        `</infEvento>`;

    const eventoXml =
        `<evento xmlns="${NFE_NAMESPACE}" versao="1.00">` +
        infEvento +
        `</evento>`;

    const { privateKeyPem, certBase64 } =
        extrairCertificadoA1(pfxBase64, password);

    const assinatura = new SignedXml();

    assinatura.canonicalizationAlgorithm =
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

    assinatura.signatureAlgorithm =
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    assinatura.addReference({
        xpath: `//*[local-name(.)='infEvento' and @Id='${idEvento}']`,
        transforms: [
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        ],
        digestAlgorithm:
            "http://www.w3.org/2000/09/xmldsig#sha1"
    });

    assinatura.privateKey = privateKeyPem;

    assinatura.getKeyInfoContent = () =>
        `<X509Data><X509Certificate>${certBase64}</X509Certificate></X509Data>`;

    assinatura.keyInfoProvider = {
        getKeyInfo: () =>
            `<X509Data><X509Certificate>${certBase64}</X509Certificate></X509Data>`
    };

    assinatura.computeSignature(eventoXml, {
        location: {
            reference: `//*[local-name(.)='infEvento' and @Id='${idEvento}']`,
            action: "after"
        }
    });

    const xmlAssinado = assinatura.getSignedXml();

    if (!xmlAssinado.includes("<Signature")) {
        throw new Error("Falha ao gerar assinatura XML.");
    }

    return xmlAssinado;
}

function gerarManifestacaoXML(
    cnpj,
    chave,
    tipoManifestacao,
    pfxBase64,
    password
) {
    const eventoAssinado = gerarEventoManifestacaoAssinado(
        cnpj,
        chave,
        tipoManifestacao,
        pfxBase64,
        password
    );

    return (
        `<?xml version="1.0" encoding="utf-8"?>` +
        `<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ` +
        `xmlns:xsd="http://www.w3.org/2001/XMLSchema" ` +
        `xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">` +
        `<soap12:Body>` +
        `<nfeDadosMsg xmlns="${NFE_EVENTO_WSDL_NAMESPACE}">` +
        `<envEvento xmlns="${NFE_NAMESPACE}" versao="1.00">` +
        `<idLote>${gerarIdLote()}</idLote>` +
        eventoAssinado +
        `</envEvento>` +
        `</nfeDadosMsg>` +
        `</soap12:Body>` +
        `</soap12:Envelope>`
    );
}

function interpretarRespostaManifestacao(body, statusCode) {
    const cStats = extrairTagsXml(body, "cStat");
    const motivos = extrairTagsXml(body, "xMotivo");

    const cStatLote = cStats[0] || null;
    const cStatEvento =
        cStats.length > 1
            ? cStats[cStats.length - 1]
            : cStatLote;

    const sucesso =
        statusCode === 200 &&
        ["135", "136"].includes(cStatEvento);

    return {
        sucesso,
        cStatLote,
        cStatEvento,
        motivo: motivos[motivos.length - 1] || null,
        protocolo: extrairTagXml(body, "nProt"),
        dhRegEvento: extrairTagXml(body, "dhRegEvento")
    };
}

app.post("/rpa/xml/manifest", validarAPI, async (req, res) => {
    let finalizado = false;
    const requestId = crypto.randomUUID();

    try {
        const {
            pfxBase64,
            password,
            cnpj,
            chave,
            tipoManifestacao,
            endpoint
        } = req.body;

        if (
            !pfxBase64 ||
            !password ||
            !cnpj ||
            !chave ||
            !tipoManifestacao
        ) {
            return res.status(400).json({
                success: false,
                requestId,
                error:
                    "pfxBase64, password, cnpj, chave e tipoManifestacao são obrigatórios."
            });
        }

        if (!TIPOS_MANIFESTACAO[tipoManifestacao]) {
            return res.status(400).json({
                success: false,
                requestId,
                error: "Tipo de manifestação inválido."
            });
        }

        const cnpjLimpo = normalizarCNPJ(cnpj);
        const chaveLimpa = normalizarChaveNFe(chave);
        const certificado = Buffer.from(
            sanitizarBase64(pfxBase64),
            "base64"
        );

        tls.createSecureContext({
            pfx: certificado,
            passphrase: password
        });

        const soapEnvelope = gerarManifestacaoXML(
            cnpjLimpo,
            chaveLimpa,
            tipoManifestacao,
            pfxBase64,
            password
        );

        const urlDestino = obterEndpointManifestacao(endpoint);
        const endpointUrl = new URL(urlDestino);
        const soapBuffer = Buffer.from(soapEnvelope, "utf8");

        const options = {
            hostname: endpointUrl.hostname,
            port: endpointUrl.port || 443,
            path: endpointUrl.pathname + endpointUrl.search,
            method: "POST",
            pfx: certificado,
            passphrase: password,
            minVersion: "TLSv1.2",
            rejectUnauthorized: true,
            headers: {
                "Content-Type": `application/soap+xml; charset=utf-8; action="${NFE_EVENTO_SOAP_ACTION}"`,
                Accept: "application/soap+xml, text/xml, */*",
                "User-Agent": "Bridge-SEFAZ/1.4",
                "Content-Length": soapBuffer.length
            }
        };

        const requisicao = https.request(options, (resposta) => {
            let body = "";

            resposta.setEncoding("utf8");

            resposta.on("data", (chunk) => {
                body += chunk;
            });

            resposta.on("end", () => {
                if (finalizado) return;

                finalizado = true;

                const retorno = interpretarRespostaManifestacao(
                    body,
                    resposta.statusCode
                );

                if (retorno.sucesso) {
                    return res.json({
                        success: true,
                        requestId,
                        cStat: retorno.cStatEvento,
                        message:
                            retorno.motivo ||
                            "Manifestação registrada com sucesso.",
                        protocolo: retorno.protocolo,
                        dhRegEvento: retorno.dhRegEvento
                    });
                }

                const erro =
                    retorno.motivo ||
                    extrairTagXml(body, "faultstring") ||
                    extrairTagXml(body, "Text") ||
                    `HTTP ${resposta.statusCode} retornado pela SEFAZ.`;

                return res.status(400).json({
                    success: false,
                    requestId,
                    statusCode: resposta.statusCode,
                    cStat: retorno.cStatEvento,
                    error: erro
                });
            });
        });

        requisicao.setTimeout(60000, () => {
            requisicao.destroy();

            if (!finalizado) {
                finalizado = true;

                return res.status(504).json({
                    success: false,
                    requestId,
                    error: "Timeout ao conectar com a SEFAZ."
                });
            }
        });

        requisicao.on("error", (error) => {
            if (!finalizado) {
                finalizado = true;

                return res.status(502).json({
                    success: false,
                    requestId,
                    error: "Erro de comunicação: " + error.message
                });
            }
        });

        requisicao.write(soapBuffer);
        requisicao.end();
    } catch (error) {
        if (!res.headersSent) {
            return res.status(500).json({
                success: false,
                requestId,
                error: error.message
            });
        }
    }
});

/* ============================================================
   TRATAMENTO DE ROTAS
============================================================ */

app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: "Endpoint inexistente."
    });
});

app.use((error, req, res, next) => {
    console.error("ERRO INTERNO:", error);

    if (res.headersSent) {
        return next(error);
    }

    return res.status(500).json({
        success: false,
        error: "Erro interno do servidor."
    });
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(
        `BRIDGE SEFAZ ONLINE - Porta: ${PORT} - Ambiente: ${
            process.env.NODE_ENV || "development"
        }`
    );
});
