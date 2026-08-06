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
import bwipjs from "bwip-js";

const app = express();

const PORT = Number(process.env.PORT || 3000);
const AUTH_KEY = process.env.AUTH_KEY;
const XML_KEY = process.env.XML_KEY;

const NFE_NAMESPACE = "http://www.portalfiscal.inf.br/nfe";

const NFE_EVENTO_WSDL_NAMESPACE =
    "http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4";

const NFE_EVENTO_SOAP_ACTION =
    "http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4/nfeRecepcaoEvento";

const VERSAO = "2.0.0";

process.on("uncaughtException", (error) => {
    console.error("ERRO NÃO TRATADO:", error);
});

process.on("unhandledRejection", (reason) => {
    console.error("PROMISE NÃO TRATADA:", reason);
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

/* ============================================================
   FUNÇÕES GERAIS
============================================================ */

function sanitizarBase64(valor) {
    if (typeof valor !== "string") {
        return "";
    }

    return valor
        .replace(/^data:.*?;base64,/i, "")
        .replace(/\s+/g, "")
        .trim();
}

function somenteDigitos(valor) {
    return String(valor || "").replace(/\D/g, "");
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
    if (!valor) {
        return "";
    }

    return String(valor)
        .replace(/&amp;/g, "&")
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&quot;/g, '"')
        .replace(/&apos;/g, "'")
        .replace(/&#(\d+);/g, (_, codigo) =>
            String.fromCharCode(Number(codigo))
        )
        .replace(/&#x([0-9a-f]+);/gi, (_, codigo) =>
            String.fromCharCode(parseInt(codigo, 16))
        )
        .trim();
}

function extrairTagXml(xml, tag, origem = null) {
    if (!xml) {
        return "";
    }

    const conteudo = origem || xml;

    const regex = new RegExp(
        `<(?:[\\w.-]+:)?${tag}\\b[^>]*>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?${tag}>`,
        "i"
    );

    const resultado = conteudo.match(regex);

    return resultado ? decodeXml(resultado[1]) : "";
}

function extrairTagsXml(xml, tag) {
    if (!xml) {
        return [];
    }

    const regex = new RegExp(
        `<(?:[\\w.-]+:)?${tag}\\b[^>]*>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?${tag}>`,
        "gi"
    );

    const valores = [];
    let resultado;

    while ((resultado = regex.exec(xml)) !== null) {
        valores.push(decodeXml(resultado[1]));
    }

    return valores;
}

function extrairBlocoXml(xml, tag) {
    if (!xml) {
        return "";
    }

    const regex = new RegExp(
        `<(?:[\\w.-]+:)?${tag}\\b[^>]*>[\\s\\S]*?<\\/(?:[\\w.-]+:)?${tag}>`,
        "i"
    );

    const resultado = xml.match(regex);

    return resultado ? resultado[0] : "";
}

function extrairTodosBlocosXml(xml, tag) {
    if (!xml) {
        return [];
    }

    const regex = new RegExp(
        `<(?:[\\w.-]+:)?${tag}\\b[^>]*>[\\s\\S]*?<\\/(?:[\\w.-]+:)?${tag}>`,
        "gi"
    );

    return xml.match(regex) || [];
}

function extrairAtributoXml(bloco, atributo) {
    if (!bloco) {
        return "";
    }

    const regex = new RegExp(
        `${atributo}\\s*=\\s*["']([^"']*)["']`,
        "i"
    );

    const resultado = bloco.match(regex);

    return resultado ? decodeXml(resultado[1]) : "";
}

function converterNumero(valor) {
    if (valor === null || valor === undefined || valor === "") {
        return 0;
    }

    const texto = String(valor).trim();

    const numero = Number(texto);

    if (Number.isFinite(numero)) {
        return numero;
    }

    const brasileiro = Number(
        texto.replace(/\./g, "").replace(",", ".")
    );

    return Number.isFinite(brasileiro) ? brasileiro : 0;
}

function formatarMoeda(valor) {
    return converterNumero(valor).toLocaleString("pt-BR", {
        style: "currency",
        currency: "BRL"
    });
}

function formatarNumero(valor, casas = 2) {
    return converterNumero(valor).toLocaleString("pt-BR", {
        minimumFractionDigits: casas,
        maximumFractionDigits: casas
    });
}

function formatarCnpjCpf(valor) {
    const digitos = somenteDigitos(valor);

    if (digitos.length === 14) {
        return digitos.replace(
            /^(\d{2})(\d{3})(\d{3})(\d{4})(\d{2})$/,
            "$1.$2.$3/$4-$5"
        );
    }

    if (digitos.length === 11) {
        return digitos.replace(
            /^(\d{3})(\d{3})(\d{3})(\d{2})$/,
            "$1.$2.$3-$4"
        );
    }

    return valor || "";
}

function formatarCep(valor) {
    const digitos = somenteDigitos(valor);

    if (digitos.length === 8) {
        return digitos.replace(/^(\d{5})(\d{3})$/, "$1-$2");
    }

    return valor || "";
}

function formatarChave(chave) {
    const digitos = somenteDigitos(chave);

    return digitos.replace(/(.{4})/g, "$1 ").trim();
}

function formatarData(valor) {
    if (!valor) {
        return "N/D";
    }

    const texto = String(valor)
        .replace("T", " ")
        .replace(/[+-]\d{2}:\d{2}$/, "");

    const data = new Date(valor);

    if (Number.isNaN(data.getTime())) {
        return texto;
    }

    return data.toLocaleString("pt-BR");
}

function obterChaveNFe(xml) {
    const chaveDireta =
        extrairTagXml(xml, "chNFe") ||
        extrairTagXml(xml, "chCTe") ||
        extrairTagXml(xml, "chMDFe");

    if (chaveDireta) {
        return somenteDigitos(chaveDireta);
    }

    const id = xml.match(
        /Id=["'](?:NFe|CTe|MDFe)?([0-9]{44})["']/i
    );

    return id ? id[1] : "";
}

function limitarTexto(valor, tamanho = 100) {
    const texto = String(valor || "").trim();

    if (texto.length <= tamanho) {
        return texto;
    }

    return `${texto.substring(0, tamanho - 3)}...`;
}

function textoSeguro(valor, padrao = "N/D") {
    const texto = String(valor || "").trim();

    return texto || padrao;
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
   ROTAS BÁSICAS
============================================================ */

app.get("/health", (req, res) => {
    res.json({
        status: "online",
        service: "Bridge SEFAZ",
        version: VERSAO,
        node: process.version,
        timestamp: new Date().toISOString()
    });
});

app.get("/version", (req, res) => {
    res.json({
        service: "Bridge SEFAZ",
        version: VERSAO,
        node: process.version
    });
});

app.get("/api/info", (req, res) => {
    res.json({
        success: true,
        service: "Bridge SEFAZ",
        version: VERSAO,
        authKeyConfigured: Boolean(AUTH_KEY),
        xmlKeyConfigured: Boolean(XML_KEY)
    });
});

app.get("/api/test-auth", validarAPI, (req, res) => {
    res.json({
        success: true,
        message: "Autenticação OK"
    });
});

/* ============================================================
   COMUNICAÇÃO HTTPS COM A SEFAZ
============================================================ */

function executarRequisicaoHttps({
    endpoint,
    certificado,
    password,
    body,
    soapAction
}) {
    return new Promise((resolve, reject) => {
        const endpointUrl = new URL(endpoint);

        if (endpointUrl.protocol !== "https:") {
            reject(new Error("O endpoint da SEFAZ precisa utilizar HTTPS."));
            return;
        }

        const bodyBuffer = Buffer.from(body, "utf8");

        const opcoes = {
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
                "User-Agent": "Bridge-SEFAZ/2.0",
                "Content-Length": bodyBuffer.length
            }
        };

        const requisicao = https.request(opcoes, (resposta) => {
            let respostaBody = "";

            resposta.setEncoding("utf8");

            resposta.on("data", (chunk) => {
                respostaBody += chunk;
            });

            resposta.on("end", () => {
                resolve({
                    statusCode: resposta.statusCode,
                    body: respostaBody
                });
            });
        });

        requisicao.setTimeout(60000, () => {
            requisicao.destroy(
                new Error("Timeout na comunicação com a SEFAZ.")
            );
        });

        requisicao.on("error", reject);

        requisicao.write(bodyBuffer);
        requisicao.end();
    });
}

/* ============================================================
   DISTRIBUIÇÃO DF-E
============================================================ */

function processarRespostaSefaz(soapXml) {
    const retorno = {
        cStat: extrairTagXml(soapXml, "cStat"),
        xMotivo: extrairTagXml(soapXml, "xMotivo"),
        ultNSU: extrairTagXml(soapXml, "ultNSU"),
        maxNSU: extrairTagXml(soapXml, "maxNSU"),
        docs: []
    };

    const regex =
        /<docZip\b[^>]*NSU="([^"]+)"[^>]*schema="([^"]+)"[^>]*>([\s\S]*?)<\/docZip>/gi;

    let resultado;

    while ((resultado = regex.exec(soapXml)) !== null) {
        const nsu = resultado[1];
        const schema = resultado[2];
        const conteudo = resultado[3].replace(/\s+/g, "");

        try {
            const xml = zlib
                .gunzipSync(Buffer.from(conteudo, "base64"))
                .toString("utf8");

            retorno.docs.push({
                nsu,
                schema,
                xml
            });
        } catch (error) {
            console.error(
                `Erro ao descompactar NSU ${nsu}:`,
                error.message
            );
        }
    }

    return retorno;
}

async function consultarSefaz(req, res) {
    const requestId = crypto.randomUUID();

    try {
        const {
            pfxBase64,
            password,
            endpoint,
            soapEnvelope,
            soapAction
        } = req.body || {};

        if (!pfxBase64 || !password || !endpoint || !soapEnvelope) {
            return res.status(400).json({
                success: false,
                requestId,
                error:
                    "pfxBase64, password, endpoint e soapEnvelope são obrigatórios."
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
                error: `Erro no certificado PFX: ${error.message}`
            });
        }

        const action =
            soapAction ||
            "http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe/nfeDistDFeInteresse";

        const resposta = await executarRequisicaoHttps({
            endpoint,
            certificado,
            password,
            body: soapEnvelope,
            soapAction: action
        });

        const processado = processarRespostaSefaz(resposta.body);
        const sucesso = resposta.statusCode === 200;

        return res.status(sucesso ? 200 : 422).json({
            success: sucesso,
            requestId,
            statusCode: resposta.statusCode,
            cStat: processado.cStat,
            xMotivo: processado.xMotivo,
            ultNSU: processado.ultNSU,
            maxNSU: processado.maxNSU,
            docs: processado.docs,
            soapResponse: resposta.body
        });
    } catch (error) {
        console.error("Erro na consulta SEFAZ:", error);

        return res.status(502).json({
            success: false,
            requestId,
            error: error.message || "Erro de comunicação com a SEFAZ."
        });
    }
}

app.post(
    "/api/sefaz/distribuicao",
    validarAPI,
    consultarSefaz
);

app.post(
    "/api/sefaz/consultar",
    validarAPI,
    consultarSefaz
);

app.post(
    "/backend/v1/xml/sync",
    validarAPI,
    consultarSefaz
);

/* ============================================================
   EXTRAÇÃO DOS DADOS DA NF-E
============================================================ */

function extrairDadosNfe(xml, tipo = "NFe") {
    const blocoInfNFe =
        extrairBlocoXml(xml, "infNFe") || xml;

    const blocoEmit =
        extrairBlocoXml(blocoInfNFe, "emit");

    const blocoDest =
        extrairBlocoXml(blocoInfNFe, "dest");

    const blocoIde =
        extrairBlocoXml(blocoInfNFe, "ide");

    const blocoTotal =
        extrairBlocoXml(blocoInfNFe, "total");

    const blocoIcmsTot =
        extrairBlocoXml(blocoTotal, "ICMSTot");

    const blocoTransp =
        extrairBlocoXml(blocoInfNFe, "transp");

    const blocoInfAdic =
        extrairBlocoXml(blocoInfNFe, "infAdic");

    const blocoProt =
        extrairBlocoXml(xml, "infProt");

    const emitEndereco = [
        extrairTagXml(blocoEmit, "xLgr"),
        extrairTagXml(blocoEmit, "nro")
    ]
        .filter(Boolean)
        .join(", ");

    const emitCidade = [
        extrairTagXml(blocoEmit, "xBairro"),
        extrairTagXml(blocoEmit, "xMun"),
        extrairTagXml(blocoEmit, "UF")
    ]
        .filter(Boolean)
        .join(" - ")
        .replace(/ - ([A-Z]{2})$/, "/$1");

    const destEndereco = [
        extrairTagXml(blocoDest, "xLgr"),
        extrairTagXml(blocoDest, "nro")
    ]
        .filter(Boolean)
        .join(", ");

    const destinatarioDocumento =
        extrairTagXml(blocoDest, "CNPJ") ||
        extrairTagXml(blocoDest, "CPF");

    const produtos = extrairTodosBlocosXml(
        blocoInfNFe,
        "det"
    ).map((det, indice) => {
        const blocoProduto = extrairBlocoXml(det, "prod");

        const blocoImposto = extrairBlocoXml(det, "imposto");

        return {
            numero: indice + 1,
            codigo: extrairTagXml(blocoProduto, "cProd"),
            descricao: extrairTagXml(blocoProduto, "xProd"),
            ncm: extrairTagXml(blocoProduto, "NCM"),
            cfop: extrairTagXml(blocoProduto, "CFOP"),
            unidade: extrairTagXml(blocoProduto, "uCom"),
            quantidade: extrairTagXml(blocoProduto, "qCom"),
            valorUnitario: extrairTagXml(blocoProduto, "vUnCom"),
            valorTotal: extrairTagXml(blocoProduto, "vProd"),
            valorDesconto: extrairTagXml(blocoProduto, "vDesc"),
            imposto: blocoImposto
        };
    });

    const informacoesAdicionais =
        extrairTagXml(blocoInfAdic, "infCpl") ||
        extrairTagXml(blocoInfAdic, "infAdFisco");

    return {
        tipo,

        chave: obterChaveNFe(xml),

        numero: extrairTagXml(blocoIde, "nNF"),
        serie: extrairTagXml(blocoIde, "serie"),
        modelo: extrairTagXml(blocoIde, "mod"),
        naturezaOperacao: extrairTagXml(blocoIde, "natOp"),
        tipoOperacao: extrairTagXml(blocoIde, "tpNF"),
        dataEmissao:
            extrairTagXml(blocoIde, "dhEmi") ||
            extrairTagXml(blocoIde, "dEmi"),

        emitente: {
            nome: extrairTagXml(blocoEmit, "xNome"),
            fantasia: extrairTagXml(blocoEmit, "xFant"),
            cnpj: extrairTagXml(blocoEmit, "CNPJ"),
            ie: extrairTagXml(blocoEmit, "IE"),
            endereco: emitEndereco,
            bairro: extrairTagXml(blocoEmit, "xBairro"),
            cidade: emitCidade,
            cep: extrairTagXml(blocoEmit, "CEP"),
            uf: extrairTagXml(blocoEmit, "UF")
        },

        destinatario: {
            nome: extrairTagXml(blocoDest, "xNome"),
            documento: destinatarioDocumento,
            ie: extrairTagXml(blocoDest, "IE"),
            endereco: destEndereco,
            bairro: extrairTagXml(blocoDest, "xBairro"),
            cidade: extrairTagXml(blocoDest, "xMun"),
            uf: extrairTagXml(blocoDest, "UF"),
            cep: extrairTagXml(blocoDest, "CEP")
        },

        protocolo:
            extrairTagXml(blocoProt, "nProt") ||
            extrairTagXml(xml, "nProt"),

        produtos,

        transporte: {
            modalidade: extrairTagXml(blocoTransp, "modFrete"),
            transportadora: extrairTagXml(blocoTransp, "xNome"),
            cnpj: extrairTagXml(blocoTransp, "CNPJ"),
            placa: extrairTagXml(blocoTransp, "placa"),
            uf: extrairTagXml(blocoTransp, "UF")
        },

        totais: {
            produtos: extrairTagXml(blocoIcmsTot, "vProd"),
            frete: extrairTagXml(blocoIcmsTot, "vFrete"),
            seguro: extrairTagXml(blocoIcmsTot, "vSeg"),
            desconto: extrairTagXml(blocoIcmsTot, "vDesc"),
            outrasDespesas: extrairTagXml(blocoIcmsTot, "vOutro"),
            ipi: extrairTagXml(blocoIcmsTot, "vIPI"),
            icms: extrairTagXml(blocoIcmsTot, "vICMS"),
            valorNota: extrairTagXml(blocoIcmsTot, "vNF")
        },

        informacoesAdicionais
    };
}

/* ============================================================
   COMPONENTES DO DANFE (PADRÃO OFICIAL MOC)
============================================================ */

async function criarCodigoBarras(chave) {
    return bwipjs.toBuffer({
        bcid: "code128",
        text: chave,
        scale: 2,
        height: 10,
        includetext: false,
        backgroundcolor: "FFFFFF"
    });
}

function desenharBorda(doc, x, y, largura, altura, espessura = 0.5) {
    doc.lineWidth(espessura)
       .strokeColor("#000000")
       .rect(x, y, largura, altura)
       .stroke();
}

function desenharCampo(doc, titulo, valor, x, y, largura, altura, tamTitulo = 5.5, tamValor = 7) {
    desenharBorda(doc, x, y, largura, altura);
    
    doc.font("Helvetica-Bold")
       .fontSize(tamTitulo)
       .fillColor("#000000")
       .text(titulo, x + 3, y + 3, { width: largura - 6, lineBreak: false });

    doc.font("Helvetica")
       .fontSize(tamValor)
       .text(textoSeguro(valor, ""), x + 3, y + 12, { 
           width: largura - 6, 
           height: altura - 14, 
           ellipsis: true, 
           lineBreak: false 
       });
}

function desenharLinhaTracejada(doc, margem, largura, y) {
    doc.lineWidth(0.5)
       .strokeColor("#000000")
       .dash(3, { space: 3 })
       .moveTo(margem, y)
       .lineTo(margem + largura, y)
       .stroke()
       .undash();
}

function desenharCanhoto(doc, margem, largura, y) {
    const altura = 35;
    desenharBorda(doc, margem, y, largura, altura);
    
    doc.font("Helvetica").fontSize(6)
       .text("RECEBEMOS DOS PRODUTOS E/OU SERVIÇOS CONSTANTES DA NOTA FISCAL ELETRÔNICA INDICADA ABAIXO", margem + 3, y + 3, { width: largura - 150 });
       
    desenharBorda(doc, margem, y + 12, 110, 23);
    doc.font("Helvetica-Bold").fontSize(5.5).text("DATA DE RECEBIMENTO", margem + 3, y + 14);
    
    desenharBorda(doc, margem + 110, y + 12, largura - 260, 23);
    doc.font("Helvetica-Bold").fontSize(5.5).text("IDENTIFICAÇÃO E ASSINATURA DO RECEBEDOR", margem + 113, y + 14);

    // Bloco direito do canhoto (NF-e Número)
    desenharBorda(doc, margem + largura - 150, y, 150, altura);
    doc.font("Helvetica-Bold").fontSize(10)
       .text("NF-e", margem + largura - 140, y + 8, { width: 130, align: "center" });
    
    return y + altura + 10;
}

function desenharCabecalhoPrincipal(doc, dados, margem, largura, y, codigoBarras, paginaAtual, totalPaginas) {
    const altura = 90;
    
    // Bloco Emitente
    const wEmit = 240;
    desenharBorda(doc, margem, y, wEmit, altura);
    doc.font("Helvetica-Bold").fontSize(9).text(limitarTexto(dados.emitente.nome, 60), margem + 3, y + 5, { width: wEmit - 6, align: "center" });
    doc.font("Helvetica").fontSize(7).text(`${dados.emitente.endereco}, ${dados.emitente.bairro}`, margem + 3, y + 30, { width: wEmit - 6, align: "center" });
    doc.text(`${dados.emitente.cidade} - ${dados.emitente.uf} | CEP: ${formatarCep(dados.emitente.cep)}`, margem + 3, y + 40, { width: wEmit - 6, align: "center" });
    doc.text(`CNPJ: ${formatarCnpjCpf(dados.emitente.cnpj)}`, margem + 3, y + 55, { width: wEmit - 6, align: "center" });

    // Bloco Central DANFE
    const xDanfe = margem + wEmit;
    const wDanfe = 70;
    desenharBorda(doc, xDanfe, y, wDanfe, altura);
    doc.font("Helvetica-Bold").fontSize(12).text("DANFE", xDanfe, y + 5, { width: wDanfe, align: "center" });
    doc.font("Helvetica").fontSize(6).text("Documento Auxiliar da Nota Fiscal Eletrônica", xDanfe + 2, y + 20, { width: wDanfe - 4, align: "center" });
    
    doc.font("Helvetica").fontSize(7).text("0 - Entrada", xDanfe + 5, y + 40);
    doc.font("Helvetica").fontSize(7).text("1 - Saída", xDanfe + 5, y + 50);
    
    desenharBorda(doc, xDanfe + 50, y + 43, 12, 12);
    doc.font("Helvetica-Bold").fontSize(8).text(dados.tipoOperacao || "1", xDanfe + 50, y + 46, { width: 12, align: "center" });

    doc.font("Helvetica-Bold").fontSize(8).text(`Nº ${dados.numero}`, xDanfe, y + 65, { width: wDanfe, align: "center" });
    doc.text(`SÉRIE ${dados.serie}`, xDanfe, y + 75, { width: wDanfe, align: "center" });

    // Bloco Direito (Código de Barras / Chave)
    const xDir = xDanfe + wDanfe;
    const wDir = largura - wEmit - wDanfe;
    desenharBorda(doc, xDir, y, wDir, altura);
    
    if (codigoBarras) {
        doc.image(codigoBarras, xDir + 10, y + 5, { width: wDir - 20, height: 35 });
    }
    
    doc.font("Helvetica-Bold").fontSize(6).text("CHAVE DE ACESSO", xDir + 5, y + 45);
    doc.font("Helvetica-Bold").fontSize(8).text(formatarChave(dados.chave), xDir + 5, y + 55, { width: wDir - 10, align: "center" });
    
    doc.font("Helvetica").fontSize(7).text("Consulta de autenticidade no portal nacional da NF-e www.nfe.fazenda.gov.br/portal ou no site da Sefaz Autorizadora", xDir + 5, y + 70, { width: wDir - 10, align: "center" });

    // Natureza da Operação / Protocolo
    desenharCampo(doc, "NATUREZA DA OPERAÇÃO", dados.naturezaOperacao, margem, y + altura, largura - 200, 20);
    desenharCampo(doc, "PROTOCOLO DE AUTORIZAÇÃO DE USO", dados.protocolo, margem + largura - 200, y + altura, 200, 20);

    return y + altura + 25; // Retorna o próximo Y
}

function desenharDestinatario(doc, dados, margem, largura, y) {
    doc.font("Helvetica-Bold").fontSize(7).text("DESTINATÁRIO / REMETENTE", margem, y);
    y += 8;
    
    const h = 20;
    desenharCampo(doc, "NOME / RAZÃO SOCIAL", dados.destinatario.nome, margem, y, 320, h);
    desenharCampo(doc, "CNPJ / CPF", formatarCnpjCpf(dados.destinatario.documento), margem + 320, y, 130, h);
    desenharCampo(doc, "DATA DA EMISSÃO", formatarData(dados.dataEmissao).split(' ')[0], margem + 450, y, largura - 450, h);
    
    y += h;
    desenharCampo(doc, "ENDEREÇO", dados.destinatario.endereco, margem, y, 220, h);
    desenharCampo(doc, "BAIRRO / DISTRITO", dados.destinatario.bairro, margem + 220, y, 100, h);
    desenharCampo(doc, "CEP", formatarCep(dados.destinatario.cep), margem + 320, y, 70, h);
    desenharCampo(doc, "DATA DE SAÍDA", "", margem + 390, y, 60, h); // Campo fixo no padrão
    desenharCampo(doc, "HORA DE SAÍDA", "", margem + 450, y, largura - 450, h); // Campo fixo
    
    y += h;
    desenharCampo(doc, "MUNICÍPIO", dados.destinatario.cidade, margem, y, 220, h);
    desenharCampo(doc, "UF", dados.destinatario.uf, margem + 220, y, 30, h);
    desenharCampo(doc, "INSCRIÇÃO ESTADUAL", dados.destinatario.ie, margem + 250, y, 140, h);
    
    return y + h + 5;
}

function desenharTotais(doc, dados, margem, largura, y) {
    doc.font("Helvetica-Bold").fontSize(7).text("CÁLCULO DO IMPOSTO", margem, y);
    y += 8;
    
    const h = 20;
    const w = largura / 6;
    
    desenharCampo(doc, "BASE DE CÁLC. ICMS", formatarMoeda(0), margem, y, w, h);
    desenharCampo(doc, "VALOR DO ICMS", formatarMoeda(dados.totais.icms), margem + w, y, w, h);
    desenharCampo(doc, "BASE CÁLC. ICMS ST", formatarMoeda(0), margem + w*2, y, w, h);
    desenharCampo(doc, "VALOR DO ICMS ST", formatarMoeda(0), margem + w*3, y, w, h);
    desenharCampo(doc, "V. TOTAL PRODUTOS", formatarMoeda(dados.totais.produtos), margem + w*4, y, w*2, h);
    
    y += h;
    desenharCampo(doc, "VALOR DO FRETE", formatarMoeda(dados.totais.frete), margem, y, w, h);
    desenharCampo(doc, "VALOR DO SEGURO", formatarMoeda(dados.totais.seguro), margem + w, y, w, h);
    desenharCampo(doc, "DESCONTO", formatarMoeda(dados.totais.desconto), margem + w*2, y, w, h);
    desenharCampo(doc, "OUTRAS DESPESAS", formatarMoeda(dados.totais.outrasDespesas), margem + w*3, y, w, h);
    desenharCampo(doc, "VALOR DO IPI", formatarMoeda(dados.totais.ipi), margem + w*4, y, w, h);
    desenharCampo(doc, "VALOR TOTAL DA NOTA", formatarMoeda(dados.totais.valorNota), margem + w*5, y, w, h);
    
    return y + h + 5;
}

function desenharTransporte(doc, dados, margem, largura, y) {
    doc.font("Helvetica-Bold").fontSize(7).text("TRANSPORTADOR / VOLUMES TRANSPORTADOS", margem, y);
    y += 8;
    
    const h = 20;
    desenharCampo(doc, "RAZÃO SOCIAL", dados.transporte.transportadora, margem, y, 220, h);
    desenharCampo(doc, "FRETE POR CONTA", dados.transporte.modalidade, margem + 220, y, 80, h);
    desenharCampo(doc, "CÓDIGO ANTT", "", margem + 300, y, 70, h);
    desenharCampo(doc, "PLACA VEÍC.", dados.transporte.placa, margem + 370, y, 70, h);
    desenharCampo(doc, "UF", dados.transporte.uf, margem + 440, y, 30, h);
    desenharCampo(doc, "CNPJ / CPF", formatarCnpjCpf(dados.transporte.cnpj), margem + 470, y, largura - 470, h);
    
    return y + h + 5;
}

function desenharCabecalhoProdutos(doc, colunas, margem, y) {
    let x = margem;
    const h = 15;
    
    for (const col of colunas) {
        desenharBorda(doc, x, y, col.w, h);
        doc.font("Helvetica-Bold").fontSize(5.5).text(col.tit, x + 2, y + 5, { width: col.w - 4, align: "center" });
        x += col.w;
    }
    return y + h;
}

function desenharProdutosPaginados(doc, dados, margem, largura, startY, drawHeaderCallback) {
    let y = startY;
    doc.font("Helvetica-Bold").fontSize(7).text("DADOS DO PRODUTO / SERVIÇO", margem, y);
    y += 8;

    const colunas = [
        { tit: "CÓD.", w: 45 },
        { tit: "DESCRIÇÃO DO PRODUTO / SERVIÇO", w: 175 },
        { tit: "NCM/SH", w: 45 },
        { tit: "CFOP", w: 30 },
        { tit: "UNID", w: 30 },
        { tit: "QTD.", w: 40 },
        { tit: "V. UNIT.", w: 50 },
        { tit: "V. TOTAL", w: 50 },
        { tit: "BC ICMS", w: 40 },
        { tit: "V. ICMS", w: 40 }
    ];

    y = desenharCabecalhoProdutos(doc, colunas, margem, y);
    
    const limitY = 750; // Limite inferior antes de quebrar página
    const hLinha = 15;

    dados.produtos.forEach((prod) => {
        // Se ultrapassar a página, cria nova e refaz o topo
        if (y + hLinha > limitY) {
            doc.addPage();
            y = 20; // reset margem superior nova página
            y = drawHeaderCallback(doc, y);
            doc.font("Helvetica-Bold").fontSize(7).text("DADOS DO PRODUTO / SERVIÇO (Continuação)", margem, y);
            y += 8;
            y = desenharCabecalhoProdutos(doc, colunas, margem, y);
        }

        let x = margem;
        const valores = [
            prod.codigo,
            limitarTexto(prod.descricao, 45),
            prod.ncm,
            prod.cfop,
            prod.unidade,
            formatarNumero(prod.quantidade, 4),
            formatarMoeda(prod.valorUnitario),
            formatarMoeda(prod.valorTotal),
            "", // bc icms (simplificado)
            ""  // v. icms (simplificado)
        ];

        colunas.forEach((col, i) => {
            desenharBorda(doc, x, y, col.w, hLinha);
            doc.font("Helvetica").fontSize(5.5).text(valores[i] || "", x + 2, y + 5, { 
                width: col.w - 4, 
                align: (i >= 5) ? "right" : "left", 
                lineBreak: false 
            });
            x += col.w;
        });

        y += hLinha;
    });

    return y + 10;
}

function desenharInformacoesAdicionais(doc, dados, margem, largura, y) {
    const spaceLeft = 800 - y;
    const h = Math.max(spaceLeft, 50); // Preenche o resto da página

    doc.font("Helvetica-Bold").fontSize(7).text("DADOS ADICIONAIS", margem, y);
    y += 8;
    
    desenharCampo(doc, "INFORMAÇÕES COMPLEMENTARES", dados.informacoesAdicionais || "Nenhuma informação adicional informada.", margem, y, largura - 150, h);
    desenharCampo(doc, "RESERVADO AO FISCO", "", margem + largura - 150, y, 150, h);
}

async function gerarDanfePdf(xml, tipo) {
    const dados = extrairDadosNfe(xml, tipo);

    if (!dados.chave || dados.chave.length !== 44) {
        throw new Error("Não foi possível identificar a chave de acesso de 44 dígitos.");
    }

    // Resolve as dependências assíncronas ANTES de abrir o fluxo do PDF
    let codigoBarras = null;
    try {
        codigoBarras = await criarCodigoBarras(dados.chave);
    } catch (e) {
        console.warn("Falha ao gerar código de barras:", e.message);
    }

    const doc = new PDFDocument({
        size: "A4",
        margin: 20,
        autoFirstPage: true,
        bufferPages: true
    });

    const paginas = [];
    doc.on("data", (chunk) => paginas.push(chunk));

    const margem = 20;
    const largura = 555; // 595 - (20 * 2)

    // Helper para desenhar o topo padronizado independente da página
    const desenharTopo = (docInstance, currentY = 20) => {
        return desenharCabecalhoPrincipal(docInstance, dados, margem, largura, currentY, codigoBarras);
    };

    let y = margem;

    // Página 1: Desenha o Canhoto
    y = desenharCanhoto(doc, margem, largura, y);
    desenharLinhaTracejada(doc, margem, largura, y);
    y += 10;

    // Cabeçalho e Quadros principais
    y = desenharTopo(doc, y);
    y = desenharDestinatario(doc, dados, margem, largura, y);
    y = desenharTotais(doc, dados, margem, largura, y);
    y = desenharTransporte(doc, dados, margem, largura, y);

    // Produtos (com quebra de página automática embutida)
    y = desenharProdutosPaginados(doc, dados, margem, largura, y, desenharTopo);

    // Informações Adicionais (Se faltar espaço, joga pra próxima página)
    if (y > 700) {
        doc.addPage();
        y = desenharTopo(doc, 20);
    }
    desenharInformacoesAdicionais(doc, dados, margem, largura, y);

    doc.end();

    return new Promise((resolve, reject) => {
        doc.on("end", () => {
            resolve({
                pdf: Buffer.concat(paginas),
                chave: dados.chave,
                numero: dados.numero,
                serie: dados.serie
            });
        });
        doc.on("error", reject);
    });
}

/* ============================================================
   ROTA DE GERAÇÃO DO DANFE
============================================================ */

app.post("/api/xml/render-pdf", async (req, res) => {
    try {
        const { xmlBase64, tipo } = req.body || {};

        if (!xmlBase64 || typeof xmlBase64 !== "string") {
            return res.status(400).json({
                success: false,
                error: "xmlBase64 não fornecido."
            });
        }

        const xmlString = Buffer
            .from(sanitizarBase64(xmlBase64), "base64")
            .toString("utf8")
            .replace(/^\uFEFF/, "")
            .trim();

        const pareceXml =
            xmlString.startsWith("<?xml") ||
            xmlString.includes("<nfeProc") ||
            xmlString.includes("<NFe") ||
            xmlString.includes("<infNFe");

        if (!pareceXml) {
            return res.status(400).json({
                success: false,
                error: "O conteúdo enviado não parece ser um XML NF-e válido."
            });
        }

        const resultado = await gerarDanfePdf(xmlString, tipo || "NFe");

        return res.status(200).json({
            success: true,
            tipo: tipo || "NFe",
            chave: resultado.chave,
            numero: resultado.numero,
            serie: resultado.serie,
            pdfBase64: resultado.pdf.toString("base64")
        });
    } catch (error) {
        console.error("Erro ao gerar DANFE:", error);
        return res.status(500).json({
            success: false,
            error: error.message || "Erro interno ao gerar o DANFE."
        });
    }
});

/* ============================================================
   MANIFESTAÇÃO DO DESTINATÁRIO
   (Mantenha o restante do seu código exatamente como estava)
============================================================ */

function obterAmbienteNFe() {
    return process.env.NFE_AMBIENTE === "2" ? "2" : "1";
}

function obterEndpointManifestacao(endpointFornecido) {
    if (endpointFornecido) {
        const url = new URL(endpointFornecido);

        if (url.protocol !== "https:") {
            throw new Error("O endpoint precisa utilizar HTTPS.");
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
        throw new Error("CNPJ inválido. Informe 14 dígitos.");
    }

    return valor;
}

function normalizarChaveNFe(chave) {
    const valor = somenteDigitos(chave);

    if (valor.length !== 44) {
        throw new Error("Chave NF-e inválida. Informe 44 dígitos.");
    }

    return valor;
}

function gerarDhEvento() {
    const agora = new Date();
    const offset = -agora.getTimezoneOffset();
    const sinal = offset >= 0 ? "+" : "-";
    const absoluto = Math.abs(offset);

    const pad = (valor) =>
        String(valor).padStart(2, "0");

    return (
        `${agora.getFullYear()}-` +
        `${pad(agora.getMonth() + 1)}-` +
        `${pad(agora.getDate())}T` +
        `${pad(agora.getHours())}:` +
        `${pad(agora.getMinutes())}:` +
        `${pad(agora.getSeconds())}` +
        `${sinal}${pad(Math.floor(absoluto / 60))}:` +
        `${pad(absoluto % 60)}`
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
    if (!pfxBase64 || !password) {
        throw new Error("Certificado e senha são obrigatórios.");
    }

    try {
        const pfxDer = forge.util.decode64(
            sanitizarBase64(pfxBase64)
        );

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
            throw new Error("Chave privada não encontrada no certificado.");
        }

        if (!certificate) {
            throw new Error("Certificado X509 não encontrado.");
        }

        const privateKeyPem =
            forge.pki.privateKeyToPem(privateKey);

        const certPem =
            forge.pki.certificateToPem(certificate);

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
        throw new Error(
            `Erro ao abrir certificado A1: ${error.message}`
        );
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
        throw new Error("Tipo de manifestação inválido.");
    }

    const cnpjLimpo = normalizarCNPJ(cnpj);
    const chaveLimpa = normalizarChaveNFe(chave);

    const idEvento =
        `ID${evento.codigo}${chaveLimpa}01`;

    const justificativa =
        evento.codigo === "210240"
            ? "<xJust>Operacao nao realizada pelo destinatario</xJust>"
            : "";

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
        justificativa +
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
        xpath:
            `//*[local-name(.)='infEvento' and @Id='${idEvento}']`,
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
            reference:
                `//*[local-name(.)='infEvento' and @Id='${idEvento}']`,
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
    const eventoAssinado =
        gerarEventoManifestacaoAssinado(
            cnpj,
            chave,
            tipoManifestacao,
            pfxBase64,
            password
        );

    return (
        `<?xml version="1.0" encoding="utf-8"?>` +
        `<soap12:Envelope ` +
        `xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ` +
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

app.post(
    "/rpa/xml/manifest",
    validarAPI,
    async (req, res) => {
        const requestId = crypto.randomUUID();

        try {
            const {
                pfxBase64,
                password,
                cnpj,
                chave,
                tipoManifestacao,
                endpoint
            } = req.body || {};

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

            const soapEnvelope =
                gerarManifestacaoXML(
                    cnpjLimpo,
                    chaveLimpa,
                    tipoManifestacao,
                    pfxBase64,
                    password
                );

            const endpointFinal =
                obterEndpointManifestacao(endpoint);

            const resposta =
                await executarRequisicaoHttps({
                    endpoint: endpointFinal,
                    certificado,
                    password,
                    body: soapEnvelope,
                    soapAction: NFE_EVENTO_SOAP_ACTION
                });

            const retorno =
                interpretarRespostaManifestacao(
                    resposta.body,
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
                extrairTagXml(resposta.body, "faultstring") ||
                extrairTagXml(resposta.body, "Text") ||
                `HTTP ${resposta.statusCode} retornado pela SEFAZ.`;

            return res.status(400).json({
                success: false,
                requestId,
                statusCode: resposta.statusCode,
                cStat: retorno.cStatEvento,
                error: erro
            });
        } catch (error) {
            console.error("Erro na manifestação:", error);

            return res.status(500).json({
                success: false,
                requestId,
                error: error.message || "Erro na manifestação."
            });
        }
    }
);

/* ============================================================
   TRATAMENTO DE ERROS
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
    console.log("====================================");
    console.log("BRIDGE SEFAZ ONLINE");
    console.log(`Porta: ${PORT}`);
    console.log(`Versão: ${VERSAO}`);
    console.log(`Ambiente: ${process.env.NODE_ENV || "development"}`);
    console.log("AUTH_KEY carregada:", Boolean(AUTH_KEY));
    console.log("XML_KEY carregada:", Boolean(XML_KEY));
    console.log("====================================");
});
