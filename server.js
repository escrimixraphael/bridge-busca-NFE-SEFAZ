import 'dotenv/config';

import express from 'express';
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

const AUTH_KEY = process.env.AUTH_KEY;



// ================================
// CONFIGURAÇÃO
// ================================

app.disable('x-powered-by');


app.use(
helmet()
);


app.use(
cors({
origin:"*"
})
);


app.use(
compression()
);


app.use(
express.json({
limit:"20mb"
})
);


app.use(
morgan("combined")
);



// ================================
// RATE LIMIT
// ================================

const limiter = rateLimit({

windowMs:60 * 1000,

max:120,

message:{
success:false,
error:"Muitas requisições"
}

});


app.use(
"/api",
limiter
);



// ================================
// HEALTH CHECK
// ================================

app.get(
"/health",

(req,res)=>{


res.json({

status:"online",

service:"Bridge SEFAZ",

node:
process.version,

timestamp:
new Date()

});


}

);



// ================================
// VALIDAÇÃO API KEY
// ================================


function validarAPI(req,res,next){


const key =
req.headers["x-api-key"];



if(
!AUTH_KEY ||
key !== AUTH_KEY
){


return res.status(403)
.json({

success:false,

error:
"API Key inválida"

});


}



next();


}



// ================================
// CONSULTA SEFAZ MTLS
// ================================


app.post(

"/api/sefaz/consultar",

validarAPI,


async(req,res)=>{


let finalizado=false;



try{


const {

pfxBase64,

password,

endpoint,

soapAction,

soapEnvelope,

empresaId

}=req.body;




if(

!pfxBase64 ||

!password ||

!endpoint ||

!soapEnvelope

){


return res.status(400)
.json({

success:false,

error:

"Campos obrigatórios ausentes"

});


}




const url =
new URL(endpoint);



if(
url.protocol !== "https:"
){


return res.status(400)
.json({

success:false,

error:
"Somente HTTPS permitido"

});


}





const certificado =

Buffer.from(

pfxBase64,

"base64"

);



if(
!certificado.length
){


return res.status(400)
.json({

success:false,

error:
"Certificado inválido"

});


}





console.log(
`
================================

CONSULTA SEFAZ

Empresa:
${empresaId || "N/A"}

Servidor:
${url.hostname}

Data:
${new Date()}

================================
`
);





const options={


hostname:url.hostname,


port:url.port || 443,


path:

url.pathname + url.search,


method:"POST",



pfx:certificado,


passphrase:password,



// mTLS

rejectUnauthorized:false,


secureOptions:

crypto.constants.SSL_OP_NO_TLSv1 |

crypto.constants.SSL_OP_NO_TLSv1_1,



headers:{


"Content-Type":

'application/soap+xml; charset=utf-8',



SOAPAction:

soapAction || "",



Accept:

"text/xml",



"Content-Length":

Buffer.byteLength(

soapEnvelope

)

}


};






const sefazRequest =

https.request(

options,


(sefazResponse)=>{


let body="";



sefazResponse.setEncoding(
"utf8"
);



console.log(

`SEFAZ STATUS ${sefazResponse.statusCode}`

);





sefazResponse.on(

"data",

(chunk)=>{

body+=chunk;

}

);




sefazResponse.on(

"end",

()=>{


if(finalizado)
return;


finalizado=true;



res.status(

sefazResponse.statusCode || 502

)

.json({

success:

sefazResponse.statusCode===200,


statusCode:

sefazResponse.statusCode,


xmlResponse:

body,


empresaId

});


});


}

);





sefazRequest.setTimeout(

60000,

()=>{


console.error(
"Timeout SEFAZ"
);


sefazRequest.destroy();



if(!finalizado){


finalizado=true;


res.status(504)
.json({

success:false,

error:
"Timeout SEFAZ"

});


}


}

);





sefazRequest.on(

"error",

(error)=>{


console.error(

"Erro HTTPS:",

error.message

);



if(!finalizado){


finalizado=true;


res.status(502)
.json({

success:false,

error:error.message

});


}


}

);






sefazRequest.write(

soapEnvelope,

"utf8"

);


sefazRequest.end();





}

catch(error){



console.error(

"Erro Bridge",

error

);



if(!res.headersSent){


res.status(500)
.json({

success:false,

error:

error.message

});


}



}



}

);



// ================================
// 404
// ================================


app.use(

(req,res)=>{


res.status(404)
.json({

success:false,

error:
"Endpoint inexistente"

});


}

);



// ================================
// ERRO GLOBAL
// ================================


app.use(

(error,req,res,next)=>{


console.error(
error
);



res.status(500)
.json({

success:false,

error:
"Erro interno"

});


}

);



// ================================
// START
// ================================


app.listen(

PORT,

"0.0.0.0",

()=>{


console.log(
`
====================================

BRIDGE SEFAZ ONLINE

Porta:
${PORT}

Health:
/health


Consulta:
/api/sefaz/consultar


====================================
`
);


}

);
