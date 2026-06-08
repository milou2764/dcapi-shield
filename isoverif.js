import * as cbor2 from 'cbor2';
import * as asn1js from "asn1js";
import { Certificate } from "pkijs";

export async function verify(dcapiObj){
    let globalValid=true
    let cbor=cbor2.decode(dcapiObj.deviceRequest.replaceAll('-','+').replaceAll('_','/'),{encoding:'base64'})
    for(const req of cbor.docRequests){
        let signature=req.readerAuth[3]
        let leaf=req.readerAuth[1].get(33)[0]
        let asn1=asn1js.fromBER(leaf)
        const cert = new Certificate({ schema: asn1.result })
        const spki = cert.subjectPublicKeyInfo
        const cryptoKey = await crypto.subtle.importKey(
            "spki",
            spki.toSchema().toBER(false),
            {
                name: "ECDSA",
                namedCurve: "P-256"
            },
            true,
            ["verify"]
        )
        const dcapiInfo=cbor2.encode([dcapiObj.encryptionInfo,"https://verifier.multipaz.org"])
        const dcapiInfoHash=await crypto.subtle.digest('SHA-256', dcapiInfo)
        const st3 = ["dcapi",new Uint8Array(dcapiInfoHash)]
        const st = [null,null,st3]
        const readerAuthentication = ["ReaderAuthentication",st,req.itemsRequest]
        const readerAuthenticationBytes = cbor2.encode(new cbor2.Tag(24, cbor2.encode(readerAuthentication)))

        let tbs=["Signature1",req.readerAuth[0],new Uint8Array(0),readerAuthenticationBytes]
        tbs=cbor2.encode(tbs)

        const valid = await crypto.subtle.verify(
            {
                name: "ECDSA",
                hash: "SHA-256"
            },
            cryptoKey,
            signature,
            tbs
        )

        console.log("valid",valid)
        globalValid=globalValid&&valid
    }
    return globalValid
}
