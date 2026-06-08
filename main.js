import * as isoverif from './isoverif.js'

function originMatch(req){
    if(req.protocol.startsWith('openid4vp-v1')){
        let payload=req.data.request
        if(req.protocol==='openid4vp-v1-signed')
            payload=payload.split('.')[1]
        payload=JSON.parse(atob(payload))
        console.log(payload)
        if(!payload.expected_origins)
            return false
        for(const origin of payload.expected_origins)
            if(origin===document.location.origin)
                return true
    }else if(req.protocol==='org-iso-mdoc'){
        return isoverif.verify(req.data)
    }
    return false
}

const originalGet = navigator.credentials.get;

navigator.credentials.get = async function(...args) {
    let firstArg=args[0]
    if(firstArg.digital&&firstArg.digital.requests){
        let requests=firstArg.digital.requests
        for(const req of requests){
            if(!originMatch(req))
                throw new Error("origin do not match")
        }
    }

    window.postMessage({
        type: "CREDENTIALS_GET_CALLED",
        args
    }, "*");
    const result = await originalGet.apply(this, args);
    return result;
};

