
function get_cookies(){
    const cstr = document.cookie;
    const splt = cstr.split(";")

    const a = {}
    for (i of splt){
        const kv = i.split("=");
        if (kv[0]!=""){
            a[kv[0].trim()]=kv[1].trim()
        }
    }

    return a
}

// s is uint8 bytes split by _
async function parse_peer_pub(s){
    const bytes = s.split("_")

    const arr = Uint8Array.fromHex(bytes.join(""))

    // make a pubkey from that ?
    return await crypto.subtle.importKey(
            "raw",
            arr,
            { name: "X25519", namedCurve: "X25519" },
            false,
            []
    );
}

async function mk_shared(pub, priv){
    return await crypto.subtle.deriveBits( {
        name: "X25519",
        public: pub,
      },
      priv,
      256
    );
}

async function setup_encryption(){
    const keyPair = await crypto.subtle.generateKey( { name: "X25519", namedCurve: "X25519" }, true, ["deriveKey","deriveBits"])

    const rawPublicKey = await crypto.subtle.exportKey("raw", keyPair.publicKey);
    const exportedPrivateKey = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

    const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(rawPublicKey)));

    const res = await fetch("setup_encryption",{
            method:"POST",
            body:publicKeyBase64,
        }
    )
    sessionStorage.setItem("pubkey", publicKeyBase64)
    sessionStorage.setItem("privkey", JSON.stringify(exportedPrivateKey))
}

async function import_key(){
    const storedPrivateKey = JSON.parse(sessionStorage.getItem("privkey"));
    return await crypto.subtle.importKey(
        "jwk",
        storedPrivateKey,
        { name: "X25519", namedCurve: "X25519" },
        true,
        ["deriveKey", "deriveBits"]
    );
}

async function getEncryptionKey(secret){
    const hkdfKey = await crypto.subtle.importKey(
      "raw",
      secret,
      "HKDF",
      false,
      ["deriveKey"]
    );
    const salt = new TextEncoder().encode("mysaltstring")
    const info = new TextEncoder().encode("sessionkeyv1")

    return await crypto.subtle.deriveKey(
        {
            name: "HKDF",
            salt,
            info,
            hash: "SHA-256"
        },
        hkdfKey,
        { 
            name: "AES-GCM", 
            length: 256 
        },
        false, 
        ["encrypt", "decrypt"]
    );
}

async function encrypt(msg, encKey){
    const encoder = new TextEncoder();
    const iv = new Uint8Array([1,2,1,2,3,1,4,2,2,34,23,42])
    return await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv
        },
        encKey,
        encoder.encode(msg)
    );
}

function connectWebSocket(port) {
	return new WebSocket("ws://"+ window.location.hostname + ":" + port.toString())
}

async function main(){

    let cookies = get_cookies()
    if(!cookies["server_pub"]){
        console.log("setting encryption")
        await setup_encryption()
    }

    cookies = get_cookies()
    
    const peer_pub = await parse_peer_pub(cookies["server_pub"])
    const priv = await import_key()

    const shared = await mk_shared(peer_pub, priv)

    const encryptionKey = await getEncryptionKey(shared)

    const ws = connectWebSocket(8889)
    ws.onmessage=(a)=>{console.log("ws get",a)}
    ws.onclose=()=>{console.log("shutdown")}
    ws.onopen=()=>{console.log("ws open")}

    document.getElementById("submit-button").addEventListener("click", async ()=>{
        const inp = document.getElementById("input-field").value
        console.log("inputting ",inp)

        const dmp = JSON.stringify({"cmd":"authenticate","content":inp})
        let enc_msg = await encrypt(dmp, encryptionKey)
        console.log("enc_msg",new Uint8Array( enc_msg))
        ws.send(enc_msg)
    })
}

main()
