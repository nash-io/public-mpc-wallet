import * as MPCwallet from "MPC_WALLET";
import * as axios from 'axios';


var RPOOL_SIZE = 10;
var MIN_RPOOL_SIZE = RPOOL_SIZE / 2;

let set_state = (state_name, state) => {
    window.localStorage.setItem(state_name, state);
}

let get_state = (state_name) => {
    let result = window.localStorage.getItem(state_name);
    if (result === null){
        return false;
    }
    else{
        return result;
    }
}

async function create_api_childkey() {
    // create API childkey for either secp256k1 or secp256r1
    if (document.getElementById("Secp256k1").checked === true) {
        set_state('curve', JSON.stringify("Secp256k1"));
    } else if (document.getElementById("Secp256r1").checked === true) {
        set_state('curve', JSON.stringify("Secp256r1"));
    } else {
        console.log("ERROR: Invalid curve!");
        return;
    }
    let curve = get_state("curve");

    // set key pair from html input
    let secret_key = document.getElementById("secret_key").value;
    set_state('secret_key', secret_key);
    let public_key_result = JSON.parse(MPCwallet.publickey_from_secretkey(secret_key, curve));
    if (public_key_result[0] === false) {
        console.log("Error deriving public key from secret key." + public_key_result[1]);
        return;
    }
    let public_key = JSON.stringify(public_key_result[1]);
    set_state('public_key', public_key);

    let paillier_pk = get_state("paillier_pk");
    // paillier key not verified yet.
    if (paillier_pk === false) {
        console.log("Initializing API key creation.");
        let result1 = JSON.parse(MPCwallet.init_api_childkey_creator(secret_key));
        if (result1[0] === false) {
            console.log("ERROR: initalization failed. " + result1[1]);
            return;
        } else {
            var api_childkey_creator = JSON.stringify(result1[1]);
            console.log("Requestion correct key proof from server.")
            await axios.post("http://localhost:4000/api/v1/get_paillier_keypair_and_proof", {}).then((response) => {
                console.log("Received response from server.")
                let correct_key_proof = JSON.stringify(response.data["correct_key_proof"]);
                paillier_pk = JSON.stringify(response.data["paillier_pk"]);
                set_state('paillier_pk', paillier_pk);

                console.log("Verifying correct key proof.")
                let result2 = JSON.parse(MPCwallet.verify_paillier(api_childkey_creator, paillier_pk, correct_key_proof));
                if (result2[0] === false) {
                    console.log("ERROR: paillier key verification failed. " + result2[1]);
                    return;
                } else {
                    api_childkey_creator = JSON.stringify(result2[1]);
                    console.log("Paillier key is correct.");
                }
            })
        }
    // paillier key already verified; skip verification
    } else {
        console.log("Initializing (fast) API key creation.");
        let result1 = JSON.parse(MPCwallet.init_api_childkey_creator_with_verified_paillier(secret_key, paillier_pk));
        if (result1[0] === false) {
            console.log("ERROR: (fast) initalization failed. " + result1[1]);
            return;
        } else {
            var api_childkey_creator = JSON.stringify(result1[1]);
        }
    }

    console.log("Computing secret shares for " + JSON.parse(curve));
    let result3 = JSON.parse(MPCwallet.create_api_childkey(api_childkey_creator, curve));
    if (result3[0] === false) {
        console.log("ERROR: paillier key not verified. " + result3[1]);
    } else {
        let api_childkey = JSON.stringify(result3[1]);
        console.log("API childkey created successfully.")
        set_state('api_childkey', api_childkey);
        // show api childkey in html page
        document.getElementById("api_childkey").innerHTML = api_childkey;
    }

    // fill pools of r-values (as well as Paillier pool).
    fill_r_pool(JSON.stringify("Secp256k1"));
    fill_r_pool(JSON.stringify("Secp256r1"));
}


async function fill_r_pool(curve) {
    console.log("Filling pool of r values.");
    let paillier_pk = get_state("paillier_pk");
    if (paillier_pk === false) {
        console.log("Cannot fill pools yet: Paillier key not verified.");
        return;
    }
    let dh_keys_result = JSON.parse(MPCwallet.dh_init(RPOOL_SIZE, curve));
    if (dh_keys_result[0] === false) {
        console.log("ERROR: DH init failed. " + dh_keys_result[1]);
    } else {
        console.log("DH init done.");
        let client_dh_secrets = JSON.stringify(dh_keys_result[1]);
        let client_dh_publics = JSON.stringify(dh_keys_result[2]);
        await axios.post("http://localhost:4000/api/v1/dh_rpool", {
            client_dh_publics: client_dh_publics,
            curve: curve,
        }).then((response) => {
            let server_dh_publics = response.data;
            // populate r_pool
            let r_pool_result = JSON.parse(MPCwallet.fill_rpool(client_dh_secrets, server_dh_publics, curve, paillier_pk));
            if (r_pool_result[0] === true) {
                console.log("Pool filled successfully.");
                let result_size = JSON.parse(MPCwallet.get_rpool_size(curve));
                if (result_size[0] === true){
                    console.log("Successfully queried rpool size.");
                    let rpool_size = result_size[1];
                    console.log(curve + " rpool size: " + rpool_size);
                } else {
                    console.log("Error querying rpool size. " + result_size[1]);
                    return;
                }
            } else {
                console.log("ERROR: computing r_pool failed: " + r_pool_result[1]);
            }
        })
    }
}

async function compute_presig() {
    let message_hash = document.getElementById("message_hash").value;
    let api_childkey = get_state("api_childkey");
    let curve = get_state("curve");

    // ensure that pool is indeed not empty (and refill if it is)
    let result_size1 = JSON.parse(MPCwallet.get_rpool_size(curve));
    if (result_size1[0] === true){
        console.log("Successfully queried rpool size.");
        let rpool_size1 = result_size1[1];
        console.log("rpool size: " + rpool_size1);
        if (rpool_size1 <= 0) {
            console.log("Triggering rpool refill..");
            await fill_r_pool(curve);
        }
    } else {
        console.log("Error querying rpool size. " + result_size1[1]);
        return;
    }

    console.log("Computing presignature on client...")
    let result = JSON.parse(MPCwallet.compute_presig(api_childkey, message_hash, curve));
    if (result[0] === true) {
        let presig = result[1];
        let r = result[2];
        console.log("Presig computed successfully.");
        let presig_html = document.getElementById("presig");
        presig_html.innerHTML = presig;
        console.log("Sending presignature to server for completion.")
        axios.post("http://localhost:4000/api/v1/complete_sig", {
            presig: presig,
            r: r,
            curve: curve,
        }).then((response) =>{
            let recovery_id = response.data["recovery_id"];
            let r = response.data["r"];
            let s = response.data["s"];
            let signature_html = document.getElementById("signature");
            signature_html.innerHTML = "r:" + JSON.stringify(r) + ", s:" + JSON.stringify(s) + ", recovery_id:" + recovery_id;
            console.log("Server has completed the signature.")
            let result = JSON.parse(MPCwallet.verify(r, s, get_state("public_key"), message_hash, curve));
            if (result[0] === true){
                console.log("Signature verified successfully.");
            } else {
                console.log("Error verifying signature. " + result[1]);
            }
        })
    } else {
        console.log("Error computing presig: " + result[1]);
    }

    // refill pool of r-values (asynchronously) as soon as it gets below MIN_RPOOL_SIZE
    let result_size2 = JSON.parse(MPCwallet.get_rpool_size(curve));
    if (result_size2[0] === true){
        console.log("Successfully queried rpool size.");
        let rpool_size2 = result_size2[1];
        console.log("rpool size: " + rpool_size2);
        if (rpool_size2 < MIN_RPOOL_SIZE) {
            console.log("Triggering rpool refill..");
            fill_r_pool(curve);
        }
    } else {
        console.log("Error querying rpool size. " + result_size2[1]);
    }
}

document.getElementById("create_api_childkey").onclick = () => {
    create_api_childkey();
}

document.getElementById("sig").onclick = () => {
    compute_presig();
}

// make sure that local storage is empty in the beginning
localStorage.clear();
