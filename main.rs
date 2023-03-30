use bitcoin::blockdata::opcodes::{self, All};
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::witness::Witness;
use bitcoin::{Script, SigHashType};
use bitcoin::util::address::Address;
use bitcoin_wallet::account::{Unlocker, MasterAccount};
use rand::RngCore;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1;
use bitcoin::secp256k1::SecretKey;
use std::str::FromStr;
use bitcoin;
use bitcoin::util::sighash::EcdsaSighashType;
use bitcoin::{OutPoint, TxIn, TxOut, Transaction};
mod wallet;
use ripemd160::Ripemd160;
use sha2::{Sha256, Digest};
use bitcoin::consensus::encode::serialize_hex;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoin::util::bip32::DerivationPath;
use hex;


use crate::wallet::{save_to_file, read_from_file};


fn main() {
    // let master = wallet::create_new_wallet();
    // let master = wallet::import_wallet();
    let master = wallet::load_wallet();

    // let script = generate_script(&master);
    // let address = generate_address(script);
    let tx = generate_tx(&master);

}

fn hash160(data: &[u8]) -> Vec<u8> {
    // Perform SHA-256 hash
    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(data);
    let sha256_result = sha256_hasher.finalize();

    // Perform RIPEMD-160 hash on the result of the SHA-256 hash
    let mut ripemd160_hasher = Ripemd160::new();
    ripemd160_hasher.update(sha256_result);
    let ripemd160_result = ripemd160_hasher.finalize();

    // Convert the GenericArray to a Vec<u8>
    ripemd160_result.as_slice().to_vec()
}

fn generate_payment_preimage() -> Vec<u8>{
    let mut rng = rand::thread_rng();
    let mut preimage: Vec<u8> = vec![0; 32];
    rng.fill_bytes(&mut preimage);
    println!("payment preimage is : {:?}", preimage);
    save_to_file("preimage.txt", &preimage);
    return preimage
}

fn generate_script(master: &MasterAccount)->Script{
    let path = DerivationPath::from_str("m/84/0/0/0/0").unwrap();
    let public_key = wallet::get_public_key(&master, &path);

    let payment_preimage = generate_payment_preimage();
    let payment_hash = hash160(&payment_preimage);
  
    let pubkey2 = bitcoin::util::key::PublicKey::from_str("02b4632d08485ff1df2db55b9dafd23347d1c47a457072a1e87be26896549a8737").unwrap();

    let custom_script = Builder::new()
    .push_opcode(opcodes::all::OP_SIZE)
    .push_int(32)
    .push_opcode(opcodes::all::OP_EQUALVERIFY)
    .push_opcode(opcodes::all::OP_HASH160)
    .push_slice(&payment_hash)
    .push_opcode(opcodes::all::OP_EQUALVERIFY)
    .push_int(1)
    .push_key(&public_key)
    .push_key(&pubkey2)
    .push_int(2)
    .push_opcode(opcodes::all::OP_CHECKMULTISIG)
    .into_script();

    save_to_file("script.txt", &custom_script.to_bytes());

    return custom_script;
}

fn generate_address(custom_script: Script) -> Address{
        // Calculate the WitnessScriptHash from the custom script
        let script_hash = Script::wscript_hash(&custom_script);
    
        // Create the P2WSH script_pubkey
        let version = bitcoin::blockdata::opcodes::all::OP_PUSHBYTES_0;
        let version = bitcoin::util::address::WitnessVersion::try_from(version).unwrap();
        let script_pubkey = Script::new_witness_program(version, &script_hash[..]);
    
        // Generate the P2WSH address from the script_pubkey
        let address = Address::from_script(&script_pubkey, bitcoin::Network::Testnet).unwrap();
    
        println!("Custom P2WSH script: {:?}", custom_script);
        println!("P2WSH script_pubkey: {:?}", script_pubkey);
        println!("P2WSH address: {}", address);
        return address
}

fn generate_tx(wallet: &bitcoin_wallet::account::MasterAccount){
    // // Create a P2WPKH script_pubkey as the recipient output
    // let recipient_public_key = bitcoin::hash_types::WPubkeyHash::from_str("03f4d4c7a4e8f03b9506e0b6f9c6d8a3a3f1fcd5a5f01e5a40a2c7f5b5f1b76a9a").unwrap();
    // let recipient_script_pubkey = Script::new_v0_p2wpkh(&recipient_public_key);


    // Create the input referencing a previous P2WSH output
    let prev_outpoint = OutPoint::from_str("c31a573f9133fcbc5018042dd83e020c4cf983020bbe88ca721ea566b5edc76c:0").unwrap();
    let tx_input = TxIn {
        previous_output: prev_outpoint,
        script_sig: Script::new(),
        sequence: bitcoin::blockdata::transaction::Sequence::MAX,
        witness: bitcoin::blockdata::witness::Witness::new(),
    };


    let address_str = "tb1qtupfy9c8tjpsuvy0c8n08s0er73zwys9y5u7xl";
    let address = Address::from_str(address_str).expect("Invalid address");
    let recipient_script_pubkey = address.script_pubkey();
    // Create the output
    let tx_output = TxOut {
        value: 1000,
        script_pubkey: recipient_script_pubkey,
    };

    // Create the unsigned transaction
    let unsigned_tx = Transaction {
        version: 2,
        lock_time: bitcoin::blockdata::locktime::PackedLockTime::from_str("0").unwrap(),
        input: vec![tx_input],
        output: vec![tx_output],
    };

    let redeem_script = read_from_file("script.txt");
    let redeem_script = Script::from(redeem_script);
 
    let priv_key =  wallet::get_private_key(&wallet, &DerivationPath::from_str("m/84/0/0/0/0").unwrap());

    let mut sighash_components = bitcoin::util::sighash::SighashCache::new(&unsigned_tx);
    let sighash = sighash_components.segwit_signature_hash(
        0,
        &redeem_script,
        2000,
        EcdsaSighashType::All 
    ).unwrap();


    let sighash = sighash.to_vec();
    let msg = secp256k1::Message::from_slice(&sighash).unwrap();

    // let mut unsigned_tx_mut = unsigned_tx.clone()
    let secret = SecretKey::from_slice(&priv_key).unwrap();

    // let private_key = bitcoin::util::key::PrivateKey::from_slice(secret.as_ref(), bitcoin::Network::Bitcoin).unwrap();

    let secp = Secp256k1::new();
    let sig = secp.sign_ecdsa(&msg, &secret);

    let public_key = wallet::get_public_key(&wallet, &DerivationPath::from_str("m/84/0/0/0/0").unwrap()).to_bytes();
    let public_key = secp256k1::PublicKey::from_slice(&public_key).unwrap();
    let verify = secp.verify_ecdsa(&msg, &sig, &public_key).is_ok();

    println!("verify: {}", verify);

    let mut sig_serialized = sig.serialize_der().to_vec();
    sig_serialized.push(EcdsaSighashType::All as u8);

    // Create the witness for the input
    let preimage = read_from_file("preimage.txt");
    let script = read_from_file("script.txt");

    let mut dummy: [u8; 0] = [];
    let witness = vec![dummy.to_vec(),sig_serialized, preimage, script];

    println!("{:?}", witness);

    let mut witness = Witness::from_vec(witness);
    // witness.push(&dummy);

    let mut signed_tx = unsigned_tx.clone();
    signed_tx.input[0].witness = witness;
    println!("signed P2WSH transaction: {}", serialize_hex(&signed_tx));

}

async fn broadcast_tx(data: String)-> Result<(), Box<dyn std::error::Error>>{
    // Replace with your Bitcoin Core RPC credentials
    let rpc_url = "http://127.0.0.1:8332";
    let rpc_user = "bitcoin";
    let rpc_password = "=======";

    let auth = Auth::UserPass(rpc_user.to_string(), rpc_password.to_string());
    let rpc = Client::new(rpc_url.to_string(), auth)?;
    let txid = rpc.send_raw_transaction(data).unwrap();
    println!("Transaction broadcasted with txid: {}", txid);
    Ok(())
}

