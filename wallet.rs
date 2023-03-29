use bitcoin_wallet;
use bitcoin_wallet::mnemonic;
use bitcoin_wallet::account::{MasterAccount, Seed};
use bitcoin::network::constants::Network;
use bitcoin_wallet::account::Unlocker;
use std::fs;
use std::fs::File;
use std::io::{Write, Read};
use std::path::Path;
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::DerivationPath;
use hex;

const PASSPHRASE: &str = "correct horse battery staple";

pub fn create_new_wallet() -> MasterAccount {
    let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
    let nemonic = mnemonic::Mnemonic::new(&random_bytes).unwrap();
    println!("{}", nemonic.to_string());
    let master = MasterAccount::from_mnemonic(&nemonic, 0, Network::Bitcoin, PASSPHRASE, None).unwrap();
    save_to_file("wallet.txt", master.encrypted());
    return master
}

pub fn import_wallet() -> MasterAccount{
    let words = "announce damage viable ticket engage curious yellow ten clock finish burden orient faculty rigid smile host offer affair suffer slogan mercy another switch park";
    let mnemonic = mnemonic::Mnemonic::from_str(words).unwrap();
    let master = MasterAccount::from_mnemonic(&mnemonic, 0, Network::Bitcoin, PASSPHRASE, None).unwrap();
    save_to_file("wallet.txt", master.encrypted());

    return master
}

pub fn load_wallet() -> MasterAccount{
    let buffer = read_from_file("wallet.txt");
    let seed = Seed::decrypt(&buffer, PASSPHRASE).unwrap();
    let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs();
        
    let master = MasterAccount::from_seed(&seed, 0, Network::Bitcoin, PASSPHRASE).unwrap();
    return master
}

pub fn get_public_key(master: &MasterAccount, path: &DerivationPath) -> bitcoin::PublicKey{
    let secp = Secp256k1::new();
    let extended_public_key = master.master_public().derive_pub(&secp, &path).unwrap();
    let public_key = extended_public_key.to_pub();
    println!("Public key: {}", public_key);
    return public_key
}

pub fn get_private_key(master: &MasterAccount, path: &DerivationPath)-> Vec<u8> {
    let secp = Secp256k1::new();
    let unlocker = get_unlocker(&master);
    let priv_key = unlocker.master_private();
    let priv_key = priv_key.derive_priv(&secp, &path).unwrap().to_priv().to_bytes();
    let hex_string = hex::encode(priv_key.clone());
    println!("Private key: {}", hex_string);
    return priv_key
}

pub fn get_unlocker(master: &MasterAccount) -> Unlocker {
    let mut unlocker = Unlocker::new_for_master(&master, PASSPHRASE).unwrap();
    return unlocker
}

pub fn save_to_file(name: &str, buffer: &Vec<u8> ){
    let path: &Path = Path::new(&name);
    let mut file = fs::OpenOptions::new()
    .write(true).create(true).truncate(true)
    .open(path).unwrap();
    file.write_all(&buffer).unwrap();
}

pub fn read_from_file(name: &str) -> Vec<u8>{
    let path: &Path = Path::new(&name);
    let mut f = File::open(path).expect("no file found");
    let metadata = fs::metadata(path).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");
    return buffer
}