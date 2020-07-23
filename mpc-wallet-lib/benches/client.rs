#[macro_use]
extern crate criterion;

use bigints::traits::Converter;
use bigints::BigInt;
use criterion::{black_box, Criterion};
use mpc_wallet_lib::client::{
    compute_presig, encrypt_secret_share, fill_rpool_secp256k1, fill_rpool_secp256r1,
    get_rpool_size, APIchildkeyCreator,
};
use mpc_wallet_lib::common::{dh_init_secp256k1, dh_init_secp256r1, CorrectKeyProof, Curve};
use paillier::{EncryptionKey, MinimalEncryptionKey};

fn criterion_benchmark(c: &mut Criterion) {
    let secret_key =
        BigInt::from_hex("4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1")
            .unwrap();
    c.bench_function("APIchildkeyCreator::init", |b| {
        b.iter(|| APIchildkeyCreator::init(black_box(&secret_key)))
    });

    let mut api_childkey_creator = APIchildkeyCreator::init(&secret_key);
    let paillier_pk = EncryptionKey::from(MinimalEncryptionKey{n: BigInt::from_hex("9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129").unwrap()});
    c.bench_function("APIchildkeyCreator::init_with_verified_paillier", |b| {
        b.iter(|| {
            APIchildkeyCreator::init_with_verified_paillier(
                black_box(&secret_key),
                black_box(&paillier_pk),
            );
        })
    });
    let correct_key_proof: CorrectKeyProof = serde_json::from_str(&"{\"sigma_vec\":[\"14f21d17357e5d0d8d2cb3cf6d0b9439323473be7e1f68db541b77450f87a20941640bf8a317d4ea6272b12923449e73ea5598a6197219fb6c7ca416a3552301c9cc5b47580ce35e4c9e37a97ec0bdbe2b48c2db21cde5bcef9fc04c6e767c59c0500929b76f87901e5a4d8adb38097c44ed790a0ae2e9f6985823f1789aa47a8298d02763751b73942bbee79c4544f9bd2b82e405f15d801cb41d4831012f99172ef49fee6ea33599caadcdb89c1eb768e30b11878f37e12d232b624cbe589a7767af46d958632574535893c0337858399aed65638b97bcaddee45e40fe79a5014fcd1e398b19807439f58236373197653a8ea82ab3a84173d5a8d45bcae823\",\"32beda264c7fde6cb41d48ce44e6e93af5ed0e1cb5c7cd29f7fa3cbf72b78b9bc3e5267c4f9a75de40eb95a4bdc73dd1d8a435799daf2365f9377aed3c4524016d2ea58002c66fd0a8bcb8e74bac9923b723bc9f8752f82d9cba8bec4f414f314a40842031427b0bb8cdc514bfb61a5f85a51d8b7a290ccbd1000af937a6a7fd7a6070ba40a6801a2909e11d71a773958195d82f72995e69b989ab91207b68ac891e6585848f7aea80e1a0693427a0a512c0cbfbfe5d9ffe02462856ca918af9ebd2ad2f9b44a84b628ec7a7ed4d7232e72c52f2af5ef8988e3c09715fbe1a0af871109028335fb95370ae3e7ecf646063c1914ceeff8cf22ca06d250f02904c\",\"27236e62e810849d58c24b57d2061be4223a175224a89b94ce1261ae9f7a61ec058a43589c83aa3029e61c488fa33b0ea8fb72c36f4b3f962f858f4b0dd822a2810124cba42c8c2a42046b324a3c0712799979be7da1e6dff82c466149484246769f43683231ba8a89185587086cef1de589a4d59b74ac20fcbe0310403f9347417a4c8a8b90b78671d265471fe5ca839e509d4b6f5c2ec33ae255abf54aa12700772a174074048bc4edecc142c268b765f8bf4c0ab7b253882f77c1cb0e410e8e21a23ba364ec37adee59e0395920ab403ab77f095ed8bda39fad9b00886c9e2682a8314bd71fc2db9d2b2a8476ac295c262ba16d4657c62af9bb6a4729c214\",\"974e6e3a63e90275733cbf0b1516d940f0b0c8bd6140f16abb22988289b88b327c5a3e2a1de6d00f03e6f78ee934da02590ee45c6b4c0c8f53ccf6adc35cd0e9ee73f5ad88c8b8bc5b2a489c6e2b900cdc5c2b8ef0aaeb4a99dae6bac9a4bbeb12ceacbafc181a43f9176e503d71100b39b71e5f3975daffd3735b8d26c0b3ae43a92737373730bb22bdc3c06b8b281da79a6994c4c21dda8b89e2a0c9767efa559c895da05e127935b4d33eb1e2acab29cd096e5ed73a4812f86f8839aff7ab8e0baff3535098f1cdddb4ae14e1e7eb702674b4bd8253fefe3bd4245afd6dcb365de617df815ff0cc761415f7001a4149825c50626ebbd0aeeb92172be401e2\",\"43e75be1f60bc68a05aaceea143aa14498880ce8ab1417621f7041d8dd76a80e16484e07580060033bb6eeb67a516215f2bdbdcf2bbbe327ae22000b342a51cafe49ea50ce0b459d5e8334b84de284227a3d504d5fcde913b08b27c6997a27b9a307d132379e0688ce6c38f418b1e94ad87b85e86ab48374d736a7c2f402016255b728c258d945591760a314ebc0e98411fdf3c73e6ed8fd7e23cb1cab8a0517d79a33c27de6548be0ab506db1c2b4b573faf7bcb817cbf0d489da9c168a8c8e6bb4ba0edbfcd1fd01f5eddb89ac84d7a218d83635e354e77619725be00426aaaae90221b65c063ef479184599036182098f3e623a57567ff52172fcd0463e23\",\"70ab52b4bde2f26ba9603b1d211ab94ce95d84a8f09fbb1817700897bc1beb4b3bfe24850f61751204cec784ddd182e5a4432a8d6f48ff475a58d4e63ddc70de5b68a4ee392384031d2b3f352a74c5b8b9fe6f8113a046dcab29b6a168203031d783a4321a7d3f2e971761164454af67367c51a4d46218f817034705c3b013162b83b609647944dd7173e37d02f04b0aef42d1ad2f53902b3e88ccf2523c8526b50b3e47a9d51673992d69ed1f0ac39849b473c1ca0fdb5c34c9b344cf820a3b6566d3db80fb0d6646646080e19bf1448f8859ac1c0275c863950779cd22d248a358a3edb4e60676b4ec353d62c25f7b8c836293108be03a353ea8815c3dba9c\",\"84fb3dcc1348efc024c59df79e69c33d0d67d3f7af328cf0af6048d0080862f0ad0eae3bb676851b58b22db6e7c46474cb6aed94a73b35caf65e0c9f36743f55853bbc1d895649435edfeff25977e8130133078577d547c67c8d31236e1dbcac18252f71fac884078e229f97a7b451391f501b85266252137674f898ab9afb505d4f1ca7455e2339ee992395afd3c9a5cb8724733bdb40ed625932106b47dfe890bdea045178a46dffa1608a1ef01b4dda7a7381ee24f4c10fd63b84b1ece8c425435992f567c709d21324aa50a751042fc4cd2afc283ddb8b2867a694945337fe985a2090e45a8df28c68c828a0e6bae3d18f9a8251dbf46e4e7898feb23ca6\",\"23346102965ad3e6d474ac60f0fb4154dff2bf4250204390db22560f1ffcf47047489c38f02708c9776ed349078bcf7822c2bf50e0af9999a610d69e6f14e3d2ff138e706fbad8359bf496d2519ee900a04ac69eaa7e26bb11e4f302288221889bc58ce20608829db11fbc0a64ad066d7cd1704ae730d954dd84a1a35fb03dfab608b8e483d05ad71c2f6e2e38f59afe3005b60d508383ef160f23aed233bf76e108e3d0e3e6a87032b5b6b7b14f50c5b40aeefde5811ea5fa8a601124370b3d58ebca0906fa0ce72e90a23d713d3d74f2d59256d043011c6b350ebb664ba0a96ae7a5611d71f03d60b60d75e328f6a086aa1932f58026a20c3c3ac4f797587e\",\"12786ce1db47ed46d0bd326d844d3c611f9816b59817fb32a0729d4eb7c3975442410b86f5054d3de4be3f9ba442f0750aa0f284269c57e73ad7c644d3182a3ed26f46462ac687287260117abca70255461dc728adced54b9da10206a88fd213dc423ecc7db4842c3b4ff031ee8eb16304178f4e8eaed9db3e2f6c150dca1532a0a6d8e455cf13e7b4beed736ac8525b84b213ba96fced8ab8a9f47d5cdc8fe02e7eede3f417d2dc07ea10eea71486d3b1f9a0b9d6612efc83908702e6b77499a4861d770d136440962c0b35148b4a1af55989b94509a0ca765bdf1fee850eb175be5676581be779c94192a0326513a768c326fa67a202e66d0eaa70a91932d6\",\"354fd63ff01cf79fd2c90928231e364195a4b6c1d7874011ab6440b583f7027990c37eb4a9bd0125c31a61c31bbed0e36850261df09d5395a1885e5faf9f7bbdff0e545495f7e4761894493ace3de65ca7135a2a751aa2f40d21907bdcf65cec2fa896e457eb02889b0e3e8a5bcfdf133847ccec39c886823aef9f7f2ef9650345324efd55d0fc2e349cebffd6b7a542d4b9db9a4353e30da8f4e9aacd35ff5023180d34488261ba80413fd0cb56257db3e543f72e6d2bd82776e24d2db62107f83d6169fbf63eecfb1b33e58058bff6c0a04a6605d14f3ea77c4959293a19c3309e55d86d1ce1d308967bd2b550fbe2df0219444801d842fab7f6b0f26436e4\",\"61186ef51490cf59e822d5e3f84561ffb4f0b921c205581540ac13d8f978765791ab43942dcf470eac454dc13ce375df68bee5e152ee048fd14c5b6edfc053c2d548008e29a50fcf392069e9fe851fcc58c0f3f4ecd14d2885b9940b2a7bc7cc2818910fef3800a7dcf7e7f5a58905fcaedbf7fcd0dbff40293a403148cffedf1a5730554a10a1eed001cfbad38c4051b2a640a79271e43aae09e7733fe3b881fdba14cd397af91a1499f40069f47f65a0bc167d4c66ab5d8c0fcde37383911f75b4d3207a8a5c4dfa6ecf610c6ac20da6e96c0cd691c0642c8bb7a6be2837785774f4bbaac2529bf5291c94ab49961373e8991eb2018aa9d93529f66dd7695a\"]}".to_string()).unwrap();
    c.bench_function("APIchildkeyCreator::verify_paillier", |b| {
        b.iter(|| {
            let api_childkey_creator = APIchildkeyCreator::init(&secret_key);
            api_childkey_creator
                .verify_paillier(black_box(&paillier_pk), black_box(&correct_key_proof))
        })
    });
    api_childkey_creator = api_childkey_creator
        .verify_paillier(&paillier_pk, &correct_key_proof)
        .unwrap();

    c.bench_function("APIchildkeyCreator::create_api_childkey_k1", |b| {
        b.iter(|| {
            let api_childkey_creator =
                APIchildkeyCreator::init_with_verified_paillier(&secret_key, &paillier_pk);
            api_childkey_creator
                .create_api_childkey(black_box(Curve::Secp256k1))
                .unwrap();
        })
    });
    c.bench_function("APIchildkeyCreator::create_api_childkey_r1", |b| {
        b.iter(|| {
            let api_childkey_creator =
                APIchildkeyCreator::init_with_verified_paillier(&secret_key, &paillier_pk);
            api_childkey_creator
                .create_api_childkey(black_box(Curve::Secp256r1))
                .unwrap();
        })
    });

    c.bench_function("encrypt_secret_share", |b| {
        b.iter(|| {
            encrypt_secret_share(black_box(&paillier_pk), black_box(&secret_key));
        })
    });

    let (dh_secrets_k1, dh_publics_k1) = dh_init_secp256k1(10).unwrap();
    c.bench_function("fill_rpool_secp256k1", |b| {
        b.iter(|| {
            fill_rpool_secp256k1(
                black_box(dh_secrets_k1.clone()),
                black_box(&dh_publics_k1),
                black_box(&paillier_pk),
            )
            .unwrap();
        })
    });

    c.bench_function("get_rpool_size_k1", |b| {
        b.iter(|| {
            get_rpool_size(black_box(black_box(Curve::Secp256k1))).unwrap();
        })
    });

    c.bench_function("get_rpool_size_r1", |b| {
        b.iter(|| {
            get_rpool_size(black_box(black_box(Curve::Secp256r1))).unwrap();
        })
    });

    let (dh_secrets_r1, dh_publics_r1) = dh_init_secp256r1(10).unwrap();
    c.bench_function("fill_rpool_secp256r1", |b| {
        b.iter(|| {
            fill_rpool_secp256r1(
                black_box(dh_secrets_r1.clone()),
                black_box(&dh_publics_r1),
                black_box(&paillier_pk),
            )
            .unwrap();
        })
    });

    let msg_hash =
        BigInt::from_hex("000000000000000fffffffffffffffffff00000000000000ffffffffff000000")
            .unwrap();
    let api_childkey_k1 = api_childkey_creator
        .create_api_childkey(Curve::Secp256k1)
        .unwrap();
    for _ in 0..100 {
        let (dh_secrets_k1, dh_publics_k1) = dh_init_secp256k1(100).unwrap();
        fill_rpool_secp256k1(dh_secrets_k1, &dh_publics_k1, &paillier_pk).unwrap();
    }
    c.bench_function("compute_presig_k1", |b| {
        b.iter(|| {
            compute_presig(
                black_box(&api_childkey_k1),
                black_box(&msg_hash),
                black_box(Curve::Secp256k1),
            )
            .unwrap();
        })
    });

    let api_childkey_creator2 =
        APIchildkeyCreator::init_with_verified_paillier(&secret_key, &paillier_pk);
    let api_childkey_r1 = api_childkey_creator2
        .create_api_childkey(Curve::Secp256r1)
        .unwrap();
    for _ in 0..100 {
        let (dh_secrets_r1, dh_publics_r1) = dh_init_secp256r1(100).unwrap();
        fill_rpool_secp256r1(dh_secrets_r1, &dh_publics_r1, &paillier_pk).unwrap();
    }
    c.bench_function("compute_presig_r1", |b| {
        b.iter(|| {
            compute_presig(
                black_box(&api_childkey_r1),
                black_box(&msg_hash),
                black_box(Curve::Secp256r1),
            )
            .unwrap();
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().without_plots();
    targets = criterion_benchmark
}

criterion_main!(benches);
