use crate::signature::utils::*;
use crate::signature::{POINT, SCALAR};
use secp256k1::{Error, PublicKey, SecretKey};
use sha2::{Digest, Sha256};

#[allow(non_snake_case)]
pub fn verify_aggregate(pk: &POINT, r: &SCALAR, s: &SCALAR, message: &[u8]) -> Result<bool, Error> {
    if &P <= r || &N <= s {
        return Err(Error::IncorrectSignature);
    }
    if !has_square_y(r) {
        return Err(Error::IncorrectSignature);
    }

    // hash by sha256
    let mut vec = Vec::with_capacity(32 + 33 + 32);
    vec.extend_from_slice(r);
    vec.extend_from_slice(pk);
    vec.extend_from_slice(message);
    let c = Sha256::digest(&vec);

    // calc: sG = G * signature_fe
    let signature_fe = SecretKey::from_slice(s)?;
    let mut sG = generator();
    scalar_mul(&mut sG, &signature_fe)?;

    // calc: cY = pk * C
    let c = SecretKey::from_slice(&c)?;
    let mut cY = PublicKey::from_slice(pk)?;
    scalar_mul(&mut cY, &c)?;

    // calc: R = sG - cY
    let minus_point = sub_point(&sG, &cY)?;

    // check point is on Jacobian-curve
    if !is_jacobi(&minus_point) {
        return Err(Error::InvalidSignature);
    }

    Ok(&minus_point.serialize()[1..33] == r.as_ref())
}

/// https://github.com/guggero/bip-schnorr/blob/master/test/test-vectors-schnorr.json
/// aggregate single-sig check vectors
#[cfg(test)]
mod single_verify {
    use crate::signature::{verify_signature, Signature};
    use secp256k1::Error;
    #[test]
    fn vector_0() {
        // comment: None
        // expectedError: None
        let _sk = hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let pk = hex::decode("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap();
        let msg = hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let r = hex::decode("787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF6").unwrap(); // r
        let s = hex::decode("7031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05").unwrap(); // s

        let signature = Signature::new_single_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_1() {
        // comment: None
        // expectedError: None
        let _sk = hex::decode("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF").unwrap();
        let pk = hex::decode("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659").unwrap();
        let msg = hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89").unwrap();
        let r = hex::decode("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D").unwrap(); // r
        let s = hex::decode("1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD").unwrap(); // s

        let signature = Signature::new_single_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_2() {
        // comment: None
        // expectedError: None
        let _sk = hex::decode("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C7").unwrap();
        let pk = hex::decode("03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B").unwrap();
        let msg = hex::decode("5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C").unwrap();
        let r = hex::decode("00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE").unwrap(); // r
        let s = hex::decode("00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380").unwrap(); // s

        let signature = Signature::new_single_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_3() {
        // comment: None
        // expectedError: None
        let _sk = hex::decode("6D6C66873739BC7BFB3526629670D0EA357E92CC4581490D62779AE15F6B787B").unwrap();
        let pk = hex::decode("026D7F1D87AB3BBC8BC01F95D9AECE1E659D6E33C880F8EFA65FACF83E698BBBF7").unwrap();
        let msg = hex::decode("B2F0CD8ECB23C1710903F872C31B0FD37E15224AF457722A87C5E0C7F50FFFB3").unwrap();
        let r = hex::decode("68CA1CC46F291A385E7C255562068357F964532300BEADFFB72DD93668C0C1CA").unwrap(); // r
        let s = hex::decode("C8D26132EB3200B86D66DE9C661A464C6B2293BB9A9F5B966E53CA736C7E504F").unwrap(); // s

        let signature = Signature::new_single_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_4() {
        // comment: None
        // expectedError: None
        let pk = hex::decode("03DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34").unwrap();
        let msg = hex::decode("4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703").unwrap();
        let r = hex::decode("00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63").unwrap(); // r
        let s = hex::decode("02A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D").unwrap(); // s

        let signature = Signature::new_single_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_5() {
        // comment: test fails if jacobi symbol of x(R) instead of y(R) is used
        // expectedError: None
        let pk = hex::decode("031B84C5567B126440995D3ED5AABA0565D71E1834604819FF9C17F5E9D5DD078F").unwrap();
        let msg = hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let r = hex::decode("52818579ACA59767E3291D91B76B637BEF062083284992F2D95F564CA6CB4E35").unwrap(); // r
        let s = hex::decode("30B1DA849C8E8304ADC0CFE870660334B3CFC18E825EF1DB34CFAE3DFC5D8187").unwrap(); // s

        let signature = Signature::new_single_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_6() {
        // comment: test fails if msg is reduced
        // expectedError: None
        let pk = hex::decode("03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B").unwrap();
        let msg = hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap();
        let r = hex::decode("570DD4CA83D4E6317B8EE6BAE83467A1BF419D0767122DE409394414B05080DC").unwrap(); // r
        let s = hex::decode("E9EE5F237CBD108EABAE1E37759AE47F8E4203DA3532EB28DB860F33D62D49BD").unwrap(); // s

        let signature = Signature::new_single_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_7() {
        // comment: public key not on the curve
        // expectedError: signature verification failed
        let pk = hex::decode("03EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34").unwrap();
        let msg = hex::decode("4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703").unwrap();
        let r = hex::decode("00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63").unwrap(); // r
        let s = hex::decode("02A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D").unwrap(); // s

        let signature = Signature::new_single_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Err(Error::InvalidPublicKey));
    }

    #[test]
    fn vector_8() {
        // comment: incorrect R residuosity
        // expectedError: signature verification failed
        let pk = hex::decode("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659").unwrap();
        let msg = hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89").unwrap();
        let r = hex::decode("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D").unwrap(); // r
        let s = hex::decode("FA16AEE06609280A19B67A24E1977E4697712B5FD2943914ECD5F730901B4AB7").unwrap(); // s

        let signature = Signature::new_single_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Err(Error::InvalidSignature));
    }

    #[test]
    fn vector_9() {
        // comment: negated message hash
        // expectedError: signature verification failed
        let pk = hex::decode("03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B").unwrap();
        let msg = hex::decode("5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C").unwrap();
        let r = hex::decode("00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE").unwrap(); // r
        let s = hex::decode("D092F9D860F1776A1F7412AD8A1EB50DACCC222BC8C0E26B2056DF2F273EFDEC").unwrap(); // s

        let signature = Signature::new_single_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Err(Error::InvalidSignature));
    }

    #[test]
    fn vector_10() {
        // comment: negated s value
        // expectedError: signature verification failed
        let pk = hex::decode("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap();
        let msg = hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let r = hex::decode("787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF6").unwrap(); // r
        let s = hex::decode("8FCE5677CE7A623CB20011225797CE7A8DE1DC6CCD4F754A47DA6C600E59543C").unwrap(); // s

        let signature = Signature::new_single_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Err(Error::InvalidSignature));
    }

    #[test]
    fn vector_11() {
        // comment: negated public key
        // expectedError: signature verification failed
        let pk = hex::decode("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659").unwrap();
        let msg = hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89").unwrap();
        let r = hex::decode("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D").unwrap(); // r
        let s = hex::decode("1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD").unwrap(); // s

        let signature = Signature::new_single_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Err(Error::InvalidSignature));
    }

    #[test]
    fn vector_12() {
        // comment: sG - eP is infinite. Test fails in single verification if jacobi(y(inf)) is defined as 1 and x(inf) as 0
        // expectedError: signature verification failed
        let pk = hex::decode("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659").unwrap();
        let msg = hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89").unwrap();
        let r = hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap(); // r
        let s = hex::decode("9E9D01AF988B5CEDCE47221BFA9B222721F3FA408915444A4B489021DB55775F").unwrap(); // s

        let signature = Signature::new_single_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Err(Error::IncorrectSignature));
    }

    #[test]
    fn vector_13() {
        // comment: sG - eP is infinite. Test fails in single verification if jacobi(y(inf)) is defined as 1 and x(inf) as 1
        // expectedError: signature verification failed
        let pk = hex::decode("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659").unwrap();
        let msg = hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89").unwrap();
        let r = hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap(); // r
        let s = hex::decode("D37DDF0254351836D84B1BD6A795FD5D523048F298C4214D187FE4892947F728").unwrap(); // s

        let signature = Signature::new_single_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Err(Error::InvalidPublicKey));
    }

    #[test]
    fn vector_14() {
        // comment: sig[0:32] is not an X coordinate on the curve
        // expectedError: signature verification failed
        let pk = hex::decode("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659").unwrap();
        let msg = hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89").unwrap();
        let r = hex::decode("4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D").unwrap(); // r
        let s = hex::decode("1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD").unwrap(); // s

        let signature = Signature::new_single_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Err(Error::IncorrectSignature));
    }

    #[test]
    fn vector_15() {
        // comment: sig[0:32] is equal to field size
        // expectedError: r is larger than or equal to field size
        let pk = hex::decode("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659").unwrap();
        let msg = hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89").unwrap();
        let r = hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC2F").unwrap(); // r
        let s = hex::decode("1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD").unwrap(); // s

        let signature = Signature::new_single_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Err(Error::IncorrectSignature));
    }

    #[test]
    fn vector_16() {
        // comment: sig[32:64] is equal to curve order
        // expectedError: s is larger than or equal to curve order
        let pk = hex::decode("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659").unwrap();
        let msg = hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89").unwrap();
        let r = hex::decode("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D").unwrap(); // r
        let s = hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141").unwrap(); // s

        let signature = Signature::new_single_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Err(Error::IncorrectSignature));
    }

    #[test]
    fn vector_17() {
        // comment: public key is only 16 bytes
        // expectedError: pubKey must be 33 bytes long
        let pk = hex::decode("6d6c66873739bc7bfb3526629670d0ea").unwrap();
        let _msg = hex::decode("b2f0cd8ecb23c1710903f872c31b0fd37e15224af457722a87c5e0c7f50fffb3").unwrap();
        let r = hex::decode("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D").unwrap(); // r
        let s = hex::decode("1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD").unwrap(); // s

        assert!(Signature::new_single_sig(&pk, &r, &s).is_err());
    }
}

/// https://github.com/guggero/bip-schnorr/blob/master/test/test-vectors-mu-sig.json
/// aggregate multi-sig verify check vectors
#[cfg(test)]
mod multi_verify {
    use crate::signature::{verify_signature, Signature};

    #[test]
    fn vector_0() {
        let pk = hex::decode("0226d77f91bcfe366a4f9390c38a7c03d025e541940a881cca98ac4237a0352537").unwrap();
        let msg = hex::decode("746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721").unwrap();
        let r = hex::decode("69039691323f6d26a1ab2903730496cf3247f258b438abdbd350e3cf2814e368").unwrap();
        let s = hex::decode("3c179ac0a44fa7f25c3f734ff9e29a85f9be1ea541a92ceb542882ab95e8aa2a").unwrap();

        let signature = Signature::new_aggregate_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_1() {
        let pk = hex::decode("023e9bfed377ec8cb39aa46bb94a482877ad2d367b83f141c35980065fa725e98d").unwrap();
        let msg = hex::decode("746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721").unwrap();
        let r = hex::decode("e42205af485ef63ab37f1f161ba66faa3c35899268ff0e63600ade607859b49c").unwrap();
        let s = hex::decode("d2ef8b9bcf79fc36351faba0631b6fd03cd8425fab663708c3b8d5c42cf3d7f0").unwrap();

        let signature = Signature::new_aggregate_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_2() {
        let pk = hex::decode("024ab0ed9bbcc5d04dcb00d7218774e08ef45150f67b193df7e80d1b09b951f298").unwrap();
        let msg = hex::decode("746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721").unwrap();
        let r = hex::decode("833c66e66dac07f2265a7279d08e75d620e156d36763a5d2cf842c46c048e7be").unwrap();
        let s = hex::decode("c6a7c2992d86cac0cd00a17dc43b6d76d08c1ce5b255cd23c71135c12438899d").unwrap();

        let signature = Signature::new_aggregate_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_3() {
        let pk = hex::decode("0257be95ce7596cf9b9250c99757f5da1a7ca8e75309e2e95863e8b8b0063c3182").unwrap();
        let msg = hex::decode("746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721").unwrap();
        let r = hex::decode("76fdf4ff659723f94d908b43962b5f7b7072e1147315f213e71cce8c9cf16be9").unwrap();
        let s = hex::decode("10e3a75b0d806f7dd59408fb277c5f96fe7004a75acc5c5d393bd3838a4750ed").unwrap();

        let signature = Signature::new_aggregate_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_4() {
        let pk = hex::decode("0295eae1fa390cd97df85830fa425d62b0cd228d46f4d1e044c6b3aea90b2cb7d8").unwrap();
        let msg = hex::decode("746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721").unwrap();
        let r = hex::decode("f5d1e66d52875f3fa11fe5b2cca269f245d2eca18b64d0188f46c0cc6960f83e").unwrap();
        let s = hex::decode("1e0e488dd781654fef94c8fef06be675620803d4fb614de4625e6dc0d13bd3fe").unwrap();

        let signature = Signature::new_aggregate_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_5() {
        let pk = hex::decode("03690346d1f465023deb0c6b7af0fe001bf2a88da618e99781396c0d7d2dcb5bb0").unwrap();
        let msg = hex::decode("746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721").unwrap();
        let r = hex::decode("706b6efd02ecc58f8cf0acc797423a0c2b7352883ff5f96da09b5342a7717529").unwrap();
        let s = hex::decode("f00de80094b4c3ae817589488984b82c60b2ce656137339590f82a6b326deea5").unwrap();

        let signature = Signature::new_aggregate_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_6() {
        let pk = hex::decode("0357e0c8df844c41f77a3f83288e66cba738015b63aaf2c923f0ebe4c573d4175f").unwrap();
        let msg = hex::decode("746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721").unwrap();
        let r = hex::decode("250efe3a4140a2dd46b700d0d3a42de7d6dcd5b692e499bab6012c764d9f1250").unwrap();
        let s = hex::decode("01811686ee7d5c65907b45e5f16edefe70c7520d7149526fa9589f5ddc4eb45e").unwrap();

        let signature = Signature::new_aggregate_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_7() {
        let pk = hex::decode("0384731e84ff6af4888b0707599ed9080cc56b2b71f9e532cdf8e4bdace33b5afa").unwrap();
        let msg = hex::decode("746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721").unwrap();
        let r = hex::decode("ccb2bb6ac8740d20289ec6128120d3476c8cc170612785822c3e655189229e81").unwrap();
        let s = hex::decode("f9371dc6d8e977fc7bf8c75e4f517506c1ef90f7d461f6238e8ac838b23158bb").unwrap();

        let signature = Signature::new_aggregate_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_8() {
        let pk = hex::decode("0311fe6804261e3092ed5a3ece206fda8e001398ba0e3d2e0bdeccaa57e458e209").unwrap();
        let msg = hex::decode("746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721").unwrap();
        let r = hex::decode("08efabbe885471c6dadb3e7ffc8da9e1699154d1ed768f769ec705512d7dc4d6").unwrap();
        let s = hex::decode("743fa559d1167a22f065bfabee317bb12d667d5d039faa7c8438b1135a4fbb3d").unwrap();

        let signature = Signature::new_aggregate_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_9() {
        let pk = hex::decode("035229b606e8cec7162e9c1038aa802052de3c38e90c0d684eafa8c33d52d03421").unwrap();
        let msg = hex::decode("746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721").unwrap();
        let r = hex::decode("bd6554315e2a1e55b751254eed9de4c7da5dd3df13ace77bcb6ccdb1b8a7fe9f").unwrap();
        let s = hex::decode("065354aaa410f563fd139012663e801d32caca1e124fe01f6c74cdf2621db34e").unwrap();

        let signature = Signature::new_aggregate_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_10() {
        let pk = hex::decode("02f9bf93ac63e254e1b4c1f0b64ffdaa542c7ac699d7c9e99003ae292de65d00e2").unwrap();
        let msg = hex::decode("746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721").unwrap();
        let r = hex::decode("ae053ab55c2f52cf61bc3bd9a924dfd752f459a6cc70a2910ccf696f010aa0e2").unwrap();
        let s = hex::decode("0adcffeb47e36189d2e52d519b65867b3ad0603069d34ac6ec127381a0d91b24").unwrap();

        let signature = Signature::new_aggregate_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_11() {
        let pk = hex::decode("032b5616e1aad6a622c5fa06543487360a224c847838c1e11b6b4de0fc321f1350").unwrap();
        let msg = hex::decode("746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721").unwrap();
        let r = hex::decode("d86e1838c4dcf01727aa23762b1e2470480aa2153ec4e01efa50687145964940").unwrap();
        let s = hex::decode("67228f65a5c8b427528adfbd19a3caa1345d8b32df2157c761596b142fb2569e").unwrap();

        let signature = Signature::new_aggregate_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_12() {
        let pk = hex::decode("028cb8a2da3cb14aea36affd120398872a93e67cbb5e944d7a14abfaa80870a931").unwrap();
        let msg = hex::decode("746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721").unwrap();
        let r = hex::decode("636d43f9c8c54d75fc840ebe13c590b1ad49b5dfeaf843d4c95011bef1b231d5").unwrap();
        let s = hex::decode("cc9cd120e9e062c79ce6ed6e7eba46b8d01470a874c8ebb0c5e70f0930e950fe").unwrap();

        let signature = Signature::new_aggregate_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_13() {
        let pk = hex::decode("02cdc8eb62f7f94a9fe5b081211f467d2400a53e86c3988ecc1e95a436823aefbe").unwrap();
        let msg = hex::decode("746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721").unwrap();
        let r = hex::decode("3e14527635b60be2cd9937c743780a88b99fad04513cb56741d3f6d12b2efd97").unwrap();
        let s = hex::decode("2150ba86083d4d268b7a9b1ecc4d6f145d3b7b8aa3073e9f597d689232290983").unwrap();

        let signature = Signature::new_aggregate_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_14() {
        let pk = hex::decode("03a17e7ba73e9c64bc20c1658546f0f10afabf3747884e927138ea1842c94c48ad").unwrap();
        let msg = hex::decode("746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721").unwrap();
        let r = hex::decode("0b3411a17c537f8dc51fd7cf925d9d8e3e29d7adf8f82d7a895db86b7d7c5a4d").unwrap();
        let s = hex::decode("4aa3c75dc56921272bf764ac22315bcec9de45fb27ed4e7b21299c3bc6ed9350").unwrap();

        let signature = Signature::new_aggregate_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_15() {
        let pk = hex::decode("03bbadc7d50184861d39919af072be085d6febad6a38b815614d0af622ce05abca").unwrap();
        let msg = hex::decode("746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721").unwrap();
        let r = hex::decode("5139b6714136d7242dff7ff1d2ddda0b50dc9b8fafbc1377eb294ae2427e6a98").unwrap();
        let s = hex::decode("51c45411f3520aa12612a814e324fdcc1e7b47bb368feed642b68956d28bfc8b").unwrap();

        let signature = Signature::new_aggregate_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_16() {
        let pk = hex::decode("0278dbd2c33a41b81ef74525dcc6c948f04924aec5a7dc3d49dbbe51ab79eb6719").unwrap();
        let msg = hex::decode("746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721").unwrap();
        let r = hex::decode("715e6296bfb31075cd9de8bba9d6c85b79cd981ca9f912a205a1278cbd70e5ce").unwrap();
        let s = hex::decode("d331c4d98816782a7a001d5e7d8d3fb22681d3180c436e56439e9984c07d50e0").unwrap();

        let signature = Signature::new_aggregate_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_17() {
        let pk = hex::decode("0381c19334cbc4ef66078dd97f278fabc125de76164f68c7cf85a50e1e6839124a").unwrap();
        let msg = hex::decode("746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721").unwrap();
        let r = hex::decode("0646899715f1bece907c1a89116995a71df90a45dc312139ba018c3fafcc0493").unwrap();
        let s = hex::decode("ce04ffa7989d94cf19f4210b0f073896aa91138797e7ca651949edaf4dbed29a").unwrap();

        let signature = Signature::new_aggregate_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_18() {
        let pk = hex::decode("03d26dc364ab8d668bcd1010e9c96ad166315bb0b100a84cd5856e7ab282650136").unwrap();
        let msg = hex::decode("746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721").unwrap();
        let r = hex::decode("69e90468c4a788d79677aff546bbe45ff047212140eebe726408280496f9e5a7").unwrap();
        let s = hex::decode("c05f3ce32666bf5ba247c05629c7d848dbf5c6fae9ee3359f247d8c46a0f675e").unwrap();

        let signature = Signature::new_aggregate_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }

    #[test]
    fn vector_19() {
        let pk = hex::decode("03da2a4b86abd79d8650fe75315e8adf5eaae3edb84fa19e180db507d87ce64ccc").unwrap();
        let msg = hex::decode("746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721").unwrap();
        let r = hex::decode("2f50922466958f2517589336718f455ae73291a575a7a15ec0b3112c4fc7ea10").unwrap();
        let s = hex::decode("77400b2bfc81d169cb3d18d3c231a65927700c0a54611e353cf0edff129d53eb").unwrap();

        let signature = Signature::new_aggregate_sig(&pk, &r, &s).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }
}
