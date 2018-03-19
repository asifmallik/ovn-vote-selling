pragma solidity ^0.4.18;

import "./Secp256k1.sol";

contract LocalCryptoVoteSelling {

        event loge2(uint[2] asdasd);
        event loge3(uint[3] asdasd);

    // Modulus for public keys
    uint constant pp = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    // Base point (generator) G
    uint constant Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint constant Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    // Modulus for private keys (sub-group)
    uint constant nn = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    uint[2] public G;

    function LocalCryptoVoteSelling() {
        G[0] = Gx;
        G[1] = Gy;
    }

    // a - b = c;
    function submod(uint a, uint b) constant returns (uint){
        uint a_nn;

        if(a>b) {
          a_nn = a;
        } else {
          a_nn = a+nn;
        }

        uint c = addmod(a_nn - b,0,nn);

        return c;
    }


    /* function computeRealStep (uint w, uint[2] storage base1, uint[2] storage base2) internal returns (uint[3], uint[3]) {
        uint[3] temp1 = Secp256k1._mul(w, base1);
        ECCMath.toZ1(temp1, pp);
        uint[3] temp2 = Secp256k1._mul(w, base2);
        ECCMath.toZ1(temp2, pp);
        return (temp1,temp2);
    } */


    function multiply(uint[2] H, uint x) constant returns (uint[2]) {
        uint[3] memory xH = Secp256k1._mul(x, H);

        // Convert to Affine Co-ordinates
        ECCMath.toZ1(xH, pp);

        return [xH[0], xH[1]];
    }

    function computePublicKeyFromYesVote (uint[2] vote) constant returns (uint[2]) {
        // Negate the 'y' co-ordinate of G
        uint[3] memory temp1;
        uint[2] memory temp_affine1 = [G[0], pp - G[1]];

        temp1 = Secp256k1._addMixed([vote[0], vote[1], 1], temp_affine1);
        ECCMath.toZ1(temp1, pp);
        return [temp1[0], temp1[1]];
    }

    function computeIndividualRealZKP (uint[2] base, uint[2] publicKey, uint w, uint[2] H) constant returns (uint[4] res) {
        uint[3] memory temp1;
        temp1 = Secp256k1._mul(w, H);
        ECCMath.toZ1(temp1, pp);

        res[0] = temp1[0];
        res[1] = temp1[1];

        temp1 = Secp256k1._mul(w, [base[0], base[1]]);
        ECCMath.toZ1(temp1, pp);

        res[2] = temp1[0];
        res[3] = temp1[1];
    }

    function computeIndividualFakeZKP (uint[2] base, uint[2] publicKey, uint[2] params, uint[2] y, uint[2] H) constant returns (uint[4] res) {
        uint[3] memory temp1;
        temp1 = Secp256k1._mul(params[1], H);
        temp1 = Secp256k1._add(temp1, Secp256k1._mul(params[0], y));
        ECCMath.toZ1(temp1, pp);

        res[0] = temp1[0];
        res[1] = temp1[1];

        temp1 = Secp256k1._mul(params[1], [base[0], base[1]]);
        temp1 = Secp256k1._add(temp1, Secp256k1._mul(params[0], [publicKey[0], publicKey[1]]));
        ECCMath.toZ1(temp1, pp);

        res[2] = temp1[0];
        res[3] = temp1[1];
    }

    function computeORZKP (uint[] params, uint[] res, uint w, uint x, uint[2] y, uint[2] H, uint proverIndex) constant returns (uint[2], uint[], uint[]) {
        uint dSum;

        for(uint i = 0; i < params.length/2; i++) {
            if(i != proverIndex) {
                dSum = addmod(dSum, params[i*2], nn);
            }
        }

        // d_prover_index = c - d_sum mod q
        params[proverIndex*2] = submod(uint(sha256(msg.sender, H, y, res)), dSum);

        // r_prover_index = w - (x * d_prover_index) mod q
        params[proverIndex*2+1] = submod(w, mulmod(x, params[proverIndex*2], nn));

        return (y, res, params);
    }
}
