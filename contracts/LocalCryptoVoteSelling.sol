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

    uint[2] G;

    function LocalCryptoVoteSelling() {
        G[0] = Gx;
        G[1] = Gy;
    }

    function legendreSymbol(uint a, uint p) returns (int) {
        uint ls = ECCMath.expmod(a, (p - 1) / 2, p);
        if (ls == p - 1) {
            return -1;
        } else {
            return int(ls);
        }
    }

    function sqrtmod(uint a, uint p) returns (uint) {
        if (legendreSymbol(a, p) != 1) {
            return 0;
        } else if (a == 0) {
            return 0;
        } else if (p == 2) {
            return p;
        } else if (p % 4 == 3) {
            return ECCMath.expmod(a, (p + 1) / 4, p);
        }

        uint s = p - 1;
        uint e = 0;
        while (s % 2 == 0) {
            s /= 2;
            e += 1;
        }

        uint n = 2;
        while (legendreSymbol(n, p) != -1) {
            n += 1;
        }
        uint x = ECCMath.expmod(a, (s + 1) / 2, p);
        uint b = ECCMath.expmod(a, s, p);
        uint g = ECCMath.expmod(n, s, p);
        uint r = e;

        while (true) {
            uint t = b;
            for (uint m = 0; m < r; m++) {
                if (t == 1) {
                    break;
                }
                t = ECCMath.expmod(t, 2, p);
            }

            if (m == 0) {
                return x;
            }
            uint gs = ECCMath.expmod(g, 2 ** (r - m - 1), p);
            g = (gs * gs) % p;
            x = (x * gs) % p;
            b = (b * g) % p;
            r = m;
        }
    }

    function mapToCurve(uint x) returns (uint[2]) {
        x -= 1;
        uint y;
        uint f_x;

        while (true) {
            x = (x + 1) % pp;
            f_x = addmod(mulmod(mulmod(x, x, pp), x, pp), 7, pp);
            y = sqrtmod(f_x, pp);
            if (y != 0) {
                return [x, y];
            }
        }
    }

    // a - b = c;
    function submod(uint a, uint b) returns (uint){
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


    function multiply(uint[2] H, uint x) returns (uint[2]) {
        uint[3] memory xH = Secp256k1._mul(x, H);

        // Convert to Affine Co-ordinates
        ECCMath.toZ1(xH, pp);

        return [xH[0], xH[1]];
    }

    function createZKPPublicKeys(uint[] publicKeys, uint[] params, uint w, uint x, uint[2] y, uint[2] H, uint proverIndex) returns (uint[2], uint[], uint[]) {
        uint[] memory bases = new uint[](publicKeys.length);
        for(uint i = 0; i < publicKeys.length/2; i++) {
            bases[i*2] = G[0];
            bases[i*2+1] = G[1];
        }
        uint[] memory res = computeIndividualZKPs(bases, publicKeys, params, w, y, H, proverIndex);
        return computeORZKP(params, res, w, x, y, H, proverIndex);
    }

    function createZKPVotes (uint[] recomputedBases, uint[] votes, uint[] params, uint w, uint x, uint[2] y, uint[2] H, uint proverIndex, bool yesVote) returns (uint[2], uint[], uint[]) {
        uint[] memory res;
        if (yesVote) {
            res = computeIndividualZKPs(recomputedBases, computePublicKeysFromYesVotes(votes), params, w, y, H, proverIndex);
        } else {
            res = computeIndividualZKPs(recomputedBases, votes, params, w, y, H, proverIndex);
        }
        return computeORZKP(params, res, w, x, y, H, proverIndex);
    }

    function computePublicKeysFromYesVotes (uint[] votes) returns (uint[]) {
        // Negate the 'y' co-ordinate of G
        uint[3] memory temp1;
        uint[2] memory temp_affine1 = [G[0], pp - G[1]];

        for (uint i = 0; i < votes.length/2; i++) {
            temp1 = Secp256k1._addMixed([votes[i*2], votes[i*2+1], 1], temp_affine1);
            ECCMath.toZ1(temp1, pp);
            votes[i*2] = temp1[0];
            votes[i*2+1] = temp1[1];
        }
        return votes;
    }

    function computeIndividualZKPs (uint[] bases, uint[] publicKeys, uint[] params, uint w, uint[2] y, uint[2] H, uint proverIndex) returns (uint[]) {
        uint[] memory res = new uint[](publicKeys.length*2);
        uint[3] memory temp1;

        for (uint i = 0; i < params.length/2; i++) {
            if (i == proverIndex) {
                temp1 = Secp256k1._mul(w, H);
                ECCMath.toZ1(temp1, pp);

                res[i*4] = temp1[0];
                res[i*4+1] = temp1[1];

                temp1 = Secp256k1._mul(w, [bases[i*2], bases[i*2+1]]);
                ECCMath.toZ1(temp1, pp);

                res[i*4+2] = temp1[0];
                res[i*4+3] = temp1[1];
            } else {
                temp1 = Secp256k1._mul(params[i*2+1], H);
                temp1 = Secp256k1._add(temp1, Secp256k1._mul(params[i*2], y));
                ECCMath.toZ1(temp1, pp);

                res[i*4] = temp1[0];
                res[i*4+1] = temp1[1];

                temp1 = Secp256k1._mul(params[i*2+1], [bases[i*2], bases[i*2+1]]);
                temp1 = Secp256k1._add(temp1, Secp256k1._mul(params[i*2], [publicKeys[i*2], publicKeys[i*2+1]]));
                ECCMath.toZ1(temp1, pp);

                res[i*4+2] = temp1[0];
                res[i*4+3] = temp1[1];
            }
        }
        return res;
    }

    function computeORZKP (uint[] params, uint[] res, uint w, uint x, uint[2] y, uint[2] H, uint proverIndex) returns (uint[2], uint[], uint[]) {
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
