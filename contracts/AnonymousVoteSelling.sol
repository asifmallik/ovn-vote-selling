pragma solidity ^0.4.18;

import "./AnonymousVoting.sol";

contract AnonymousVoteSelling {
    AnonymousVoting anonymousVoting;
    bool onchainVerification;
    bool yesVote;
    uint n;
    uint deadline;
    uint reward;

    // Modulus for public keys
    uint constant pp = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    // Base point (generator) G
    uint constant Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint constant Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    // Modulus for private keys (sub-group)
    uint constant nn = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    uint[2] G;
    uint[2] public H;

    struct Proof {
        uint[2] xH;
        uint completedPublicKeysProofSteps;
        uint completedVotesProofSteps;
        uint[] publicKeysParams;
        uint[] publicKeysRes;
        uint[] votesParams;
        uint[] votesRes;
        bool faulty;
    }

    mapping (address => Proof) proofs;
    mapping (bytes32 => bool) collected;

    function AnonymousVoteSelling (address _anonymousVoting, bool _onchainVerification, uint _reward, uint _deadline, bool _yesVote) payable {
        anonymousVoting = AnonymousVoting(_anonymousVoting);
        reward = _reward;
        deadline = _deadline;
        onchainVerification = _onchainVerification;
        n = anonymousVoting.totalregistered();
        yesVote = _yesVote;
        H = mapToCurve(uint(sha256(this, _anonymousVoting)));
        /* require(Secp256k1.isPubKey(H)); */
        G[0] = Gx;
        G[1] = Gy;

        uint state = uint(anonymousVoting.state());
        require(state > 1);
        if (state == 4) {
            require(msg.value == reward * anonymousVoting.finaltally(0));
        } else {
            require(msg.value == reward * n);
        }
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

    function submitPublicKeysProof (uint[2] y, uint[] params, uint[] res) {
        require(params.length == n*2 && res.length == n*4);
        require(proofs[msg.sender].publicKeysParams.length == 0);

        proofs[msg.sender].xH = y;
        proofs[msg.sender].publicKeysParams = params;
        proofs[msg.sender].publicKeysRes = res;
    }

    function submitVoteProof (uint[] params, uint[] res) {
        require(proofs[msg.sender].publicKeysParams.length > 0);
        require(params.length == n*2 && res.length == n*4);
        require(proofs[msg.sender].votesParams.length == 0);

        proofs[msg.sender].votesParams = params;
        proofs[msg.sender].votesRes = res;
    }

    function verifyPublicKeysProof (uint numSteps) returns (bool) {
        Proof storage proof = proofs[msg.sender];
        require(proof.publicKeysParams.length > 0);
        /* require(numSteps > 0); */
        require(!proof.faulty);

        uint[2] memory temp1;
        uint[3] memory temp2;
        uint[3] memory temp3;
        uint endStep = numSteps + proof.completedPublicKeysProofSteps;
        if (n < endStep) {
            endStep = n;
        }

        if(proof.completedPublicKeysProofSteps == 0) {
            uint _c;
            for (uint i = 0; i < n; i++) {
                _c = addmod(_c, proof.publicKeysParams[i*2], nn);
            }
            if(_c != uint(sha256(msg.sender, H, proof.xH, proof.publicKeysRes))) {
                proof.faulty = true;
                return false;
            }
        }

        for (i = proof.completedPublicKeysProofSteps; i < endStep; i++) {
            temp2 = Secp256k1._mul(proof.publicKeysParams[i*2], proof.xH);
            temp3 = Secp256k1._add(temp2, Secp256k1._mul(proof.publicKeysParams[i*2+1], H));
            ECCMath.toZ1(temp3, pp);
            if (proof.publicKeysRes[i*4] != temp3[0] || proof.publicKeysRes[i*4+1] != temp3[1]) {
                proof.faulty = true;
                return false;
            }
            (temp1,,) = anonymousVoting.getVoterById(i);
            temp2 = Secp256k1._mul(proof.publicKeysParams[i*2], temp1);
            temp3 = Secp256k1._add(temp2, Secp256k1._mul(proof.publicKeysParams[i*2+1], G));
            ECCMath.toZ1(temp3, pp);
            if (proof.publicKeysRes[i*4+2] != temp3[0] || proof.publicKeysRes[i*4+3] != temp3[1]) {
                proof.faulty = true;
                return false;
            }
        }
        proof.completedPublicKeysProofSteps = endStep;
        return true;
    }

    function verifyVoteProof (uint numSteps) returns (bool) {
        Proof storage proof = proofs[msg.sender];
        require(proof.votesParams.length > 0);
        require(numSteps > 0);
        require(!proof.faulty);

        uint[2] memory temp1;
        uint[2] memory temp2;
        uint[3] memory temp3;
        uint[3] memory temp4;
        uint endStep = numSteps + proof.completedVotesProofSteps;
        if (n < endStep) {
            endStep = n;
        }

        if(proof.completedVotesProofSteps == 0) {
            uint _c;
            for (uint i = 0; i < n; i++) {
                _c = addmod(_c, proof.votesParams[i*2], nn);
            }
            if(_c != uint(sha256(msg.sender, H, proof.xH, proof.votesRes))) {
                proof.faulty = true;
                return false;
            }
        }

        for (i = proof.completedVotesProofSteps; i < endStep; i++) {
            temp3 = Secp256k1._mul(proof.votesParams[i*2], proof.xH);
            temp4 = Secp256k1._add(temp3, Secp256k1._mul(proof.votesParams[i*2+1], H));
            ECCMath.toZ1(temp4, pp);
            if (proof.votesRes[i*4] != temp4[0] || proof.votesRes[i*4+1] != temp4[1]) {
                proof.faulty = true;
                return false;
            }
            (,temp1,temp2) = anonymousVoting.getVoterById(i); //temp1 = reconstructed, temp2 = vote
            temp3 = Secp256k1._mul(proof.votesParams[i*2+1], temp1);
            if (yesVote) {
                uint[2] memory temp_affine1 = [G[0], pp - G[1]];
                temp4 = Secp256k1._addMixed([temp2[0], temp2[1], 1], temp_affine1);
                ECCMath.toZ1(temp4, pp);
                temp4 = Secp256k1._add(temp3, Secp256k1._mul(proof.votesParams[i*2], [temp4[0], temp4[1]]));
            } else {
                temp4 = Secp256k1._add(temp3, Secp256k1._mul(proof.votesParams[i*2], temp2));
            }
            ECCMath.toZ1(temp4, pp);
            if (proof.votesRes[i*4+2] != temp4[0] || proof.votesRes[i*4+3] != temp4[1]) {
                proof.faulty = true;
                return false;
            }
        }
        proof.completedVotesProofSteps = endStep;
        return true;
    }

    function collectReward (address receiver) {
        Proof proof = proofs[msg.sender];
        require(proof.completedPublicKeysProofSteps == n);
        require(proof.completedVotesProofSteps == n);
        require(!collected[sha256(proof.xH)]);
        collected[sha256(proof.xH)] = true;
        receiver.transfer(reward);
    }
}
