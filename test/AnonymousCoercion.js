let AnonymousVoting = artifacts.require("AnonymousVoting");
let AnonymousVoteSelling = artifacts.require("AnonymousVoteSelling");
let LocalCrypto = artifacts.require("LocalCrypto");
let LocalCryptoVoteSelling = artifacts.require("LocalCryptoVoteSelling");
let Secp256k1 = artifacts.require("Secp256k1");

let utils = require("./utils");

/*contract("LocalCryptoVoteSelling", (accounts) => {
    it("Should find roots correctly", async () => {
        let localCryptoVoteSelling = await LocalCryptoVoteSelling.deployed();
        // let smallPrimes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,151, 157, 163, 167, 173, 179, 181, 191, 193, 197,199, 211, 223, 227, 229, 233, 239, 241, 251, 257,263, 269, 271, 277, 281, 283, 293, 307, 311, 313,317, 331, 337, 347, 349, 353, 359, 367, 373, 379,383, 389, 397, 401, 409, 419, 421, 431, 433, 439,443, 449, 457, 461, 463, 467, 479, 487, 491, 499,503, 509, 521, 523, 541, 547, 557, 563, 569, 571,577, 587, 593, 599, 601, 607, 613, 617, 619, 631,641, 643, 647, 653, 659, 661, 673, 677, 683, 691,701, 709, 719, 727, 733, 739, 743, 751, 757, 761,769, 773, 787, 797, 809, 811, 821, 823, 827, 829,839, 853, 857, 859, 863, 877, 881, 883, 887, 907,911, 919, 929, 937, 941, 947, 953, 967, 971, 977,983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033,1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093,1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163,1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229];
        let smallPrimes = [3, 5, 7, 11, 13, 17, 19, 23];
        for (let i = 0; i < smallPrimes.length; i++){
            let p = smallPrimes[i];
            let squares = [];
            for (let root = 0; root < 1 + Math.floor(p/2); root++) {
                let sq = (root * root) % p;
                squares.push(sq);
                let calculated = await localCryptoVoteSelling.sqrtmod.call(sq, p);
                assert.equal((calculated * calculated) % p, sq, "Failed to find correct square root");

            }
            for (let nonSquare = 0; nonSquare < p; nonSquare++){
                if (squares.indexOf(nonSquare) == -1) {
                    let calculated = await localCryptoVoteSelling.sqrtmod.call(nonSquare, p);
                    assert.equal(calculated, 0, "Found a root for a non square integer");
                }
            }
        }
    });
});*/

contract("AnonymousVoteSelling", (accounts) => {
    let anonymousVoting, anonymousVoteSelling, localCrypto, localCryptoVoteSelling, voters;
    before(async () => {
        localCrypto = await LocalCrypto.deployed();
        anonymousVoting = await AnonymousVoting.deployed();
        let n = 4;
        voters = await utils.generateVoters(accounts, n, localCrypto);
        await anonymousVoting.setEligible(voters.map(voter => voter.address));
        let gap = 3600;
        let finishSignup = (await utils.getCurrentBlock()).timestamp + gap;
        let endSignup = finishSignup + gap;
        let endComputation = endSignup + gap;
        let endCommitment = endComputation + gap;
        let endVoting = endCommitment - 1 + gap;
        let endRefund = endVoting + gap;
        await anonymousVoting.beginSignUp("Should Satoshi Nakamoto reveal his identity?", false, finishSignup, endSignup, endCommitment, endVoting, endRefund, 0);
        utils.increaseTime(gap * 0.5);
        utils.advanceBlock();
        for(let i = 0; i < voters.length; i++) {
            await anonymousVoting.register(voters[i].xG, voters[i].vG, voters[i].r, {from: voters[i].address});
        }
        utils.increaseTime(gap);
        utils.advanceBlock();
        await anonymousVoting.finishRegistrationPhase();
        await utils.populateRecomputedKeys(voters, localCrypto, anonymousVoting);
        for (let i = 0; i < voters.length; i++) {
            await anonymousVoting.submitVote(voters[i].params, voters[i].vote, voters[i].a1, voters[i].b1, voters[i].a2, voters[i].b2, {from: voters[i].address});
        }
        await anonymousVoting.computeTally();
        localCryptoVoteSelling = await LocalCryptoVoteSelling.deployed();
    });

    it("should be able to verify no votes", async () => {
        anonymousVoteSelling = await AnonymousVoteSelling.new(AnonymousVoting.address, false, "1000000000000000000", 13, false, {value: "2000000000000000000"});
        var H = [(await anonymousVoteSelling.H(0)).toString(10), (await anonymousVoteSelling.H(1)).toString(10)];
        let [y, res, params] = await utils.generatePublicKeysZKP(voters, localCryptoVoteSelling, H, 0, accounts[9]);
        console.log(await anonymousVoteSelling.submitPublicKeysProof(y, params, res, {from: accounts[9]}));
        console.log(await anonymousVoteSelling.verifyPublicKeysProof(3, {from: accounts[9]}));
        console.log(await anonymousVoteSelling.verifyPublicKeysProof(1, {from: accounts[9]}));
        [y, res, params] = await utils.generateVoteZKP(voters, localCryptoVoteSelling, H, 0, false, accounts[9]);
        console.log(await anonymousVoteSelling.submitVoteProof(params, res, {from: accounts[9]}));
        console.log(await anonymousVoteSelling.verifyVoteProof(3, {from: accounts[9]}));
        console.log(await anonymousVoteSelling.verifyVoteProof(1, {from: accounts[9]}));
        let initialBalance = await utils.getBalance(accounts[8]);
        await anonymousVoteSelling.collectReward(accounts[8], {from: accounts[9]});
        let finalBalance = await utils.getBalance(accounts[8]);
        assert.equal(finalBalance.minus(initialBalance).toString(10), web3.toWei(1, "ether").toString(10));
    });
});
