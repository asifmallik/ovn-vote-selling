let EC = require('elliptic').ec;
let ec = new EC('secp256k1');

let generateVoters = async (accounts, n, localCrypto) => {
    let voters = [];
    for(let i = 1; i < n+1; i++) {
        var key = ec.genKeyPair();
        var publicKey = key.getPublic();

        let voter = {
            address: accounts[i],
            x: key.priv.toString(10),
            d: ec.genKeyPair().priv.toString(10),
            r: ec.genKeyPair().priv.toString(10),
            v: ec.genKeyPair().priv.toString(10),
            w: ec.genKeyPair().priv.toString(10),
            xG: [publicKey.getX().toString(10), publicKey.getY().toString(10)]
        };
        let ZKP = await localCrypto.createZKP.call(voter.x, voter.v, voter.xG, {from: voter.address});
        voter.r = ZKP[0].toString(10);
        voter.vG = ZKP.slice(1, 4).map((x)=>x.toString(10));
        voters.push(voter);
    }
    return voters;
}

let populateRecomputedKeys = async (voters, localCrypto, anonymousVoting) => {
    for (var i = 0; i < voters.length; i++) {
        let [,reconstructedKey,] = await anonymousVoting.getVoter.call({from: voters[i].address});
        let res, res2;
        if (i % 2 == 0) {
            [res, res2] = await localCrypto.create1outof2ZKPNoVote.call(voters[i].xG, reconstructedKey, voters[i].w, voters[i].r, voters[i].d, voters[i].x, {from: voters[i].address});
        } else {
            [res, res2] = await localCrypto.create1outof2ZKPYesVote.call(voters[i].xG, reconstructedKey, voters[i].w, voters[i].r, voters[i].d, voters[i].x, {from: voters[i].address});
        }
        voters[i].reconstructedKey = reconstructedKey.map((x)=>x.toString(10));
        voters[i].vote = [res[0].toString(10), res[1].toString(10)];
        voters[i].a1 = [res[2].toString(10), res[3].toString(10)];
        voters[i].b1 = [res[4].toString(10), res[5].toString(10)];
        voters[i].a2 = [res[6].toString(10), res[7].toString(10)];
        voters[i].b2 = [res[8].toString(10), res[9].toString(10)];
        voters[i].params = res2.map((x)=>x.toString(10));
    }
}

let increaseTime = (web3, addSeconds) => {
    return new Promise((resolve, reject) => {
        web3.currentProvider.sendAsync({
            jsonrpc: "2.0",
            method: "evm_increaseTime",
            params: [addSeconds],
            id: 0
        }, (error, result) => {
            if (error) {
                reject(error);
            } else {
                resolve(result);
            }
        });
    });
};


let advanceBlock = (web3) => {
    return new Promise((resolve, reject) => {
        web3.currentProvider.sendAsync({
            jsonrpc: "2.0",
            method: "evm_mine",
            params: [],
            id: 0
        }, (error, result) => {
            if (error) {
                reject(error);
            } else {
                resolve(result);
            }
        });
    });
};

let getCurrentBlock = (web3) => {
    return new Promise((resolve, reject) => {
        web3.eth.getBlock(web3.eth.blockNumber, (error, result) => {
            if (error) {
                reject(error);
            } else {
                resolve(result);
            }
        });
    });
};

let generatePublicKeysZKP = async (voters, localCryptoVoteSelling, H, voterIndex, sender) => {
    let publicKeys = [];
    let params = [];
    let y = await localCryptoVoteSelling.multiply.call(H, voters[voterIndex].x);
    let G = [await localCryptoVoteSelling.G(0), await localCryptoVoteSelling.G(1)];
    let res = [];
    let w = ec.genKeyPair().priv.toString();
    for(let i = 0; i < voters.length; i++) {
        let tempRes;
        if (i == voterIndex) {
            tempRes = await localCryptoVoteSelling.computeIndividualRealZKP(G, [voters[i].xG[0], voters[i].xG[1]], w, H);
            params.push(0);
            params.push(0);
        } else {
            params.push(ec.genKeyPair().priv.toString());
            params.push(ec.genKeyPair().priv.toString());
            tempRes = await localCryptoVoteSelling.computeIndividualFakeZKP(G, [voters[i].xG[0], voters[i].xG[1]], [params[i*2], params[i*2+1]], y, H);
        }
        res.push(tempRes[0]);
        res.push(tempRes[1]);
        res.push(tempRes[2]);
        res.push(tempRes[3]);
    }
    return await localCryptoVoteSelling.computeORZKP.call(params, res, w, voters[voterIndex].x, y, H, voterIndex, {from: sender});
}

let generateVoteZKP = async (voters, localCryptoVoteSelling, H, voterIndex, voteOption, sender) => {
    let recomputedBases = [];
    let params = [];
    let res = [];
    let w = ec.genKeyPair().priv.toString();
    let y = await localCryptoVoteSelling.multiply.call(H, voters[voterIndex].x);
    for(let i = 0; i < voters.length; i++) {
        let tempRes, publicKey;
        if (voteOption) {
            publicKey = await localCryptoVoteSelling.computePublicKeyFromYesVote.call([voters[i].vote[0], voters[i].vote[1]]);
        } else {
            publicKey = [voters[i].vote[0], voters[i].vote[1]];
        }
        if (i == voterIndex) {
            tempRes = await localCryptoVoteSelling.computeIndividualRealZKP.call([voters[i].reconstructedKey[0], voters[i].reconstructedKey[1]], publicKey, w, H);
            params.push(0);
            params.push(0);
        } else {
            params.push(ec.genKeyPair().priv.toString());
            params.push(ec.genKeyPair().priv.toString());
            tempRes = await localCryptoVoteSelling.computeIndividualFakeZKP.call([voters[i].reconstructedKey[0], voters[i].reconstructedKey[1]], publicKey, [params[i*2], params[i*2+1]], y, H);
        }
        res.push(tempRes[0]);
        res.push(tempRes[1]);
        res.push(tempRes[2]);
        res.push(tempRes[3]);
    }
    return await localCryptoVoteSelling.computeORZKP.call(params, res, w, voters[voterIndex].x, y, H, voterIndex, {from: sender});
};

let getBalance = (web3, account) => {
    return new Promise((resolve, error) => {
        web3.eth.getBalance(account, (err, balance) => {
            if (err) {
                error(err);
            } else {
                resolve(balance);
            }
        });
    });
};

module.exports = {
    advanceBlock, increaseTime, getCurrentBlock, generateVoters, populateRecomputedKeys, generatePublicKeysZKP, generateVoteZKP, getBalance
}
