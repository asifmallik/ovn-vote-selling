let EC = require('elliptic').ec;
let ec = new EC('secp256k1');

let generateVoters = async (accounts, n, localCrypto) => {
    let voters = [];
    for(let i = 1; i < n+1; i++) {
        var key = ec.genKeyPair();
        var publicKey = key.getPublic();

        let voter = {
            address: web3.eth.accounts[i],
            x: key.priv.toString(),
            d: ec.genKeyPair().priv.toString(),
            r: ec.genKeyPair().priv.toString(),
            v: ec.genKeyPair().priv.toString(),
            w: ec.genKeyPair().priv.toString(),
            xG: [publicKey.getX().toString(), publicKey.getY().toString()]
        };
        let ZKP = await localCrypto.createZKP.call(voter.x, voter.v, voter.xG, {from: voter.address});
        voter.r = ZKP[0];
        voter.vG = ZKP.slice(1, 4);
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
        voters[i].reconstructedKey = reconstructedKey;
        voters[i].vote = [res[0], res[1]];
        voters[i].a1 = [res[2], res[3]];
        voters[i].b1 = [res[4], res[5]];
        voters[i].a2 = [res[6], res[7]];
        voters[i].b2 = [res[8], res[9]];
        voters[i].params = res2;
    }
}

let increaseTime = (addSeconds) => {
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


let advanceBlock = () => {
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

let getCurrentBlock = () => {
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
    for(let i = 0; i < voters.length; i++) {
        publicKeys.push(voters[i].xG[0].toString(10));
        publicKeys.push(voters[i].xG[1].toString(10));
        params.push(ec.genKeyPair().priv.toString());
        params.push(ec.genKeyPair().priv.toString());
    }
    let y = await localCryptoVoteSelling.multiply.call(H, voters[voterIndex].x);
    return await localCryptoVoteSelling.createZKPPublicKeys.call(publicKeys, params, ec.genKeyPair().priv.toString(), voters[voterIndex].x, y, H, voterIndex, {from: sender});
}

let generateVoteZKP = async (voters, localCryptoVoteSelling, H, voterIndex, voteOption, sender) => {
    let votes = [];
    let recomputedBases = [];
    let params = [];
    for(let i = 0; i < voters.length; i++) {
        recomputedBases.push(voters[i].reconstructedKey[0].toString(10))
        recomputedBases.push(voters[i].reconstructedKey[1].toString(10))
        votes.push(voters[i].vote[0].toString(10));
        votes.push(voters[i].vote[1].toString(10));
        params.push(ec.genKeyPair().priv.toString());
        params.push(ec.genKeyPair().priv.toString());
    }
    let y = await localCryptoVoteSelling.multiply.call(H, voters[voterIndex].x);
    return await localCryptoVoteSelling.createZKPVotes.call(recomputedBases, votes, params, ec.genKeyPair().priv.toString(), voters[voterIndex].x, y, H, voterIndex, voteOption, {from: sender});
};

let getBalance = (account) => {
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
