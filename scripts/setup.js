let AnonymousVoting = artifacts.require("AnonymousVoting");
let LocalCrypto = artifacts.require("LocalCrypto");
let utils = require("./utils");
let accounts = web3.eth.accounts;
let fs = require('mz/fs');

let simulate = async () => {
    let anonymousVoting, localCrypto, voters;
    localCrypto = await LocalCrypto.deployed();
    anonymousVoting = await AnonymousVoting.deployed();
    let n = parseInt(process.argv[4]);
    voters = await utils.generateVoters(accounts, n, localCrypto);
    await anonymousVoting.setEligible(voters.map(voter => voter.address));
    let gap = 3600;
    let finishSignup = (await utils.getCurrentBlock(web3)).timestamp + gap;
    let endSignup = finishSignup + gap;
    let endComputation = endSignup + gap;
    let endCommitment = endComputation + gap;
    let endVoting = endCommitment - 1 + gap;
    let endRefund = endVoting + gap;
    await anonymousVoting.beginSignUp("Should Satoshi Nakamoto reveal his identity?", false, finishSignup, endSignup, endCommitment, endVoting, endRefund, 0);
    utils.increaseTime(web3, gap * 0.5);
    utils.advanceBlock(web3);
    for(let i = 0; i < voters.length; i++) {
        await anonymousVoting.register(voters[i].xG, voters[i].vG, voters[i].r, {from: voters[i].address});
    }
    utils.increaseTime(web3, gap);
    utils.advanceBlock(web3);
    await anonymousVoting.finishRegistrationPhase();
    await utils.populateRecomputedKeys(voters, localCrypto, anonymousVoting);
    for (let i = 0; i < voters.length; i++) {
        await anonymousVoting.submitVote(voters[i].params, voters[i].vote, voters[i].a1, voters[i].b1, voters[i].a2, voters[i].b2, {from: voters[i].address});
    }
    await anonymousVoting.computeTally();
    await fs.writeFile("voters.json", JSON.stringify(voters));
}

module.exports = function(callback) {
    simulate().then(callback);
}
