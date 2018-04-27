let AnonymousVoting = artifacts.require("AnonymousVoting");
let AnonymousVoteSelling = artifacts.require("AnonymousVoteSelling");
let LocalCrypto = artifacts.require("LocalCrypto");
let LocalCryptoVoteSelling = artifacts.require("LocalCryptoVoteSelling");
let utils = require("./utils");
let accounts = web3.eth.accounts;

let simulate = async (voteOption, n) => {
    let anonymousVoting, anonymousVoteSelling, localCrypto, localCryptoVoteSelling, voters, tx;
    voters = require("./voters.json");
    localCrypto = await LocalCrypto.deployed();
    anonymousVoting = await AnonymousVoting.deployed();
    localCryptoVoteSelling = await LocalCryptoVoteSelling.deployed();
    anonymousVoteSelling = await AnonymousVoteSelling.new(AnonymousVoting.address, false, "1000000000000000000", 13, voteOption, 0, 3600, {value:  (voteOption ? Math.floor(n/2) : Math.ceil(n/2)).toString() + "000000000000000000"});
    var H = [(await anonymousVoteSelling.H(0)).toString(10), (await anonymousVoteSelling.H(1)).toString(10)];
    let [y, res, params] = await utils.generatePublicKeysZKP(voters, localCryptoVoteSelling, H, (voteOption ? 1 : 0), accounts[40]);
    let gas = {n};
    tx = await anonymousVoteSelling.submitPublicKeysProof(y, params, res, {from: accounts[40]});
    gas.submissionCost = tx.receipt.gasUsed;
    [y, res, params] = await utils.generateVoteZKP(voters, localCryptoVoteSelling, H, (voteOption ? 1 : 0), voteOption, accounts[40]);
    tx = await anonymousVoteSelling.submitVoteProof(params, res, {from: accounts[40]});
    gas.submissionCost += tx.receipt.gasUsed;
    utils.increaseTime(web3, 13600);
    utils.advanceBlock(web3);
    tx = await anonymousVoteSelling.collectReward(accounts[41], {from: accounts[40]});
    gas.collectionCost = tx.receipt.gasUsed;
    gas.totalCost = gas.submissionCost + gas.collectionCost;
    console.log(gas);
}

module.exports = function(callback) {
    simulate(false, parseInt(process.argv[4])).then(callback);
}
