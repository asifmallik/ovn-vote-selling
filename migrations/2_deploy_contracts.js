let LocalCrypto = artifacts.require("./LocalCrypto.sol");
let LocalCryptoVoteSelling = artifacts.require("./LocalCryptoVoteSelling.sol");
let AnonymousVoting = artifacts.require("./AnonymousVoting.sol");
let AnonymousVoteSelling = artifacts.require("./AnonymousVoteSelling.sol");
let Secp256k1 = artifacts.require("./Secp256k1.sol");
let ECCMath = artifacts.require("./ECCMath.sol");
let Utils = artifacts.require("./Utils.sol");

module.exports = function(deployer) {
    deployer.deploy(ECCMath).then(() => {
        return deployer.link(ECCMath, [Secp256k1]);
    }).then(() => {
        return deployer.deploy(Secp256k1);
    }).then(() => {
        return deployer.link(Secp256k1, [AnonymousVoting, AnonymousVoteSelling, LocalCrypto, LocalCryptoVoteSelling, Utils]);
    }).then(() => {
        return deployer.deploy(Utils);
    }).then(() => {
        return deployer.link(Utils, [LocalCrypto, AnonymousVoting]);
    }).then(() => {
        return deployer.deploy(LocalCrypto);
    }).then(() => {
        return deployer.deploy(LocalCryptoVoteSelling);
    }).then(() => {
        return deployer.deploy(AnonymousVoting, 1, 0);
    });
};
