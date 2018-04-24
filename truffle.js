module.exports = {
    networks: {
        development: {
            gas: 8000000,
            host: "localhost",
            port: 8545,
            accounts: 100,
            network_id: "*" // Match any network id
        }
    }
};
