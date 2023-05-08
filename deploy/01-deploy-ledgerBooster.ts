module.exports = async ({ getNamedAccounts, deployments }) => {
  const { deploy, log } = deployments;
  const { deployer } = await getNamedAccounts();

  const ledgerBooster = await deploy("LedgerBooster", {
    from: deployer,
    args: [],
    log: true,
    waitConfirmations: 1,
  });

  log("----------------------------------------------------------------");
};

module.exports.tags = ["all", "ledgerBooster"];
