module.exports = async ({ getNamedAccounts, deployments }) => {
  const { deploy, log } = deployments;
  const { deployer } = await getNamedAccounts();

  const ecRecover = await deploy("ecRecover", {
    from: deployer,
    args: [],
    log: true,
    waitConfirmations: 1,
  });

  log("----------------------------------------------------------------");
};

module.exports.tags = ["all", "ecRecover"];
